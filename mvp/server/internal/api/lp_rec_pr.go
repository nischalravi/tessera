package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Right-sizing recommendations as reviewable changes (issue #665, LP-9; design docs/design/differentiators-plan.md):
//
//	POST /api/lp/recommendations/{id}/pull-request  {unused_days}   open (or update) a pull request on the policy repository
//	GET  /api/lp/revocations/{id}/terraform                         a Terraform suggestion for an AWS right-size candidate
//
// The pull request. {id} is the numeric id of a grant recommendation (GET /api/least-privilege/recommendations: id "17" is "grant-17").
// It is computed again from the usage data now and must still be a "remove" or "redundant" recommendation of a grant the
// evaluator found unconditional (never approximate or conditional: the same gate as POST /api/least-privilege/revoke).
// The grant must be an entitlement of exactly one active business role, which the repository defines as
// roles/<key>.yaml. Tessera reads that file at the repository's default branch head, removes the entitlement, commits it
// to the branch tessera/rightsize-grant-<id> (cut from the head, or reused) and opens a pull request, then posts the
// policy check run of AC-10 on it. The body is deterministic and escapes every name from the estate (ghapp.RightSizeBody).
// Nothing is merged. The same recommendation never has two open pull requests: the mapping is stored (lp_rec_prs) and a
// repeat request updates the branch and the pull request in place; a closed pull request gets a new one on the same branch.
// The App's installation token is asked for contents:write besides checks and pull_requests, for the one repository, on
// this route only (ghapp.ContentsPermissions); the installation must have accepted that permission.
//
// It reaches outside Tessera with stored credentials, so it needs lp.manage with STEP_UP_POLICY and the App enabled; it
// is capped at lpRecPRHourlyCap new pull requests an hour per tenant and at the policy file size. The audit event
// (lp.recommendation.pull_request) is written in the transaction that records the mapping.
//
// The Terraform suggestion. {id} is a candidate of POST /api/lp/candidates: a verified right-size of one AWS managed policy.
// The answer is a narrowed aws_iam_policy resource for the user to paste into their own Terraform; nothing is written.
// A low-confidence candidate is refused, and so is one that is no longer open.

// lpSupersededNotice replaces the body of a pull request found on a commit Tessera did not make.
const lpSupersededNotice = "Superseded, do not merge: this branch was pushed by someone other than Tessera, so Tessera closed this pull request and did not check it."

const (
	lpRecPRHourlyCap = 20
	lpRecPRBranch    = "tessera/rightsize-"
)

func (s *Server) registerLPRecRoutes() {
	rt := s.handle(http.MethodPost, "/api/lp/recommendations/{id}/pull-request", phased, needStepUp(auth.PermLPManage, auth.StepUpPolicy), s.lpRecPullRequest)
	rt.timeout = s.cfg.PolicyDiffTimeout + 90*time.Second
	s.handle(http.MethodGet, "/api/lp/revocations/{id}/terraform", read, need(auth.PermGraphRead), s.rd(s.lpTerraform))
}

// ---------------------------------------------------------------- terraform

type lpTerraformView struct {
	ID            string `json:"id"`
	PolicyARN     string `json:"policy_arn"`
	Format        string `json:"format"`
	Snippet       string `json:"snippet"`
	SnippetSHA256 string `json:"snippet_sha256"`
	Confidence    string `json:"confidence"`
	UnusedDays    int    `json:"unused_days"`
}

func (s *Server) lpTerraform(r *http.Request, p *params) (int, any, error) {
	x, err := lpLoad(store.TxFrom(r.Context()), p.path["id"])
	if err != nil {
		return 0, nil, err
	}
	refuse := func(status int, code, msg string) (int, any, error) {
		return 0, nil, &readiness.Error{Status: status, Code: code, Msg: msg}
	}
	switch {
	case x.Kind != target.AWSSetPolicyVersion:
		return refuse(http.StatusUnprocessableEntity, "not_a_right_size", "only the right-size of a managed policy has a Terraform suggestion")
	case x.State != store.LPCandidate && x.State != store.LPAnnounced:
		return refuse(http.StatusConflict, "candidate_not_open", "the candidate is "+x.State+": a suggestion is made only for an open one")
	case x.Confidence != string(leastpriv.ConfHigh) && x.Confidence != string(leastpriv.ConfMedium):
		return refuse(http.StatusUnprocessableEntity, "confidence_too_low", "the evidence for the removed permissions is rated "+x.Confidence+": only high or medium is suggested")
	}
	var payload lpPayload
	if json.Unmarshal([]byte(x.RestorePayload), &payload) != nil || payload.Document == "" || payload.PolicyARN != x.PolicyARN {
		return refuse(http.StatusConflict, "candidate_unreadable", "the candidate holds no right-sized document")
	}
	removed := -1
	var ev struct {
		Diff struct {
			Removed *int `json:"permissions_removed"`
		} `json:"diff_summary"`
	}
	if json.Unmarshal([]byte(x.Evidence), &ev) == nil && ev.Diff.Removed != nil {
		removed = *ev.Diff.Removed
	}
	snippet, err := leastpriv.Terraform(leastpriv.TerraformInput{ID: x.ID, PolicyARN: x.PolicyARN, Document: payload.Document,
		UnusedDays: x.UnusedDays, Confidence: x.Confidence, Removed: removed})
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "no_terraform_suggestion", err.Error())
	}
	sum := sha256.Sum256([]byte(snippet))
	return http.StatusOK, lpTerraformView{ID: x.ID, PolicyARN: x.PolicyARN, Format: "hcl", Snippet: snippet,
		SnippetSHA256: hex.EncodeToString(sum[:]), Confidence: x.Confidence, UnusedDays: x.UnusedDays}, nil
}

// ---------------------------------------------------------------- pull request

type lpRecPRIn struct {
	UnusedDays int `json:"unused_days"`
}

type lpRecPRView struct {
	Status           string   `json:"status"` // opened | updated
	RecommendationID string   `json:"recommendation_id"`
	Repo             string   `json:"repo"`
	Branch           string   `json:"branch"`
	BaseBranch       string   `json:"base_branch"`
	PullNumber       int      `json:"pull_number"`
	PullURL          string   `json:"pull_url,omitempty"`
	HeadSHA          string   `json:"head_sha"`
	Committed        bool     `json:"committed"`
	File             string   `json:"file"`
	Entitlement      string   `json:"entitlement"`
	Conclusion       string   `json:"conclusion"`
	CheckRunID       int64    `json:"check_run_id"`
	Title            string   `json:"title"`
	BodySHA256       string   `json:"body_sha256"`
	DiffSHA256       string   `json:"diff_sha256"`
	Reasons          []string `json:"reasons"`
}

// lpRecPlan is what the read phase works out: the recommendation, the file to edit and its rendering.
type lpRecPlan struct {
	rs       ghapp.RightSize
	file     string
	group    string
	preview  ghapp.Preview
	verdict  ghapp.Verdict
	diffSHA  string
	bundle   string
	prev     *store.LPRecPR
	prevChk  *store.GitHubPRCheck
	settings *store.GitHubAppSettings
	edited   []byte // Tessera's export of the role file with the edit
	// closedSeen: the recorded pull request was found closed on GitHub
	closedSeen bool
}

func lpRefuse(status int, code, msg string) error {
	return &readiness.Error{Status: status, Code: code, Msg: msg}
}

func (s *Server) lpRecPullRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var in lpRecPRIn
	if err := decodeBody(r, &in, true); err != nil {
		return nil, err
	}
	if in.UnusedDays == 0 {
		in.UnusedDays = 60
	}
	if in.UnusedDays < 1 || in.UnusedDays > 90 {
		return nil, badRequest("invalid_unused_days", "unused_days is 1 to 90")
	}
	edgeID, err := strconv.ParseInt(p.path["id"], 10, 64)
	if err != nil || edgeID < 1 || strconv.FormatInt(edgeID, 10) != p.path["id"] {
		return nil, badRequest("invalid_recommendation_id", "the recommendation id is the number GET /api/least-privilege/recommendations shows for a grant")
	}
	recID := "grant-" + p.path["id"]
	pr := principal(r)
	ctx := r.Context()
	now := s.clock()
	client, err := s.githubClient(s.clock)
	if err != nil {
		return nil, err
	}

	var plan *lpRecPlan
	err = p.scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		plan, err = s.lpRecPlanOf(ctx, tx, recID, edgeID, in.UnusedDays, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	st := plan.settings
	branch := lpRecPRBranch + recID

	// reserve one of the hourly attempts before GitHub is called, so a request that fails, repeats or races still counts
	var reserved bool
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		var err error
		if reserved, err = c.ReserveLPRecPRAttempt(recID, st.Repo, pr.Display, now, now.Add(-time.Hour), lpRecPRHourlyCap); err != nil || !reserved {
			return err
		}
		return c.Audit(now, pr.Display, "lp.recommendation.pull_request.attempt", ojson.Object{{Key: "recommendation_id", Value: recID},
			{Key: "repo", Value: st.Repo}, {Key: "branch", Value: branch}})
	}); err != nil {
		return nil, err
	}
	if !reserved {
		return nil, lpRefuse(http.StatusTooManyRequests, "pull_request_rate_limited", "too many right-sizing pull request attempts in the last hour")
	}

	pemKey, err := s.cfg.Sealer.Open(st.KeyEnc, githubKeyAAD(p.scope.Tenant))
	if err != nil {
		s.log.Error("github app key cannot be opened")
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be opened; set it again"}
	}
	key, err := ghapp.ParseKey(pemKey)
	if err != nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be read; set it again"}
	}
	cr := &ghapp.Credentials{AppID: st.AppID, InstallationID: st.InstallationID, Repo: st.Repo, Key: key, Scope: p.scope.Tenant.String(),
		KeyID: st.KeyFingerprint, Contents: true}
	gctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	out, pub, gerr := s.lpPublish(gctx, client, cr, plan, branch)
	if out != nil {
		out.RecommendationID, out.Repo, out.Branch, out.File, out.Entitlement = recID, st.Repo, branch, plan.file, plan.group
		out.Conclusion, out.DiffSHA256, out.Reasons = plan.verdict.Conclusion, plan.diffSHA, plan.verdict.Reasons
	}

	detail := ojson.Object{{Key: "recommendation_id", Value: recID}, {Key: "repo", Value: st.Repo}, {Key: "branch", Value: branch},
		{Key: "file", Value: plan.file}, {Key: "entitlement", Value: plan.group}, {Key: "role", Value: plan.rs.RoleKey},
		{Key: "identity", Value: plan.rs.IdentityName}, {Key: "unused_days", Value: in.UnusedDays},
		{Key: "conclusion", Value: plan.verdict.Conclusion}, {Key: "diff_sha256", Value: plan.diffSHA}, {Key: "bundle_sha256", Value: plan.bundle}}
	action, code := "lp.recommendation.pull_request", ""
	if gerr != nil {
		action, code = "lp.recommendation.pull_request.failed", ghapp.ErrCode(gerr)
		detail = append(detail, ojson.KV{Key: "error", Value: code})
	}
	if out != nil && out.HeadSHA != "" {
		detail = append(detail, ojson.KV{Key: "pull_number", Value: out.PullNumber}, ojson.KV{Key: "head_sha", Value: out.HeadSHA},
			ojson.KV{Key: "committed", Value: out.Committed}, ojson.KV{Key: "status", Value: out.Status})
	}
	werr := p.scope.Write(ctx, func(c *store.TenantTx) error {
		if out != nil && out.HeadSHA != "" {
			// the branch head is recorded even when no pull request exists yet: it is what the next request verifies the branch against
			if err := c.PutLPRecPR(&store.LPRecPR{RecID: recID, Repo: st.Repo, Branch: branch, PullNumber: out.PullNumber, HeadSHA: out.HeadSHA,
				RoleKey: plan.rs.RoleKey, BodySHA256: out.BodySHA256, State: store.LPRecPROpen, CreatedBy: pr.Display}, now); err != nil {
				return err
			}
			if pub != nil && pub.CheckRunID > 0 && out.PullNumber > 0 {
				if err := c.PutGitHubPRCheck(&store.GitHubPRCheck{Repo: st.Repo, PullNumber: out.PullNumber, HeadSHA: out.HeadSHA, CheckRunID: pub.CheckRunID,
					Conclusion: plan.verdict.Conclusion, DiffSHA256: plan.diffSHA}, now); err != nil {
					return err
				}
			}
		}
		if plan.closedSeen && (out == nil || out.HeadSHA == "") && plan.prev != nil {
			// the pull request was closed on GitHub: say so, so the next request does not look for it
			cl := *plan.prev
			cl.State = store.LPRecPRClosed
			if err := c.PutLPRecPR(&cl, now); err != nil {
				return err
			}
		}
		return c.Audit(now, pr.Display, action, detail)
	})
	if werr != nil {
		s.log.Error("lp recommendation pull request audit failed", "err", werr)
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "audit_unavailable", Msg: "the outcome could not be recorded"}
	}
	audit.Mark(ctx, "lp_recommendation_pr_conclusion", plan.verdict.Conclusion)
	if gerr != nil {
		return nil, githubFailure(gerr, "the pull request could not be opened on GitHub", map[string]any{"reason": code})
	}
	return out, nil
}

// githubFailure maps a GitHub client error to the API's answer.
func githubFailure(err error, msg string, extra map[string]any) error {
	var rl *ghapp.RateLimitError
	status, code := http.StatusBadGateway, "github_failed"
	switch {
	case errors.As(err, &rl):
		status, code = http.StatusServiceUnavailable, "github_rate_limited"
	case errors.Is(err, ghapp.ErrBranchConflict):
		status, code = http.StatusConflict, "branch_conflict"
	case errors.Is(err, ghapp.ErrPullConflict):
		status, code = http.StatusConflict, "pull_request_conflict"
	case errors.Is(err, ghapp.ErrFileNotFound):
		status, code = http.StatusUnprocessableEntity, "role_file_not_in_repo"
	case errors.Is(err, policybundle.ErrEntitlementAbsent):
		status, code = http.StatusConflict, "entitlement_not_in_repo"
	case errors.Is(err, ghapp.ErrNotAFile), errors.Is(err, policybundle.ErrRoleUnreadable):
		status, code = http.StatusUnprocessableEntity, "role_file_unreadable"
	case errors.Is(err, ghapp.ErrPullNotFound):
		status, code = http.StatusUnprocessableEntity, "pull_request_not_found"
	}
	return &readiness.Error{Status: status, Code: code, Msg: msg, Extra: extra}
}

// lpRecPlanOf works out, in a read transaction, what the pull request changes and says.
func (s *Server) lpRecPlanOf(ctx context.Context, tx *store.TenantTx, recID string, edgeID int64, days int, _ time.Time) (*lpRecPlan, error) {
	st, err := tx.GitHubAppSettings()
	if err != nil {
		return nil, err
	}
	if !st.Enabled || st.AppID == "" || st.InstallationID < 1 || st.Repo == "" || len(st.KeyEnc) == 0 {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "github_app_disabled", Msg: "the GitHub App is not configured and enabled for this tenant (PUT /api/policy/github/app)"}
	}
	pl := &lpRecPlan{settings: st}
	// the cap is checked before the work of the preview (the reservation before GitHub is the one that counts)
	if n, err := tx.LPRecPRAttemptsSince(s.clock().Add(-time.Hour)); err != nil {
		return nil, err
	} else if n >= lpRecPRHourlyCap {
		return nil, lpRefuse(http.StatusTooManyRequests, "pull_request_rate_limited", "too many right-sizing pull request attempts in the last hour")
	}
	if pl.prev, err = tx.LPRecPR(recID, st.Repo); err != nil {
		return nil, err
	}
	a, err := s.newAnalysis(tx)
	if err != nil {
		return nil, err
	}
	var rec *leastpriv.Recommendation
	for _, c := range leastpriv.GrantRecommendations(a.g, a.u, days, nil) {
		if c.EdgeID == edgeID {
			c := c
			rec = &c
			break
		}
	}
	if rec == nil {
		return nil, lpRefuse(http.StatusNotFound, "recommendation_not_found", "no right-sizing recommendation for that grant at this usage window: the grant may have changed or been used")
	}
	if rec.Kind != "remove" && rec.Kind != "redundant" {
		return nil, lpRefuse(http.StatusUnprocessableEntity, "not_removable", "only a recommendation to remove a grant (nothing it gives was used) becomes a pull request; a right-size is a suggestion")
	}
	e, err := getOrNil(tx.Edge(edgeID))
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, lpRefuse(http.StatusNotFound, "recommendation_not_found", "grant not found")
	}
	if e.Outcome == graph.OutcomeConditional || e.Fidelity == graph.FidelityApprox || e.Fidelity == graph.FidelityUnsupp {
		return nil, lpRefuse(http.StatusUnprocessableEntity, "confidence_too_low", "the grant rests on a conditional or approximate evaluation: only an exact one is changed by a pull request")
	}
	kind, gid, err := graph.ParseKey(e.Dst)
	if err != nil || kind != "group" || e.Source != "role" || rec.IdentityID == nil {
		return nil, lpRefuse(http.StatusUnprocessableEntity, "not_policy_managed", "the grant is not a group membership made by a business role, so no file in the policy repository defines it")
	}
	groups, err := tx.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.ID == gid {
			pl.group = g.System + ":" + g.Name
		}
	}
	if pl.group == "" {
		return nil, lpRefuse(http.StatusNotFound, "recommendation_not_found", "the group of the grant does not exist")
	}
	rs, err := tx.BusinessRoles()
	if err != nil {
		return nil, err
	}
	var role *store.BusinessRole
	var roleMembers []*store.RoleMember
	for _, br := range rs {
		if br.Status != store.RoleActive || br.Key == "" {
			continue
		}
		ents, err := tx.RoleEntitlements(br.ID)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(ents, gid) {
			continue
		}
		ms, err := tx.RoleMembers(br.ID)
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(ms, func(m *store.RoleMember) bool { return m.IdentityID == *rec.IdentityID }) {
			continue
		}
		if role != nil {
			return nil, lpRefuse(http.StatusUnprocessableEntity, "ambiguous_role", "more than one of the identity's business roles grants that group: remove it from the right one by hand")
		}
		role, roleMembers = br, ms
	}
	if role == nil {
		return nil, lpRefuse(http.StatusUnprocessableEntity, "not_policy_managed", "no business role the identity holds grants that group, so the policy repository has no file that defines the grant")
	}
	members := roleMembers
	if ents, err := tx.RoleEntitlements(role.ID); err != nil {
		return nil, err
	} else if len(ents) < 2 {
		return nil, lpRefuse(http.StatusUnprocessableEntity, "role_would_be_empty", "the group is the role's only entitlement, and a role file grants at least one: retire the role instead")
	}
	pl.file = policybundle.DirRoles + "/" + role.Key + ".yaml"
	if !ghapp.ValidPath(pl.file) {
		return nil, lpRefuse(http.StatusUnprocessableEntity, "not_policy_managed", "the role's key is not a usable file name")
	}

	// the same edit on the files Tessera exports: the policy diff of the result is the change's blast radius
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	files, err := rolesascode.Export(tx, t.Slug)
	if err != nil {
		return nil, bundleErr(err)
	}
	edited, err := policybundle.RemoveRoleEntitlement(files[pl.file], pl.group)
	if err != nil {
		return nil, lpRefuse(http.StatusConflict, "role_not_exportable", "the role's file does not list the entitlement")
	}
	if len(edited) > ghapp.MaxFileBytes {
		return nil, lpRefuse(http.StatusRequestEntityTooLarge, "file_too_large", "the edited role file is over the size limit")
	}
	files[pl.file] = edited
	pl.edited = edited
	strFiles := make(map[string]string, len(files))
	for pth, b := range files {
		strFiles[pth] = string(b)
	}
	view, extras, err := s.computePolicyDiff(ctx, tx, &policyDiffIn{Files: strFiles})
	if err != nil {
		return nil, err
	}
	pl.preview = previewOf(view, extras)
	pl.verdict = ghapp.Evaluate(pl.preview)
	pl.diffSHA, pl.bundle = view.DiffSHA256, view.BundleSHA256

	if pl.prev != nil && pl.prev.PullNumber > 0 {
		if pl.prevChk, err = tx.GitHubPRCheck(st.Repo, pl.prev.PullNumber); err != nil {
			return nil, err
		}
	}

	perms := append([]string(nil), rec.UnusedExamples...)
	sort.Strings(perms)
	pl.rs = ghapp.RightSize{RecID: recID, Kind: rec.Kind, IdentityName: rec.IdentityName, IdentityType: rec.IdentityType, Grant: rec.Grant,
		Group: pl.group, RoleKey: role.Key, RoleFile: pl.file, RoleMembers: len(members), Permissions: perms,
		PermissionsLost: rec.PermissionsLost, UnusedLost: rec.UnusedLost, UsedLost: rec.UsedLost, UnusedDays: days,
		Fidelity: graph.FidelityExact, ExplanationID: rec.ExplanationID, Preview: pl.preview}
	if rec.LastUsed != nil {
		pl.rs.LastUsed = *rec.LastUsed
	}
	return pl, nil
}

// lpPublish does the GitHub half with no transaction open: branch, commit, pull request, check run. It returns what was
// done even when a later step failed (the branch is committed but the pull request was not opened).
//
// Nothing already on the repository is trusted. A branch of the name that exists is used only when its tip is the commit
// Tessera recorded (or it holds no commit of its own) and its comparison with the base shows no file but the role file
// changed; otherwise the request is refused with branch_conflict and nothing is written (delete the branch on GitHub to
// start again: Tessera never force-resets a ref). An open pull request on the branch is adopted only when the App opened it
// and its head is the verified tip; the check run is posted only on a commit Tessera made or verified. The verdict comes
// from Tessera's export with the same edit; when the repository's file is not that export the body says so and the check
// is neutral.
func (s *Server) lpPublish(ctx context.Context, c *ghapp.Client, cr *ghapp.Credentials, pl *lpRecPlan, branch string) (*lpRecPRView, *ghapp.Published, error) {
	base, err := c.DefaultBranch(ctx, cr)
	if err != nil {
		return nil, nil, err
	}
	baseHead, err := c.BranchHead(ctx, cr, base)
	if err != nil {
		return nil, nil, err
	}
	// the file as the repository has it now, edited the same way
	repoFile, err := c.GetFile(ctx, cr, pl.file, baseHead)
	if err != nil {
		return nil, nil, err
	}
	want, err := policybundle.RemoveRoleEntitlement(repoFile.Content, pl.group)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(want, pl.edited) {
		pl.rs.RepoDiffers = true
		pl.verdict = ghapp.Verdict{Conclusion: ghapp.Neutral, Reasons: append([]string{"The role file in the repository differs from the one Tessera exports, so the simulation is of Tessera's export with the same edit."}, pl.verdict.Reasons...)}
	}
	title, body := ghapp.RightSizeTitle(pl.rs), ghapp.RightSizeBody(pl.rs)
	bodySum := sha256.Sum256([]byte(body))
	out := &lpRecPRView{BaseBranch: base, Title: title, BodySHA256: hex.EncodeToString(bodySum[:])}

	slug, err := c.AppSlug(ctx, cr)
	if err != nil {
		return nil, nil, err
	}
	bot := slug + "[bot]"

	// the branch: accept an existing one only after verifying it (a new one is created at the commit, below)
	tip, err := c.BranchHead(ctx, cr, branch)
	isNew := errors.Is(err, ghapp.ErrBranchNotFound)
	switch {
	case isNew:
		tip = baseHead
	case err != nil:
		return nil, nil, err
	default:
		cmp, err := c.CompareBranch(ctx, cr, base, tip)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range cmp.Files {
			if f != pl.file {
				return nil, nil, ghapp.ErrBranchConflict
			}
		}
		if (pl.prev == nil || pl.prev.HeadSHA != tip) && cmp.AheadBy != 0 {
			return nil, nil, ghapp.ErrBranchConflict
		}
	}

	// the pull request: the recorded one while it is open, else the App's own among those open on the branch, else a new one
	var pull *ghapp.Pull
	if !isNew {
		if pl.prev != nil && pl.prev.State == store.LPRecPROpen && pl.prev.PullNumber > 0 {
			if pull, err = c.GetPull(ctx, cr, pl.prev.PullNumber); err != nil && !errors.Is(err, ghapp.ErrPullNotFound) {
				return nil, nil, err
			}
			if pull != nil && pull.State != "open" {
				pl.closedSeen, pull = true, nil
			}
		}
		if pull == nil {
			open, err := c.FindOpenPulls(ctx, cr, branch, base)
			if err != nil {
				return nil, nil, err
			}
			for _, o := range open {
				if o.Author == bot {
					pull = o
					break
				}
			}
			if pull == nil && len(open) > 0 {
				return nil, nil, ghapp.ErrPullConflict // someone else's pull request is open on our branch
			}
		}
		if pull != nil && (pull.Author != bot || pull.HeadSHA != tip) {
			return nil, nil, ghapp.ErrPullConflict
		}
	}

	// the commit, made on the verified tip through the Git Data API and moved onto the branch without force, so a push that
	// landed after the verification makes the move fail (branch_conflict) rather than sit under Tessera's commit
	head := tip
	if isNew {
		if head, err = c.CommitFile(ctx, cr, pl.file, baseHead, ghapp.RightSizeCommitMessage(pl.rs), want); err != nil {
			return nil, nil, err
		}
		if err = c.CreateBranchAt(ctx, cr, branch, head); err != nil {
			return nil, nil, err
		}
		out.Committed = true
	} else {
		onBranch, err := c.GetFile(ctx, cr, pl.file, tip)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(onBranch.Content, want) {
			if head, err = c.CommitFile(ctx, cr, pl.file, tip, ghapp.RightSizeCommitMessage(pl.rs), want); err != nil {
				return nil, nil, err
			}
			if err = c.MoveBranch(ctx, cr, branch, head); err != nil {
				return nil, nil, err
			}
			out.Committed = true
		}
	}
	out.HeadSHA = head

	// the pull request must be at the head Tessera made or verified before anything is posted or recorded
	if pull != nil {
		// read its head again right before the body is replaced: not at the commit Tessera made or verified, no update
		cur, err := c.GetPull(ctx, cr, pull.Number)
		if err != nil {
			return out, nil, err
		}
		if cur.State != "open" || cur.HeadSHA != head {
			return nil, nil, ghapp.ErrPullConflict
		}
		if pull, err = c.UpdatePull(ctx, cr, pull.Number, title, body); err != nil {
			return out, nil, err
		}
		out.Status = "updated"
	} else {
		var exists bool
		if pull, exists, err = c.CreatePull(ctx, cr, title, branch, base, body); err != nil {
			return out, nil, err
		}
		if exists { // opened by someone between the search and the create: not adopted
			return out, nil, ghapp.ErrPullConflict
		}
		out.Status = "opened"
	}
	if pull.HeadSHA != head {
		// GitHub has published Tessera's title and body on a commit that is not Tessera's: replace them and close the pull
		// request (a failure to do so is not hidden; the request still ends in the conflict, which is audited)
		_ = c.ClosePull(ctx, cr, pull.Number, lpSupersededNotice)
		return nil, nil, ghapp.ErrPullConflict
	}
	out.PullNumber, out.PullURL = pull.Number, pull.HTMLURL

	// the policy check of AC-10 on the head Tessera made or verified: updated in place on the same commit
	chk := ghapp.Check{HeadSHA: head, Conclusion: pl.verdict.Conclusion, Title: ghapp.Title(pl.preview, pl.verdict),
		Summary: ghapp.Summary(pl.preview, pl.verdict, head)}
	pub := &ghapp.Published{HeadSHA: head}
	if pc := pl.prevChk; pc != nil && pc.CheckRunID > 0 && pc.HeadSHA == head && pc.PullNumber == pull.Number {
		err = c.UpdateCheckRun(ctx, cr, pc.CheckRunID, chk)
		switch {
		case err == nil:
			pub.CheckRunID = pc.CheckRunID
		case ghapp.IsStatus(err, http.StatusNotFound):
			err = nil
		default:
			return out, nil, err
		}
	}
	if pub.CheckRunID == 0 {
		if pub.CheckRunID, pub.CheckURL, err = c.CreateCheckRun(ctx, cr, chk); err != nil {
			return out, nil, err
		}
		pub.CheckCreated = true
	}
	out.CheckRunID = pub.CheckRunID
	return out, pub, nil
}
