package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/syncverify"
)

// Merge sync, prediction check and rollback (issue #657, AC-11; design docs/design/access-as-code-repo.md sections 6-8):
//
//	GET  /api/policy/github/sync      the last synced commit, the latest syncs with their prediction check, and the
//	                                  findings of a check that did not match (connections.read)
//	POST /api/policy/github/sync      {sha}: read the policy bundle at that commit of the default branch and file ONE change
//	                                  request (policy.sync.apply) carrying the plan digest, the commit and the prediction
//	POST /api/policy/github/rollback  {to_sha}: the same for the bundle of an earlier commit Tessera applied, so the plan
//	                                  returns to that state
//
// There is no webhook: an authenticated caller triggers the sync (a tenant admin with a fresh step-up, or CI holding the
// scope tessera:policy-sync, which can file and never approve). Tessera reads the bundle itself through the AC-10 GitHub
// App (a token for the one configured repository with contents:read only), after checking the commit is the head of the
// default branch or one of its ancestors (409 sha_not_on_default_branch) and, for a sync, a descendant of the commit last
// synced (409 not_a_descendant). The preview is the AC-8 blast-radius answer; its predicted permission changes and
// violations are stored in the request. Applying needs a different human admin with a step-up (two people, #569);
// the apply and the prediction check run in one transaction, record the commit and mark the sync verified or raise findings.
// A commit is filed once: a repeat while the request is open, or after it was applied and is still the last sync, answers the
// same sync (200). Bundles are capped as policybundle caps them (2,000 files, 4 MiB, 256 KiB per file).

func (s *Server) registerPolicySyncRoutes() {
	s.handle(http.MethodGet, "/api/policy/github/sync", read, need(auth.PermConnectionsRead), s.rd(s.getPolicySync))
	// phased: GitHub is called with no transaction open; the request is filed by internal/admin in its own
	for _, path := range []string{"/api/policy/github/sync", "/api/policy/github/rollback"} {
		rt := s.handle(http.MethodPost, path, phased, need(auth.PermPolicySync), s.policySyncTrigger(strings.HasSuffix(path, "rollback")))
		rt.answersRead = true
		rt.timeout = s.cfg.PolicyDiffTimeout + 90*time.Second
	}
}

// policySyncTopLevel are the names at the top of the repository a bundle is read from.
var policySyncTopLevel = []string{policybundle.ConfigFile, "schema", policybundle.DirRoles, policybundle.DirBirthright, policybundle.DirJit,
	policybundle.DirSod, policybundle.DirAgents, policybundle.DirInvariants, policybundle.DirTests}

func policySyncKeep(p string) bool {
	if p == policybundle.ConfigFile || p == policybundle.SchemaFile {
		return true
	}
	top, _, ok := strings.Cut(p, "/")
	if !ok || top == "schema" {
		return false
	}
	for _, d := range policySyncTopLevel[2:] {
		if top == d {
			return true
		}
	}
	return false
}

type policySyncView struct {
	ID           string          `json:"id"`
	Repo         string          `json:"repo"`
	SHA          string          `json:"sha"`
	Kind         string          `json:"kind"`
	RollbackFrom string          `json:"rollback_from,omitempty"`
	ChangeID     string          `json:"change_id"`
	ChangeStatus string          `json:"change_status"`
	BundleSHA256 string          `json:"bundle_sha256"`
	PlanSHA256   string          `json:"plan_sha256"`
	RequestedBy  string          `json:"requested_by"`
	CreatedAt    string          `json:"created_at"`
	AppliedAt    any             `json:"applied_at"`
	CheckStatus  string          `json:"check_status"`
	CheckedAt    any             `json:"checked_at"`
	Check        json.RawMessage `json:"check"`
	Prediction   json.RawMessage `json:"prediction"`
	Findings     int             `json:"findings"`
	// FindingList is the first findings of a check that did not match.
	FindingList []policySyncFindingView `json:"finding_list,omitempty"`
}

type policySyncFindingView struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Predicted string `json:"predicted"`
	Observed  string `json:"observed"`
	RaisedAt  string `json:"raised_at"`
}

// predictionSummary is the counts of a stored prediction, without its lists.
func predictionSummary(raw string) json.RawMessage {
	var p syncverify.Prediction
	if json.Unmarshal([]byte(raw), &p) != nil {
		return json.RawMessage(`{}`)
	}
	b, _ := json.Marshal(map[string]any{"diff_sha256": p.DiffSHA256, "permission_changes": p.PermsTotal, "identities_affected": p.IdentitiesAffected,
		"violations_before": p.ViolationsBefore, "violations_after": p.ViolationsAfter, "violations_introduced": p.IntroducedTotal,
		"violations_resolved": p.ResolvedTotal})
	return b
}

func syncViewOf(tx *store.TenantTx, sy *store.PolicySync, withFindings bool) (*policySyncView, error) {
	v := &policySyncView{ID: sy.ID, Repo: sy.Repo, SHA: sy.SHA, Kind: sy.Kind, RollbackFrom: sy.RollbackFrom, ChangeID: sy.ChangeID,
		ChangeStatus: sy.ChangeStatus, BundleSHA256: sy.BundleSHA256, PlanSHA256: sy.PlanSHA256, RequestedBy: sy.RequestedBy,
		CreatedAt: rt3339(sy.CreatedAt), AppliedAt: opt(sy.AppliedAt), CheckStatus: sy.CheckStatus, CheckedAt: opt(sy.CheckedAt),
		Check: json.RawMessage(sy.CheckDetail), Prediction: predictionSummary(sy.Prediction)}
	if !json.Valid(v.Check) {
		v.Check = json.RawMessage(`{}`)
	}
	fs, n, err := tx.PolicySyncFindings(sy.ID, 50)
	if err != nil {
		return nil, err
	}
	v.Findings = n
	if withFindings {
		for _, f := range fs {
			v.FindingList = append(v.FindingList, policySyncFindingView{Kind: f.Kind, Subject: f.Subject, Predicted: f.Predicted,
				Observed: f.Observed, RaisedAt: rt3339(f.RaisedAt)})
		}
	}
	return v, nil
}

func (s *Server) getPolicySync(r *http.Request, _ *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	st, err := tx.GitHubAppSettings()
	if err != nil {
		return 0, nil, err
	}
	out := map[string]any{"enabled": st.Enabled, "repo": st.Repo, "last_synced": nil, "syncs": []*policySyncView{}}
	if st.Repo == "" {
		return http.StatusOK, out, nil
	}
	last, err := tx.LastPolicySync(st.Repo)
	if err != nil {
		return 0, nil, err
	}
	if last != nil {
		lv, err := syncViewOf(tx, last, true)
		if err != nil {
			return 0, nil, err
		}
		out["last_synced"] = lv
	}
	recent, err := tx.RecentPolicySyncs(st.Repo, 20)
	if err != nil {
		return 0, nil, err
	}
	views := make([]*policySyncView, 0, len(recent))
	for _, sy := range recent {
		v, err := syncViewOf(tx, sy, sy.CheckStatus == store.PolicySyncMismatch)
		if err != nil {
			return 0, nil, err
		}
		views = append(views, v)
	}
	out["syncs"] = views
	return http.StatusOK, out, nil
}

// terminalWithoutApply reports a change request that ended and did not apply: its commit may be filed again.
func terminalWithoutApply(status string) bool {
	switch status {
	case store.ChangeRejected, store.ChangeCancelled, store.ChangeExpired, store.ChangeFailed:
		return true
	}
	return false
}

func (s *Server) policySyncTrigger(rollback bool) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		var in struct {
			SHA   string `json:"sha"`
			ToSHA string `json:"to_sha"`
		}
		if err := decodeBody(r, &in, false); err != nil {
			return nil, err
		}
		sha, field := in.SHA, "sha"
		if rollback {
			sha, field = in.ToSHA, "to_sha"
		}
		if !ghapp.ValidSHA(sha) {
			return nil, badRequest("invalid_"+field, field+" must be the full commit id in lower-case hex")
		}
		return s.policySync(r, p, sha, rollback)
	}
}

func syncGitHubErr(err error, msg string) error {
	switch {
	case errors.Is(err, ghapp.ErrCommitNotFound):
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "commit_not_found", Msg: "GitHub does not know that commit"}
	case errors.Is(err, ghapp.ErrBundleTooLarge):
		return &readiness.Error{Status: http.StatusRequestEntityTooLarge, Code: "bundle_too_large",
			Msg: "the policy bundle at that commit is larger than a bundle may be (2,000 files, 4 MiB, 256 KiB per file)"}
	case errors.Is(err, ghapp.ErrNotAFile):
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "bundle_unreadable",
			Msg: "a file of the policy bundle at that commit is not a regular file the repository API returns"}
	}
	return githubFailure(err, msg, map[string]any{"reason": ghapp.ErrCode(err)})
}

func (s *Server) policySync(r *http.Request, p *params, sha string, rollback bool) (any, error) {
	ctx := r.Context()
	pr := principal(r)
	now := s.clock()
	kind := admin.SyncKindSync
	if rollback {
		kind = admin.SyncKindRollback
	}
	client, err := s.githubClient(s.clock)
	if err != nil {
		return nil, err
	}

	// the settings, what was synced before, and whether this commit is filed already
	var st *store.GitHubAppSettings
	var last, existing, target *store.PolicySync
	var tenantSlug string
	err = p.scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		if st, err = tx.GitHubAppSettings(); err != nil {
			return err
		}
		if !st.Enabled || st.AppID == "" || st.InstallationID < 1 || st.Repo == "" || len(st.KeyEnc) == 0 {
			return &readiness.Error{Status: http.StatusConflict, Code: "github_app_disabled", Msg: "the GitHub App is not configured and enabled for this tenant (PUT /api/policy/github/app)"}
		}
		if last, err = tx.LastPolicySync(st.Repo); err != nil {
			return err
		}
		if rollback {
			var err error
			target, err = tx.AppliedPolicySync(st.Repo, sha)
			if err != nil {
				return err
			}
			if target == nil {
				return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "rollback_target_unknown",
					Msg: "a rollback returns to a commit Tessera applied before; that commit was never synced"}
			}
			if last == nil || last.SHA == sha {
				return &readiness.Error{Status: http.StatusConflict, Code: "already_at_commit", Msg: "the last synced commit is already that commit"}
			}
		}
		if existing, err = tx.PolicySyncByKey(st.Repo, sha, kind); err != nil {
			return err
		}
		t, err := tx.TenantRecord()
		if err != nil {
			return err
		}
		tenantSlug = t.Slug
		return nil
	})
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.ActiveKey != "" {
		if terminalWithoutApply(existing.ChangeStatus) {
			// free the commit so it can be filed again (a failed apply has no afterEnd hook)
			if err := p.scope.Write(ctx, func(c *store.TenantTx) error { return c.ClosePolicySync(existing.ChangeID) }); err != nil {
				return nil, err
			}
		} else if existing.AppliedAt == nil || (last != nil && last.ID == existing.ID) {
			// idempotent: the same commit is open, or applied and still the last sync
			var v *policySyncView
			err := p.scope.Read(ctx, func(tx *store.TenantTx) error {
				var err error
				v, err = syncViewOf(tx, existing, true)
				return err
			})
			if err != nil {
				return nil, err
			}
			audit.Mark(ctx, "policy_sync_existing", true)
			return map[string]any{"status": "existing", "sync": v}, nil
		}
	}

	// GitHub, with no transaction open: the commit must be on the default branch; then the bundle is read
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
		KeyID: st.KeyFingerprint, ContentsRead: true}
	gctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	branch, err := client.DefaultBranch(gctx, cr)
	if err != nil {
		return nil, syncGitHubErr(err, "the default branch could not be read from GitHub")
	}
	on, err := client.OnBranch(gctx, cr, sha, branch)
	if err != nil {
		return nil, syncGitHubErr(err, "the commit could not be compared with the default branch on GitHub")
	}
	if !on {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "sha_not_on_default_branch",
			Msg: "that commit is not the head of the default branch or one of its ancestors", Extra: map[string]any{"default_branch": branch}}
	}
	if !rollback && last != nil && last.SHA != sha {
		rel, err := client.Relate(gctx, cr, last.SHA, sha)
		if err != nil {
			return nil, syncGitHubErr(err, "the commit could not be compared with the last synced commit on GitHub")
		}
		if rel.Status != "ahead" || rel.BehindBy != 0 {
			return nil, &readiness.Error{Status: http.StatusConflict, Code: "not_a_descendant",
				Msg: "a sync must be a descendant of the last synced commit; roll back to return to an earlier one", Extra: map[string]any{"last_synced": last.SHA}}
		}
	}
	files, err := client.ReadBundle(gctx, cr, sha, policySyncTopLevel, policySyncKeep,
		ghapp.BundleLimits{MaxFiles: policybundle.MaxFiles, MaxBytes: policybundle.MaxBytes, MaxFileBytes: ghapp.MaxFileBytes})
	if err != nil {
		return nil, syncGitHubErr(err, "the policy bundle could not be read from GitHub")
	}
	if len(files) == 0 {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "empty_bundle", Msg: "the commit holds no policy bundle (tessera.yaml and the roles, jit, sod or agents folders)"}
	}
	if rollback && rolesascode.Digest(files) != target.BundleSHA256 {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "rollback_bundle_changed",
			Msg: "the bundle at that commit is not the one Tessera applied (the commit or the repository changed); roll back to a commit whose bundle is unchanged"}
	}
	text := make(map[string]string, len(files))
	for path, b := range files {
		text[path] = string(b)
	}

	// the plan of every kind and the prediction, in one read transaction
	var plan *admin.PolicySyncPlan
	var view *policyDiffView
	var extras *diffExtras
	err = p.scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		if plan, err = admin.BuildPolicySync(tx, files, tenantSlug, s.admin.PolicyMaxSteps, now); err != nil {
			return bundleErr(err)
		}
		view, extras, err = s.computePolicyDiff(ctx, tx, &policyDiffIn{Files: text})
		return err
	})
	if err != nil {
		return nil, err
	}
	prediction := syncverify.Predict(extras.graph, view.DiffSHA256)
	rollbackFrom, lastID := "", ""
	if last != nil {
		lastID = last.ID
	}
	if rollback {
		rollbackFrom = last.SHA
	}
	payload, err := json.Marshal(map[string]any{"repo": st.Repo, "sha": sha, "kind": kind, "rollback_from": rollbackFrom, "last_sync_id": lastID, "default_branch": branch,
		"files": text, "bundle_sha256": plan.BundleSHA256, "plan_sha256": plan.PlanSHA256, "kinds": plan.Kinds, "prediction": prediction})
	if err != nil {
		return nil, err
	}
	ch, err := s.admin.SubmitPolicySync(ctx, pr, payload)
	if err != nil {
		return nil, err
	}
	audit.Mark(ctx, "policy_sync_sha", sha)
	audit.Mark(ctx, "policy_sync_kind", kind)
	audit.Mark(ctx, "policy_sync_plan_sha256", plan.PlanSHA256)
	var chv any
	if pr != nil && pr.Kind == auth.KindAPIClient {
		chv = s.proposalView(ch, "")
	} else if chv, err = s.changeResponse(r, ch); err != nil {
		return nil, err
	}
	var sv *policySyncView
	err = p.scope.Read(ctx, func(tx *store.TenantTx) error {
		sy, err := tx.PolicySyncByChange(ch.ID.String())
		if err != nil || sy == nil {
			return err
		}
		sv, err = syncViewOf(tx, sy, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, map[string]any{"status": "filed", "sync": sv, "change_request": chv, "plan": plan,
		"no_changes": plan.Changes == 0 && prediction.PermsTotal == 0, "blast": view.Summary}}, nil
}
