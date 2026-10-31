package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// GitHub App check run for policy pull requests (issue #656, AC-10):
//
//	GET  /api/policy/github/app    the tenant's GitHub App settings (connections.read); the private key is never returned
//	PUT  /api/policy/github/app    {enabled, app_id, installation_id, repo, private_key, remove_key}   (connections.manage, STEP_UP_POLICY)
//	POST /api/policy/github/check  {repo, pull_number, head_sha, files, operations, terraform_plan, base_snapshot, profile}
//
// The App replaces the stored personal token of PUT /api/aws/pr-comment. Its private key (PEM) is validated, sealed with
// internal/seal (AAD bound to tenant, table and column) and never returned: the settings show a "set" flag and the key's
// SHA-256 fingerprint, and sending a new private_key rotates it. A request signs a 9-minute App JWT in memory, exchanges
// it for an installation token limited to the configured repository and the checks and pull_requests permissions
// (internal/ghapp), and drops the key again.
//
// The check route runs the blast-radius preview of POST /api/policy/diff (bundle, operations and Terraform plan) in a
// read transaction, with no transaction open posts one check run on head_sha and one comment on the pull request (the
// comment is updated in place on a re-run, the check run on the same commit), and records the outcome. The conclusion is
// failure when the change introduces policy violations, neutral when the preview is conditional, success otherwise
// (ghapp.Evaluate). Posting reaches outside Tessera with stored credentials, so it needs connections.manage with a fresh
// phishing-resistant sign-in (as the AWS comment does), and graph.read as well, since the comment shows what the preview
// reads. It acts only on the one repository the tenant configured and is refused until the tenant has enabled the App. A
// GitHub webhook trigger is not built: CI calls this route.

func (s *Server) registerPolicyGitHubRoutes() {
	s.handle(http.MethodGet, "/api/policy/github/app", read, need(auth.PermConnectionsRead), s.rd(s.getGitHubApp))
	s.handle(http.MethodPut, "/api/policy/github/app", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putGitHubApp))
	// phased: the preview is computed in a read transaction, the post is made with none open, and its outcome is then recorded
	rt := s.handle(http.MethodPost, "/api/policy/github/check", phased, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.githubCheck)
	rt.answersRead = true
	// the preview's deadline, and the time the post may take after it
	rt.timeout = s.cfg.PolicyDiffTimeout + 60*time.Second
}

// githubKeyAAD binds the sealed private key to its tenant, table and column.
func githubKeyAAD(t tenancy.ID) []byte { return seal.AAD(t, "github_app_settings", "key_enc") }

type githubAppView struct {
	Enabled        bool              `json:"enabled"`
	AppID          string            `json:"app_id"`
	InstallationID int64             `json:"installation_id"`
	Repo           string            `json:"repo"`
	KeySet         bool              `json:"key_set"`
	KeyFingerprint string            `json:"key_fingerprint"`
	KeySetAt       *string           `json:"key_set_at"`
	UpdatedBy      string            `json:"updated_by"`
	UpdatedAt      *string           `json:"updated_at"`
	APIBase        string            `json:"api_base"`
	Permissions    map[string]string `json:"permissions"`
}

func (s *Server) githubAppViewOf(st *store.GitHubAppSettings) githubAppView {
	base := s.cfg.GitHubAPIBase
	if base == "" {
		base = ghapp.DefaultAPIBase
	}
	v := githubAppView{Enabled: st.Enabled, AppID: st.AppID, InstallationID: st.InstallationID, Repo: st.Repo, KeySet: len(st.KeyEnc) > 0,
		KeyFingerprint: st.KeyFingerprint, UpdatedBy: st.UpdatedBy, APIBase: base, Permissions: ghapp.Permissions}
	if st.KeySetAt != "" {
		v.KeySetAt = &st.KeySetAt
	}
	if !st.UpdatedAt.IsZero() {
		t := store.RT(st.UpdatedAt)
		v.UpdatedAt = &t
	}
	return v
}

func (s *Server) getGitHubApp(r *http.Request, _ *params) (int, any, error) {
	st, err := store.TxFrom(r.Context()).GitHubAppSettings()
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, s.githubAppViewOf(st), nil
}

// putGitHubApp stores the App settings. private_key is optional (omit it to keep the stored key; send a new one to
// rotate it); remove_key deletes the stored key (and so turns the feature off).
func (s *Server) putGitHubApp(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Enabled        bool    `json:"enabled"`
		AppID          string  `json:"app_id"`
		InstallationID int64   `json:"installation_id"`
		Repo           string  `json:"repo"`
		PrivateKey     *string `json:"private_key"`
		RemoveKey      bool    `json:"remove_key"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	switch {
	case in.AppID != "" && !ghapp.ValidAppID(in.AppID):
		return 0, nil, badRequest("invalid_app_id", "app_id must be the digits GitHub shows on the App's page")
	case in.InstallationID < 0 || in.InstallationID > 1<<53:
		return 0, nil, badRequest("invalid_installation_id", "installation_id must be a positive integer")
	case in.Repo != "" && !ghapp.ValidRepo(in.Repo):
		return 0, nil, badRequest("invalid_repo", "repo must be owner/name")
	case in.RemoveKey && in.PrivateKey != nil:
		return 0, nil, badRequest("invalid_private_key", "send either private_key or remove_key, not both")
	}
	var newKey []byte
	var fingerprint string
	if in.PrivateKey != nil {
		key, err := ghapp.ParseKey([]byte(*in.PrivateKey))
		if err != nil {
			return 0, nil, badRequest("invalid_private_key", "private_key must be the App's RSA private key in PEM form (2048 bits or more)")
		}
		fingerprint = ghapp.Fingerprint(key)
		newKey = []byte(*in.PrivateKey)
	}
	var out githubAppView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		cur, err := c.GitHubAppSettings()
		if err != nil {
			return err
		}
		next := &store.GitHubAppSettings{Enabled: in.Enabled, AppID: in.AppID, InstallationID: in.InstallationID, Repo: in.Repo,
			KeyEnc: cur.KeyEnc, KeyFingerprint: cur.KeyFingerprint, KeySetAt: cur.KeySetAt, UpdatedBy: actor(r), UpdatedAt: now}
		switch {
		case in.RemoveKey:
			next.KeyEnc, next.KeyFingerprint, next.KeySetAt = nil, "", ""
		case newKey != nil:
			if s.cfg.Sealer == nil {
				return &readiness.Error{Status: http.StatusServiceUnavailable, Code: "no_kek", Msg: "the server has no key for sealing secrets"}
			}
			if next.KeyEnc, err = s.cfg.Sealer.Seal(newKey, githubKeyAAD(c.Tenant())); err != nil {
				return err
			}
			next.KeyFingerprint, next.KeySetAt = fingerprint, store.RT(now)
		}
		if in.Enabled && (next.AppID == "" || next.InstallationID < 1 || next.Repo == "" || len(next.KeyEnc) == 0) {
			return badRequest("incomplete_settings", "enabling the GitHub App needs app_id, installation_id, repo and a private_key")
		}
		if err := c.PutGitHubAppSettings(next, now); err != nil {
			return err
		}
		if err := c.Audit(now, actor(r), "policy.github_app.settings", ojson.Object{{Key: "enabled", Value: next.Enabled},
			{Key: "app_id", Value: next.AppID}, {Key: "installation_id", Value: next.InstallationID}, {Key: "repo", Value: next.Repo},
			{Key: "key_changed", Value: newKey != nil}, {Key: "key_removed", Value: in.RemoveKey}, {Key: "key_fingerprint", Value: next.KeyFingerprint}}); err != nil {
			return err
		}
		out = s.githubAppViewOf(next)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

type githubCheckIn struct {
	Repo       string `json:"repo"`
	PullNumber int    `json:"pull_number"`
	HeadSHA    string `json:"head_sha"`
	policyDiffIn
}

// githubCheckView is the answer: what was posted and why.
type githubCheckView struct {
	Status         string   `json:"status"` // posted
	Repo           string   `json:"repo"`
	PullNumber     int      `json:"pull_number"`
	HeadSHA        string   `json:"head_sha"`
	Conclusion     string   `json:"conclusion"`
	Reasons        []string `json:"reasons"`
	Title          string   `json:"title"`
	CheckRunID     int64    `json:"check_run_id"`
	CheckURL       string   `json:"check_url,omitempty"`
	CheckCreated   bool     `json:"check_created"`
	CommentID      int64    `json:"comment_id"`
	CommentURL     string   `json:"comment_url,omitempty"`
	CommentCreated bool     `json:"comment_created"`
	BundleSHA256   string   `json:"bundle_sha256"`
	DiffSHA256     string   `json:"diff_sha256"`
	Summary        string   `json:"summary"`
}

// githubClient builds the GitHub client of the running server, or says why there is none.
func (s *Server) githubClient(now func() time.Time) (*ghapp.Client, error) {
	if s.cfg.OutboundHTTP == nil || s.cfg.Sealer == nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_unavailable", Msg: "the server has no outbound client or no key for sealing secrets"}
	}
	hc := s.cfg.OutboundHTTP
	if s.cfg.GitHubAPIBase != "" {
		hc = safehttp.WithConfiguredPorts(hc, s.cfg.GitHubAPIBase) // a GitHub Enterprise base may name a port
	}
	return &ghapp.Client{HTTP: hc, APIBase: s.cfg.GitHubAPIBase, Cache: s.ghCache, Now: now}, nil
}

func (s *Server) githubCheck(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var in githubCheckIn
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	switch {
	case !ghapp.ValidRepo(in.Repo):
		return nil, badRequest("invalid_repo", "repo must be owner/name")
	case in.PullNumber < 1 || in.PullNumber > 1<<31-1:
		return nil, badRequest("invalid_pull_number", "pull_number must be a positive integer")
	case !ghapp.ValidSHA(in.HeadSHA):
		return nil, badRequest("invalid_head_sha", "head_sha must be the full commit id in lower-case hex")
	}
	pr := principal(r)
	ctx := r.Context()
	now := s.clock()
	if d := auth.Check(pr, auth.PermGraphRead, nil, now); d != nil {
		return nil, denial{d}
	}
	client, err := s.githubClient(s.clock)
	if err != nil {
		return nil, err
	}

	// the settings and the preview, in one read transaction
	var st *store.GitHubAppSettings
	var prev *store.GitHubPRCheck
	var view *policyDiffView
	var extras *diffExtras
	err = p.scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		if st, err = tx.GitHubAppSettings(); err != nil {
			return err
		}
		if !st.Enabled || st.AppID == "" || st.InstallationID < 1 || st.Repo == "" || len(st.KeyEnc) == 0 {
			return &readiness.Error{Status: http.StatusConflict, Code: "github_app_disabled", Msg: "the GitHub App is not configured and enabled for this tenant (PUT /api/policy/github/app)"}
		}
		if !strings.EqualFold(in.Repo, st.Repo) {
			return badRequest("repo_not_configured", "repo is not the repository the GitHub App is configured for")
		}
		if prev, err = tx.GitHubPRCheck(st.Repo, in.PullNumber); err != nil {
			return err
		}
		view, extras, err = s.computePolicyDiff(ctx, tx, &in.policyDiffIn)
		return err
	})
	if err != nil {
		return nil, err
	}

	prev0 := ghapp.Previous{}
	if prev != nil {
		prev0 = ghapp.Previous{HeadSHA: prev.HeadSHA, CheckRunID: prev.CheckRunID, CommentID: prev.CommentID}
	}
	preview := previewOf(view, extras)
	verdict := ghapp.Evaluate(preview)
	chk := ghapp.Check{HeadSHA: in.HeadSHA, Conclusion: verdict.Conclusion, Title: ghapp.Title(preview, verdict), Summary: ghapp.Summary(preview, verdict, in.HeadSHA)}
	comment := ghapp.Comment(preview, verdict, in.HeadSHA)

	// the private key is opened only to sign the App JWT, with no transaction open, and is not kept
	pemKey, err := s.cfg.Sealer.Open(st.KeyEnc, githubKeyAAD(p.scope.Tenant))
	if err != nil {
		s.log.Error("github app key cannot be opened")
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be opened; set it again"}
	}
	key, err := ghapp.ParseKey(pemKey)
	if err != nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be read; set it again"}
	}
	cr := &ghapp.Credentials{AppID: st.AppID, InstallationID: st.InstallationID, Repo: st.Repo, Key: key, Scope: p.scope.Tenant.String(), KeyID: st.KeyFingerprint}
	pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	pub, perr := client.Publish(pctx, cr, in.PullNumber, chk, comment, prev0)

	// record what was posted (even half of it, so a re-run updates it), and the event
	detail := ojson.Object{{Key: "repo", Value: st.Repo}, {Key: "pull_number", Value: in.PullNumber}, {Key: "head_sha", Value: in.HeadSHA},
		{Key: "conclusion", Value: verdict.Conclusion}, {Key: "bundle_sha256", Value: view.BundleSHA256}, {Key: "diff_sha256", Value: view.DiffSHA256}}
	action := "policy.github_check.posted"
	code := ""
	if perr != nil {
		action, code = "policy.github_check.failed", ghapp.ErrCode(perr)
		detail = append(detail, ojson.KV{Key: "error", Value: code})
	}
	if pub != nil {
		detail = append(detail, ojson.KV{Key: "check_run_id", Value: pub.CheckRunID}, ojson.KV{Key: "comment_id", Value: pub.CommentID})
	}
	werr := p.scope.Write(ctx, func(c *store.TenantTx) error {
		if pub != nil && pub.CheckRunID > 0 {
			rec := &store.GitHubPRCheck{Repo: st.Repo, PullNumber: in.PullNumber, HeadSHA: in.HeadSHA, CheckRunID: pub.CheckRunID, CommentID: pub.CommentID,
				Conclusion: verdict.Conclusion, DiffSHA256: view.DiffSHA256}
			if pub.CommentID == 0 && prev != nil && prev.CommentID > 0 {
				rec.CommentID = prev.CommentID
			}
			if err := c.PutGitHubPRCheck(rec, now); err != nil {
				return err
			}
		}
		return c.Audit(now, pr.Display, action, detail)
	})
	if werr != nil {
		s.log.Error("github check audit failed", "err", werr)
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "audit_unavailable", Msg: "the outcome could not be recorded"}
	}
	audit.Mark(ctx, "policy_github_check_conclusion", verdict.Conclusion)
	audit.Mark(ctx, "policy_github_check_diff_sha256", view.DiffSHA256)
	if perr != nil {
		var rl *ghapp.RateLimitError
		status, errCode := http.StatusBadGateway, "github_failed"
		if errors.As(perr, &rl) {
			status, errCode = http.StatusServiceUnavailable, "github_rate_limited"
		}
		return nil, &readiness.Error{Status: status, Code: errCode, Msg: "the check could not be posted to GitHub",
			Extra: map[string]any{"reason": code, "conclusion": verdict.Conclusion, "diff_sha256": view.DiffSHA256}}
	}
	return &githubCheckView{Status: "posted", Repo: st.Repo, PullNumber: in.PullNumber, HeadSHA: in.HeadSHA, Conclusion: verdict.Conclusion,
		Reasons: verdict.Reasons, Title: chk.Title, CheckRunID: pub.CheckRunID, CheckURL: pub.CheckURL, CheckCreated: pub.CheckCreated,
		CommentID: pub.CommentID, CommentURL: pub.CommentURL, CommentCreated: pub.CommentCreated, BundleSHA256: view.BundleSHA256,
		DiffSHA256: view.DiffSHA256, Summary: chk.Summary}, nil
}

// previewOf is the check's view of a preview.
func previewOf(v *policyDiffView, x *diffExtras) ghapp.Preview {
	p := ghapp.Preview{Report: v.Report, BundleSHA256: v.BundleSHA256, DiffSHA256: v.DiffSHA256}
	if x != nil {
		p.SoDPolicyIDs = x.sodPolicies
	}
	if t := v.Terraform; t != nil {
		ti := &ghapp.TerraformInfo{Conditional: t.Conditional, Resources: t.Resources, Unsupported: t.Unsupported,
			ConditionalChanges: t.ConditionalChanges, Unresolved: t.Unresolved}
		for _, f := range t.Findings {
			switch f.Status {
			case "conditional", "unresolved", "unsupported":
				ti.Findings = append(ti.Findings, ghapp.TFFinding{Address: f.Address, Type: f.Type, Status: f.Status, Reason: f.Reason})
			}
		}
		p.Terraform = ti
	}
	return p
}
