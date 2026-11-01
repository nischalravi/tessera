package api

import (
	"context"
	"encoding/hex"
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
//	PUT  /api/policy/github/app    {enabled, app_id, installation_id, repo, private_key, remove_key, rotate_webhook_secret, remove_webhook_secret}   (connections.manage, STEP_UP_POLICY)
//	POST /api/policy/github/check  {repo, pull_number, head_sha, files, operations, terraform_plan, base_snapshot, profile}
//
// The App replaces the stored personal token of PUT /api/aws/pr-comment. Its private key (PEM) is validated, sealed with
// internal/seal (AAD bound to tenant, table and column) and never returned: the settings show a "set" flag and the key's
// SHA-256 fingerprint, and sending a new private_key rotates it. The webhook secret (issue #771) is kept the same way
// (github_webhook_secrets, AAD bound to tenant, table and column): rotate_webhook_secret makes a new 256-bit one and returns it
// once in that answer; GET only says it is set. A request signs a 9-minute App JWT in memory, exchanges
// it for an installation token limited to the configured repository and the checks and pull_requests permissions
// (internal/ghapp), and drops the key again.
//
// The check route runs the blast-radius preview of POST /api/policy/diff (bundle, operations and Terraform plan) in a
// read transaction, with no transaction open posts one check run on head_sha and one comment on the pull request (the
// comment is updated in place on a re-run, the check run on the same commit), and records the outcome. The conclusion is
// failure when the change introduces policy violations, neutral when the preview is conditional, success otherwise
// (ghapp.Evaluate). Posting reaches outside Tessera with stored credentials, but CI is a machine client and cannot meet a
// step-up, so the route has its own narrow permission, policy.github.check (scope tessera:policy-github-check); the App's
// settings stay connections.manage with step-up. head_sha must be the pull request's head now. The check is advisory: the
// caller supplies the bundle, plan and operations, and the comment says so. It acts only on the one repository the tenant
// configured and is refused until the tenant has enabled the App. Posting is serialized per pull request by a claim row
// (github_pr_check_claims) taken before GitHub is called; a request that cannot get it answers 409 check_in_progress.
// The pull_request webhook (policy_github_webhook.go, issue #771) is the second trigger and shares publishGitHubCheck.

// githubCheckTimeout is how long the check route may run: the preview's deadline and the time the post may take after it.
func githubCheckTimeout(diffTimeout time.Duration) time.Duration { return diffTimeout + 60*time.Second }

// githubClaimTTL is how long a request's claim on a pull request holds before another may replace it: the route's
// whole timeout plus a minute, so a slow check never outlives its claim.
func githubClaimTTL(diffTimeout time.Duration) time.Duration {
	return githubCheckTimeout(diffTimeout) + time.Minute
}

func (s *Server) registerPolicyGitHubRoutes() {
	s.handle(http.MethodGet, "/api/policy/github/app", read, need(auth.PermConnectionsRead), s.rd(s.getGitHubApp))
	s.handle(http.MethodPut, "/api/policy/github/app", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.putGitHubApp))
	// phased: the preview is computed in a read transaction, the post is made with none open, and its outcome is then recorded
	rt := s.handle(http.MethodPost, "/api/policy/github/check", phased, need(auth.PermPolicyGitHubCheck), s.githubCheck)
	rt.answersRead = true
	// the preview's deadline, and the time the post may take after it
	rt.timeout = githubCheckTimeout(s.cfg.PolicyDiffTimeout)
}

// githubKeyAAD binds the sealed private key to its tenant, table and column.
func githubKeyAAD(t tenancy.ID) []byte { return seal.AAD(t, "github_app_settings", "key_enc") }

// githubWebhookAAD binds the sealed webhook secret to its tenant, table and column.
func githubWebhookAAD(t tenancy.ID) []byte {
	return seal.AAD(t, "github_webhook_secrets", "secret_enc")
}

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
	// ContentsPermissions are what the right-sizing pull requests of LP-9 ask the installation for (contents:write added);
	// the installation must have accepted them, or those routes answer installation_scope_mismatch.
	ContentsPermissions map[string]string `json:"contents_permissions"`
	// The pull_request webhook (issue #771): where GitHub delivers to, whether the shared secret is set and since when.
	// The secret itself is never returned, except once, in the answer to the PUT that rotated it (WebhookSecret).
	WebhookPath        string  `json:"webhook_path"`
	WebhookSecretSet   bool    `json:"webhook_secret_set"`
	WebhookSecretSetAt *string `json:"webhook_secret_set_at"`
	WebhookSecret      string  `json:"webhook_secret,omitempty"`
}

func githubWebhookPath(slug string) string { return "/public/t/" + slug + "/github/webhook" }

// withWebhook adds the webhook half of the settings to v.
func withWebhook(v githubAppView, slug string, hs *store.GitHubWebhookSecret) githubAppView {
	v.WebhookPath = githubWebhookPath(slug)
	if hs != nil {
		at := store.RT(hs.SetAt)
		v.WebhookSecretSet, v.WebhookSecretSetAt = true, &at
	}
	return v
}

func (s *Server) githubAppViewOf(st *store.GitHubAppSettings) githubAppView {
	base := s.cfg.GitHubAPIBase
	if base == "" {
		base = ghapp.DefaultAPIBase
	}
	v := githubAppView{Enabled: st.Enabled, AppID: st.AppID, InstallationID: st.InstallationID, Repo: st.Repo, KeySet: len(st.KeyEnc) > 0,
		KeyFingerprint: st.KeyFingerprint, UpdatedBy: st.UpdatedBy, APIBase: base, Permissions: ghapp.Permissions,
		ContentsPermissions: ghapp.ContentsPermissions}
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
	tx := store.TxFrom(r.Context())
	st, err := tx.GitHubAppSettings()
	if err != nil {
		return 0, nil, err
	}
	hs, err := tx.GitHubWebhookSecret()
	if err != nil {
		return 0, nil, err
	}
	slug, err := s.slugOf(r, tx.Tenant())
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, withWebhook(s.githubAppViewOf(st), slug, hs), nil
}

// putGitHubApp stores the App settings. A field the request omits (app_id, installation_id, repo) keeps its stored
// value (enabled too, so rotating the webhook secret never turns the feature off); one sent, even empty, replaces it. private_key is optional (omit it to keep the stored key; send a new one to
// rotate it); remove_key deletes the stored key (and so turns the feature off).
func (s *Server) putGitHubApp(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Enabled        *bool   `json:"enabled"`
		AppID          *string `json:"app_id"`
		InstallationID *int64  `json:"installation_id"`
		Repo           *string `json:"repo"`
		PrivateKey     *string `json:"private_key"`
		RemoveKey      bool    `json:"remove_key"`
		// RotateWebhookSecret makes a new webhook secret (shown once in the answer); RemoveWebhookSecret deletes it, and the
		// receiver then refuses every delivery.
		RotateWebhookSecret bool `json:"rotate_webhook_secret"`
		RemoveWebhookSecret bool `json:"remove_webhook_secret"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	switch {
	case in.AppID != nil && *in.AppID != "" && !ghapp.ValidAppID(*in.AppID):
		return 0, nil, badRequest("invalid_app_id", "app_id must be the digits GitHub shows on the App's page")
	case in.InstallationID != nil && (*in.InstallationID < 0 || *in.InstallationID > 1<<53):
		return 0, nil, badRequest("invalid_installation_id", "installation_id must be a positive integer")
	case in.Repo != nil && *in.Repo != "" && !ghapp.ValidRepo(*in.Repo):
		return 0, nil, badRequest("invalid_repo", "repo must be owner/name")
	case in.RemoveKey && in.PrivateKey != nil:
		return 0, nil, badRequest("invalid_private_key", "send either private_key or remove_key, not both")
	case in.RotateWebhookSecret && in.RemoveWebhookSecret:
		return 0, nil, badRequest("invalid_webhook_secret", "send either rotate_webhook_secret or remove_webhook_secret, not both")
	}
	slug, err := s.slugOf(r, store.TxFrom(r.Context()).Tenant())
	if err != nil {
		return 0, nil, err
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
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		cur, err := c.GitHubAppSettings()
		if err != nil {
			return err
		}
		// a field the request omits keeps its stored value, so {"enabled": false} only turns the feature off
		next := &store.GitHubAppSettings{Enabled: cur.Enabled, AppID: cur.AppID, InstallationID: cur.InstallationID, Repo: cur.Repo,
			KeyEnc: cur.KeyEnc, KeyFingerprint: cur.KeyFingerprint, KeySetAt: cur.KeySetAt, UpdatedBy: actor(r), UpdatedAt: now}
		if in.Enabled != nil {
			next.Enabled = *in.Enabled
		}
		if in.AppID != nil {
			next.AppID = *in.AppID
		}
		if in.InstallationID != nil {
			next.InstallationID = *in.InstallationID
		}
		if in.Repo != nil {
			next.Repo = *in.Repo
		}
		switch {
		case in.RemoveKey:
			if in.Enabled == nil {
				next.Enabled = false // no key, no feature: removing the key without a word about enabled turns it off, as documented
			}
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
		if next.Enabled && (next.AppID == "" || next.InstallationID < 1 || next.Repo == "" || len(next.KeyEnc) == 0) {
			return badRequest("incomplete_settings", "enabling the GitHub App needs app_id, installation_id, repo and a private_key")
		}
		if err := c.PutGitHubAppSettings(next, now); err != nil {
			return err
		}
		hs, err := c.GitHubWebhookSecret()
		if err != nil {
			return err
		}
		var shown string
		switch {
		case in.RemoveWebhookSecret:
			if err := c.DeleteGitHubWebhookSecret(); err != nil {
				return err
			}
			hs = nil
		case in.RotateWebhookSecret:
			if s.cfg.Sealer == nil {
				return &readiness.Error{Status: http.StatusServiceUnavailable, Code: "no_kek", Msg: "the server has no key for sealing secrets"}
			}
			shown = "whsec_" + hex.EncodeToString(seal.RandomBytes(32))
			enc, err := s.cfg.Sealer.Seal([]byte(shown), githubWebhookAAD(c.Tenant()))
			if err != nil {
				return err
			}
			if err := c.PutGitHubWebhookSecret(enc, actor(r), now); err != nil {
				return err
			}
			hs = &store.GitHubWebhookSecret{SetAt: now}
		}
		if err := c.Audit(now, actor(r), "policy.github_app.settings", ojson.Object{{Key: "enabled", Value: next.Enabled},
			{Key: "app_id", Value: next.AppID}, {Key: "installation_id", Value: next.InstallationID}, {Key: "repo", Value: next.Repo},
			{Key: "key_changed", Value: newKey != nil}, {Key: "key_removed", Value: in.RemoveKey}, {Key: "key_fingerprint", Value: next.KeyFingerprint},
			{Key: "webhook_secret_rotated", Value: in.RotateWebhookSecret}, {Key: "webhook_secret_removed", Value: in.RemoveWebhookSecret}}); err != nil {
			return err
		}
		out = withWebhook(s.githubAppViewOf(next), slug, hs)
		out.WebhookSecret = shown
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
	client, err := s.githubClient(s.clock)
	if err != nil {
		return nil, err
	}

	// the settings and the preview, in one read transaction
	var st *store.GitHubAppSettings
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
		view, extras, err = s.computePolicyDiff(ctx, tx, &in.policyDiffIn)
		return err
	})
	if err != nil {
		return nil, err
	}

	out, err := s.publishGitHubCheck(ctx, p.scope, client, st, in.PullNumber, in.HeadSHA, view, extras, ghPublishOpts{Actor: pr.Display})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ghPublishOpts says who a check is posted for and how it waits.
type ghPublishOpts struct {
	// Actor is the audit actor of the outcome event.
	Actor string
	// ClaimWait is how long to wait for the pull request's claim when another request holds it (the webhook, whose
	// delivery GitHub does not retry); zero refuses at once with 409 check_in_progress.
	ClaimWait time.Duration
	// Extra is added to the outcome event's detail (the webhook adds its trigger and delivery id).
	Extra ojson.Object
	// Findings, when set, replaces the preview: the bundle did not validate, so the check fails and lists them (issue #808).
	Findings []ghapp.Finding
}

// githubClaimPoll is how often a waiting request tries the claim again.
var githubClaimPoll = 500 * time.Millisecond

// publishGitHubCheck posts the check run and the comment for a computed preview on one pull request and records the
// outcome: the part of a check that both the API trigger and the webhook share. It claims the pull request first, so
// two requests for one pull request never both create a check run or a comment, and refuses a head that is no longer
// the pull request's (409 stale_head_sha), so a re-run for an older commit never overwrites a newer one's result.
func (s *Server) publishGitHubCheck(ctx context.Context, scope readiness.Scope, client *ghapp.Client, st *store.GitHubAppSettings,
	pull int, headSHA string, view *policyDiffView, extras *diffExtras, o ghPublishOpts) (*githubCheckView, error) {
	now := s.clock()
	var verdict ghapp.Verdict
	var chk ghapp.Check
	var comment string
	if o.Findings != nil {
		view = &policyDiffView{} // nothing was previewed: no bundle or preview hash
		verdict = ghapp.Verdict{Conclusion: ghapp.Failure, Reasons: []string{"The policy bundle does not validate."}}
		chk = ghapp.Check{HeadSHA: headSHA, Conclusion: ghapp.Failure, Title: ghapp.FindingsTitle(len(o.Findings)), Summary: ghapp.FindingsSummary(o.Findings, headSHA)}
		comment = ghapp.FindingsComment(o.Findings, headSHA)
	} else {
		preview := previewOf(view, extras)
		verdict = ghapp.Evaluate(preview)
		chk = ghapp.Check{HeadSHA: headSHA, Conclusion: verdict.Conclusion, Title: ghapp.Title(preview, verdict), Summary: ghapp.Summary(preview, verdict, headSHA)}
		comment = ghapp.Comment(preview, verdict, headSHA)
	}

	// the private key is opened only to sign the App JWT, with no transaction open, and is not kept
	pemKey, err := s.cfg.Sealer.Open(st.KeyEnc, githubKeyAAD(scope.Tenant))
	if err != nil {
		s.log.Error("github app key cannot be opened")
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be opened; set it again"}
	}
	key, err := ghapp.ParseKey(pemKey)
	if err != nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be read; set it again"}
	}
	cr := &ghapp.Credentials{AppID: st.AppID, InstallationID: st.InstallationID, Repo: st.Repo, Key: key, Scope: scope.Tenant.String(), KeyID: st.KeyFingerprint}

	// claim the pull request before anything is posted, and read the earlier record only once the claim is held: two
	// requests for one pull request can then never both create a check run or a comment (issue #781)
	var claimed bool
	var prev *store.GitHubPRCheck
	waitUntil := time.Now().Add(o.ClaimWait)
	for {
		if err := scope.Write(ctx, func(c *store.TenantTx) error {
			var err error
			if claimed, err = c.ClaimGitHubPRCheck(st.Repo, pull, s.clock(), githubClaimTTL(s.cfg.PolicyDiffTimeout)); err != nil || !claimed {
				return err
			}
			prev, err = c.GitHubPRCheck(st.Repo, pull)
			return err
		}); err != nil {
			return nil, err
		}
		if claimed || !time.Now().Before(waitUntil) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(githubClaimPoll):
		}
	}
	if !claimed {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "check_in_progress", Msg: "another check of this pull request is being posted; retry in a moment"}
	}
	defer func() {
		if claimed { // an early return or a failed record: do not make the next request wait for the claim to expire
			_ = scope.Write(context.WithoutCancel(ctx), func(c *store.TenantTx) error { return c.ReleaseGitHubPRCheck(st.Repo, pull) })
		}
	}()
	prev0 := ghapp.Previous{}
	if prev != nil {
		prev0 = ghapp.Previous{HeadSHA: prev.HeadSHA, CheckRunID: prev.CheckRunID, CommentID: prev.CommentID}
	}
	pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// head_sha must be the pull request's head now (this also proves pull_number is a pull request)
	var pub *ghapp.Published
	perr := client.VerifyHead(pctx, cr, pull, headSHA)
	if perr == nil {
		pub, perr = client.Publish(pctx, cr, pull, chk, comment, prev0)
	}

	// record what was posted (even half of it, so a re-run updates it), and the event
	detail := ojson.Object{{Key: "repo", Value: st.Repo}, {Key: "pull_number", Value: pull}, {Key: "head_sha", Value: headSHA},
		{Key: "conclusion", Value: verdict.Conclusion}, {Key: "bundle_sha256", Value: view.BundleSHA256}, {Key: "diff_sha256", Value: view.DiffSHA256}}
	detail = append(detail, o.Extra...)
	action := "policy.github_check.posted"
	code := ""
	if perr != nil {
		action, code = "policy.github_check.failed", ghapp.ErrCode(perr)
		detail = append(detail, ojson.KV{Key: "error", Value: code})
	}
	if pub != nil {
		detail = append(detail, ojson.KV{Key: "check_run_id", Value: pub.CheckRunID}, ojson.KV{Key: "comment_id", Value: pub.CommentID})
	}
	werr := scope.Write(ctx, func(c *store.TenantTx) error {
		if err := c.ReleaseGitHubPRCheck(st.Repo, pull); err != nil {
			return err
		}
		if pub != nil && pub.CheckRunID > 0 {
			rec := &store.GitHubPRCheck{Repo: st.Repo, PullNumber: pull, HeadSHA: headSHA, CheckRunID: pub.CheckRunID, CommentID: pub.CommentID,
				Conclusion: verdict.Conclusion, DiffSHA256: view.DiffSHA256}
			if pub.CommentID == 0 && prev != nil && prev.CommentID > 0 {
				rec.CommentID = prev.CommentID
			}
			if err := c.PutGitHubPRCheck(rec, now); err != nil {
				return err
			}
		}
		return c.Audit(now, o.Actor, action, detail)
	})
	if werr == nil {
		claimed = false
	}
	if werr != nil {
		s.log.Error("github check audit failed", "err", werr)
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "audit_unavailable", Msg: "the outcome could not be recorded"}
	}
	audit.Mark(ctx, "policy_github_check_conclusion", verdict.Conclusion)
	audit.Mark(ctx, "policy_github_check_diff_sha256", view.DiffSHA256)
	if perr != nil {
		var rl *ghapp.RateLimitError
		status, errCode := http.StatusBadGateway, "github_failed"
		switch {
		case errors.As(perr, &rl):
			status, errCode = http.StatusServiceUnavailable, "github_rate_limited"
		case errors.Is(perr, ghapp.ErrHeadMismatch):
			status, errCode = http.StatusConflict, "stale_head_sha"
		case errors.Is(perr, ghapp.ErrPullNotFound):
			status, errCode = http.StatusUnprocessableEntity, "pull_request_not_found"
		}
		return nil, &readiness.Error{Status: status, Code: errCode, Msg: "the check could not be posted to GitHub",
			Extra: map[string]any{"reason": code, "conclusion": verdict.Conclusion, "diff_sha256": view.DiffSHA256}}
	}
	return &githubCheckView{Status: "posted", Repo: st.Repo, PullNumber: pull, HeadSHA: headSHA, Conclusion: verdict.Conclusion,
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
