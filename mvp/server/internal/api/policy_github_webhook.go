package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The GitHub pull_request webhook (issue #771, AC-10 follow-up; docs/design/access-as-code-repo.md section 6):
//
//	POST /public/t/{slug}/github/webhook   the receiver (no session; HMAC-signed by GitHub with the tenant's webhook secret)
//
// The registered App delivers pull_request events here; the action opened, synchronize or reopened runs the same check as
// POST /api/policy/github/check, on the pull request's own files: Tessera reads the policy bundle at the head commit
// through the installation (a token limited to contents:read), previews it and posts the check run and comment
// (publishGitHubCheck), so the check is a verifiable gate and not the caller's say-so. The App registration (webhook URL,
// secret, the pull_request event, contents:read) is a human step; see mvp/README.md.
//
// A delivery is trusted only when all of these hold, checked in this order:
//   - X-Hub-Signature-256 is the HMAC-SHA256 of the raw body under the tenant's sealed webhook secret, compared with
//     hmac.Equal. A missing or wrong signature, an unknown or inactive tenant slug, and a tenant with no secret all
//     answer the same 401, after the same work, so the response does not say which.
//   - the tenant comes from the URL slug, never from the body, and the payload's installation id and repository are the
//     ones in that tenant's App settings (403 installation_mismatch otherwise);
//   - the pull request's head is in that same repository: a pull request from a fork, or from a deleted one, is ignored
//     (202 fork_pull_request), so an outside author's files are never previewed against the tenant's graph (issue #805);
//   - the X-GitHub-Delivery id was not handled before (409 replayed_delivery). The id is recorded for 72 hours, atomically,
//     and forgotten again when the delivery fails for a reason that may pass, so GitHub's redelivery is handled.
//
// The body is capped at 1 MiB (413). Authentic deliveries are rate-limited per tenant (429); unauthenticated traffic is
// limited per IP by the server's anonymous bucket, so a flood of bad signatures cannot use up a tenant's allowance.
// Every delivery is audited: one that fails authentication in the request's http.request event (platform chain, outcome
// "rejected", no tenant is trusted yet), every other one as a tenant event (policy.github_webhook.ignored / rejected, or
// policy.github_check.posted / failed with trigger "webhook"). A head that is no longer the pull request's is ignored
// (stale_head), so a re-run for an older commit never overwrites a newer commit's result; deliveries for one pull request
// are serialized by the claim of POST /api/policy/github/check, which the webhook waits for up to 20 seconds.

const (
	// githubHookBody caps what the receiver reads.
	githubHookBody = 1 << 20
	// githubDeliveryRetention is how long a handled delivery id is remembered.
	githubDeliveryRetention = 72 * time.Hour
	// githubHookClaimWait is how long a delivery waits for another check of the same pull request.
	githubHookClaimWait = 20 * time.Second
)

var githubDeliveryRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)

func (s *Server) registerPolicyGitHubWebhookRoutes() {
	rt := s.handle(http.MethodPost, "/public/t/{slug}/github/webhook", noTenant, publicRoute, s.githubWebhook)
	// reading the bundle, the preview, the wait for the claim and the post
	rt.timeout = s.cfg.PolicyDiffTimeout + 150*time.Second
}

// githubHookPayload is the part of a pull_request event the receiver reads.
type githubHookPayload struct {
	Action       string `json:"action"`
	Number       int    `json:"number"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	PullRequest struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
			// Repo is the repository the head branch lives in: the tenant's own for a pull request opened inside it, a
			// fork's otherwise, and null once a fork is deleted.
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
}

// githubHookDummy stands in for the secret when the tenant has none, so the comparison runs either way.
var githubHookDummy = seal.RandomBytes(32)

// githubSignatureOK says whether header is "sha256=" and the hex HMAC-SHA256 of body under secret. The comparison is
// hmac.Equal (constant time); the MAC is computed even when the header is missing or malformed.
func githubSignatureOK(secret, body []byte, header string) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	want := mac.Sum(nil)
	var got []byte
	if hx, ok := strings.CutPrefix(header, "sha256="); ok {
		// GitHub sends lower-case hex; an upper-case digest is not what it signs, so it is refused (issue #809)
		if hx == strings.ToLower(hx) {
			if b, err := hex.DecodeString(hx); err == nil {
				got = b
			}
		}
	}
	return hmac.Equal(got, want)
}

// hookReply is an answer of the receiver.
func hookReply(status int, kv ...ojson.KV) statusBody { return statusBody{status, ojson.Object(kv)} }

func hookIgnored(reason string) statusBody {
	return hookReply(http.StatusAccepted, ojson.KV{Key: "outcome", Value: "ignored"}, ojson.KV{Key: "reason", Value: reason})
}

// hookEvent records a tenant event for a delivery, in its own transaction.
func (s *Server) hookEvent(ctx context.Context, tenant tenancy.ID, action string, detail ojson.Object) error {
	err := s.store.InTenant(ctx, tenant, func(c *store.TenantTx) error { return c.Audit(s.clock(), githubHookActor, action, detail) })
	if err != nil {
		s.log.Error("github webhook audit failed", "err", err)
		return &readiness.Error{Status: http.StatusServiceUnavailable, Code: "audit_unavailable", Msg: "the delivery could not be recorded"}
	}
	return nil
}

// githubHookActor is the system actor of the receiver's tenant events.
const githubHookActor = "github-webhook"

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ctx := r.Context()
	if r.ContentLength > githubHookBody {
		return nil, &readiness.Error{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Msg: "the body is larger than 1 MiB"}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, githubHookBody+1))
	if err != nil {
		// a chunked body has no Content-Length to check; the server's own cap says it is too large
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, &readiness.Error{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Msg: "the body is larger than 1 MiB"}
		}
		return nil, badRequest("invalid_body", "the body could not be read")
	}
	if len(raw) > githubHookBody {
		return nil, &readiness.Error{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Msg: "the body is larger than 1 MiB"}
	}

	// the tenant of the slug and what it configured; an unknown slug goes on with nothing, like a tenant without a secret
	var tenant store.Tenant
	var st *store.GitHubAppSettings
	var hs *store.GitHubWebhookSecret
	if slug := p.path["slug"]; store.ValidSlug(slug) {
		err := s.store.ReadSystem(ctx, "github webhook: tenant", func(sx *store.SystemTx) error {
			var err error
			tenant, err = sx.TenantBySlug(slug)
			return err
		})
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		case tenant.Status == "active" && tenant.ID != tenancy.Platform:
			err := s.store.ReadTenant(ctx, tenant.ID, func(c *store.TenantTx) error {
				var err error
				if st, err = c.GitHubAppSettings(); err != nil {
					return err
				}
				hs, err = c.GitHubWebhookSecret()
				return err
			})
			if err != nil {
				return nil, err
			}
		}
	}
	secret := githubHookDummy
	known := false
	if hs != nil && s.cfg.Sealer != nil {
		if b, err := s.cfg.Sealer.Open(hs.SecretEnc, githubWebhookAAD(tenant.ID)); err == nil {
			secret, known = b, true
		} else {
			s.log.Error("github webhook secret cannot be opened")
		}
	}
	sigOK := githubSignatureOK(secret, raw, r.Header.Get("X-Hub-Signature-256"))
	if !sigOK || !known {
		audit.Mark(ctx, "github_webhook_outcome", "rejected")
		return lpDenied(), nil
	}

	// from here the delivery is GitHub's, for this tenant
	tid := tenant.ID
	actx := audit.AsSystem(ctx, githubHookActor)
	if !s.ghHookLimit.Allow(ratelimit.TenantKey(tid.String())) {
		audit.Mark(ctx, "github_webhook_outcome", "rate_limited")
		w.Header().Set("Retry-After", "2")
		return statusBody{http.StatusTooManyRequests, ojson.Object{{Key: "error", Value: "rate_limited"}, {Key: "retry_after", Value: 2}}}, nil
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if !githubDeliveryRE.MatchString(delivery) {
		return nil, badRequest("invalid_delivery", "X-GitHub-Delivery must be the delivery's id")
	}
	event := r.Header.Get("X-GitHub-Event")
	base := ojson.Object{{Key: "delivery_id", Value: delivery}, {Key: "event", Value: event}}
	ignore := func(reason string, extra ...ojson.KV) (any, error) {
		audit.Mark(ctx, "github_webhook_outcome", "ignored")
		if err := s.hookEvent(actx, tid, "policy.github_webhook.ignored", append(append(ojson.Object{}, base...), append(extra, ojson.KV{Key: "reason", Value: reason})...)); err != nil {
			return nil, err
		}
		return hookIgnored(reason), nil
	}
	reject := func(status int, code, msg string, extra ...ojson.KV) (any, error) {
		audit.Mark(ctx, "github_webhook_outcome", "rejected")
		if err := s.hookEvent(actx, tid, "policy.github_webhook.rejected", append(append(ojson.Object{}, base...), append(extra, ojson.KV{Key: "reason", Value: code})...)); err != nil {
			return nil, err
		}
		return nil, &readiness.Error{Status: status, Code: code, Msg: msg}
	}
	if event != "pull_request" {
		if event == "ping" {
			return ignore("ping")
		}
		return ignore("event_not_handled")
	}
	var in githubHookPayload
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, badRequest("invalid_body", "the body is not a pull_request event")
	}
	extra := []ojson.KV{{Key: "action", Value: in.Action}}
	switch in.Action {
	case "opened", "synchronize", "reopened":
	default:
		return ignore("action_not_handled", extra...)
	}
	if !st.Enabled || st.AppID == "" || st.InstallationID < 1 || st.Repo == "" || len(st.KeyEnc) == 0 {
		return reject(http.StatusConflict, "github_app_disabled", "the GitHub App is not configured and enabled for this tenant", extra...)
	}
	pull := in.PullRequest.Number
	if pull == 0 {
		pull = in.Number
	}
	head := in.PullRequest.Head.SHA
	if in.Installation.ID != st.InstallationID || !strings.EqualFold(in.Repository.FullName, st.Repo) {
		return reject(http.StatusForbidden, "installation_mismatch", "the delivery is not for this tenant's installation and repository", extra...)
	}
	// the head must live in the tenant's own repository: for a pull request from a fork, "repository" is still the base, so
	// the binding above passes, and the fork's author would have Tessera preview their files against the tenant's graph and
	// read the result in the comment (issue #805)
	if hr := in.PullRequest.Head.Repo; hr == nil || !strings.EqualFold(hr.FullName, st.Repo) {
		return ignore("fork_pull_request", extra...)
	}
	if pull < 1 || pull > 1<<31-1 || !ghapp.ValidSHA(head) {
		return nil, badRequest("invalid_pull_request", "the event names no pull request number or head commit")
	}
	extra = append(extra, ojson.KV{Key: "repo", Value: st.Repo}, ojson.KV{Key: "pull_number", Value: pull}, ojson.KV{Key: "head_sha", Value: head})

	// a delivery id is handled once; it is forgotten again on a failure that may pass, so GitHub's redelivery is handled
	var fresh bool
	if err := s.store.InTenant(actx, tid, func(c *store.TenantTx) error {
		now := s.clock()
		var err error
		if fresh, err = c.RecordGitHubDelivery(delivery, now.Add(githubDeliveryRetention), now); err != nil {
			return err
		}
		if !fresh {
			return c.Audit(now, githubHookActor, "policy.github_webhook.rejected",
				append(append(ojson.Object{}, base...), append(extra, ojson.KV{Key: "reason", Value: "replayed_delivery"})...))
		}
		return nil
	}); err != nil {
		s.log.Error("github webhook delivery record failed", "err", err)
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "audit_unavailable", Msg: "the delivery could not be recorded"}
	}
	if !fresh {
		audit.Mark(ctx, "github_webhook_outcome", "rejected")
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "replayed_delivery", Msg: "that delivery was handled already"}
	}
	done := false
	defer func() {
		if !done {
			_ = s.store.InTenant(context.WithoutCancel(actx), tid, func(c *store.TenantTx) error { return c.ForgetGitHubDelivery(delivery) })
		}
	}()

	out, err := s.githubWebhookCheck(actx, tid, st, pull, head, delivery)
	var re *readiness.Error
	switch {
	case errors.As(err, &re) && re.Code == "stale_head_sha":
		done = true
		audit.Mark(ctx, "github_webhook_outcome", "ignored")
		return hookIgnored("stale_head"), nil
	case err != nil:
		return nil, err
	case out == nil:
		done = true
		return ignore("no_policy_bundle", extra...)
	}
	done = true
	audit.Mark(ctx, "github_webhook_outcome", "checked")
	audit.Mark(ctx, "policy_github_check_conclusion", out.Conclusion)
	return hookReply(http.StatusAccepted, ojson.KV{Key: "outcome", Value: "checked"}, ojson.KV{Key: "conclusion", Value: out.Conclusion},
		ojson.KV{Key: "pull_number", Value: pull}, ojson.KV{Key: "head_sha", Value: head}, ojson.KV{Key: "check_run_id", Value: out.CheckRunID}), nil
}

// githubWebhookCheck evaluates the policy bundle of the pull request's head commit and posts the check, exactly as
// POST /api/policy/github/check does. It returns nil when the commit holds no policy bundle (nothing to check).
func (s *Server) githubWebhookCheck(ctx context.Context, tid tenancy.ID, st *store.GitHubAppSettings, pull int, head, delivery string) (*githubCheckView, error) {
	client, err := s.githubClient(s.clock)
	if err != nil {
		return nil, err
	}
	pemKey, err := s.cfg.Sealer.Open(st.KeyEnc, githubKeyAAD(tid))
	if err != nil {
		s.log.Error("github app key cannot be opened")
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be opened; set it again"}
	}
	key, err := ghapp.ParseKey(pemKey)
	if err != nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "github_key_unreadable", Msg: "the stored GitHub App private key cannot be read; set it again"}
	}
	rd := &ghapp.Credentials{AppID: st.AppID, InstallationID: st.InstallationID, Repo: st.Repo, Key: key, Scope: tid.String(),
		KeyID: st.KeyFingerprint, ContentsRead: true}
	gctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	files, err := client.ReadBundle(gctx, rd, head, policySyncTopLevel, policySyncKeep,
		ghapp.BundleLimits{MaxFiles: policybundle.MaxFiles, MaxBytes: policybundle.MaxBytes, MaxFileBytes: ghapp.MaxFileBytes})
	if err != nil {
		return nil, syncGitHubErr(err, "the policy bundle could not be read from GitHub")
	}
	if len(files) == 0 {
		return nil, nil
	}
	text := make(map[string]string, len(files))
	for path, b := range files {
		text[path] = string(b)
	}
	scope := readiness.Scope{DB: s.store, Tenant: tid}
	var view *policyDiffView
	var extras *diffExtras
	if err := scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		view, extras, err = s.computePolicyDiff(ctx, tx, &policyDiffIn{Files: text})
		return err
	}); err != nil {
		// a bundle with findings is the most useful thing a gate can report: post it as a failing check (issue #808)
		var re *readiness.Error
		if !errors.As(err, &re) || re.Code != "invalid_bundle" {
			return nil, err
		}
		if diags, _ := re.Extra["diagnostics"].([]rolesascode.Diag); len(diags) > 0 {
			var fs []ghapp.Finding
			for _, d := range diags {
				fs = append(fs, ghapp.Finding{Path: d.Path, Line: d.Line, Code: d.Code, Message: d.Msg})
			}
			return s.publishGitHubCheck(ctx, scope, client, st, pull, head, nil, nil, ghPublishOpts{Actor: githubHookActor, ClaimWait: githubHookClaimWait,
				Findings: fs, Extra: ojson.Object{{Key: "trigger", Value: "webhook"}, {Key: "delivery_id", Value: delivery}, {Key: "bundle_files", Value: strconv.Itoa(len(files))},
					{Key: "findings", Value: len(fs)}}})
		}
		return nil, err
	}
	out, err := s.publishGitHubCheck(ctx, scope, client, st, pull, head, view, extras, ghPublishOpts{Actor: githubHookActor, ClaimWait: githubHookClaimWait,
		Extra: ojson.Object{{Key: "trigger", Value: "webhook"}, {Key: "delivery_id", Value: delivery}, {Key: "bundle_files", Value: strconv.Itoa(len(files))}}})
	return out, err
}
