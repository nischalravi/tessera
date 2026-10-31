package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	awsq "github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/render"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/prcomment"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// POST /api/aws/simulate-policy-change (design §11.3): "a policy PR shows
// exactly who gains or loses which permission".
//
//	{"changes":[{"op","target_arn","document","policy_arn"}...],   1 to 100 changes, in order
//	 "base_snapshot": "<id>",     optional, default the newest
//	 "profile": "default",        see aws_eval.go
//	 "head": "PR #12",            optional label for the comment
//	 "comment": {"pull_number": 12}}   optional: post the diff as a comment on that pull request
//
// The answer lists the changes (a group of principals, the actions and
// resources, the decision before and after, and a trace line) and the text of
// the pull request comment. Nothing is stored: the head snapshot is built in
// memory (snapshot.Apply) and indexed incrementally from the base.
//
// Posting is off unless the tenant has turned it on (PUT /api/aws/pr-comment),
// and needs connections.manage with a fresh phishing-resistant sign-in. The
// diff is computed in a read transaction; the post is made with none open, and
// its outcome is then recorded in the audit ledger.

const (
	awsMaxPolicyChanges = 100
	awsMaxDiffChanges   = 500 // changes returned; the rest are counted
	awsMaxExplained     = 100 // changes that carry a trace line
	awsMaxHeadLabel     = 80
)

type awsPRRequest struct {
	PullNumber int `json:"pull_number"`
}

type awsSimulateIn struct {
	BaseSnapshot string                  `json:"base_snapshot"`
	Changes      []snapshot.PolicyChange `json:"changes"`
	Profile      string                  `json:"profile"`
	Head         string                  `json:"head"`
	Comment      *awsPRRequest           `json:"comment"`
}

type awsDiffChange struct {
	Principals    []string     `json:"principals"`
	Actions       []string     `json:"actions"`
	Resources     []string     `json:"resources"`
	ActionCount   int          `json:"action_count"`
	ResourceCount int          `json:"resource_count"`
	Kind          string       `json:"kind"`
	Before        *awsCellView `json:"before"`
	After         *awsCellView `json:"after"`
	Trace         []string     `json:"trace"`
	// UsedDaysAgo is, for a lost permission, the fewest days since any of its
	// principals used it (nil: no usage is known).
	UsedDaysAgo *int `json:"used_days_ago"`
	// Gap is true when a collection finding reaches the change (design §3.3).
	Gap bool `json:"gap"`
}

type awsDiffSummary struct {
	Gained             int `json:"gained"`
	Lost               int `json:"lost"`
	ConditionalChanged int `json:"conditional_changed"`
	FidelityChanged    int `json:"fidelity_changed"`
	PrincipalsAffected int `json:"principals_affected"`
	Groups             int `json:"groups"`
	Recomputed         int `json:"recomputed"`
	// Global: something every decision depends on changed (the organization's
	// switches, the canonical-id map, VPC endpoint policies), so everything was
	// recomputed.
	Global bool `json:"global"`
}

type awsPRCommentResult struct {
	Status string `json:"status"` // not_requested | disabled | unavailable | posted | failed
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
}

type awsSimulateView struct {
	BaseSnapshot string          `json:"base_snapshot"`
	HeadSnapshot string          `json:"head_snapshot"`
	Profile      string          `json:"profile"`
	Catalog      string          `json:"catalog_version"`
	Engine       string          `json:"engine_version"`
	Summary      awsDiffSummary  `json:"summary"`
	Changes      []awsDiffChange `json:"changes"`
	// OmittedChanges counts the changes beyond what is listed.
	OmittedChanges int                `json:"omitted_changes"`
	Comment        string             `json:"comment"`
	Gaps           []awsGapView       `json:"collection_gaps"`
	PRComment      awsPRCommentResult `json:"pr_comment"`
}

func validHead(h string) bool {
	if len(h) > awsMaxHeadLabel || !utf8.ValidString(h) {
		return false
	}
	for _, r := range h {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) awsSimulate(r *http.Request, p *params) (int, any, error) {
	var in awsSimulateIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if n := len(in.Changes); n < 1 || n > awsMaxPolicyChanges {
		return 0, nil, badRequest("invalid_changes", fmt.Sprintf("changes must hold 1 to %d changes", awsMaxPolicyChanges))
	}
	if !validHead(in.Head) {
		return 0, nil, badRequest("invalid_head", fmt.Sprintf("head must be printable text of at most %d characters", awsMaxHeadLabel))
	}
	pr := principal(r)
	now := s.clock()
	if in.Comment != nil {
		if in.Comment.PullNumber < 1 || in.Comment.PullNumber > 1<<31-1 {
			return 0, nil, badRequest("invalid_pull_number", "comment.pull_number must be a positive integer")
		}
		// Posting reaches outside Tessera with a stored secret: it needs more
		// than reading the diff, and a fresh phishing-resistant sign-in.
		if d := auth.Check(pr, auth.PermConnectionsManage, &auth.StepUpPolicy, now); d != nil {
			return 0, nil, denial{d}
		}
	}
	ctx := r.Context()

	var out *awsSimulateView
	var settings *store.AWSPRCommentSettings
	err := p.scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		if out, err = s.awsDiff(ctx, tx, &in, now); err != nil {
			return err
		}
		if in.Comment != nil {
			settings, err = tx.AWSPRCommentSettings()
		}
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	out.PRComment = awsPRCommentResult{Status: "not_requested"}
	if in.Comment != nil {
		out.PRComment = s.postPRComment(ctx, p, pr, now, settings, in.Comment.PullNumber, out)
	}
	return http.StatusOK, out, nil
}

// awsDiff computes the diff inside the read transaction tx.
func (s *Server) awsDiff(ctx context.Context, tx *store.TenantTx, in *awsSimulateIn, now time.Time) (*awsSimulateView, error) {
	ac, err := s.awsContext(tx, in.BaseSnapshot)
	if err != nil {
		return nil, err
	}
	opts, label, err := awsOptions(in.Profile, now)
	if err != nil {
		return nil, err
	}
	head, err := snapshot.Apply(ac.eng.snap, in.Changes, snapshot.ApplyOptions{FetchedAt: now, MultivaluedKey: ac.cat.MultivaluedKey})
	if err != nil {
		var ce *snapshot.ChangeError
		if errors.As(err, &ce) {
			return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_change", Msg: ce.Error(),
				Extra: map[string]any{"change_index": ce.Index}}
		}
		return nil, err
	}
	// The head index reuses what it can of the base's (design §12.5), and both
	// queriers share one memo, so the cells the change does not touch are asked once.
	hix, err := ac.eng.ix.Refine(head, ac.cat.indexConfig(head))
	if err != nil {
		return nil, err
	}
	bq, err := awsq.New(ac.eng.ix, ac.eng.memo, opts)
	if err != nil {
		return nil, badRequest("invalid_profile", err.Error())
	}
	hq, err := awsq.New(hix, ac.eng.memo, opts)
	if err != nil {
		return nil, badRequest("invalid_profile", err.Error())
	}
	res, err := awsq.Diff(ctx, bq, hq, awsq.DiffOptions{MaxExpand: 25})
	if err != nil {
		return nil, awsEvalErr(err)
	}
	used, err := awsUsageLookup(tx, now)
	if err != nil {
		return nil, err
	}
	explain := render.Explainer(ctx, bq, hq)
	meta := render.Meta{BaseSnapshot: ac.hdr.ID, Head: headLabel(in.Head), CatalogVersion: ac.cat.Cat.Version(), EngineVersion: eval.EngineVersion}

	view := &awsSimulateView{BaseSnapshot: ac.hdr.ID, HeadSnapshot: head.ID, Profile: label, Catalog: meta.CatalogVersion,
		Engine: meta.EngineVersion, Changes: []awsDiffChange{}, Gaps: gapViews(ac.eng.findings)}
	view.Summary.Groups, view.Summary.Recomputed, view.Summary.Global = res.Groups, res.Recomputed, res.Global
	affected := map[string]bool{}
	for i := range res.Changes {
		c := &res.Changes[i]
		switch c.Kind {
		case awsq.Gained:
			view.Summary.Gained++
		case awsq.Lost:
			view.Summary.Lost++
		case awsq.ConditionalChanged:
			view.Summary.ConditionalChanged++
		case awsq.FidelityChanged:
			view.Summary.FidelityChanged++
		}
		for _, pa := range c.Principals {
			affected[pa] = true
		}
	}
	view.Summary.PrincipalsAffected = len(affected)
	for i := range res.Changes {
		if i >= awsMaxDiffChanges {
			view.OmittedChanges = len(res.Changes) - i
			break
		}
		c := &res.Changes[i]
		dc := awsDiffChange{Principals: c.Principals, Actions: c.Actions, Resources: c.Resources, ActionCount: c.ActionCount,
			ResourceCount: c.ResourceCount, Kind: c.Kind.String(), Before: cellViewOf(c.Before, nil), After: cellViewOf(c.After, nil),
			Trace: []string{}, Gap: changeHasGap(ac.eng, c)}
		if i < awsMaxExplained {
			if lines := explain(c); lines != nil {
				dc.Trace = lines
			}
		}
		if c.Kind == awsq.Lost {
			dc.UsedDaysAgo = minUsedDays(c, used)
		}
		view.Changes = append(view.Changes, dc)
	}
	view.Comment = render.Markdown(res, meta, render.Options{Why: explain, UsedDays: used})
	return view, nil
}

func headLabel(h string) string {
	if h == "" {
		return "PR head"
	}
	return h
}

// changeHasGap checks the first few principals and resources of a change
// against the collection findings.
func changeHasGap(e *awsEngine, c *awsq.Change) bool {
	if len(e.findings) == 0 {
		return false
	}
	ps, rs := c.Principals, c.Resources
	if len(ps) > 25 {
		ps = ps[:25]
	}
	if len(rs) > 25 {
		rs = rs[:25]
	}
	for _, p := range ps {
		for _, r := range rs {
			if len(e.gapsFor(p, r)) > 0 {
				return true
			}
		}
	}
	return false
}

func minUsedDays(c *awsq.Change, used func(principal, action string) *int) *int {
	var best *int
	for _, p := range c.Principals {
		for _, a := range c.Actions {
			if d := used(p, a); d != nil && (best == nil || *d < *best) {
				v := *d
				best = &v
			}
		}
	}
	return best
}

// awsUsageLookup joins the AWS permissions a principal holds to the usage
// index (design §11.3 step 5): the days since the principal's identity last
// used a permission of the action, or nil when nothing is known (usage events
// arrive with the CloudTrail connector, which is not collected yet).
func awsUsageLookup(tx *store.TenantTx, now time.Time) (func(principal, action string) *int, error) {
	u, err := usage.Build(tx, now)
	if err != nil {
		return nil, err
	}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	identity := map[string]int64{}
	for _, a := range accts {
		if a.System == "aws" && a.IdentityID != nil {
			identity[a.ExternalID] = *a.IdentityID
		}
	}
	perms, err := tx.Permissions()
	if err != nil {
		return nil, err
	}
	byAction := map[string][]int64{}
	for _, pm := range perms {
		if pm.System == "aws" {
			byAction[pm.Action] = append(byAction[pm.Action], pm.ID)
		}
	}
	return func(principal, action string) *int {
		iid, ok := identity[principal]
		if !ok {
			return nil
		}
		var best *int
		for _, pid := range byAction[action] {
			if d := u.Get(iid, pid).DaysSince(now); d != nil && (best == nil || *d < *best) {
				v := *d
				best = &v
			}
		}
		return best
	}, nil
}

// ---------------------------------------------------------------- posting

// prCommentAAD binds the sealed token to its tenant, table and column.
func prCommentAAD(t tenancy.ID) []byte { return seal.AAD(t, "aws_pr_comment_settings", "token_enc") }

// postPRComment posts the rendered diff when the tenant has turned posting on,
// with no transaction open, and records the outcome. A failure to post is
// reported in the answer, not as an error: the diff is still the answer.
func (s *Server) postPRComment(ctx context.Context, p *params, pr *auth.Principal, now time.Time, st *store.AWSPRCommentSettings,
	number int, v *awsSimulateView) awsPRCommentResult {
	switch {
	case st == nil || !st.Enabled || st.Repo == "" || len(st.TokenEnc) == 0:
		return awsPRCommentResult{Status: "disabled"}
	case s.cfg.OutboundHTTP == nil || s.cfg.Sealer == nil:
		return awsPRCommentResult{Status: "unavailable"}
	case s.cfg.DisablePersonalToken:
		return awsPRCommentResult{Status: "unavailable", Error: "personal_token_disabled"}
	}
	token, err := s.cfg.Sealer.Open(st.TokenEnc, prCommentAAD(p.scope.Tenant))
	if err != nil {
		s.log.Error("aws pr comment token cannot be opened", "err", err)
		return awsPRCommentResult{Status: "failed", Error: "token_unreadable"}
	}
	post := &prcomment.Poster{HTTP: s.cfg.OutboundHTTP, APIBase: s.cfg.GitHubAPIBase}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := post.Post(cctx, string(token), st.Repo, number, v.Comment)
	out := awsPRCommentResult{Status: "posted"}
	detail := ojson.Object{{Key: "repo", Value: st.Repo}, {Key: "pull_number", Value: number},
		{Key: "base_snapshot", Value: v.BaseSnapshot}, {Key: "head_snapshot", Value: v.HeadSnapshot}}
	action := "aws.pr_comment.posted"
	if err != nil {
		action, out = "aws.pr_comment.failed", awsPRCommentResult{Status: "failed", Error: prCommentErrorCode(err)}
		detail = append(detail, ojson.KV{Key: "error", Value: out.Error})
	} else {
		out.URL = res.URL
		detail = append(detail, ojson.KV{Key: "comment_id", Value: res.ID})
	}
	if werr := p.scope.Write(ctx, func(c *store.TenantTx) error { return c.Audit(now, pr.Display, action, detail) }); werr != nil {
		s.log.Error("aws pr comment audit failed", "err", werr)
		return awsPRCommentResult{Status: "failed", Error: "audit_unavailable"}
	}
	return out
}

// prCommentErrorCode is a short code for an error of the post: never its text,
// which could carry the repository or a response.
func prCommentErrorCode(err error) string {
	var se *prcomment.StatusError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("github_%d", se.Status)
	case errors.Is(err, prcomment.ErrRepo), errors.Is(err, prcomment.ErrToken), errors.Is(err, prcomment.ErrBody), errors.Is(err, prcomment.ErrNumber):
		return "invalid_settings"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "unreachable"
}

// ---------------------------------------------------------------- settings

type awsPRCommentView struct {
	Enabled   bool    `json:"enabled"`
	Repo      string  `json:"repo"`
	TokenSet  bool    `json:"token_set"`
	UpdatedBy string  `json:"updated_by"`
	UpdatedAt *string `json:"updated_at"`
}

func prCommentViewOf(st *store.AWSPRCommentSettings) awsPRCommentView {
	v := awsPRCommentView{Enabled: st.Enabled, Repo: st.Repo, TokenSet: len(st.TokenEnc) > 0, UpdatedBy: st.UpdatedBy}
	if !st.UpdatedAt.IsZero() {
		t := store.RT(st.UpdatedAt)
		v.UpdatedAt = &t
	}
	return v
}

func (s *Server) getAWSPRComment(r *http.Request, _ *params) (int, any, error) {
	st, err := store.TxFrom(r.Context()).AWSPRCommentSettings()
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, prCommentViewOf(st), nil
}

// PUT /api/aws/pr-comment {enabled, repo, token}: token is optional (omit it to
// keep the one stored). The token is sealed under the KEK and never returned.
func (s *Server) putAWSPRComment(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Enabled bool    `json:"enabled"`
		Repo    string  `json:"repo"`
		Token   *string `json:"token"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Repo != "" && !prcomment.ValidRepo(in.Repo) {
		return 0, nil, badRequest("invalid_repo", "repo must be owner/name")
	}
	if in.Token != nil && !prcomment.ValidToken(*in.Token) {
		return 0, nil, badRequest("invalid_token", "token is not a usable GitHub token")
	}
	if in.Token != nil && s.cfg.DisablePersonalToken {
		return 0, nil, &readiness.Error{Status: http.StatusConflict, Code: "personal_token_disabled",
			Msg: "stored personal tokens are deprecated and disabled (TESSERA_GITHUB_ALLOW_PERSONAL_TOKEN); use the GitHub App (PUT /api/policy/github/app)"}
	}
	var out awsPRCommentView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		cur, err := c.AWSPRCommentSettings()
		if err != nil {
			return err
		}
		next := &store.AWSPRCommentSettings{Enabled: in.Enabled, Repo: in.Repo, TokenEnc: cur.TokenEnc, UpdatedBy: actor(r), UpdatedAt: now}
		if in.Token != nil {
			if s.cfg.Sealer == nil {
				return &readiness.Error{Status: http.StatusServiceUnavailable, Code: "no_kek", Msg: "the server has no key for sealing secrets"}
			}
			if next.TokenEnc, err = s.cfg.Sealer.Seal([]byte(*in.Token), prCommentAAD(c.Tenant())); err != nil {
				return err
			}
		}
		if in.Enabled && (in.Repo == "" || len(next.TokenEnc) == 0) {
			return badRequest("incomplete_settings", "enabling the comment needs a repo and a token")
		}
		if err := c.PutAWSPRCommentSettings(next, now); err != nil {
			return err
		}
		if err := c.Audit(now, actor(r), "aws.pr_comment.settings", ojson.Object{{Key: "enabled", Value: in.Enabled},
			{Key: "repo", Value: in.Repo}, {Key: "token_changed", Value: in.Token != nil}}); err != nil {
			return err
		}
		out = prCommentViewOf(next)
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}
