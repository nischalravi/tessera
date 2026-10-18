package containment

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Error is a caller error (an unknown connection, a bad credential).
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Service prepares, runs and records containment. The zero value of every
// field but HTTP and Sealer has a default; a Service without HTTP or Sealer
// still prepares jobs, but every item becomes a manual task (nothing can be
// called, nothing can be unsealed).
type Service struct {
	// HTTP is the outbound client; it must come from internal/safehttp.
	HTTP *http.Client
	// Sealer seals provider tokens at rest (the KEK sealer).
	Sealer *seal.Sealer
	Clock  timeutil.Clock
	// Sleep waits between rate-limit retries (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error
	// RetryBudget bounds the provider calls of one RunRetries pass (default
	// 25s); tests shorten it.
	RetryBudget time.Duration
	// SweepBudget bounds the provider calls of one lifecycle sweep pass of a
	// tenant (default 25s); tests shorten it.
	SweepBudget time.Duration
}

// SweepTimeout is the time one lifecycle sweep pass may spend on provider calls.
func (s *Service) SweepTimeout() time.Duration {
	if s.SweepBudget > 0 {
		return s.SweepBudget
	}
	return 25 * time.Second
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return timeutil.System()
}

func (s *Service) revoker(system string, c Credential) (Revoker, error) {
	if s.HTTP == nil {
		return nil, errors.New("outbound HTTP is not configured")
	}
	switch system {
	case Okta:
		return newOkta(s.HTTP, c, s.Sleep)
	case Entra:
		return newEntra(s.HTTP, c, s.Sleep)
	case Google:
		return newGoogle(s.HTTP, c, s.Sleep)
	case GitHub:
		return newGitHub(s.HTTP, c, s.Sleep)
	}
	return nil, fmt.Errorf("no revoker for system %q", system)
}

// ---------------------------------------------------------------- credentials

// CredentialInput is a connection's revocation credential as submitted.
type CredentialInput struct {
	Token   string `json:"token"`
	BaseURL string `json:"base_url"`
	Org     string `json:"org"`
}

func credAAD(c *store.TenantTx, connectionID string) []byte {
	return seal.AAD(c.Tenant(), "containment_credentials", "token_enc", connectionID)
}

// PutCredential seals and stores the credential the kill switch uses for a
// connection, and audits the change (never the token) in the same transaction.
func (s *Service) PutCredential(c *store.TenantTx, connectionID string, in CredentialInput, actor string, now time.Time) error {
	if s.Sealer == nil {
		return &Error{"sealing is not configured"}
	}
	conn, err := c.Connection(connectionID)
	if errors.Is(err, store.ErrNotFound) {
		return &Error{"no such connection"}
	}
	if err != nil {
		return err
	}
	switch {
	case conn.RetiredAt != nil:
		return &Error{"the connection is retired"}
	case !GrantCapable(conn.System):
		return &Error{fmt.Sprintf("containment supports okta, entra, google and github connections, not %q", conn.System)}
	case in.Token == "" || len(in.Token) > 8192:
		return &Error{"token is required and at most 8 KiB"}
	case conn.System == Okta && in.BaseURL == "":
		return &Error{"base_url (the Okta org URL) is required"}
	case conn.System == GitHub && !userIDRE.MatchString(in.Org):
		return &Error{"org (the GitHub organization) is required"}
	}
	if in.BaseURL != "" {
		u, err := url.Parse(in.BaseURL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || len(in.BaseURL) > 512 {
			return &Error{"base_url must be an https URL"}
		}
	}
	if len(in.Org) > 100 {
		return &Error{"org is too long"}
	}
	enc, err := s.Sealer.Seal([]byte(in.Token), credAAD(c, connectionID))
	if err != nil {
		return err
	}
	if err := c.PutContainmentCredential(&store.ContainmentCredential{ConnectionID: connectionID, BaseURL: in.BaseURL,
		Org: in.Org, TokenEnc: enc, UpdatedBy: actor, UpdatedAt: now}); err != nil {
		return err
	}
	return c.Audit(now, actor, "containment.credential_set", ojson.Object{{Key: "connection_id", Value: connectionID},
		{Key: "system", Value: conn.System}, {Key: "base_url", Value: in.BaseURL}, {Key: "org", Value: in.Org}})
}

// ---------------------------------------------------------------- jobs

// Spec names one containment step on one account.
type Spec struct {
	Action    string // ActionRevokeSessions or ActionRevokeGrants
	AccountID int64
}

// Steps lists the containment steps of an identity: revoke_sessions for each
// active account on a session-capable IdP, revoke_grants for each on a
// grant-capable system. With onlyConnected, accounts on a system without a
// live (not retired) connection are left out, so a plan only carries steps a
// connection can serve.
func Steps(c *store.TenantTx, identityID int64, onlyConnected bool) ([]Spec, error) {
	accts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	var conns map[string]*store.Connection
	if onlyConnected {
		if conns, err = liveConnections(c); err != nil {
			return nil, err
		}
	}
	var out []Spec
	for _, act := range []string{ActionRevokeSessions, ActionRevokeGrants} {
		for _, a := range accts {
			capable := SessionCapable(a.System)
			if act == ActionRevokeGrants {
				capable = GrantCapable(a.System)
			}
			if a.Status != "active" || !capable || (onlyConnected && conns[a.System] == nil) {
				continue
			}
			out = append(out, Spec{act, a.ID})
		}
	}
	return out, nil
}

func liveConnections(c *store.TenantTx) (map[string]*store.Connection, error) {
	conns, err := c.Connections()
	if err != nil {
		return nil, err
	}
	out := map[string]*store.Connection{}
	for _, cn := range conns {
		if cn.RetiredAt == nil {
			out[cn.System] = cn
		}
	}
	return out, nil
}

// Item is one prepared step. Its credential stays inside the package.
type Item struct {
	Action     string
	AccountID  int64
	Target     Target
	Connection string // the connection id, "" when the system has none
	cred       *Credential
	prepErr    string // why the credential could not be loaded (fails the step)
}

// Job is what Run executes: prepared in a read transaction, run with no
// transaction open (it makes network calls), recorded in a write transaction.
type Job struct {
	IdentityID int64
	Identity   string
	Trigger    string // manual, leaver, agent
	Items      []Item
}

// Keys identify the items (action and account), to check a job still matches
// the plan it came from.
func (j *Job) Keys() []string {
	out := make([]string, len(j.Items))
	for i, it := range j.Items {
		out[i] = fmt.Sprintf("%s:%d", it.Action, it.AccountID)
	}
	return out
}

func targetFor(a *store.Account) Target {
	t := Target{System: a.System, UserID: a.ExternalID, Username: a.Username}
	switch a.System {
	case Google:
		if strings.Contains(a.Username, "@") {
			t.UserID = a.Username
		}
	case GitHub:
		t.UserID = a.Username
	}
	return t
}

// BuildJob resolves the specs of an identity into a job: the account's
// provider id and the connection's unsealed credential, if one is set.
func (s *Service) BuildJob(c *store.TenantTx, identityID int64, trigger string, specs []Spec) (*Job, error) {
	ident, err := c.Identity(identityID)
	if err != nil {
		return nil, err
	}
	conns, err := liveConnections(c)
	if err != nil {
		return nil, err
	}
	j := &Job{IdentityID: ident.ID, Identity: ident.Name, Trigger: trigger}
	creds := map[string]*Credential{}
	failed := map[string]string{}
	for _, sp := range specs {
		a, err := c.Account(sp.AccountID)
		if err != nil {
			return nil, err
		}
		if a.IdentityID == nil || *a.IdentityID != identityID {
			return nil, &Error{"account does not belong to the identity"}
		}
		it := Item{Action: sp.Action, AccountID: a.ID, Target: targetFor(a)}
		if cn := conns[a.System]; cn != nil {
			it.Connection = cn.ID
			if _, done := creds[cn.ID]; !done && failed[cn.ID] == "" {
				cred, why, err := s.loadCredential(c, cn.ID)
				if err != nil {
					return nil, err
				}
				creds[cn.ID], failed[cn.ID] = cred, why
			}
			it.cred, it.prepErr = creds[cn.ID], failed[cn.ID]
		}
		j.Items = append(j.Items, it)
	}
	return j, nil
}

// loadCredential returns the connection's credential (nil: none set), or why
// a stored one cannot be used.
func (s *Service) loadCredential(c *store.TenantTx, connectionID string) (*Credential, string, error) {
	k, err := c.ContainmentCredential(connectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if s.Sealer == nil {
		return nil, "the stored credential cannot be unsealed: no key is configured", nil
	}
	tok, err := s.Sealer.Open(k.TokenEnc, credAAD(c, connectionID))
	if err != nil {
		return nil, "the stored credential cannot be unsealed", nil
	}
	return &Credential{BaseURL: k.BaseURL, Org: k.Org, Token: string(tok)}, "", nil
}

// ---------------------------------------------------------------- run

// Step outcomes.
const (
	OutcomeDone   = "done"   // the provider revoked and a re-read found nothing left
	OutcomeManual = "manual" // nothing was called; a person must do it
	OutcomeFailed = "failed" // a call was refused, or a re-read still found something
)

// StepResult is one step on one account.
type StepResult struct {
	Action     string   `json:"action"`
	System     string   `json:"system"`
	Account    string   `json:"account"`
	Outcome    string   `json:"outcome"`
	Revoked    int      `json:"revoked"`
	Verified   bool     `json:"verified"`
	Detail     string   `json:"detail,omitempty"`
	Notes      []string `json:"notes,omitempty"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	DurationMS int64    `json:"duration_ms"`
}

// ProviderOutcome rolls the steps of one system up.
type ProviderOutcome struct {
	System     string `json:"system"`
	Outcome    string `json:"outcome"` // done, manual, failed (failed beats manual beats done)
	Steps      int    `json:"steps"`
	Failed     int    `json:"failed"`
	Manual     int    `json:"manual"`
	DurationMS int64  `json:"duration_ms"`
}

// ManualTask is what a person must still do.
type ManualTask struct {
	System       string `json:"system"`
	Account      string `json:"account"`
	Action       string `json:"action"`
	Instructions string `json:"instructions"`
}

// Report is the record of one containment run. It holds no credential.
type Report struct {
	IdentityID int64             `json:"identity_id"`
	Identity   string            `json:"identity"`
	Trigger    string            `json:"trigger"`
	OK         bool              `json:"ok"` // no step failed (manual tasks may remain)
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	DurationMS int64             `json:"duration_ms"`
	Providers  []ProviderOutcome `json:"providers"`
	Steps      []StepResult      `json:"steps"`
	Manual     []ManualTask      `json:"manual_tasks"`
}

// Failed lists the failed steps.
func (r *Report) Failed() []StepResult {
	var out []StepResult
	for _, st := range r.Steps {
		if st.Outcome == OutcomeFailed {
			out = append(out, st)
		}
	}
	return out
}

// Run executes the job: each step revokes at the provider, then re-reads it.
// A failed step does not stop the others (a partial failure is reported per
// step), but the report is not OK. Run opens no transaction.
func (s *Service) Run(ctx context.Context, j *Job) *Report {
	started := s.now()
	r := &Report{IdentityID: j.IdentityID, Identity: j.Identity, Trigger: j.Trigger, Steps: []StepResult{},
		Manual: []ManualTask{}}
	revokers := map[string]Revoker{}
	for _, it := range j.Items {
		t0 := s.now()
		st := StepResult{Action: it.Action, System: it.Target.System, Account: it.Target.Username}
		manual := s.runItem(ctx, &st, it, revokers, t0)
		t1 := s.now()
		st.StartedAt, st.FinishedAt, st.DurationMS = timeutil.ISO(t0), timeutil.ISO(t1), t1.Sub(t0).Milliseconds()
		r.Steps = append(r.Steps, st)
		for _, m := range manual {
			r.Manual = append(r.Manual, ManualTask{System: st.System, Account: st.Account, Action: st.Action, Instructions: m})
		}
	}
	finished := s.now()
	r.StartedAt, r.FinishedAt, r.DurationMS = timeutil.ISO(started), timeutil.ISO(finished), finished.Sub(started).Milliseconds()
	r.OK = len(r.Failed()) == 0
	r.Providers = rollUp(r.Steps)
	return r
}

func rollUp(steps []StepResult) []ProviderOutcome {
	out := []ProviderOutcome{}
	idx := map[string]int{}
	for _, st := range steps {
		i, ok := idx[st.System]
		if !ok {
			i = len(out)
			idx[st.System] = i
			out = append(out, ProviderOutcome{System: st.System, Outcome: OutcomeDone})
		}
		p := &out[i]
		p.Steps++
		p.DurationMS += st.DurationMS
		switch st.Outcome {
		case OutcomeFailed:
			p.Failed++
			p.Outcome = OutcomeFailed
		case OutcomeManual:
			p.Manual++
			if p.Outcome != OutcomeFailed {
				p.Outcome = OutcomeManual
			}
		}
	}
	return out
}

// runItem fills st and returns the manual tasks of the step.
func (s *Service) runItem(ctx context.Context, st *StepResult, it Item, revokers map[string]Revoker, started time.Time) []string {
	fail := func(format string, a ...any) []string {
		st.Outcome, st.Detail = OutcomeFailed, fmt.Sprintf(format, a...)
		return nil
	}
	what := "sessions and refresh tokens"
	if it.Action == ActionRevokeGrants {
		what = "OAuth consents and credentials"
	}
	if it.prepErr != "" {
		return fail("%s", it.prepErr)
	}
	if it.cred == nil {
		st.Outcome = OutcomeManual
		st.Detail = "no revocation credential is configured for this system; nothing was revoked"
		return []string{fmt.Sprintf("Not done. Revoke the %s of %s in the %s admin console (no live credential is configured for the %s connection).",
			what, it.Target.Username, it.Target.System, it.Target.System)}
	}
	rv, ok := revokers[it.Connection]
	if !ok {
		var err error
		if rv, err = s.revoker(it.Target.System, *it.cred); err != nil {
			return fail("%v", err)
		}
		revokers[it.Connection] = rv
	}
	var out Outcome
	var err error
	check := CheckSessions
	switch it.Action {
	case ActionRevokeSessions:
		out, err = rv.RevokeSessions(ctx, it.Target)
	case ActionRevokeGrants:
		out, err = rv.RevokeGrants(ctx, it.Target)
		check = CheckGrants
	default:
		return fail("unknown containment action %q", it.Action)
	}
	st.Revoked = out.Revoked
	if err != nil {
		return fail("%s", describe(err))
	}
	rem, err := rv.Verify(ctx, it.Target, started, check)
	if err != nil {
		return fail("verification could not re-read the provider: %s", describe(err))
	}
	st.Notes = rem.Unverified
	switch {
	case rem.Sessions > 0:
		return fail("verification still found %d active session(s) or refresh token(s)", rem.Sessions)
	case rem.Grants > 0:
		return fail("verification still found %d grant(s) or credential authorization(s)", rem.Grants)
	}
	st.Outcome, st.Verified = OutcomeDone, true
	manual := []string{}
	for _, m := range out.Manual {
		manual = append(manual, "Not done by Tessera. "+m)
	}
	return manual
}

// describe renders a provider error without anything that could carry a secret.
func describe(err error) string {
	var se *StatusError
	switch {
	case errors.Is(err, ErrNotFound):
		return "the provider does not know this user (check the account's external id): " + err.Error()
	case errors.Is(err, ErrRateLimited), errors.As(err, &se), errors.Is(err, ErrBadTarget):
		return err.Error()
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "the provider did not answer in time"
	}
	return err.Error()
}

// ---------------------------------------------------------------- record

// Record writes the run to the audit ledger in the caller's transaction:
// started, finished, duration and the outcome per provider and per step.
func Record(c *store.TenantTx, now time.Time, actor string, r *Report) error {
	manual := len(r.Manual)
	return c.Audit(now, actor, "containment.run", ojson.Object{{Key: "identity_id", Value: r.IdentityID},
		{Key: "identity", Value: r.Identity}, {Key: "trigger", Value: r.Trigger}, {Key: "ok", Value: r.OK},
		{Key: "started_at", Value: r.StartedAt}, {Key: "finished_at", Value: r.FinishedAt},
		{Key: "duration_ms", Value: r.DurationMS}, {Key: "providers", Value: r.Providers},
		{Key: "steps", Value: r.Steps}, {Key: "manual_tasks", Value: manual}})
}
