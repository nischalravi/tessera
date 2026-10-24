package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// RunnerOptions bound validation runs (§5.2).
type RunnerOptions struct {
	CheckTimeout   time.Duration // per check (default 10 s)
	RunTimeout     time.Duration // whole run (default 120 s)
	MaxRunsPerHour int           // per connection (default 6)
	Scenario       string        // demo scenario (default connectors.DefaultScenario)
	// Scheduled re-run intervals (§7.4, Scheduler): live checks every 1 to 7
	// days (default 1), post-activation reconciliation weekly.
	LiveEvery, ReconEvery time.Duration
	// ProberFor returns the prober for a revision. The default is the real
	// LDAP prober for non-demo ldap revisions (see Live) and the simulated
	// scenario prober for everything else; simulated results can never gate
	// a real connector type.
	ProberFor func(b *Bundle, now time.Time) (connectors.Prober, error)
	// SCIM configures the real prober for non-demo scim_app revisions (DR-18).
	SCIM SCIMLiveOptions
	// Gov configures the real probers and connectors of the governed connector
	// types (AWS Organizations, GitHub, ERP, vaults, contractor feeds, AgentCore).
	Gov GovOptions
	// Live configures the real probers (credential opening, network policy).
	Live LiveOptions
}

func (o *RunnerOptions) withDefaults() RunnerOptions {
	r := *o
	if r.CheckTimeout <= 0 {
		r.CheckTimeout = 10 * time.Second
	}
	if r.RunTimeout <= 0 {
		r.RunTimeout = 120 * time.Second
	}
	if r.MaxRunsPerHour <= 0 {
		r.MaxRunsPerHour = 6
	}
	if r.Scenario == "" {
		r.Scenario = connectors.DefaultScenario
	}
	if r.LiveEvery < 24*time.Hour || r.LiveEvery > 7*24*time.Hour {
		r.LiveEvery = 24 * time.Hour
	}
	if r.ReconEvery <= 0 {
		r.ReconEvery = 7 * 24 * time.Hour
	}
	if r.ProberFor == nil {
		scenario, live, scimOpts, govOpts := r.Scenario, r.Live, r.SCIM, r.Gov
		r.ProberFor = func(b *Bundle, now time.Time) (connectors.Prober, error) {
			if p, ok, err := live.liveProber(b, now); ok {
				return p, err
			}
			if p, ok, err := scimOpts.prober(b, now); ok {
				return p, err
			}
			if p, ok, err := govOpts.prober(b, now); ok {
				return p, err
			}
			var fixed []string
			if b.Simulated() {
				fixed = b.Config.DemoFixedChecks
			}
			return connectors.NewScenarioProber(b.Template.ID, scenario, now, b.Config.BaseDNs, fixed)
		}
	}
	return r
}

// checkEnv builds what checks may see of a revision. Config text is passed
// only so cred_storage can look for secret-shaped values.
func checkEnv(b *Bundle, p connectors.Prober, now time.Time) checks.Env {
	env := checks.Env{Probe: p, Now: now, TemplateID: b.Template.ID, Filters: map[string]string{},
		ConfigStrings: map[string]string{}, RequiredAttrs: b.Template.RequiredAttributes["user"],
		WriteScope: b.Config.WriteScope}
	if b.Rev.SecretRef != nil {
		env.SecretRef = *b.Rev.SecretRef
	}
	env.BaseDNs = append(append(env.BaseDNs, b.Config.BaseDNs...), b.Config.ServiceAccountOUs...)
	if b.Config.UserFilter != "" {
		env.Filters["user_filter"] = b.Config.UserFilter
	}
	if b.Config.GroupFilter != "" {
		env.Filters["group_filter"] = b.Config.GroupFilter
	}
	raw, _ := json.Marshal(b.Config) // ConnConfig always marshals
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for k, v := range m {
		if k == "ca_bundle" { // public certificates; their base64 would trip the secret-shape scan
			continue
		}
		switch x := v.(type) {
		case string:
			env.ConfigStrings[k] = x
		case []any:
			var parts []string
			for _, e := range x {
				if s, ok := e.(string); ok {
					parts = append(parts, s)
				}
			}
			env.ConfigStrings[k] = strings.Join(parts, "\n")
		}
	}
	return env
}

type runResult struct {
	item, check, status, message string
	observed                     map[string]any
	dur                          time.Duration
	simulated                    bool
}

// Validate runs the live checks of a connection's in-progress revision (or
// of its live revision, as a scheduled re-run). Checks run outside the
// write lock; the run row is created before and finished after.
func (s *Service) Validate(ctx context.Context, st Scope, connID, actor string, clock func() time.Time) (*RunView, error) {
	opts := s.Runner.withDefaults()
	var b *Bundle
	var run *store.CheckRun
	start := clock()
	err := st.Write(ctx, func(c *store.TenantTx) error {
		conn, live, pending, err := Revisions(c, connID)
		if err != nil {
			return err
		}
		if conn.RetiredAt != nil {
			return conflict("connection_retired", "connection %s is retired", conn.Name)
		}
		rev, kind := pending, "validation"
		if rev == nil {
			rev, kind = live, "scheduled"
		}
		if rev == nil {
			return conflict("no_revision", "nothing to validate")
		}
		if b, err = s.Load(c, rev, start); err != nil {
			return err
		}
		if err = s.loadCredential(c, b); err != nil {
			return err
		}
		if rev.State == store.StateDraft {
			return blocked("not_ready_to_validate", b.Gate(store.StateReadyToValidate, start))
		}
		if running, err := c.RunningLiveRun(rev.ID); err != nil {
			return err
		} else if running != nil {
			e := conflict("validation_running", "validation run %s is still running", running.ID)
			e.Extra = map[string]any{"run_id": running.ID}
			return e
		}
		n := 0
		for _, k := range []string{"validation", "scheduled"} {
			m, err := c.CountCheckRunsSince(rev.ID, k, start.Add(-time.Hour))
			if err != nil {
				return err
			}
			n += m
		}
		if n >= opts.MaxRunsPerHour {
			return newErr(http.StatusTooManyRequests, "rate_limited", "at most %d validation runs per connection per hour", opts.MaxRunsPerHour)
		}
		run = &store.CheckRun{ID: store.NewID(), RevisionID: rev.ID, Kind: kind, Simulated: !(liveCapable(b) || scimLive(b) || govLive(b)), Status: "running",
			ActorID: actor, ConfigHash: b.ConfigHash, StartedAt: start}
		if err := c.InsertCheckRun(run); err != nil {
			return err
		}
		return c.Audit(start, actor, "readiness.validation.started", ojson.Object{{Key: "connection_id", Value: conn.ID},
			{Key: "revision_id", Value: rev.ID}, {Key: "run_id", Value: run.ID}, {Key: "kind", Value: kind}})
	})
	if err != nil {
		return nil, err
	}
	results, status := s.execute(ctx, b, opts, start)
	finish := clock()
	err = st.Write(context.WithoutCancel(ctx), func(c *store.TenantTx) error {
		passed, failed := 0, 0
		for _, r := range results {
			it, _ := b.Eval.Item(r.item)
			obs, err := json.Marshal(r.observed)
			if err != nil {
				return err
			}
			if err := c.InsertCheckResult(&store.CheckResult{RunID: run.ID, ItemID: r.item, CheckID: r.check, Status: r.status,
				Observed: string(obs), Message: r.message, DurationMS: int(r.dur.Milliseconds()), ItemHash: it.ItemHash,
				Simulated: r.simulated}); err != nil {
				return err
			}
			switch r.status {
			case checks.Pass, checks.Warn:
				passed++
			default:
				failed++
			}
		}
		if err := c.FinishCheckRun(run.ID, status, finish); err != nil {
			return err
		}
		if err := c.BumpEvidence(run.RevisionID, finish); err != nil {
			return err
		}
		if err := c.Audit(finish, actor, "readiness.validation.completed", ojson.Object{{Key: "connection_id", Value: connID},
			{Key: "revision_id", Value: run.RevisionID}, {Key: "run_id", Value: run.ID}, {Key: "status", Value: status},
			{Key: "passed", Value: passed}, {Key: "failed", Value: failed},
			{Key: "duration_ms", Value: finish.Sub(start).Milliseconds()}}); err != nil {
			return err
		}
		nb, err := s.reload(c, run.RevisionID, finish)
		if err != nil {
			return err
		}
		if run.Kind == "validation" {
			return s.advanceAfterValidation(c, nb, actor, finish)
		}
		return s.persist(c, nb, finish)
	})
	if err != nil {
		return nil, err
	}
	var v *RunView
	err = st.Read(ctx, func(c *store.TenantTx) error {
		var err error
		v, err = s.RunView(c, connID, run.ID, clock())
		return err
	})
	return v, err
}

// execute runs every applicable live check in dependency order. A check
// whose item depends on an item that is not passing is recorded as blocked
// and not run (§5.1).
func (s *Service) execute(ctx context.Context, b *Bundle, opts RunnerOptions, now time.Time) ([]runResult, string) {
	runCtx, cancel := context.WithTimeout(ctx, opts.RunTimeout)
	defer cancel()
	prober, err := opts.ProberFor(b, now)
	status := "completed"
	sim, _ := prober.(connectors.Simulator)
	env := checkEnv(b, prober, now)
	order := topoOrder(b.Eval)
	liveOK := map[string]bool{}
	var depOK func(id string) bool
	depOK = func(id string) bool {
		ie, ok := b.Eval.Item(id)
		if !ok || !ie.Applicable || ie.Status == StatusSkipped {
			return true
		}
		if ie.HasKind(template.Live) {
			return liveOK[id]
		}
		if st, _, _ := ie.partsOf(template.Attestation); st != StatusPass {
			return false
		}
		for _, d := range ie.DependsOn {
			if !depOK(d) {
				return false
			}
		}
		return true
	}
	cache := map[string]runResult{}
	var out []runResult
	for _, ie := range order {
		if !ie.Applicable || !ie.HasKind(template.Live) {
			continue
		}
		var blockers []string
		for _, d := range ie.DependsOn {
			if !depOK(d) {
				blockers = append(blockers, d)
			}
		}
		allOK := len(blockers) == 0
		for _, v := range ie.Verify {
			if v.Kind != template.Live {
				continue
			}
			r := runResult{item: ie.ID, check: v.Check, simulated: sim != nil, observed: map[string]any{}}
			switch {
			case err != nil:
				r.status, r.message = checks.Error, "no prober is available for this connection"
			case status != "completed":
				r.status, r.message = checks.Skipped, "the run stopped early ("+status+")"
			case len(blockers) > 0:
				r.status, r.message = checks.Blocked, "blocked by "+strings.Join(blockers, ", ")
			default:
				key := v.Check + "|" + paramsKey(v.Params)
				if c, ok := cache[key]; ok {
					c.item = ie.ID
					r = c
				} else {
					r = runOne(runCtx, v, env, sim, opts.CheckTimeout)
					r.item = ie.ID
					cache[key] = r
				}
				if runCtx.Err() != nil {
					status = "aborted"
				} else if rl, _ := r.observed["rate_limited"].(bool); rl {
					status = "rate_limited"
				}
			}
			if r.status != checks.Pass && r.status != checks.Warn && !b.attestedInstead(ie, v, r, now) {
				allOK = false
			}
			out = append(out, r)
		}
		liveOK[ie.ID] = allOK
	}
	return out, status
}

// attestedInstead reports whether a result the system could not answer is
// covered by a current attestation, so dependants may run. Simulated results
// never count for a real connector type.
func (b *Bundle) attestedInstead(ie *ItemEval, v template.Verify, r runResult, now time.Time) bool {
	if v.OnUnsupported != template.Attestation || r.status != checks.Skipped || (r.simulated && !IsDemoType(b.Conn.ConnectorType)) {
		return false
	}
	if u, _ := r.observed["unsupported"].(bool); !u {
		return false
	}
	ok, _ := liveAttestationFresh(b.Evidence.LiveAttestations[ie.ID], ie.ItemHash, now, b.LiveTTL)
	return ok
}

func paramsKey(p map[string]any) string {
	b, _ := json.Marshal(p) // map keys are sorted
	return string(b)
}

// runOne runs one check under its own timeout. The simulator override, when
// the scenario has one, replaces the check's verdict but is still labelled.
func runOne(ctx context.Context, v template.Verify, env checks.Env, sim connectors.Simulator, timeout time.Duration) (r runResult) {
	r = runResult{check: v.Check, simulated: sim != nil}
	start := time.Now()
	defer func() { r.dur = time.Since(start) }()
	if sim != nil {
		if o, ok := sim.Override(v.Check); ok {
			r.status, r.message, r.observed = o.Status, o.Message, map[string]any{}
			for k, x := range o.Observed {
				r.observed[k] = x
			}
			if o.Fixable {
				r.observed["simulated_fix_available"] = true
			}
			return r
		}
	}
	c, ok := checks.Get(v.Check)
	if !ok {
		r.status, r.message, r.observed = checks.Error, "no implementation for check "+v.Check, map[string]any{}
		return r
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan checks.Result, 1)
	go func() { done <- checks.Run(cctx, c, env, checks.Params(v.Params)) }()
	select {
	case res := <-done:
		r.status, r.message, r.observed = res.Status, res.Message, res.Observed
		if errors.Is(cctx.Err(), context.DeadlineExceeded) && res.Status == checks.Error {
			r.message = fmt.Sprintf("the check timed out after %s", timeout)
		}
	case <-cctx.Done():
		r.status, r.message, r.observed = checks.Error, fmt.Sprintf("the check timed out after %s", timeout), map[string]any{"timeout": true}
	}
	return r
}

// topoOrder orders items so every dependency comes before its dependants.
func topoOrder(e *Evaluation) []*ItemEval {
	var out []*ItemEval
	seen := map[string]bool{}
	var visit func(ie *ItemEval)
	visit = func(ie *ItemEval) {
		if seen[ie.ID] {
			return
		}
		seen[ie.ID] = true
		for _, d := range ie.DependsOn {
			if dep, ok := e.Item(d); ok {
				visit(dep)
			}
		}
		out = append(out, ie)
	}
	for _, ie := range e.Items {
		visit(ie)
	}
	return out
}

// ---------------------------------------------------------------- views

// RunSummary counts results by status.
type RunSummary struct {
	Passed  int `json:"passed"`
	Warned  int `json:"warned"`
	Failed  int `json:"failed"`
	Errors  int `json:"errors"`
	Blocked int `json:"blocked"`
	Skipped int `json:"skipped"`
}

// ResultView is one check result row.
type ResultView struct {
	ItemID      string               `json:"item_id"`
	ItemTitle   string               `json:"item_title"`
	Category    string               `json:"category"`
	Level       string               `json:"level"`
	CheckID     string               `json:"check_id"`
	Kind        string               `json:"kind"`
	Status      string               `json:"status"`
	Message     string               `json:"message"`
	Observed    map[string]any       `json:"observed"`
	DurationMS  int                  `json:"duration_ms"`
	Simulated   bool                 `json:"simulated"`
	Fixable     bool                 `json:"fixable"`
	Remediation template.Remediation `json:"remediation"`
}

// RunView is GET /api/connections/{id}/validations/{run}.
type RunView struct {
	ID           string       `json:"id"`
	ConnectionID string       `json:"connection_id"`
	RevisionID   string       `json:"revision_id"`
	Kind         string       `json:"kind"`
	Status       string       `json:"status"`
	Simulated    bool         `json:"simulated"`
	Scenario     string       `json:"scenario,omitempty"`
	ConfigHash   string       `json:"config_hash"`
	Stale        bool         `json:"stale"`
	StaleReason  string       `json:"stale_reason,omitempty"`
	Actor        string       `json:"actor"`
	StartedAt    string       `json:"started_at"`
	FinishedAt   *string      `json:"finished_at"`
	DurationMS   int64        `json:"duration_ms"`
	Summary      RunSummary   `json:"summary"`
	Results      []ResultView `json:"results"`
}

// RunView renders a check run of a connection.
func (s *Service) RunView(c *store.TenantTx, connID, runID string, now time.Time) (*RunView, error) {
	run, err := c.CheckRun(runID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no run %s", runID)
	}
	if err != nil {
		return nil, err
	}
	rev, err := c.Revision(run.RevisionID)
	if err != nil {
		return nil, err
	}
	if rev.ConnectionID != connID {
		return nil, notFound("no run %s for this connection", runID)
	}
	b, err := s.Load(c, rev, now)
	if err != nil {
		return nil, err
	}
	rows, err := c.CheckResults(run.ID)
	if err != nil {
		return nil, err
	}
	v := &RunView{ID: run.ID, ConnectionID: connID, RevisionID: rev.ID, Kind: run.Kind, Status: run.Status,
		Simulated: run.Simulated, ConfigHash: run.ConfigHash, Actor: run.ActorID, StartedAt: store.RT(run.StartedAt),
		Results: []ResultView{}}
	if run.Simulated {
		v.Scenario = s.Runner.withDefaults().Scenario
	}
	if run.FinishedAt != nil {
		f := store.RT(*run.FinishedAt)
		v.FinishedAt, v.DurationMS = &f, run.FinishedAt.Sub(run.StartedAt).Milliseconds()
		if run.Kind != "dry_run" && now.Sub(*run.FinishedAt) > s.LiveTTL {
			v.Stale, v.StaleReason = true, fmt.Sprintf("older than %s: re-run before activating", fmtTTL(s.LiveTTL))
		}
		if run.Kind == "dry_run" && run.ConfigHash != b.ConfigHash {
			v.Stale, v.StaleReason = true, "configuration changed since this dry run"
		}
	}
	for _, r := range rows {
		if it, ok := b.Eval.Item(r.ItemID); ok && it.ItemHash != r.ItemHash && !v.Stale {
			v.Stale, v.StaleReason = true, "configuration changed since this run for "+r.ItemID
		}
	}
	for _, r := range rows {
		rv := ResultView{ItemID: r.ItemID, CheckID: r.CheckID, Status: r.Status, Message: r.Message,
			DurationMS: r.DurationMS, Simulated: r.Simulated}
		if err := json.Unmarshal([]byte(r.Observed), &rv.Observed); err != nil {
			return nil, err
		}
		if fx, _ := rv.Observed["simulated_fix_available"].(bool); fx {
			rv.Fixable = true
			delete(rv.Observed, "simulated_fix_available")
		}
		if it, ok := b.Eval.Item(r.ItemID); ok {
			rv.ItemTitle, rv.Category, rv.Level, rv.Remediation = it.Title, it.Category, string(it.Level), it.Remediation
		}
		if spec, ok := template.Checks[r.CheckID]; ok {
			rv.Kind = string(spec.Kind)
		}
		switch r.Status {
		case checks.Pass:
			v.Summary.Passed++
		case checks.Warn:
			v.Summary.Warned++
		case checks.Fail:
			v.Summary.Failed++
		case checks.Error:
			v.Summary.Errors++
		case checks.Blocked:
			v.Summary.Blocked++
		default:
			v.Summary.Skipped++
		}
		v.Results = append(v.Results, rv)
	}
	sort.SliceStable(v.Results, func(i, j int) bool {
		if v.Results[i].Category != v.Results[j].Category {
			return v.Results[i].Category < v.Results[j].Category
		}
		return v.Results[i].ItemID < v.Results[j].ItemID
	})
	return v, nil
}
