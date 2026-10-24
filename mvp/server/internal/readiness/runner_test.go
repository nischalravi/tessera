package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// readyAD creates a demo AD connection in ready_to_validate.
func readyAD(t *testing.T, s *Service, st Scope, name string, cfg string) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		if cfg == "" {
			cfg = `{}`
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(cfg), &m)
		m["technical_owner"], m["business_owner"] = "Ingrid Lindqvist", "Thandiwe Mokoena"
		raw, _ := json.Marshal(m)
		b, err := s.Create(c, CreateInput{Name: name, ConnectorType: "demo-ad", System: strings.ReplaceAll(strings.ToLower(name), " ", "-"),
			Config: raw}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/ad"}, "admin", t0); err != nil {
			return err
		}
		if _, err := s.Attest(c, id, "base.owner", "both owners agreed in CHG-1042", "admin", t0); err != nil {
			return err
		}
		_, err = s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	return id
}

func clockAt(t time.Time) func() time.Time { return func() time.Time { return t } }

func resultFor(v *RunView, item, check string) *ResultView {
	for i := range v.Results {
		if v.Results[i].ItemID == item && v.Results[i].CheckID == check {
			return &v.Results[i]
		}
	}
	return nil
}

func TestValidate_GapsScenarioAndSimulatedFix(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	id := readyAD(t, s, st, "AD gaps", "")
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Simulated || v.Status != "completed" || v.Scenario != "gaps" {
		t.Fatalf("run: %+v", v)
	}
	r := resultFor(v, "ad.groups.range", "range_retrieval")
	if r == nil || r.Status != "fail" || !r.Fixable || r.Observed["full_count"] != float64(2100) {
		t.Fatalf("range_retrieval: %+v", r)
	}
	if r := resultFor(v, "ad.scope.read_perms", "read_per_class"); r == nil || r.Observed["employeeID_fill"] != "61%" {
		t.Errorf("read_per_class: %+v", r)
	}
	if got := state(t, s, st, id); got != store.StateReadyToValidate {
		t.Fatalf("state after failing validation: %s", got)
	}
	// Apply the simulated fix (the scenario toggle), re-run: validated.
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.PatchConfig(c, id, []byte(`{"demo_fixed_checks":["range_retrieval"]}`), "admin", t0)
		return err
	})
	v, err = s.Validate(context.Background(), st, id, "admin", clockAt(t0.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(v, "ad.groups.range", "range_retrieval"); r.Status != "pass" {
		t.Fatalf("after fix: %+v", r)
	}
	if got := state(t, s, st, id); got != store.StateValidated {
		t.Fatalf("state after passing validation: %s", got)
	}
	// Draft connections cannot be validated.
	var draft string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "draft", ConnectorType: "demo-ad", System: "draft"}, "admin", t0)
		draft = b.Conn.ID
		return err
	})
	if _, err := s.Validate(context.Background(), st, draft, "admin", clockAt(t0)); codeOf(err) != "not_ready_to_validate" {
		t.Errorf("draft validate: %v", err)
	}
}

// slowProber blocks Connect until the context ends.
type slowProber struct{ *connectors.ScenarioProber }

func (p slowProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	select {
	case <-ctx.Done():
		return connectors.ConnInfo{}, ctx.Err()
	case <-time.After(5 * time.Second):
		return connectors.ConnInfo{}, nil
	}
}

func TestRunner_TimeoutPerCheck(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	// Allow fast checks to finish under race instrumentation and scheduler load.
	s.Runner.CheckTimeout = 500 * time.Millisecond
	s.Runner.ProberFor = func(b *Bundle, now time.Time) (connectors.Prober, error) {
		p, err := connectors.NewScenarioProber("ad", "happy", now, b.Config.BaseDNs, nil)
		return slowProber{p}, err
	}
	id := readyAD(t, s, st, "AD slow", "")
	start := time.Now()
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("run took %s; per-check timeout not applied", time.Since(start))
	}
	r := resultFor(v, "ad.tls.ldaps", "tls_handshake")
	if r == nil || r.Status != "error" || !strings.Contains(r.Message, "timed out") {
		t.Fatalf("tls_handshake: %+v", r)
	}
	// dependants are blocked, not run
	if r := resultFor(v, "ad.bind", "bind"); r == nil || r.Status != "blocked" {
		t.Errorf("bind: %+v", r)
	}
	// unrelated checks still ran
	if r := resultFor(v, "base.cred.sealed", "cred_storage"); r == nil || r.Status != "pass" {
		t.Errorf("cred_storage: %+v", r)
	}
	if v.Status != "completed" {
		t.Errorf("run status %s", v.Status)
	}
	// A whole-run timeout aborts the run.
	s.Runner.RunTimeout = 20 * time.Millisecond
	s.Runner.CheckTimeout = time.Second
	id2 := readyAD(t, s, st, "AD slower", "")
	v, err = s.Validate(context.Background(), st, id2, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "aborted" {
		t.Errorf("run status %s, want aborted", v.Status)
	}
}

// brokenTLS fails the TLS handshake.
type brokenTLS struct{ *connectors.ScenarioProber }

func (p brokenTLS) Connect(context.Context) (connectors.ConnInfo, error) {
	return connectors.ConnInfo{Reachable: true}, nil
}

func TestRunner_DependencyBlocks(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	s.Runner.ProberFor = func(b *Bundle, now time.Time) (connectors.Prober, error) {
		p, err := connectors.NewScenarioProber("ad", "happy", now, b.Config.BaseDNs, nil)
		return brokenTLS{p}, err
	}
	id := readyAD(t, s, st, "AD no TLS", "")
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(v, "ad.tls.ldaps", "tls_handshake"); r.Status != "fail" {
		t.Fatalf("ldaps: %+v", r)
	}
	for _, it := range [][2]string{{"ad.tls.chain", "tls_chain"}, {"ad.bind", "bind"}, {"ad.svc.readonly", "ad_svc_groups"},
		{"ad.scope.base_dns", "dn_exists"}, {"ad.groups.range", "range_retrieval"}, {"ad.sync.deleted", "deleted_objects_readable"}} {
		if r := resultFor(v, it[0], it[1]); r == nil || r.Status != "blocked" {
			t.Errorf("%s: %+v", it[0], r)
		}
	}
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	g := b.Gate(store.StateValidated, t0)
	if !slices.ContainsFunc(g.Blocking, func(x Blocker) bool { return x.Item == "ad.bind" && x.Status == "blocked" }) {
		t.Errorf("gate: %+v", g.Blocking)
	}
}

func validated(t *testing.T, s *Service, st Scope, name string) string {
	t.Helper()
	id := readyAD(t, s, st, name, `{"demo_fixed_checks":["range_retrieval"]}`)
	if _, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0)); err != nil {
		t.Fatal(err)
	}
	if got := state(t, s, st, id); got != store.StateValidated {
		t.Fatalf("not validated: %s", got)
	}
	return id
}

func TestRunner_ConfigHashStale(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	id := validated(t, s, st, "AD stale")
	var runID string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Current(c, id, t0)
		runID = b.Evidence.LiveRun.ID
		if err != nil {
			return err
		}
		// a field no live check depends on: still validated
		res, err := s.PatchConfig(c, id, []byte(`{"sync_schedule":"incremental hourly, full weekly"}`), "admin", t0)
		if err != nil {
			return err
		}
		if res.Bundle.Rev.State != store.StateValidated {
			t.Errorf("schedule edit invalidated live evidence: %s", res.Bundle.Rev.State)
		}
		return nil
	})
	// The host backs the TLS evidence: editing it makes that evidence stale.
	write(t, st, func(c *store.TenantTx) error {
		res, err := s.PatchConfig(c, id, []byte(`{"host":"dc07.corp.larkspur.example"}`), "admin", t0)
		if err != nil {
			return err
		}
		if res.Bundle.Rev.SecretRef != nil {
			t.Error("the stored credential survived a host change")
		}
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/ad"}, "admin", t0); err != nil {
			return err
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0); err != nil {
			return err
		}
		if res.Bundle, err = s.reload(c, res.Bundle.Rev.ID, t0); err != nil {
			return err
		}
		if res.Bundle.Rev.State != store.StateReadyToValidate {
			t.Errorf("state %s", res.Bundle.Rev.State)
		}
		// the root item is stale; its dependants are blocked by it
		if it, _ := res.Bundle.Eval.Item("ad.tls.ldaps"); it.Status != StatusStale {
			t.Errorf("ad.tls.ldaps %s", it.Status)
		}
		if it, _ := res.Bundle.Eval.Item("ad.tls.chain"); it.Status != StatusBlocked || !slices.Contains(it.BlockedBy, "ad.tls.ldaps") {
			t.Errorf("ad.tls.chain %s %v", it.Status, it.BlockedBy)
		}
		return nil
	})
	var v *RunView
	err := st.Read(context.Background(), func(c *store.TenantTx) error {
		var err error
		v, err = s.RunView(c, id, runID, t0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Stale || !strings.Contains(v.StaleReason, "configuration changed") {
		t.Errorf("run view: stale %v %q", v.Stale, v.StaleReason)
	}
}

func TestRunner_LiveTTL(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	id := validated(t, s, st, "AD ttl")
	later := t0.Add(25 * time.Hour)
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.Transition(c, id, store.StateDryRunReconciled, "admin", later)
		return err
	})
	var re *Error
	if !errors.As(err, &re) || re.Report == nil {
		t.Fatalf("transition after TTL: %v", err)
	}
	if !slices.ContainsFunc(re.Report.Blocking, func(x Blocker) bool {
		return x.Item == "validation" && x.Status == StatusStale && strings.Contains(x.Reason, "24h")
	}) {
		t.Errorf("blockers: %+v", re.Report.Blocking)
	}
	b, err := current(st, s, id, later)
	if err != nil {
		t.Fatal(err)
	}
	if it, _ := b.Eval.Item("ad.tls.ldaps"); it.Status != StatusStale || !strings.Contains(it.Reason, "older than 24h") {
		t.Errorf("ad.tls.ldaps after TTL: %s %s", it.Status, it.Reason)
	}
	// Re-running restores freshness.
	if _, err := s.Validate(context.Background(), st, id, "admin", clockAt(later)); err != nil {
		t.Fatal(err)
	}
	if got := state(t, s, st, id); got != store.StateValidated {
		t.Errorf("state %s", got)
	}
}

func TestRunner_OneRunAtATimeAndRateLimit(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	id := readyAD(t, s, st, "AD rate", "")
	// a run left running blocks the next one
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		return c.InsertCheckRun(&store.CheckRun{ID: store.NewID(), RevisionID: b.Rev.ID, Kind: "validation", Simulated: true,
			Status: "running", ActorID: "admin", ConfigHash: b.ConfigHash, StartedAt: t0})
	})
	_, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	var re *Error
	if !errors.As(err, &re) || re.Code != "validation_running" || re.Extra["run_id"] == nil {
		t.Fatalf("second run: %v", err)
	}
	id2 := readyAD(t, s, st, "AD rate2", "")
	for i := range 7 {
		_, err := s.Validate(context.Background(), st, id2, "admin", clockAt(t0.Add(time.Duration(i)*time.Minute)))
		if i < 6 && err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if i == 6 && (!errors.As(err, &re) || re.Status != http.StatusTooManyRequests) {
			t.Fatalf("7th run: %v", err)
		}
	}
}

func TestResults_NoSecretBytes(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	const token = "SSWS 00Qx7Lk2Hn9PzRt4Wv6Yb8Mc1Ne3Gf5Jh0Ks2Ld4"
	id := readyAD(t, s, st, "AD secret", `{"user_filter":"(&(objectCategory=person)(description=`+token+`))"}`)
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	r := resultFor(v, "base.cred.sealed", "cred_storage")
	if r == nil || r.Status != "fail" || !strings.Contains(r.Message, "secret-shaped") {
		t.Fatalf("cred_storage: %+v", r)
	}
	raw, _ := json.Marshal(v)
	secret := strings.TrimPrefix(token, "SSWS ")
	if strings.Contains(string(raw), secret) {
		t.Fatal("a check result contains the secret bytes")
	}
	// nor does anything stored for the run or the audit log
	var rows []*store.CheckResult
	var log []*store.AuditEvent
	read(t, st, func(c *store.TenantTx) error {
		rows, _ = c.CheckResults(v.ID)
		log, _ = c.AuditLog(50)
		return nil
	})
	for _, r := range rows {
		if strings.Contains(r.Observed+r.Message, secret) {
			t.Fatalf("stored result %s leaks the secret", r.CheckID)
		}
	}
	for _, e := range log {
		if strings.Contains(e.Action, "validation") && strings.Contains(string(e.Detail), secret) {
			t.Fatalf("audit %s leaks the secret", e.Action)
		}
	}
}

func TestScenarios_Deterministic(t *testing.T) {
	for _, scenario := range connectors.ScenarioNames() {
		for _, tid := range template.TemplateIDs {
			tmpl, _ := template.MustDefault().Get(tid)
			run := func() map[string]string {
				p, err := connectors.NewScenarioProber(tid, scenario, t0, []string{"DC=corp,DC=example"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				out := map[string]string{}
				for _, it := range tmpl.Items {
					for _, v := range it.Verify {
						if v.Kind != template.Live {
							continue
						}
						env := checks.Env{Probe: p, Now: t0, TemplateID: tid, SecretRef: "vault:x", BaseDNs: []string{"DC=corp,DC=example"},
							Filters:       map[string]string{"user_filter": "(&(objectCategory=person)(objectClass=user))"},
							RequiredAttrs: tmpl.RequiredAttributes["user"], WriteScope: []string{"OU=Provisioned"}}
						r := runOne(context.Background(), v, env, p, time.Second)
						obs, _ := json.Marshal(r.observed)
						out[it.ID+"/"+v.Check] = r.status + "|" + r.message + "|" + string(obs)
					}
				}
				return out
			}
			a, b := run(), run()
			if len(a) == 0 && tid != "workday" {
				t.Errorf("%s/%s: no live checks", scenario, tid)
			}
			for k, v := range a {
				if b[k] != v {
					t.Errorf("%s/%s %s differs between runs:\n%s\n%s", scenario, tid, k, v, b[k])
				}
				if strings.HasPrefix(v, "error|") {
					t.Errorf("%s/%s %s errored: %s", scenario, tid, k, v)
				}
			}
		}
	}
}

// recorder wraps a prober and records every operation.
type recorder struct {
	connectors.Prober
	mu  sync.Mutex
	ops []string
}

func (r *recorder) rec(op string) {
	r.mu.Lock()
	r.ops = append(r.ops, op)
	r.mu.Unlock()
}
func (r *recorder) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	r.rec("connect")
	return r.Prober.Connect(ctx)
}
func (r *recorder) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	r.rec("authenticate")
	return r.Prober.Authenticate(ctx)
}
func (r *recorder) RootInfo(ctx context.Context) (connectors.RootInfo, error) {
	r.rec("root_info")
	return r.Prober.RootInfo(ctx)
}
func (r *recorder) ObjectExists(ctx context.Context, ref string) (bool, error) {
	r.rec("object_exists")
	return r.Prober.ObjectExists(ctx, ref)
}
func (r *recorder) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	r.rec("sample")
	if q.Limit > connectors.MaxSample {
		r.rec("oversized_sample")
	}
	return r.Prober.Sample(ctx, q)
}
func (r *recorder) EffectiveRights(ctx context.Context, ref string) (connectors.Rights, error) {
	r.rec("effective_rights")
	return r.Prober.EffectiveRights(ctx, ref)
}
func (r *recorder) ChangeFeed(ctx context.Context) (connectors.FeedInfo, error) {
	r.rec("change_feed")
	return r.Prober.ChangeFeed(ctx)
}
func (r *recorder) RateLimits(ctx context.Context) (connectors.RateInfo, error) {
	r.rec("rate_limits")
	return r.Prober.RateLimits(ctx)
}
func (r *recorder) Time(ctx context.Context) (time.Time, error) {
	r.rec("time")
	return r.Prober.Time(ctx)
}

// failTransport fails (and counts) any HTTP request: probers must not use the network.
type failTransport struct{ n int }

func (f *failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.n++
	return nil, errors.New("network access in a readiness test")
}

func TestProbers_ReadOnly(t *testing.T) {
	ft := &failTransport{}
	old := http.DefaultTransport
	http.DefaultTransport = ft
	defer func() { http.DefaultTransport = old }()
	reg := template.MustDefault()
	for _, tid := range template.TemplateIDs {
		tmpl, _ := reg.Get(tid)
		for _, scenario := range connectors.ScenarioNames() {
			base, err := connectors.NewScenarioProber(tid, scenario, t0, []string{"DC=x"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, it := range tmpl.Items {
				for _, v := range it.Verify {
					c, ok := checks.Get(v.Check)
					if v.Kind != template.Live || !ok {
						continue
					}
					rec := &recorder{Prober: base}
					env := checks.Env{Probe: rec, Now: t0, TemplateID: tid, SecretRef: "vault:x", BaseDNs: []string{"DC=x"},
						Filters: map[string]string{"user_filter": "(objectCategory=person)"}, RequiredAttrs: tmpl.RequiredAttributes["user"]}
					checks.Run(context.Background(), c, env, checks.Params(v.Params))
					for _, op := range rec.ops {
						if !slices.Contains(connectors.ProberOps, op) {
							t.Errorf("%s: %s performed %s", tid, v.Check, op)
						}
						if op != c.Op {
							t.Errorf("%s: %s performed %s, but declares %s", tid, v.Check, op, c.Op)
						}
					}
					if c.Op == template.OpTessera && len(rec.ops) > 0 {
						t.Errorf("%s touched the system: %v", v.Check, rec.ops)
					}
				}
			}
		}
	}
	if ft.n > 0 {
		t.Fatalf("%d network requests", ft.n)
	}
	// The guard refuses an undeclared operation.
	sneaky := &checks.Check{ID: "tls_handshake", Kind: template.Live, Op: template.OpConnect,
		Run: func(ctx context.Context, env checks.Env, _ checks.Params) checks.Result {
			if _, err := env.Probe.EffectiveRights(ctx, "x"); errors.Is(err, checks.ErrOpNotAllowed) {
				return checks.Result{Status: "refused"}
			}
			return checks.Result{Status: "allowed"}
		}}
	p, _ := connectors.NewScenarioProber("ad", "gaps", t0, nil, nil)
	if r := checks.Run(context.Background(), sneaky, checks.Env{Probe: p}, nil); r.Status != "refused" {
		t.Errorf("guard allowed an undeclared operation")
	}
}

// Every check id the templates may reference has an implementation whose
// kind (and, for live checks, prober operation) matches the catalogue.
func TestRegistry_CoversCatalogue(t *testing.T) {
	for id, spec := range template.Checks {
		c, ok := checks.Get(id)
		if !ok {
			t.Errorf("%s check %s has no implementation", spec.Kind, id)
			continue
		}
		if c.Kind != spec.Kind || (spec.Kind == template.Live && c.Op != spec.Op) {
			t.Errorf("%s: implementation does not match the catalogue", id)
		}
	}
	if len(checks.IDs()) != len(template.Checks) {
		t.Errorf("%d implementations for %d catalogue entries", len(checks.IDs()), len(template.Checks))
	}
}
