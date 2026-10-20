package readiness

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/templates"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// activeAD returns a store, service and live demo AD connection whose
// evidence is simulated (fe): fe.fail makes Required live items fail.
func activeAD(t *testing.T) (Scope, *Service, *fakeEvidence, string) {
	t.Helper()
	st, s := newStore(t), newSvc(t)
	fe := &fakeEvidence{on: true, runAt: t0}
	fe.bind(s)
	id := createAD(t, s, st, "AD drift")
	driveTo(t, s, st, id, "active")
	return st, s, fe, id
}

func (f *fakeEvidence) setFail(items ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = map[string]bool{}
	for _, it := range items {
		f.fail[it] = true
	}
}

// schedRun records a finished scheduled run (the evidence itself is simulated).
func schedRun(t *testing.T, st Scope, id, actor string, at time.Time) string {
	t.Helper()
	runID := store.NewID()
	write(t, st, func(c *store.TenantTx) error {
		_, live, _, err := Revisions(c, id)
		if err != nil {
			return err
		}
		if err := c.InsertCheckRun(&store.CheckRun{ID: runID, RevisionID: live.ID, Kind: "scheduled", Simulated: true, Status: "running",
			ActorID: actor, ConfigHash: live.ConfigHash, StartedAt: at}); err != nil {
			return err
		}
		return c.FinishCheckRun(runID, "completed", at)
	})
	return runID
}

// fakes maps a service to its simulated evidence, whose results are as old as
// the last time a test moved the clock (live evidence expires after 24 hours).
var fakes sync.Map

func (f *fakeEvidence) bind(s *Service) {
	f.install(s)
	fakes.Store(s, f)
}

func clockTo(s *Service, now time.Time) {
	if f, ok := fakes.Load(s); ok {
		fe := f.(*fakeEvidence)
		fe.mu.Lock()
		fe.runAt = now
		fe.mu.Unlock()
	}
}

func monitor(t *testing.T, s *Service, st Scope, id string, now time.Time) *MonitorResult {
	t.Helper()
	clockTo(s, now)
	var res *MonitorResult
	write(t, st, func(c *store.TenantTx) error {
		var err error
		res, err = s.Monitor(c, id, ExternalSignals{}, now)
		return err
	})
	if res == nil {
		t.Fatal("Monitor returned nothing for a live connection")
	}
	return res
}

func baselineOfRev(t *testing.T, st Scope, id string) *store.Baseline {
	t.Helper()
	var bl *store.Baseline
	read(t, st, func(c *store.TenantTx) error {
		_, live, _, err := Revisions(c, id)
		if err != nil {
			return err
		}
		bl, err = c.Baseline(live.ID)
		return err
	})
	return bl
}

func auditCount(t *testing.T, st Scope, action string) int {
	t.Helper()
	n := 0
	read(t, st, func(c *store.TenantTx) error {
		log, err := c.AuditLog(-1)
		for _, e := range log {
			if e.Action == action {
				n++
			}
		}
		return err
	})
	return n
}

func TestDrift_Tolerances(t *testing.T) {
	for _, tc := range []struct {
		name      string
		was, now  int
		objects   bool // judged as an object count (±5%) instead of a finding count
		wantDrift bool
	}{
		{name: "finding at 10% of 1000", was: 1000, now: 1100, objects: false, wantDrift: false},
		{name: "finding just beyond 10% of 1000", was: 1000, now: 1101, objects: false, wantDrift: true},
		{name: "finding shrinking beyond 10%", was: 1000, now: 899, objects: false, wantDrift: true},
		{name: "finding at 25 objects of 100", was: 100, now: 125, objects: false, wantDrift: false},
		{name: "finding just beyond 25 objects of 100", was: 100, now: 126, objects: false, wantDrift: true},
		{name: "small finding is judged by the 25 object floor", was: 10, now: 30, objects: false, wantDrift: false},
		{name: "new finding below the floor", was: 0, now: 25, objects: false, wantDrift: false},
		{name: "new finding above the floor", was: 0, now: 26, objects: false, wantDrift: true},
		{name: "objects at 5%", was: 1000, now: 1050, objects: true, wantDrift: false},
		{name: "objects just beyond 5%", was: 1000, now: 1051, objects: true, wantDrift: true},
		{name: "objects shrinking beyond 5%", was: 1000, now: 949, objects: true, wantDrift: true},
		{name: "no previous count to compare", was: 0, now: 500, objects: true, wantDrift: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FindingDrift(tc.was, tc.now)
			if tc.objects {
				got = ObjectDrift(tc.was, tc.now)
			}
			if got != tc.wantDrift {
				t.Errorf("drift(%d → %d) = %v, want %v", tc.was, tc.now, got, tc.wantDrift)
			}
		})
	}

	base := &BaselineSnapshot{Items: map[string]string{"ad.bind": StatusPass, "ad.groups.range": StatusFail, "ad.svc.rights": StatusPass},
		Findings: map[string]int{"RF-01": 100}}
	kinds := func(es []DriftEvent) map[string]string {
		out := map[string]string{}
		for _, e := range es {
			out[e.Kind+"/"+e.Subject] = e.Severity
		}
		return out
	}
	cur := &Observation{
		Items: map[string]itemObs{
			"ad.bind":         {Status: StatusFail, Level: "required"},                    // newly failing
			"ad.groups.range": {Status: StatusFail, Level: "required"},                    // already failing at activation
			"ad.svc.rights":   {Status: StatusFail, Level: "recommended", External: true}, // write permission appeared
			"ad.other":        {Status: StatusPass, Level: "required"},
		},
		Findings:       map[string]int{"RF-01": 126, "RF-07": 20},
		Counts:         DryRunCounts{Accounts: 1051, Groups: 100, Memberships: 5000},
		CredentialDays: ip(30),
	}
	prev := &DryRunCounts{Accounts: 1000, Groups: 100, Memberships: 5200}
	got := kinds(Compare(base, prev, cur))
	want := map[string]string{
		DriftNewFailing + "/ad.bind":     "high",
		DriftExternal + "/ad.svc.rights": "medium",
		DriftFindings + "/RF-01":         "medium", // 100 → 126: beyond 25 and 10%
		DriftObjects + "/accounts":       "medium", // 1000 → 1051
		DriftExpiring + "/credential":    "medium",
	}
	if len(got) != len(want) {
		t.Errorf("events = %v, want %v", got, want)
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("event %s severity = %q, want %q (all: %v)", k, got[k], sev, got)
		}
	}
	// Memberships moved 4% and RF-07 stayed under the floor: no event; a credential 7 days out is high.
	cur.CredentialDays = ip(7)
	if got := kinds(Compare(base, nil, cur)); got[DriftExpiring+"/credential"] != "high" || got[DriftObjects+"/accounts"] != "" {
		t.Errorf("credential at 7 days / no previous counts: %v", got)
	}
	cur.CredentialDays = ip(31)
	if got := kinds(Compare(base, nil, cur)); got[DriftExpiring+"/credential"] != "" {
		t.Errorf("credential at 31 days drifted: %v", got)
	}
}

func TestDrift_BaselineAndView(t *testing.T) {
	st, s, fe, id := activeAD(t)
	bl := baselineOfRev(t, st, id)
	if !bl.CapturedAt.Equal(t0) || bl.Score == 0 || bl.ConfigHash == "" || bl.FailStreak != 0 {
		t.Fatalf("baseline at activation: %+v", bl)
	}
	if n := auditCount(t, st, "readiness.baseline.captured"); n != 1 {
		t.Errorf("baseline audit events = %d, want 1", n)
	}
	var h *ConnectionHealthView
	read(t, st, func(c *store.TenantTx) error {
		var err error
		h, err = s.Health(c, id, t0.Add(time.Hour))
		return err
	})
	if h.Drift == nil || len(h.Drift.Events) != 0 || h.Drift.Baseline.Score != bl.Score || h.Schedule["live_checks"] != "daily" {
		t.Fatalf("health drift right after activation: %+v %v", h.Drift, h.Schedule)
	}
	// A Required live check that passed at activation now fails: drift, no state change.
	fe.setFail("ad.bind")
	read(t, st, func(c *store.TenantTx) error {
		var err error
		h, err = s.Health(c, id, t0.Add(time.Hour))
		return err
	})
	if len(h.Drift.Events) != 1 || h.Drift.Events[0].Kind != DriftNewFailing || h.Drift.Events[0].Severity != "high" ||
		h.Drift.Events[0].Subject != "ad.bind" {
		t.Errorf("drift events: %+v", h.Drift.Events)
	}
	// Activating a revision twice never rewrites the baseline.
	var again *store.Baseline
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		again, err = s.captureBaseline(c, b, t0.Add(48*time.Hour))
		return err
	})
	if !again.CapturedAt.Equal(bl.CapturedAt) || again.Score != bl.Score {
		t.Errorf("baseline rewritten: %+v vs %+v", again, bl)
	}
}

func TestDegraded_TwoConsecutiveFailures(t *testing.T) {
	st, s, fe, id := activeAD(t)
	fe.setFail("ad.bind")
	hour := func(n int) time.Time { return t0.Add(time.Duration(n) * 24 * time.Hour) }

	// An administrator's on-demand re-run is evidence, not a scheduled run.
	schedRun(t, st, id, "admin", hour(1))
	if res := monitor(t, s, st, id, hour(1)); res.Degraded || baselineOfRev(t, st, id).FailStreak != 0 {
		t.Fatalf("an on-demand run counted: %+v", res)
	}
	// First scheduled failure: counted once, however often the monitor runs.
	r1 := schedRun(t, st, id, SchedulerActor, hour(2))
	for i := 0; i < 3; i++ {
		if res := monitor(t, s, st, id, hour(2)); res.Degraded || res.State != store.StateActive {
			t.Fatalf("one failure degraded the connection: %+v", res)
		}
	}
	if bl := baselineOfRev(t, st, id); bl.FailStreak != 1 || bl.LastRunID == nil || *bl.LastRunID != r1 {
		t.Fatalf("after one failing run: %+v", bl)
	}
	// A passing run in between resets the streak: fail, pass, fail is not two in a row.
	fe.setFail()
	schedRun(t, st, id, SchedulerActor, hour(3))
	monitor(t, s, st, id, hour(3))
	if bl := baselineOfRev(t, st, id); bl.FailStreak != 0 {
		t.Fatalf("streak after a passing run: %d", bl.FailStreak)
	}
	fe.setFail("ad.bind")
	schedRun(t, st, id, SchedulerActor, hour(4))
	if res := monitor(t, s, st, id, hour(4)); res.Degraded {
		t.Fatalf("fail, pass, fail degraded the connection: %+v", res)
	}
	// Second consecutive failure: degraded, with the reason, an audit event and an Inbox task.
	schedRun(t, st, id, SchedulerActor, hour(5))
	res := monitor(t, s, st, id, hour(5))
	if !res.Degraded || res.State != store.StateDegraded || len(res.Reasons) != 1 || !strings.Contains(res.Reasons[0], "ad.bind") ||
		!strings.Contains(res.Reasons[0], "2 consecutive") {
		t.Fatalf("second failure: %+v", res)
	}
	if got := state(t, s, st, id); got != store.StateDegraded {
		t.Errorf("state = %s", got)
	}
	if n := auditCount(t, st, "connection.degraded"); n != 1 {
		t.Errorf("connection.degraded events = %d, want 1", n)
	}
	var tasks []Task
	read(t, st, func(c *store.TenantTx) error {
		var err error
		tasks, err = s.Tasks(c, hour(5))
		return err
	})
	if len(tasks) != 1 || tasks[0].ConnectionID != id || tasks[0].Owner == nil || *tasks[0].Owner != "Ingrid Lindqvist" ||
		!strings.Contains(tasks[0].Reason, "ad.bind") || tasks[0].Kind != "connection" {
		t.Errorf("tasks: %+v", tasks)
	}
	// More failing runs keep it degraded without more events.
	schedRun(t, st, id, SchedulerActor, hour(6))
	monitor(t, s, st, id, hour(6))
	if n := auditCount(t, st, "connection.degraded"); n != 1 {
		t.Errorf("connection.degraded events after another failure = %d", n)
	}
}

func TestDegraded_OtherTriggers(t *testing.T) {
	now := t0
	days := func(n int) *int { return &n }
	long := now.Add(-25 * time.Hour)
	for _, tc := range []struct {
		name string
		sig  Signals
		want string // substring of the single reason; "" means none
	}{
		{"healthy", Signals{}, ""},
		{"one failing run", Signals{FailStreak: 1, FailingItems: []string{"ad.bind"}}, ""},
		{"two failing runs", Signals{FailStreak: 2, FailingItems: []string{"ad.bind"}}, "ad.bind"},
		{"credential 8 days out", Signals{CredentialDays: days(8)}, ""},
		{"credential 7 days out", Signals{CredentialDays: days(7)}, "credential expires in 7 days"},
		{"sync failing 23 h", Signals{ExternalSignals: ExternalSignals{SyncFailedSince: ptrTime(now.Add(-23 * time.Hour))}}, ""},
		{"sync failing 25 h", Signals{ExternalSignals: ExternalSignals{SyncFailedSince: &long}}, "24 hours"},
		{"cursor lost twice", Signals{ExternalSignals: ExternalSignals{CursorLosses7d: 2}}, ""},
		{"cursor lost three times", Signals{ExternalSignals: ExternalSignals{CursorLosses7d: 3}}, "cursor was lost 3 times"},
		{"template grace running", Signals{Upgrade: &TemplateUpgrade{Available: "ad@1.1", NewRequired: []string{"x"}}}, ""},
		{"template grace over", Signals{Upgrade: &TemplateUpgrade{Available: "ad@1.1", NewRequired: []string{"x"}, Overdue: true}}, "grace period ended"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DegradeReasons(tc.sig, now)
			switch {
			case tc.want == "" && len(got) != 0:
				t.Errorf("reasons = %v, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("reasons = %v, want one containing %q", got, tc.want)
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// setWriteMode puts the live revision in scoped write mode. Activating a
// write-enabled connection needs a second approver (DR-10), so a test sets
// the mode on the stored revision directly.
func setWriteMode(t *testing.T, st Scope, id string) {
	t.Helper()
	write(t, st, func(c *store.TenantTx) error {
		_, live, _, err := Revisions(c, id)
		if err != nil {
			return err
		}
		return c.UpdateRevisionConfig(live.ID, live.Config, live.ConfigHash, "scoped", nil, t0)
	})
}

func TestDegraded_BlocksWrite(t *testing.T) {
	st, s, fe, id := activeAD(t)
	can := func() (bool, error) {
		var ok bool
		var err error
		write(t, st, func(c *store.TenantTx) error {
			ok, err = s.CanWrite(c, id)
			if err == nil {
				err = s.RequireWrite(c, id)
			}
			return nil
		})
		return ok, err
	}
	// Active but not in write mode: refused with its own code.
	if ok, err := can(); ok || codeOf(err) != "write_not_enabled" {
		t.Fatalf("write mode off: %v %v", ok, err)
	}
	setWriteMode(t, st, id)
	if ok, err := can(); !ok || err != nil {
		t.Fatalf("active, scoped: %v %v", ok, err)
	}
	fe.setFail("ad.bind")
	schedRun(t, st, id, SchedulerActor, t0.Add(24*time.Hour))
	monitor(t, s, st, id, t0.Add(24*time.Hour))
	schedRun(t, st, id, SchedulerActor, t0.Add(48*time.Hour))
	if res := monitor(t, s, st, id, t0.Add(48*time.Hour)); !res.Degraded {
		t.Fatalf("not degraded: %+v", res)
	}
	if ok, err := can(); ok || codeOf(err) != "connection_degraded" {
		t.Fatalf("degraded: write allowed = %v, err %v", ok, err)
	}
	// Reads continue: the degraded connection still syncs into the graph.
	var live []ActiveConnection
	read(t, st, func(c *store.TenantTx) error {
		var err error
		live, err = s.ActiveConnections(c)
		return err
	})
	if len(live) != 1 || live[0].ConnectionID() != id {
		t.Errorf("degraded connection is not readable: %+v", live)
	}
	// A retired connection is refused too.
	write(t, st, func(c *store.TenantTx) error { return s.Retire(c, id, "admin", t0) })
	if ok, err := can(); ok || codeOf(err) == "" {
		t.Errorf("retired: %v %v", ok, err)
	}
}

func TestRecovered(t *testing.T) {
	st, s, fe, id := activeAD(t)
	setWriteMode(t, st, id)
	fe.setFail("ad.bind")
	day := func(n int) time.Time { return t0.Add(time.Duration(n) * 24 * time.Hour) }
	for n := 1; n <= 2; n++ {
		schedRun(t, st, id, SchedulerActor, day(n))
		monitor(t, s, st, id, day(n))
	}
	if got := state(t, s, st, id); got != store.StateDegraded {
		t.Fatalf("state = %s", got)
	}
	// Still failing: stays degraded. Fixed: the next scheduled run recovers it.
	schedRun(t, st, id, SchedulerActor, day(3))
	if res := monitor(t, s, st, id, day(3)); res.Recovered {
		t.Fatalf("recovered while failing: %+v", res)
	}
	fe.setFail()
	schedRun(t, st, id, SchedulerActor, day(4))
	res := monitor(t, s, st, id, day(4))
	if !res.Recovered || res.State != store.StateActive || len(res.Reasons) != 0 {
		t.Fatalf("recover: %+v", res)
	}
	if n := auditCount(t, st, "connection.recovered"); n != 1 {
		t.Errorf("connection.recovered events = %d", n)
	}
	var ok bool
	var tasks []Task
	write(t, st, func(c *store.TenantTx) error {
		var err error
		if ok, err = s.CanWrite(c, id); err != nil {
			return err
		}
		tasks, err = s.Tasks(c, day(4))
		return err
	})
	if !ok || len(tasks) != 0 {
		t.Errorf("after recovery: can write %v, tasks %v", ok, tasks)
	}
	if bl := baselineOfRev(t, st, id); bl.DegradedReason != nil || bl.FailStreak != 0 {
		t.Errorf("baseline after recovery: %+v", bl)
	}
	// A revision degraded by someone else (not by the monitor) is not recovered by it.
	write(t, st, func(c *store.TenantTx) error { return s.Degrade(c, id, "operator", day(5)) })
	schedRun(t, st, id, SchedulerActor, day(5))
	if res := monitor(t, s, st, id, day(5)); res.Recovered || res.State != store.StateDegraded {
		t.Errorf("monitor recovered a revision it did not degrade: %+v", res)
	}
}

// release11 is a registry whose current ad template is 1.1 (one more Required
// item) and whose archive still holds 1.0, so revisions pinned to 1.0 resolve.
func release11(t *testing.T) *template.Registry {
	t.Helper()
	base, _ := templates.FS.ReadFile("base.yaml")
	ad, _ := templates.FS.ReadFile("ad.yaml")
	v11 := strings.Replace(string(ad), "version: 1.0.0", "version: 1.1.0", 1) + `
  - id: ad.topo.second_dc
    title: A second domain controller is reachable
    category: topology
    level: required
    why: "A single domain controller is a single point of sync failure."
    verify:
      - kind: live
        check: dc_count
        params: { min: 2 }
    remediation:
      hint: "Add a second domain controller."
    depends_on: [ad.bind]
    config_fields: [host]
`
	reg, err := template.Load(fstest.MapFS{"base.yaml": {Data: base}, "ad.yaml": {Data: []byte(v11)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Archive(fstest.MapFS{"base.yaml": {Data: base}, "ad.yaml": {Data: ad}}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestTemplateUpgrade_GracePeriod(t *testing.T) {
	st, s1, fe, id := activeAD(t)
	s2 := NewService(release11(t), "")
	fe.bind(s2)
	day := func(n int) time.Time { return t0.Add(time.Duration(n) * 24 * time.Hour) }
	upgradeOf := func(now time.Time) (*TemplateUpgrade, []DriftEvent) {
		clockTo(s2, now)
		var v *DriftView
		read(t, st, func(c *store.TenantTx) error {
			b, err := s2.Current(c, id, now)
			if err != nil {
				return err
			}
			v, err = s2.Drift(c, b, now)
			return err
		})
		return v.Upgrade, v.Events
	}

	// Without the new release the pinned template is current: no upgrade.
	if res := monitor(t, s1, st, id, day(1)); len(res.Drift) != 0 {
		t.Fatalf("drift before the release: %+v", res.Drift)
	}

	// The release is first seen on day 2: grace starts, drift but still active.
	res := monitor(t, s2, st, id, day(2))
	if res.Degraded || len(res.Drift) != 1 || res.Drift[0].Kind != DriftTemplate || res.Drift[0].Severity != "medium" {
		t.Fatalf("day 2: %+v", res)
	}
	up, _ := upgradeOf(day(2))
	if up == nil || up.Pin != "ad@1.0" || up.Available != "ad@1.1" || up.Major || len(up.NewRequired) != 1 ||
		up.NewRequired[0] != "ad.topo.second_dc" || up.Overdue || *up.FirstSeen != store.RT(day(2)) || *up.GraceEnds != store.RT(day(32)) {
		t.Fatalf("upgrade on day 2: %+v", up)
	}
	// The clock starts once: later passes do not move it.
	monitor(t, s2, st, id, day(10))
	if up, _ = upgradeOf(day(10)); *up.FirstSeen != store.RT(day(2)) {
		t.Fatalf("first-seen moved: %s", *up.FirstSeen)
	}
	// One minute before the grace period ends: still active.
	if res := monitor(t, s2, st, id, day(32).Add(-time.Minute)); res.Degraded || res.State != store.StateActive {
		t.Fatalf("degraded inside the grace period: %+v", res)
	}
	// Grace over: degraded, the drift is high, and the connection stays degraded.
	res = monitor(t, s2, st, id, day(32))
	if !res.Degraded || len(res.Reasons) != 1 || !strings.Contains(res.Reasons[0], "ad@1.1") || res.Drift[0].Severity != "high" {
		t.Fatalf("after the grace period: %+v", res)
	}
	if res := monitor(t, s2, st, id, day(33)); res.Recovered || res.State != store.StateDegraded {
		t.Fatalf("recovered without a new revision: %+v", res)
	}

	// A revision on the new template (its own gates, one more Required item)
	// replaces the live one: no upgrade, active again, with a new baseline.
	write(t, st, func(c *store.TenantTx) error {
		_, err := s2.PatchConfig(c, id, []byte(`{"stale_days":60}`), "admin", day(34))
		return err
	})
	driveTo2(t, s2, st, id, day(34))
	res = monitor(t, s2, st, id, day(35))
	if res.State != store.StateActive || res.Degraded || len(res.Drift) != 0 {
		t.Fatalf("on the new template: %+v", res)
	}
	if up, _ = upgradeOf(day(35)); up != nil {
		t.Errorf("upgrade still offered: %+v", up)
	}
	if bl := baselineOfRev(t, st, id); !bl.CapturedAt.Equal(day(34)) {
		t.Errorf("new revision baseline captured at %s", bl.CapturedAt)
	}
}

// driveTo2 takes the pending revision of a connection to active.
func driveTo2(t *testing.T, s *Service, st Scope, id string, now time.Time) {
	t.Helper()
	clockTo(s, now)
	write(t, st, func(c *store.TenantTx) error {
		for _, item := range adAttestations {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", now); err != nil {
				return err
			}
		}
		if _, err := s.Skip(c, id, "ad.tls.signing_cb", "Scheduled for the Q1 domain controller upgrade", nil, "admin", now); err != nil {
			return err
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, "admin", now); err != nil {
			return err
		}
		b, err := s.Current(c, id, now)
		if err != nil {
			return err
		}
		if err := s.advanceAfterValidation(c, b, "admin", now); err != nil {
			return err
		}
		if _, err := s.Transition(c, id, store.StateDryRunReconciled, "admin", now); err != nil {
			return err
		}
		_, _, err = s.Activate(c, id, "admin", now)
		return err
	})
}

func TestTemplateUpgrade_MajorAndPatch(t *testing.T) {
	reg := release11(t)
	cur, _ := reg.Get("ad")
	old, err := reg.Resolve("ad@1.0")
	if err != nil {
		t.Fatal(err)
	}
	if up := upgradeOf(cur, cur, nil, t0); up != nil {
		t.Errorf("current template offered an upgrade: %+v", up)
	}
	up := upgradeOf(old, cur, nil, t0)
	if up == nil || up.Major || up.GraceEnds == nil || *up.GraceEnds != store.RT(t0.Add(UpgradeGrace)) {
		t.Fatalf("minor upgrade: %+v", up)
	}
	// A major release needs a new revision: no grace clock, so it never degrades by itself.
	major := cur.Clone()
	major.Version = "2.0.0"
	up = upgradeOf(old, major, nil, t0.Add(365*24*time.Hour))
	if up == nil || !up.Major || up.GraceEnds != nil || up.Overdue || upgradeEvent(up) != nil {
		t.Errorf("major upgrade: %+v", up)
	}
	// A minor release without new Required items is an update, not drift.
	soft := old.Clone()
	soft.Version = "1.1.0"
	soft.Items = append(soft.Items, template.Item{ID: "ad.extra", Level: template.Recommended})
	up = upgradeOf(old, soft, nil, t0)
	if up == nil || len(up.NewRequired) != 0 || up.NewOther != 1 || up.GraceEnds != nil || upgradeEvent(up) != nil {
		t.Errorf("minor upgrade without Required items: %+v", up)
	}
	if _, err := reg.Resolve("ad@1.2"); !errors.Is(err, template.ErrVersionUnavailable) {
		t.Errorf("an unknown minor resolved: %v", err)
	}
}

// testStage stages a discovery result like ingest.Stage (which this package
// cannot import: ingest depends on readiness).
func testStage(c *store.TenantTx, runID, system string, res *connectors.DiscoveryResult) error {
	for _, a := range res.Accounts {
		if a.System != system {
			continue
		}
		kind, status := a.Kind, a.Status
		if kind == "" {
			kind = "user"
		}
		if status == "" {
			status = "active"
		}
		if err := c.InsertStagedAccount(&store.StagedAccount{RunID: runID, System: a.System, ExternalID: a.ExternalID,
			Username: a.Username, Kind: kind, Status: status, CreatedAt: a.CreatedAt, LastLoginAt: a.LastLoginAt,
			Attributes: a.Attributes}); err != nil {
			return err
		}
	}
	for _, g := range res.Groups {
		if g.System != system {
			continue
		}
		kind := g.Kind
		if kind == "" {
			kind = "group"
		}
		if err := c.InsertStagedGroup(&store.StagedGroup{RunID: runID, System: g.System, ExternalID: g.ExternalID, Name: g.Name,
			Kind: kind, Privileged: g.Privileged, InScope: true}); err != nil {
			return err
		}
	}
	return nil
}

func TestScheduler_RerunsReconcilesAndDegrades(t *testing.T) {
	st, s, fe, id := activeAD(t)
	fe.mu.Lock()
	fe.on = false // from here on the evidence is what the scheduler's own runs record
	fe.mu.Unlock()
	now := t0
	clock := func() time.Time { return now }
	sc := &Scheduler{Svc: s, DB: st.DB, Clock: clock, Stage: testStage}
	pass := func(at time.Time) PassSummary {
		t.Helper()
		now = at
		sum, err := sc.RunTenant(context.Background(), st)
		if err != nil {
			t.Fatal(err)
		}
		return sum
	}
	// The default demo scenario has ranged retrieval failing (a Required check).
	sum := pass(t0.Add(25 * time.Hour))
	if sum.Connections != 1 || sum.Validated != 1 || sum.Reconciled != 1 || sum.Degraded != 0 {
		t.Fatalf("first pass: %+v", sum)
	}
	var run *store.CheckRun
	var rr *store.ReconRun
	read(t, st, func(c *store.TenantTx) error {
		_, live, _, err := Revisions(c, id)
		if err != nil {
			return err
		}
		if run, err = c.LatestLiveRun(live.ID); err != nil {
			return err
		}
		dry, err := c.LatestDryRun(live.ID)
		if err != nil || dry == nil {
			return errors.New("no live reconciliation run")
		}
		rr, err = c.ReconRunByID(dry.ID)
		return err
	})
	if run.Kind != "scheduled" || run.ActorID != SchedulerActor || rr.Mode != "live" || rr.Status != "completed" || rr.Counts == "" {
		t.Fatalf("scheduled run %+v, reconciliation %+v", run, rr)
	}
	// Nothing is due an hour later; due again after a day.
	if sum := pass(t0.Add(26 * time.Hour)); sum.Validated != 0 || sum.Reconciled != 0 {
		t.Errorf("an hour later: %+v", sum)
	}
	sum = pass(t0.Add(50 * time.Hour))
	if sum.Validated != 1 || sum.Reconciled != 0 || sum.Degraded != 1 {
		t.Fatalf("second failing day: %+v", sum)
	}
	if got := state(t, s, st, id); got != store.StateDegraded {
		t.Fatalf("state = %s", got)
	}
	// The failure is fixed (the happy scenario): the next daily run recovers it.
	s.Runner.Scenario = "happy"
	sum = pass(t0.Add(75 * time.Hour))
	if sum.Recovered != 1 {
		t.Fatalf("recovery pass: %+v", sum)
	}
	if got := state(t, s, st, id); got != store.StateActive {
		t.Fatalf("state = %s", got)
	}
	// The dashboard shows the drift row and no task once recovered.
	var d *Dashboard
	read(t, st, func(c *store.TenantTx) error {
		var err error
		d, err = s.Dashboard(c, now, "")
		return err
	})
	if len(d.Drift) != 1 || d.Connections[0].Drift == nil || len(d.Tasks) != 0 || d.Schedule["job"] != JobRerun {
		t.Errorf("dashboard drift %d, row drift %v, tasks %v, schedule %v", len(d.Drift), d.Connections[0].Drift, d.Tasks, d.Schedule)
	}
	for _, action := range []string{"readiness.validation.completed", "readiness.reconcile.started", "connection.degraded", "connection.recovered"} {
		if auditCount(t, st, action) == 0 {
			t.Errorf("no %s audit event", action)
		}
	}
}

type recordingHook struct{ jobs, ends []string }

func (h *recordingHook) Begin(_ context.Context, job string, _ time.Time) func(string, error) {
	h.jobs = append(h.jobs, job)
	return func(summary string, err error) {
		if err != nil {
			summary = "error: " + err.Error()
		}
		h.ends = append(h.ends, summary)
	}
}

func TestScheduler_RunOnceRecordsTheJob(t *testing.T) {
	st, s, _, _ := activeAD(t)
	h := &recordingHook{}
	sc := &Scheduler{Svc: s, DB: st.DB, Clock: func() time.Time { return t0.Add(time.Hour) }, Hook: h}
	if _, err := sc.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.jobs) != 1 || h.jobs[0] != JobRerun || len(h.ends) != 1 || !strings.HasPrefix(h.ends[0], "1 live connections") {
		t.Errorf("job hook: %v %v", h.jobs, h.ends)
	}
}
