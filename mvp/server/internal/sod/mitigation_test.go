package sod_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

type world struct {
	risk, control string
	alice, bob    int64
	req, appr     uuid.UUID // two platform users
	ownerUser     uuid.UUID // alice's user: owns the risk and the control
}

func user(t *testing.T, c *store.TenantTx, name string, identity *int64) uuid.UUID {
	t.Helper()
	u := &store.PlatformUser{DisplayName: name, Status: "active", IdentityID: identity, CreatedAt: testkit.Now}
	if err := c.InsertPlatformUser(u); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func setup(t *testing.T, c *store.TenantTx, ids testkit.IDs, remediation ...string) world {
	t.Helper()
	w := writer(c)
	alice, bob := ids["alice"], ids["bob"]
	fa, err := w.CreateFunction(sod.FunctionInput{Name: "Create", Selectors: pat("payments:create")})
	must(t, err)
	fb, err := w.CreateFunction(sod.FunctionInput{Name: "Approve", Selectors: pat("payments:approve")})
	must(t, err)
	rs, err := w.CreateRuleset(sod.RulesetInput{Name: "Finance", Enabled: true})
	must(t, err)
	r, err := w.CreateRisk(sod.RiskInput{Name: "Pay own", Priority: "high", RulesetID: rs.ID, FunctionIDs: []string{fa.ID, fb.ID},
		OwnerID: &alice, Remediation: remediation})
	must(t, err)
	ctl, err := w.CreateControl(sod.ControlInput{Name: "Monthly review", OwnerID: &alice, Type: "detective", Frequency: "monthly"})
	must(t, err)
	return world{risk: r.ID, control: ctl.ID, alice: alice, bob: bob, req: user(t, c, "requester", nil), appr: user(t, c, "approver", nil),
		ownerUser: user(t, c, "alice", &alice)}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func as(c *store.TenantTx, u uuid.UUID, now time.Time) *sod.Writer {
	return &sod.Writer{Tx: c, By: sod.Actor{UserID: u, Display: "user " + u.String()[:4]}, Now: now}
}

func (wd world) input(ends time.Time) sod.MitigationInput {
	return sod.MitigationInput{RiskID: wd.risk, IdentityID: wd.bob, Kind: store.MitigationControl, ControlID: wd.control,
		Justification: "reviewed monthly", EndsAt: ends, Evidence: []string{"ticket SEC-1"}}
}

func TestControlLibrary(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		w := writer(c)
		for name, in := range map[string]sod.ControlInput{
			"no owner":  {Name: "x", Type: "detective", Frequency: "daily"},
			"bad type":  {Name: "x", OwnerID: &wd.alice, Type: "magic", Frequency: "daily"},
			"bad freq":  {Name: "x", OwnerID: &wd.alice, Type: "detective", Frequency: "sometimes"},
			"no name":   {OwnerID: &wd.alice, Type: "detective", Frequency: "daily"},
			"duplicate": {Name: "Monthly review", OwnerID: &wd.alice, Type: "detective", Frequency: "daily"},
		} {
			if _, err := w.CreateControl(in); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		ctl, _ := c.SodControl(wd.control)
		up, err := w.UpdateControl(ctl.ID, 1, sod.ControlInput{Name: "Monthly review", OwnerID: &wd.alice, Type: "preventive", Frequency: "weekly",
			EvidenceRequirement: "sign-off"})
		if err != nil || up.Version != 2 || up.Type != "preventive" {
			t.Fatalf("update: %+v %v", up, err)
		}
		if _, err := w.UpdateControl(ctl.ID, 1, sod.ControlInput{Name: "x", OwnerID: &wd.alice, Type: "preventive", Frequency: "weekly"}); code(err) != "version_conflict" {
			t.Errorf("stale update: %v", err)
		}
		// in use by a pending mitigation: cannot retire
		_, err = as(c, wd.req, testkit.Now).RequestMitigation(wd.input(testkit.Now.Add(48*time.Hour)), sod.Settings{})
		must(t, err)
		if _, err := w.RetireControl(ctl.ID, "x"); code(err) != "control_in_use" {
			t.Errorf("retire in use: %v", err)
		}
		return nil
	})
}

func TestRequestValidation(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		w := as(c, wd.req, testkit.Now)
		day := 24 * time.Hour
		base := wd.input(testkit.Now.Add(30 * day))
		for name, tc := range map[string]struct {
			mut  func(*sod.MitigationInput)
			set  sod.Settings
			want string
		}{
			"no end date":        {func(m *sod.MitigationInput) { m.EndsAt = time.Time{} }, sod.Settings{}, "end_date_required"},
			"end in the past":    {func(m *sod.MitigationInput) { m.EndsAt = testkit.Now.Add(-time.Hour) }, sod.Settings{}, "invalid_end_date"},
			"beyond the default": {func(m *sod.MitigationInput) { m.EndsAt = testkit.Now.Add(366 * day) }, sod.Settings{}, "end_date_too_far"},
			"beyond a set max":   {func(m *sod.MitigationInput) {}, sod.Settings{MaxDays: 10}, "end_date_too_far"},
			"no justification":   {func(m *sod.MitigationInput) { m.Justification = " " }, sod.Settings{}, "justification_required"},
			"no control":         {func(m *sod.MitigationInput) { m.ControlID = "" }, sod.Settings{}, "control_required"},
			"unknown control":    {func(m *sod.MitigationInput) { m.ControlID = "nope" }, sod.Settings{}, "control_required"},
			"bad kind":           {func(m *sod.MitigationInput) { m.Kind = "ignore" }, sod.Settings{}, "invalid_kind"},
			"unknown risk":       {func(m *sod.MitigationInput) { m.RiskID = "nope" }, sod.Settings{}, "risk_not_found"},
			"too much evidence":  {func(m *sod.MitigationInput) { m.Evidence = make([]string, 11) }, sod.Settings{}, "invalid_evidence"},
			"empty evidence ref": {func(m *sod.MitigationInput) { m.Evidence = []string{""} }, sod.Settings{}, "invalid_evidence"},
		} {
			in := base
			in.Evidence = []string{"e"}
			tc.mut(&in)
			if _, err := w.RequestMitigation(in, tc.set); code(err) != tc.want {
				t.Errorf("%s: %v, want %s", name, err, tc.want)
			}
		}
		if _, err := writer(c).RequestMitigation(base, sod.Settings{}); code(err) != "user_required" {
			t.Errorf("no user: %v", err)
		}
		m, err := w.RequestMitigation(base, sod.Settings{})
		if err != nil || m.Status != store.MitigationPending || m.StartsAt != nil {
			t.Fatalf("request: %+v %v", m, err)
		}
		if _, err := w.RequestMitigation(base, sod.Settings{}); code(err) != "already_mitigated" {
			t.Errorf("a second live one: %v", err)
		}
		return nil
	})
}

func TestFourEyesAndLifecycle(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		now := testkit.Now
		m, err := as(c, wd.req, now).RequestMitigation(wd.input(now.Add(10*24*time.Hour)), sod.Settings{})
		must(t, err)
		if _, err := as(c, wd.req, now).DecideMitigation(m.ID, true, ""); code(err) != "four_eyes" {
			t.Errorf("requester approves own: %v", err)
		}
		if _, err := as(c, wd.appr, now).DecideMitigation(m.ID, false, ""); code(err) != "invalid_note" {
			t.Errorf("reject without a note: %v", err)
		}
		if _, err := as(c, wd.appr, now).CancelMitigation(m.ID); code(err) != "requester_only" {
			t.Errorf("someone else cancels: %v", err)
		}
		cov, _ := sod.Covers(c, now)
		if cv := cov.For(wd.risk, wd.bob); cv == nil || cv.Status != sod.StatusPending || sod.Closes(cv.Status) {
			t.Errorf("a pending request covers nothing: %+v", cv)
		}
		ap, err := as(c, wd.appr, now).DecideMitigation(m.ID, true, "ok")
		if err != nil || ap.Status != store.MitigationActive || ap.StartsAt == nil || *ap.DecidedBy != wd.appr.String() {
			t.Fatalf("approve: %+v %v", ap, err)
		}
		if _, err := as(c, wd.appr, now).DecideMitigation(m.ID, true, ""); code(err) != "not_pending" {
			t.Errorf("decide twice: %v", err)
		}
		cov, _ = sod.Covers(c, now)
		cv := cov.For(wd.risk, wd.bob)
		if cv == nil || cv.Status != sod.StatusMitigated || cv.Label != "Mitigated until "+m.EndsAt.Format("2006-01-02") || cv.Control != "Monthly review" {
			t.Errorf("cover = %+v", cv)
		}
		// applying marks a violation mitigated
		vs := []sod.Violation{{RiskID: wd.risk, IdentityID: wd.bob, Status: sod.StatusOpen}, {RiskID: wd.risk, IdentityID: wd.alice, Status: sod.StatusOpen}}
		cov.Apply(vs)
		if vs[0].Status != sod.StatusMitigated || vs[0].Mitigation == nil || vs[1].Status != sod.StatusOpen {
			t.Errorf("Apply = %+v", vs)
		}
		// early revoke reopens it
		if _, err := as(c, wd.ownerUser, now).RevokeMitigation(m.ID, ""); code(err) != "invalid_reason" {
			t.Errorf("revoke without a reason: %v", err)
		}
		rv, err := as(c, wd.ownerUser, now.Add(time.Hour)).RevokeMitigation(m.ID, "control failed")
		if err != nil || rv.Status != store.MitigationRevoked || rv.ClosedAt == nil {
			t.Fatalf("revoke: %+v %v", rv, err)
		}
		if cov, _ = sod.Covers(c, now); cov.For(wd.risk, wd.bob) != nil {
			t.Error("a revoked mitigation still covers")
		}
		if _, err := as(c, wd.ownerUser, now).RevokeMitigation(m.ID, "again"); code(err) != "not_active" {
			t.Errorf("revoke twice: %v", err)
		}
		// a rejected request and a cancelled one free the slot; accept needs the option and no control
		m2, err := as(c, wd.req, now).RequestMitigation(wd.input(now.Add(24*time.Hour)), sod.Settings{})
		must(t, err)
		rj, err := as(c, wd.appr, now).DecideMitigation(m2.ID, false, "not enough")
		if err != nil || rj.Status != store.MitigationRejected {
			t.Fatalf("reject: %+v %v", rj, err)
		}
		acc := wd.input(now.Add(24 * time.Hour))
		acc.Kind, acc.ControlID = store.MitigationAccept, ""
		m3, err := as(c, wd.req, now).RequestMitigation(acc, sod.Settings{})
		must(t, err)
		cn, err := as(c, wd.req, now).CancelMitigation(m3.ID)
		if err != nil || cn.Status != store.MitigationCancelled {
			t.Fatalf("cancel: %+v %v", cn, err)
		}
		return nil
	})
}

func TestRemediationOptionsAreEnforced(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids, sod.OptRevoke, sod.OptEscalate) // no mitigate, no accept
		now := testkit.Now
		w := as(c, wd.req, now)
		if _, err := w.RequestMitigation(wd.input(now.Add(24*time.Hour)), sod.Settings{}); code(err) != "option_not_offered" {
			t.Errorf("mitigate not offered: %v", err)
		}
		acc := wd.input(now.Add(24 * time.Hour))
		acc.Kind, acc.ControlID = store.MitigationAccept, ""
		if _, err := w.RequestMitigation(acc, sod.Settings{}); code(err) != "option_not_offered" {
			t.Errorf("accept not offered: %v", err)
		}
		if _, err := w.Escalate(wd.risk, wd.bob, "please look"); err != nil {
			t.Errorf("escalate is offered: %v", err)
		}
		risk, _ := c.SodRisk(wd.risk)
		opts, _ := sod.RiskOptions(c, risk.ID)
		if len(opts) != 2 || sod.Offers(opts, sod.OptMitigate) || !sod.Offers(opts, sod.OptRevoke) {
			t.Errorf("options = %v", opts)
		}
		if _, err := writer(c).CreateRisk(sod.RiskInput{Name: "bad", Priority: "low", RulesetID: risk.RulesetID,
			FunctionIDs: mustIDs(t, c), Remediation: []string{"ignore"}}); code(err) != "invalid_remediation" {
			t.Errorf("unknown option: %v", err)
		}
		return nil
	})
}

func mustIDs(t *testing.T, c *store.TenantTx) []string {
	fs, err := c.SodFunctions()
	must(t, err)
	return []string{fs[0].ID, fs[1].ID}
}

func TestEscalate(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		w := as(c, wd.req, testkit.Now)
		if _, err := w.Escalate(wd.risk, wd.bob, ""); code(err) != "invalid_note" {
			t.Errorf("no note: %v", err)
		}
		if _, err := w.Escalate("nope", wd.bob, "x"); code(err) != "risk_not_found" {
			t.Errorf("unknown risk: %v", err)
		}
		e, err := w.Escalate(wd.risk, wd.bob, "needs a decision")
		must(t, err)
		if e.RiskID != wd.risk {
			t.Errorf("escalation = %+v", e)
		}
		ns, err := c.Notifications(wd.ownerUser.String(), false, 10)
		must(t, err)
		if len(ns) != 1 || !strings.Contains(ns[0].Subject, "escalated") {
			t.Errorf("the risk owner was told: %+v", ns)
		}
		// a risk without an owner has nobody to escalate to
		risk, _ := c.SodRisk(wd.risk)
		fids, _ := sod.RiskFunctionIDs(c, risk.ID)
		_, err = writer(c).UpdateRisk(risk.ID, risk.Version, sod.RiskInput{Name: risk.Name, Priority: "high", RulesetID: risk.RulesetID, FunctionIDs: fids})
		must(t, err)
		if _, err := w.Escalate(wd.risk, wd.bob, "x"); code(err) != "no_risk_owner" {
			t.Errorf("no owner: %v", err)
		}
		return nil
	})
}

func TestSweepWarnsOnceThenExpiresAndReopens(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		now := testkit.Now
		end := now.Add(20 * 24 * time.Hour)
		m, err := as(c, wd.req, now).RequestMitigation(wd.input(end), sod.Settings{})
		must(t, err)
		_, err = as(c, wd.appr, now).DecideMitigation(m.ID, true, "")
		must(t, err)
		set := sod.Settings{WarnDays: 14}
		// outside the window: nothing
		if w, e, err := sod.Sweep(c, now, set); err != nil || w != 0 || e != 0 {
			t.Fatalf("early sweep: %d %d %v", w, e, err)
		}
		// inside the window: the control owner is warned, once
		in := end.Add(-10 * 24 * time.Hour)
		if w, e, err := sod.Sweep(c, in, set); err != nil || w != 1 || e != 0 {
			t.Fatalf("warning sweep: %d %d %v", w, e, err)
		}
		if w, _, _ := sod.Sweep(c, in.Add(time.Hour), set); w != 0 {
			t.Errorf("warned twice")
		}
		ns, _ := c.Notifications(wd.ownerUser.String(), false, 10)
		if len(ns) != 1 || !strings.Contains(ns[0].Subject, "Ends") {
			t.Errorf("warning notification: %+v", ns)
		}
		// after the end date: expired, the violation reopens, the owners are told
		later := end.Add(time.Hour)
		if cov, _ := sod.Covers(c, later); cov.For(wd.risk, wd.bob) != nil {
			t.Error("covered past its end date before the sweeper ran")
		}
		if w, e, err := sod.Sweep(c, later, set); err != nil || e != 1 || w != 0 {
			t.Fatalf("expiry sweep: %d %d %v", w, e, err)
		}
		got, _ := c.SodMitigation(m.ID)
		if got.Status != store.MitigationExpired || got.ClosedAt == nil {
			t.Errorf("after expiry: %+v", got)
		}
		ns, _ = c.Notifications(wd.ownerUser.String(), false, 10)
		if len(ns) != 2 {
			t.Errorf("owner notifications after expiry = %d", len(ns))
		}
		evs, err := c.AuditEvents(store.AuditFilter{})
		must(t, err)
		seen := map[string]bool{}
		for _, e := range evs {
			seen[e.Action] = true
		}
		for _, a := range []string{"sod.mitigation.request", "sod.mitigation.approve", "sod.mitigation.warn", "sod.mitigation.expire"} {
			if !seen[a] {
				t.Errorf("no %s audit event", a)
			}
		}
		// a new request is possible again
		if _, err := as(c, wd.req, later).RequestMitigation(wd.input(later.Add(24*time.Hour)), sod.Settings{}); err != nil {
			t.Errorf("request after expiry: %v", err)
		}
		return nil
	})
}

func TestRemediationOptionsRoundTripInYAML(t *testing.T) {
	st, _ := testkit.Tiny(t)
	doc := `schema: tessera.sod/v1
ruleset: {key: fin, name: Finance, enabled: true}
functions:
  - {key: a, name: A, selectors: [{name_pattern: "x"}]}
  - {key: b, name: B, selectors: [{name_pattern: "y"}]}
risks:
  - {key: r, name: R, priority: low, functions: [a, b], remediation: [escalate, revoke, revoke]}
  - {key: r2, name: R2, priority: low, functions: [a, b], remediation: [revoke, mitigate, accept, escalate]}
`
	testkit.Write(t, st, func(c *store.TenantTx) error {
		w := writer(c)
		b, err := sod.ParseYAML([]byte(doc))
		must(t, err)
		if _, err := w.Import(b, sod.ImportOptions{}); err != nil {
			return err
		}
		again, err := w.Import(b, sod.ImportOptions{})
		if err != nil || len(again.Created)+len(again.Updated) != 0 {
			t.Errorf("re-import: %+v %v", again, err)
		}
		r, _ := c.SodRiskByKey("r")
		r2, _ := c.SodRiskByKey("r2")
		o1, _ := sod.RiskOptions(c, r.ID)
		o2, _ := sod.RiskOptions(c, r2.ID)
		if len(o1) != 2 || o1[0] != "revoke" || len(o2) != 0 {
			t.Errorf("options = %v and %v (all four is stored as none)", o1, o2)
		}
		rs, _ := c.SodRulesetByKey("fin")
		out, _ := sod.BundleOf(c, rs)
		y, _ := out.MarshalYAML()
		if !strings.Contains(string(y), "remediation:") || strings.Count(string(y), "remediation:") != 1 {
			t.Errorf("export:\n%s", y)
		}
		return nil
	})
}
