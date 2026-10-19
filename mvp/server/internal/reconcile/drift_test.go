package reconcile_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The drift engine (issue #301) on the two-tenant fixture. Tenant A's okta
// system is replaced by a small scene:
//
//	ok       alice -> gOK    intended (request) and observed        no drift
//	missing  carol -> gMiss  intended (request), not observed       missing
//	rogue    alice -> gRogue observed, never intended               rogue
//	stale    bob   -> gStale intended then revoked, still observed  stale
//	orphan   account ghost (no identity) observed in gOK            orphan

type scene struct {
	t    *testing.T
	f    *storetest.Fixture
	now  time.Time // the engine's clock: after the observation and the intents
	user string    // an operator, so owner tasks have someone to tell
}

func node(kind string, id int64) string { return fmt.Sprintf("%s:%d", kind, id) }

func (s *scene) inA(fn func(*store.TenantTx) error) {
	s.t.Helper()
	if err := s.f.DB.InTenant(context.Background(), s.f.A.ID, fn); err != nil {
		s.t.Fatal(err)
	}
}

func okta(acct, ref string) store.ObservedRow {
	return store.ObservedRow{System: "okta", AccountRef: acct, EntitlementKind: "group", EntitlementSystem: "okta", EntitlementRef: ref}
}

func newScene(t *testing.T) *scene {
	t.Helper()
	s := &scene{t: t, f: storetest.TwoTenants(t), now: storetest.Now.Add(2 * time.Hour)}
	ids := s.f.A.IDs
	s.inA(func(c *store.TenantTx) error {
		for _, g := range []string{"gOK", "gMiss", "gRogue", "gStale"} {
			if err := c.UpsertGroup(&store.Group{System: "okta", ExternalID: g, Name: g, Kind: "group"}); err != nil {
				return err
			}
		}
		if err := c.UpsertAccount(&store.Account{System: "okta", ExternalID: "ghost", Username: "ghost", Kind: "user", Status: "active"}); err != nil {
			return err
		}
		gid := func(x string) int64 {
			gs, _ := c.Groups()
			for _, g := range gs {
				if g.System == "okta" && g.ExternalID == x {
					return g.ID
				}
			}
			t.Fatalf("no group %s", x)
			return 0
		}
		grant := func(acct, group, source string) int64 {
			id, err := c.InsertEdge(&store.GrantEdge{Src: node("account", ids["acct:okta:"+acct]), Dst: node("group", gid(group)),
				Relation: "member_of", Source: source, CreatedAt: storetest.Now})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		grant("alice", "gOK", "request")
		grant("carol", "gMiss", "request")
		if err := c.RevokeEdge(grant("bob", "gStale", "manual"), storetest.Now, "review"); err != nil {
			return err
		}
		if _, err := c.RecordObservedRun("okta", storetest.Now.Add(time.Hour), []store.ObservedRow{
			okta("alice", "gOK"), okta("alice", "gRogue"), okta("bob", "gStale"), okta("ghost", "gOK")}); err != nil {
			return err
		}
		u := &store.PlatformUser{DisplayName: "Decider", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		s.user = u.ID.String()
		return c.InsertRoleAssignment(&store.RoleAssignment{UserID: u.ID, Role: "operator", Source: "manual", CreatedAt: storetest.Now})
	})
	return s
}

func (s *scene) run() reconcile.DriftRun {
	s.t.Helper()
	var r reconcile.DriftRun
	s.inA(func(c *store.TenantTx) error {
		var err error
		r, err = reconcile.RunDrift(c, s.now, "system")
		return err
	})
	return r
}

// oktaDrift returns tenant A's okta drift by "class/entitlement".
func (s *scene) oktaDrift() map[string]*store.AccessDrift {
	s.t.Helper()
	out := map[string]*store.AccessDrift{}
	s.inA(func(c *store.TenantTx) error {
		ds, err := c.AccessDrifts(store.DriftFilter{System: "okta"})
		for _, d := range ds {
			k := d.Class + "/" + d.EntitlementRef
			if d.Class == store.DriftOrphan {
				k = d.Class + "/" + d.AccountRef
			}
			out[k] = d
		}
		return err
	})
	return out
}

func (s *scene) policy(system, ref, class, action string) {
	s.t.Helper()
	s.inA(func(c *store.TenantTx) error {
		return c.UpsertRemediationPolicy(&store.RemediationPolicy{TenantID: s.f.A.ID, System: system, EntitlementRef: ref,
			DriftClass: class, Action: action, CreatedBy: "test", UpdatedAt: storetest.Now})
	})
}

func (s *scene) writeBack() {
	s.t.Helper()
	s.inA(func(c *store.TenantTx) error {
		return c.UpsertProvTarget(&store.ProvTarget{ID: store.NewID(), ConnectionID: s.f.A.Refs["connection"], Kind: provision.KindSCIM,
			BaseURL: "http://127.0.0.1:1/scim/v2", Settings: "{}", WriteBack: true, CreatedBy: "test"}, storetest.Now)
	})
}

func (s *scene) ops() []*store.ProvOp {
	s.t.Helper()
	var ops []*store.ProvOp
	s.inA(func(c *store.TenantTx) error {
		var err error
		ops, err = c.ProvOps(store.ProvOpFilter{})
		return err
	})
	return ops
}

func (s *scene) audited(action string) int {
	s.t.Helper()
	n := 0
	s.inA(func(c *store.TenantTx) error {
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

func TestDrift_ClassifiesEveryClass(t *testing.T) {
	s := newScene(t)
	r := s.run()
	d := s.oktaDrift()
	for _, k := range []string{"missing/gMiss", "rogue/gRogue", "stale/gStale", "orphan/ghost"} {
		if d[k] == nil || d[k].Status != store.DriftOpen {
			t.Errorf("no open %s drift: %v", k, keysOf(d))
		}
	}
	if len(d) != 4 {
		t.Errorf("okta drift = %v, want exactly the four classes (gOK is intended and observed)", keysOf(d))
	}
	if r.Opened < 4 {
		t.Errorf("run = %+v", r)
	}
	ids := s.f.A.IDs
	if m := d["missing/gMiss"]; m != nil && (m.IdentityID == nil || *m.IdentityID != ids["carol"] || m.IntendedID == nil || m.ObservedID != nil) {
		t.Errorf("missing refs = %+v", m)
	}
	if m := d["rogue/gRogue"]; m != nil && (m.IdentityID == nil || *m.IdentityID != ids["alice"] || m.IntendedID != nil || m.ObservedID == nil) {
		t.Errorf("rogue refs = %+v", m)
	}
	if m := d["stale/gStale"]; m != nil && (m.IdentityID == nil || *m.IdentityID != ids["bob"] || m.IntendedID == nil || m.ObservedID == nil) {
		t.Errorf("stale refs = %+v", m)
	}
	if m := d["orphan/ghost"]; m != nil && (m.IdentityID != nil || m.ObservedID == nil) {
		t.Errorf("orphan refs = %+v", m)
	}
	// with no policy everything is recorded and nothing is done
	for k, x := range d {
		if x.Action != store.ActionReportOnly || x.Status != store.DriftOpen {
			t.Errorf("%s: action %s status %s, want report_only/open", k, x.Action, x.Status)
		}
	}
	if len(s.ops()) != 0 || s.audited("drift.remediate") != 0 {
		t.Error("report-only drift queued operations or wrote remediation events")
	}
}

func keysOf(m map[string]*store.AccessDrift) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDrift_RerunIsIdempotent(t *testing.T) {
	s := newScene(t)
	s.policy("okta", "", store.DriftRogue, store.ActionOwnerTask)
	s.run()
	before := s.oktaDrift()
	if r := s.run(); r.Changed() {
		t.Errorf("a second run changed %+v", r)
	}
	if r := s.run(); r.Changed() {
		t.Errorf("a third run changed %+v", r)
	}
	for k, x := range s.oktaDrift() {
		if !x.UpdatedAt.Equal(before[k].UpdatedAt) || x.Status != before[k].Status || x.Action != before[k].Action {
			t.Errorf("%s changed between runs: %+v -> %+v", k, before[k], x)
		}
	}
	if n := s.audited("drift.remediate"); n != 1 {
		t.Errorf("drift.remediate events = %d, want one (the rogue task, once)", n)
	}
}

func TestDrift_ResolvesAndReopens(t *testing.T) {
	s := newScene(t)
	s.run()
	fix := func(rows ...store.ObservedRow) {
		s.inA(func(c *store.TenantTx) error {
			_, err := c.RecordObservedRun("okta", storetest.Now.Add(90*time.Minute), rows)
			return err
		})
	}
	// carol gets gMiss, the rogue and stale access and the orphan's go away
	fix(okta("alice", "gOK"), okta("carol", "gMiss"))
	if r := s.run(); r.Resolved != 4 {
		t.Errorf("resolved = %d, want 4 (%+v)", r.Resolved, r)
	}
	for k, x := range s.oktaDrift() {
		if x.Status != store.DriftResolved || x.ResolvedAt == nil {
			t.Errorf("%s: status %s", k, x.Status)
		}
	}
	// the rogue access comes back: the same row reopens
	ids := map[string]string{}
	for k, x := range s.oktaDrift() {
		ids[k] = x.ID
	}
	fix(okta("alice", "gOK"), okta("carol", "gMiss"), okta("alice", "gRogue"))
	if r := s.run(); r.Reopened != 1 {
		t.Errorf("reopened = %d (%+v)", r.Reopened, r)
	}
	if x := s.oktaDrift()["rogue/gRogue"]; x.Status != store.DriftOpen || x.ID != ids["rogue/gRogue"] {
		t.Errorf("rogue row = %+v", x)
	}
}

func TestDrift_PolicyOwnerTask(t *testing.T) {
	s := newScene(t)
	s.policy("okta", "", store.DriftRogue, store.ActionOwnerTask)
	s.policy("okta", "gStale", store.DriftStale, store.ActionOwnerTask)
	s.policy("okta", "", store.DriftOrphan, store.ActionOwnerTask)
	s.run()
	d := s.oktaDrift()
	for _, k := range []string{"rogue/gRogue", "stale/gStale", "orphan/ghost"} {
		x := d[k]
		if x.Action != store.ActionOwnerTask || x.Status != store.DriftRemediating || x.RemediationRef == nil {
			t.Errorf("%s = %+v", k, x)
		}
	}
	if d["missing/gMiss"].Action != store.ActionReportOnly {
		t.Error("a policy for rogue drift acted on missing drift")
	}
	s.inA(func(c *store.TenantTx) error {
		// the orphan has no owner, so the people who decide access are told
		ns, err := c.Notifications(s.user, false, 10)
		if err != nil || len(ns) != 1 || ns[0].Kind != "security.alert" {
			t.Errorf("inbox = %d, %v", len(ns), err)
		}
		return nil
	})
	if s.audited("drift.remediate") != 3 {
		t.Errorf("remediation events = %d", s.audited("drift.remediate"))
	}
}

func TestDrift_PolicyAutoProvisionAndRevoke(t *testing.T) {
	s := newScene(t)
	s.writeBack()
	s.policy("okta", "", store.DriftMissing, store.ActionAutoProvision)
	s.policy("okta", "", store.DriftRogue, store.ActionAutoRevoke)
	s.policy("okta", "", store.DriftStale, store.ActionAutoRevoke)
	s.policy("okta", "", store.DriftOrphan, store.ActionAutoRevoke)
	s.run()
	kinds := map[string]string{}
	for _, op := range s.ops() {
		if op.Source != provision.SourceDrift {
			t.Errorf("op source = %s", op.Source)
		}
		kinds[op.Kind+" "+op.TargetRef] = op.Status
	}
	want := []string{"add_entitlement", "remove_entitlement", "disable_account"}
	for _, w := range want {
		found := false
		for k := range kinds {
			found = found || strings.HasPrefix(k, w)
		}
		if !found {
			t.Errorf("no %s operation: %v", w, kinds)
		}
	}
	if len(s.ops()) != 4 {
		t.Errorf("operations = %d, want 4 (provision carol, revoke rogue and stale, disable ghost)", len(s.ops()))
	}
	for k, x := range s.oktaDrift() {
		if x.Status != store.DriftRemediating || x.RemediationRef == nil {
			t.Errorf("%s = %+v", k, x)
		}
	}
	if s.audited("drift.remediate") != 4 {
		t.Errorf("remediation events = %d", s.audited("drift.remediate"))
	}
	// a rerun queues nothing more
	s.run()
	if len(s.ops()) != 4 {
		t.Errorf("a rerun queued operations: %d", len(s.ops()))
	}
	// an operation that failed puts the row back and asks a person
	op := s.ops()[0]
	s.inA(func(c *store.TenantTx) error {
		return c.SetProvOpState(op.ID, op.Status, store.ProvOpState{Status: provision.Failed, NextAttemptAt: s.now}, s.now)
	})
	s.run()
	n := 0
	for _, x := range s.oktaDrift() {
		if x.RemediationRef != nil && *x.RemediationRef == op.ID {
			t.Errorf("the failed operation still carries a row: %+v", x)
		}
		if x.Action == store.ActionOwnerTask {
			n++
		}
	}
	if n != 1 {
		t.Errorf("rows that fell back to an owner task = %d, want 1", n)
	}
}

func TestDrift_AutoWithoutWriteBackFallsBackToTask(t *testing.T) {
	s := newScene(t)
	s.policy("okta", "", store.DriftRogue, store.ActionAutoRevoke)
	s.run()
	x := s.oktaDrift()["rogue/gRogue"]
	if x.Action != store.ActionOwnerTask || x.Status != store.DriftRemediating || x.RemediationNote == nil ||
		!strings.Contains(*x.RemediationNote, "no write-back") {
		t.Errorf("row = %+v", x)
	}
	if len(s.ops()) != 0 {
		t.Error("operations were queued with no write-back target")
	}
}

func TestDrift_EntitlementPolicyBeatsSystemPolicyAndChangesApply(t *testing.T) {
	pol := []*store.RemediationPolicy{
		{System: "okta", DriftClass: "rogue", Action: store.ActionOwnerTask},
		{System: "okta", EntitlementRef: "gRogue", DriftClass: "rogue", Action: store.ActionReportOnly},
		{System: "aws", DriftClass: "rogue", Action: store.ActionAutoRevoke}}
	if got := reconcile.PolicyAction(pol, "rogue", "okta", "gRogue"); got != store.ActionReportOnly {
		t.Errorf("entitlement policy = %s", got)
	}
	if got := reconcile.PolicyAction(pol, "rogue", "okta", "other"); got != store.ActionOwnerTask {
		t.Errorf("system policy = %s", got)
	}
	if got := reconcile.PolicyAction(pol, "stale", "okta", "other"); got != store.ActionReportOnly {
		t.Errorf("no policy = %s", got)
	}
	// a policy set after the drift was recorded applies on the next run
	s := newScene(t)
	s.run()
	if x := s.oktaDrift()["rogue/gRogue"]; x.Action != store.ActionReportOnly {
		t.Fatalf("action = %s", x.Action)
	}
	s.policy("okta", "", store.DriftRogue, store.ActionOwnerTask)
	s.run()
	if x := s.oktaDrift()["rogue/gRogue"]; x.Action != store.ActionOwnerTask {
		t.Errorf("action after the policy = %s", x.Action)
	}
}

func TestDrift_ValidActions(t *testing.T) {
	for class, ok := range map[string][]string{
		"missing": {"auto_provision", "owner_task", "report_only"},
		"rogue":   {"auto_revoke", "owner_task", "report_only"},
		"orphan":  {"auto_revoke", "owner_task", "report_only"},
		"stale":   {"auto_revoke", "owner_task", "report_only"}} {
		for _, a := range store.PolicyActions {
			want := false
			for _, o := range ok {
				want = want || o == a
			}
			if reconcile.ValidAction(class, a) != want {
				t.Errorf("ValidAction(%s, %s) = %v", class, a, !want)
			}
		}
	}
}

func TestDrift_OperatorAcceptAndRemediate(t *testing.T) {
	s := newScene(t)
	s.run()
	d := s.oktaDrift()
	s.inA(func(c *store.TenantTx) error {
		if _, err := reconcile.Accept(c, s.now, "Ann", d["rogue/gRogue"].ID, " "); err == nil {
			t.Error("accepting without a reason worked")
		}
		x, err := reconcile.Accept(c, s.now, "Ann", d["rogue/gRogue"].ID, "contractor exception")
		if err != nil || x.Status != store.DriftAccepted || x.AcceptedBy == nil || *x.AcceptedBy != "Ann" {
			t.Errorf("Accept = %+v, %v", x, err)
		}
		if _, err := reconcile.Remediate(c, s.now, "Ann", x.ID, store.ActionOwnerTask); err == nil {
			t.Error("remediating accepted drift worked")
		}
		if _, err := reconcile.Remediate(c, s.now, "Ann", d["missing/gMiss"].ID, store.ActionAutoRevoke); err == nil {
			t.Error("auto_revoke on missing drift worked")
		}
		y, err := reconcile.Remediate(c, s.now, "Ann", d["missing/gMiss"].ID, store.ActionOwnerTask)
		if err != nil || y.Action != store.ActionOwnerTask || y.Status != store.DriftRemediating {
			t.Errorf("Remediate = %+v, %v", y, err)
		}
		return nil
	})
	if s.audited("drift.accept") != 1 || s.audited("drift.remediate") != 1 {
		t.Error("accept and remediate are not each audited once")
	}
	// an accepted row stays accepted while the difference lasts
	s.run()
	if x := s.oktaDrift()["rogue/gRogue"]; x.Status != store.DriftAccepted {
		t.Errorf("accepted row = %s", x.Status)
	}
}

func TestDrift_SyncNeverCreatesIntent(t *testing.T) {
	f := storetest.TwoTenants(t)
	var before, after int
	read := func(c *store.TenantTx) int { n, _ := c.CountIntendedGrants(); return n }
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		before = read(c)
		if _, err := ingest.Sync(c, storetest.Now.Add(time.Hour), []connectors.Connector{connectors.Tiny{Now: storetest.Now}}, nil); err != nil {
			return err
		}
		after = read(c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Errorf("a sync changed intended grants: %d -> %d", before, after)
	}
	// a tenant that only ever synced has observed access and no intent at all
	var in, obs int
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if _, err := ingest.Sync(c, storetest.Now, []connectors.Connector{connectors.Tiny{Now: storetest.Now, Domain: "x.example"}}, nil); err != nil {
			return err
		}
		in, obs = read(c), 0
		obs, _ = c.CountObservedEntitlements()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if obs == 0 {
		t.Error("a sync recorded no observed entitlements")
	}
	_ = in // tenant B's fixture holds JIT intents of its own; the equality above is the claim
}

func TestDrift_ApprovalNeverCreatesObservedAccess(t *testing.T) {
	s := newScene(t)
	var runs, rows int
	count := func(c *store.TenantTx) {
		rs, _ := c.ObservedRuns()
		runs = len(rs)
		rows, _ = c.CountObservedEntitlements()
	}
	s.inA(func(c *store.TenantTx) error {
		count(c)
		r0, n0 := runs, rows
		ids := s.f.A.IDs
		g, _ := c.Group(ids["group:snowflake:ANALYST"])
		e, err := c.InsertEdge(&store.GrantEdge{Src: node("account", ids["acct:okta:alice"]), Dst: node("group", g.ID),
			Relation: "member_of", Source: "request", CreatedAt: s.now})
		if err != nil {
			return err
		}
		if err := c.KeepIntent(node("account", ids["acct:okta:bob"]), node("group", g.ID), "x", s.now); err != nil {
			return err
		}
		if err := c.RevokeEdge(e, s.now, "x"); err != nil {
			return err
		}
		count(c)
		if runs != r0 || rows != n0 {
			t.Errorf("approval-side writes changed observed access: runs %d->%d rows %d->%d", r0, runs, n0, rows)
		}
		return nil
	})
}

func TestDrift_TenantsAreIsolated(t *testing.T) {
	s := newScene(t)
	s.run()
	if err := s.f.DB.InTenant(context.Background(), s.f.B.ID, func(c *store.TenantTx) error {
		ds, err := c.AccessDrifts(store.DriftFilter{})
		for _, d := range ds {
			if d.System == "okta" && (d.EntitlementRef == "gRogue" || d.EntitlementRef == "gMiss") {
				t.Errorf("tenant B sees A's drift %+v", d)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
