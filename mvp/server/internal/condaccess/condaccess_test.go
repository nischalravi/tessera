package condaccess_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/condaccess"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var (
	t0     = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	corp   = &store.NetworkRange{ID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Name: "corp", CIDRs: []string{"10.0.0.0/8", "2001:db8:1::/48"}}
	branch = &store.NetworkRange{ID: uuid.MustParse("00000000-0000-4000-8000-000000000002"), Name: "branch", CIDRs: []string{"192.0.2.0/24"}}
	ranges = []*store.NetworkRange{corp, branch}
	phr    = "urn:tessera:acr:phr"
	yes    = true
	no     = false
)

func pol(name, scope, mode, outcome string, edit func(*store.AccessPolicy)) *store.AccessPolicy {
	p := &store.AccessPolicy{ID: uuid.New(), Name: name, Scope: scope, Mode: mode, Outcome: outcome,
		NetworkOp: store.NetworkAny, Device: store.DeviceAny, Priority: 100, CreatedAt: t0}
	if outcome == store.AccessStepUp {
		p.StepUpACR, p.StepUpMaxAge = &phr, 300
	}
	if edit != nil {
		edit(p)
	}
	return p
}

func in(scope, ip string, dev condaccess.DeviceState) condaccess.Input {
	i := condaccess.Input{Scope: scope, IPVia: "peer", Device: dev}
	if ip != "" {
		i.ClientIP = netip.MustParseAddr(ip)
	}
	return i
}

var (
	unknownDev = condaccess.DeviceState{Compliance: condaccess.Unknown, ComplianceSource: condaccess.SourceNone}
	goodDev    = condaccess.DeviceState{Managed: &yes, Compliance: condaccess.Compliant, ComplianceSource: condaccess.SourceIdP}
	badDev     = condaccess.DeviceState{Managed: &yes, Compliance: condaccess.NotCompliant, ComplianceSource: condaccess.SourceIdP}
	unmanaged  = condaccess.DeviceState{Managed: &no, Compliance: condaccess.Compliant, ComplianceSource: condaccess.SourceIdP}
)

func notIn(rs ...*store.NetworkRange) func(*store.AccessPolicy) {
	return func(p *store.AccessPolicy) {
		p.NetworkOp = store.NetworkNotIn
		for _, r := range rs {
			p.NetworkRangeIDs = append(p.NetworkRangeIDs, r.ID)
		}
	}
}

func isIn(rs ...*store.NetworkRange) func(*store.AccessPolicy) {
	return func(p *store.AccessPolicy) {
		notIn(rs...)(p)
		p.NetworkOp = store.NetworkIn
	}
}

func TestEvaluate(t *testing.T) {
	S, P := store.AccessScopeSignin, store.AccessScopePrivileged
	E, R, D := store.AccessModeEnforce, store.AccessModeReportOnly, store.AccessModeDisabled
	for _, tc := range []struct {
		name     string
		policies []*store.AccessPolicy
		in       condaccess.Input
		outcome  string
		decider  string // name of the enforced policy
		reports  []string
	}{
		{"no policies allows", nil, in(S, "203.0.113.9", unknownDev), "allow", "", nil},
		{"deny outside the corporate network", []*store.AccessPolicy{pol("corp only", S, E, "deny", notIn(corp))},
			in(S, "203.0.113.9", goodDev), "deny", "corp only", nil},
		{"inside the corporate network passes", []*store.AccessPolicy{pol("corp only", S, E, "deny", notIn(corp))},
			in(S, "10.1.2.3", goodDev), "allow", "", nil},
		{"ipv6 range", []*store.AccessPolicy{pol("corp only", S, E, "deny", notIn(corp))},
			in(S, "2001:db8:1::5", goodDev), "allow", "", nil},
		{"ipv4-mapped ipv6 address is the ipv4 address", []*store.AccessPolicy{pol("corp only", S, E, "deny", notIn(corp))},
			in(S, "::ffff:10.1.2.3", goodDev), "allow", "", nil},
		{"unknown address is not in any range", []*store.AccessPolicy{pol("corp only", S, E, "deny", notIn(corp))},
			in(S, "", goodDev), "deny", "corp only", nil},
		{"unknown address never matches 'in'", []*store.AccessPolicy{pol("branch", S, E, "deny", isIn(branch))},
			in(S, "", goodDev), "allow", "", nil},
		{"any of several ranges", []*store.AccessPolicy{pol("offices", S, E, "deny", notIn(corp, branch))},
			in(S, "192.0.2.77", goodDev), "allow", "", nil},
		{"step up for a non-compliant device", []*store.AccessPolicy{pol("posture", P, E, "step_up", func(p *store.AccessPolicy) { p.Device = store.DeviceNotCompliant })},
			in(P, "10.0.0.1", badDev), "step_up", "posture", nil},
		{"unknown compliance is not compliant", []*store.AccessPolicy{pol("posture", P, E, "deny", func(p *store.AccessPolicy) { p.Device = store.DeviceNotCompliant })},
			in(P, "10.0.0.1", unknownDev), "deny", "posture", nil},
		{"compliant device passes the posture policy", []*store.AccessPolicy{pol("posture", P, E, "deny", func(p *store.AccessPolicy) { p.Device = store.DeviceNotCompliant })},
			in(P, "10.0.0.1", goodDev), "allow", "", nil},
		{"unmanaged device", []*store.AccessPolicy{pol("managed only", S, E, "deny", func(p *store.AccessPolicy) { p.Device = store.DeviceUnmanaged })},
			in(S, "10.0.0.1", unmanaged), "deny", "managed only", nil},
		{"managed unknown counts as unmanaged", []*store.AccessPolicy{pol("managed only", S, E, "deny", func(p *store.AccessPolicy) { p.Device = store.DeviceUnmanaged })},
			in(S, "10.0.0.1", unknownDev), "deny", "managed only", nil},
		{"network and device must both hold", []*store.AccessPolicy{pol("both", S, E, "deny", func(p *store.AccessPolicy) {
			notIn(corp)(p)
			p.Device = store.DeviceNotCompliant
		})}, in(S, "203.0.113.9", goodDev), "allow", "", nil},
		{"a policy of another scope is ignored", []*store.AccessPolicy{pol("priv", P, E, "deny", nil)},
			in(S, "10.0.0.1", goodDev), "allow", "", nil},
		{"a disabled policy is ignored", []*store.AccessPolicy{pol("off", S, D, "deny", nil)},
			in(S, "10.0.0.1", goodDev), "allow", "", nil},
		{"priority: the first enforced match decides (allow before deny)", []*store.AccessPolicy{
			pol("deny rest", S, E, "deny", func(p *store.AccessPolicy) { p.Priority = 50 }),
			pol("allow corp", S, E, "allow", func(p *store.AccessPolicy) { isIn(corp)(p); p.Priority = 10 })},
			in(S, "10.0.0.1", goodDev), "allow", "allow corp", nil},
		{"priority: later policy decides when the first does not match", []*store.AccessPolicy{
			pol("deny rest", S, E, "deny", func(p *store.AccessPolicy) { p.Priority = 50 }),
			pol("allow corp", S, E, "allow", func(p *store.AccessPolicy) { isIn(corp)(p); p.Priority = 10 })},
			in(S, "203.0.113.9", goodDev), "deny", "deny rest", nil},
		{"report-only never changes the outcome", []*store.AccessPolicy{pol("trial", S, R, "deny", notIn(corp))},
			in(S, "203.0.113.9", goodDev), "allow", "", []string{"trial"}},
		{"report-only beside an enforced policy", []*store.AccessPolicy{
			pol("trial", S, R, "deny", func(p *store.AccessPolicy) { p.Priority = 1 }),
			pol("real", S, E, "step_up", func(p *store.AccessPolicy) { p.Priority = 2 })},
			in(S, "10.0.0.1", goodDev), "step_up", "real", []string{"trial"}},
		{"report-only that does not match is not listed", []*store.AccessPolicy{pol("trial", S, R, "deny", notIn(corp))},
			in(S, "10.0.0.1", goodDev), "allow", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := condaccess.Evaluate(tc.policies, ranges, tc.in)
			if d.Outcome != tc.outcome {
				t.Fatalf("outcome %s, want %s (%+v)", d.Outcome, tc.outcome, d)
			}
			got := ""
			if d.Enforced != nil {
				got = d.Enforced.Name
			}
			if got != tc.decider {
				t.Errorf("decided by %q, want %q", got, tc.decider)
			}
			var reports []string
			for _, h := range d.ReportOnly {
				reports = append(reports, h.Name)
			}
			if len(reports) != len(tc.reports) || (len(reports) > 0 && reports[0] != tc.reports[0]) {
				t.Errorf("report-only hits %v, want %v", reports, tc.reports)
			}
			// the audit detail is always valid for the ledger and names the inputs
			raw, err := canon.Detail(d.Audit())
			if err != nil {
				t.Fatalf("audit detail: %v", err)
			}
			var back map[string]any
			if err := json.Unmarshal(raw, &back); err != nil || back["outcome"] != tc.outcome || back["inputs"] == nil {
				t.Errorf("audit detail %s", raw)
			}
		})
	}
}

func TestEvaluate_DeletedRangeCountsAsEmpty(t *testing.T) {
	p := pol("corp only", store.AccessScopeSignin, store.AccessModeEnforce, "deny", notIn(&store.NetworkRange{ID: uuid.New()}))
	if d := condaccess.Evaluate([]*store.AccessPolicy{p}, ranges, in(store.AccessScopeSignin, "10.0.0.1", goodDev)); d.Outcome != "deny" {
		t.Errorf("a range that no longer exists contains nothing, so not_in matches: %s", d.Outcome)
	}
}

func TestDecisionStepUp(t *testing.T) {
	d := condaccess.Evaluate([]*store.AccessPolicy{pol("p", store.AccessScopePrivileged, store.AccessModeEnforce, "step_up", nil)}, ranges,
		in(store.AccessScopePrivileged, "10.0.0.1", goodDev))
	if acr, age, ok := d.StepUp(); !ok || acr != phr || age != 300 {
		t.Errorf("StepUp() = %q %d %v", acr, age, ok)
	}
	if _, _, ok := (condaccess.Decision{Outcome: "allow"}).StepUp(); ok {
		t.Error("allow is not a step-up")
	}
}

func TestResolveDevice(t *testing.T) {
	sig := func(status, src string) *store.DeviceSignal { return &store.DeviceSignal{Status: status, Source: src} }
	for _, tc := range []struct {
		name       string
		claims     normalize.Device
		sig        *store.DeviceSignal
		compliance string
		source     string
	}{
		{"nothing known", normalize.Device{}, nil, "unknown", "none"},
		{"idp compliant", normalize.Device{Compliant: &yes}, nil, "compliant", "idp_claim"},
		{"idp not compliant", normalize.Device{Compliant: &no}, nil, "not_compliant", "idp_claim"},
		{"manual signal alone", normalize.Device{}, sig("compliant", "manual"), "compliant", "signal:manual"},
		{"signal not compliant beats an idp compliant claim", normalize.Device{Compliant: &yes}, sig("not_compliant", "caep"), "not_compliant", "signal:caep"},
		{"idp not compliant beats a compliant signal", normalize.Device{Compliant: &no}, sig("compliant", "manual"), "not_compliant", "idp_claim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := condaccess.ResolveDevice(tc.claims, tc.sig)
			if d.Compliance != tc.compliance || d.ComplianceSource != tc.source {
				t.Errorf("%s from %s, want %s from %s", d.Compliance, d.ComplianceSource, tc.compliance, tc.source)
			}
		})
	}
	if d := condaccess.ResolveDevice(normalize.Device{Managed: &yes}, nil); d.Managed == nil || !*d.Managed {
		t.Error("managed is carried through")
	}
}

func TestStoreSignals(t *testing.T) {
	f := storetest.TwoTenants(t)
	var src condaccess.SignalSource = condaccess.StoreSignals{}
	exp := t0.Add(time.Hour)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "u", CreatedAt: t0}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		if s, err := src.DeviceSignal(c, u.ID, t0); err != nil || s != nil {
			t.Errorf("no signal: %v %v", s, err)
		}
		if err := c.SetDeviceSignal(&store.DeviceSignal{UserID: u.ID, Status: store.DeviceNonCompliant,
			Source: store.DeviceSourceManual, SetAt: t0, ExpiresAt: &exp}); err != nil {
			return err
		}
		if s, err := src.DeviceSignal(c, u.ID, t0); err != nil || s == nil || s.Status != store.DeviceNonCompliant {
			t.Errorf("active signal: %v %v", s, err)
		}
		if s, err := src.DeviceSignal(c, u.ID, exp); err != nil || s != nil {
			t.Errorf("an expired signal counts for nothing: %v %v", s, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
