package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Conditional access tests (issue #163): every outcome on privileged routes,
// a spoofed X-Forwarded-For, report-only mode, the device posture, the
// management routes and their audit events, RBAC and cross-tenant behavior.

const (
	corpCIDR  = "198.51.100.0/24" // the tenant's "corporate" network in these tests
	outsideIP = "203.0.113.9"
	insideIP  = "198.51.100.7"
	proxyIP   = "10.255.0.1" // a trusted proxy
)

var (
	accessPhr = "urn:tessera:acr:phr"
	phrStale  = authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-10 * time.Minute)}
)

// accessServer is a test server whose trusted proxies are 10.255.0.0/16.
func accessServer(f *storetest.Fixture) *Server {
	return New(Config{
		Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{authtest.Origin}, Env: "test", RateLimits: noRateLimits,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.255.0.0/16")},
	})
}

type pspec struct {
	name, scope, mode, outcome string
	netOp                      string // any (default) | in | not_in, against the corporate range
	device                     string
	priority                   int
	maxAge                     int
}

// seedAccess stores the corporate range and the policies in tenant t.
func seedAccess(t *testing.T, f *storetest.Fixture, tenant storetest.Tenant, specs ...pspec) {
	t.Helper()
	seedAccessIn(t, f.DB, tenant.ID, specs...)
}

func seedAccessIn(t *testing.T, db *store.DB, tenant tenancy.ID, specs ...pspec) {
	t.Helper()
	now := storetest.Now
	err := db.InTenant(context.Background(), tenant, func(c *store.TenantTx) error {
		corp := &store.NetworkRange{Name: "corp", CIDRs: []string{corpCIDR}, CreatedAt: now, UpdatedAt: now}
		if err := c.InsertNetworkRange(corp); err != nil {
			return err
		}
		for _, s := range specs {
			p := &store.AccessPolicy{Name: s.name, Scope: s.scope, Mode: s.mode, Outcome: s.outcome, NetworkOp: store.NetworkAny,
				Device: store.DeviceAny, Priority: 100, CreatedAt: now, UpdatedAt: now}
			if s.netOp != "" {
				p.NetworkOp, p.NetworkRangeIDs = s.netOp, []uuid.UUID{corp.ID}
			}
			if s.device != "" {
				p.Device = s.device
			}
			if s.priority != 0 {
				p.Priority = s.priority
			}
			if s.outcome == store.AccessStepUp {
				p.StepUpACR, p.StepUpMaxAge = &accessPhr, s.maxAge
			}
			if err := c.InsertAccessPolicy(p); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// privileged is a step-up route whose handler does nothing harmful here:
// approving a JIT request that does not exist.
func privileged(l authtest.Login, remote string, xff ...string) *http.Request {
	req := authed(l, "POST", fmt.Sprintf("/api/jit/requests/%d/approve", missingID), `{}`)
	req.RemoteAddr = remote + ":40000"
	for _, x := range xff {
		req.Header.Add("X-Forwarded-For", x)
	}
	return req
}

func ran(rec *httptest.ResponseRecorder) bool { return rec.Code != 401 && rec.Code != 403 }

func errorOf(rec *httptest.ResponseRecorder) string {
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	s, _ := v["error"].(string)
	return s
}

// decisions are the access.decision events of tenant tn, newest first.
func decisions(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ev := range ledger(t, f.DB, tn.ID) {
		if ev.Action == "access.decision" {
			var d map[string]any
			if err := json.Unmarshal(ev.Detail, &d); err != nil {
				t.Fatal(err)
			}
			d["_outcome"] = ev.Outcome
			out = append(out, d)
		}
	}
	return out
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func TestAccess_PrivilegedOutcomes(t *testing.T) {
	S, P := store.AccessScopeSignin, store.AccessScopePrivileged
	E, R := store.AccessModeEnforce, store.AccessModeReportOnly
	for _, tc := range []struct {
		name   string
		specs  []pspec
		ctx    authtest.Ctx
		remote string
		want   int    // 0: the handler ran
		err    string // error code of a refusal
		// the audited outcome of the access.decision event ("" when none expected)
		audited string
	}{
		{"no policies: allowed and nothing recorded", nil, authtest.Phr, outsideIP, 0, "", ""},
		{"deny outside the corporate network", []pspec{{name: "corp only", scope: P, mode: E, outcome: "deny", netOp: "not_in"}},
			authtest.Phr, outsideIP, 403, "conditional_access_denied", "deny"},
		{"inside the corporate network is allowed", []pspec{{name: "corp only", scope: P, mode: E, outcome: "deny", netOp: "not_in"}},
			authtest.Phr, insideIP, 0, "", "allow"},
		{"step up outside the corporate network", []pspec{{name: "off-net step up", scope: P, mode: E, outcome: "step_up", netOp: "not_in", maxAge: 300}},
			phrStale, outsideIP, 401, "step_up_required", "step_up"},
		{"step up is met by a fresh sign-in", []pspec{{name: "off-net step up", scope: P, mode: E, outcome: "step_up", netOp: "not_in", maxAge: 300}},
			authtest.Phr, outsideIP, 0, "", "step_up"},
		{"the same step up is not asked on the corporate network", []pspec{{name: "off-net step up", scope: P, mode: E, outcome: "step_up", netOp: "not_in", maxAge: 300}},
			phrStale, insideIP, 0, "", "allow"},
		{"an allow policy ahead of a deny-all (priority)", []pspec{
			{name: "deny rest", scope: P, mode: E, outcome: "deny", priority: 50},
			{name: "allow corp", scope: P, mode: E, outcome: "allow", netOp: "in", priority: 10}},
			authtest.Phr, insideIP, 0, "", "allow"},
		{"the deny-all behind it still denies elsewhere", []pspec{
			{name: "deny rest", scope: P, mode: E, outcome: "deny", priority: 50},
			{name: "allow corp", scope: P, mode: E, outcome: "allow", netOp: "in", priority: 10}},
			authtest.Phr, outsideIP, 403, "conditional_access_denied", "deny"},
		{"report-only deny changes nothing", []pspec{{name: "trial", scope: P, mode: R, outcome: "deny", netOp: "not_in"}},
			authtest.Phr, outsideIP, 0, "", "allow"},
		{"report-only step up changes nothing", []pspec{{name: "trial", scope: P, mode: R, outcome: "step_up", netOp: "not_in", maxAge: 300}},
			phrStale, outsideIP, 0, "", "allow"},
		{"a sign-in policy does not apply to privileged actions", []pspec{{name: "signin only", scope: S, mode: E, outcome: "deny"}},
			authtest.Phr, outsideIP, 0, "", ""},
		{"a disabled policy is ignored", []pspec{{name: "off", scope: P, mode: store.AccessModeDisabled, outcome: "deny"}},
			authtest.Phr, outsideIP, 0, "", ""},
		{"unmanaged device is denied", []pspec{{name: "managed only", scope: P, mode: E, outcome: "deny", device: store.DeviceUnmanaged}},
			authtest.Ctx{AAL: 2, Phr: true, Device: `{"managed":false,"compliant":true}`}, insideIP, 403, "conditional_access_denied", "deny"},
		{"managed device passes", []pspec{{name: "managed only", scope: P, mode: E, outcome: "deny", device: store.DeviceUnmanaged}},
			authtest.Ctx{AAL: 2, Phr: true, Device: `{"managed":true,"compliant":true}`}, insideIP, 0, "", "allow"},
		{"no device claims counts as unmanaged and non-compliant", []pspec{{name: "posture", scope: P, mode: E, outcome: "deny", device: store.DeviceNotCompliant}},
			authtest.Phr, insideIP, 403, "conditional_access_denied", "deny"},
		{"non-compliant device steps up", []pspec{{name: "posture", scope: P, mode: E, outcome: "step_up", device: store.DeviceNotCompliant, maxAge: 300}},
			authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-10 * time.Minute), Device: `{"managed":true,"compliant":false}`}, insideIP, 401, "step_up_required", "step_up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			seedAccess(t, f, f.B, tc.specs...)
			h := accessServer(f).Handler()
			l := signIn(t, f.DB, f.B.ID, testAdmin, tc.ctx, storetest.Now)
			rec := serve(h, privileged(l, tc.remote))
			switch {
			case tc.want == 0 && !ran(rec):
				t.Fatalf("%d %s, want the handler to run", rec.Code, rec.Body.String())
			case tc.want != 0 && (rec.Code != tc.want || errorOf(rec) != tc.err):
				t.Fatalf("%d %s, want %d %s", rec.Code, rec.Body.String(), tc.want, tc.err)
			}
			evs := decisions(t, f, f.B)
			if tc.audited == "" {
				if len(evs) != 0 {
					t.Errorf("unexpected access.decision events: %v", evs)
				}
				return
			}
			if len(evs) != 1 {
				t.Fatalf("%d access.decision events, want 1", len(evs))
			}
			d := evs[0]
			in := asMap(d["inputs"])
			if d["outcome"] != tc.audited || d["scope"] != P || in["client_ip"] != tc.remote || in["client_ip_via"] != "peer" ||
				d["action"] != "POST /api/jit/requests/{request_id}/approve" || d["policies_evaluated"] == nil {
				t.Errorf("decision event %v", d)
			}
			if tc.audited == "deny" && d["_outcome"] != store.OutcomeDenied {
				t.Errorf("a deny is audited as denied: %v", d["_outcome"])
			}
			if len(tc.specs) > 0 && tc.specs[0].mode == R {
				ro, _ := d["report_only"].([]any)
				if len(ro) != 1 || asMap(ro[0])["name"] != "trial" || asMap(ro[0])["outcome"] != tc.specs[0].outcome {
					t.Errorf("a matching report-only policy is recorded with the outcome it would have had: %v", d)
				}
			}
			// the other tenant's chain is untouched
			if n := len(decisions(t, f, f.A)); n != 0 {
				t.Errorf("tenant A has %d access.decision events", n)
			}
		})
	}
}

// TestAccess_SpoofedForwardedFor: the client address is the TCP peer unless
// the peer is a trusted proxy, and then the rightmost X-Forwarded-For entry
// that is not itself a trusted proxy; a header from anyone else is ignored.
func TestAccess_SpoofedForwardedFor(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedAccess(t, f, f.B, pspec{name: "corp only", scope: store.AccessScopePrivileged, mode: store.AccessModeEnforce,
		outcome: "deny", netOp: "not_in"})
	h := accessServer(f).Handler()
	l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	for _, tc := range []struct {
		name    string
		remote  string
		xff     []string
		allowed bool
		ip, via string // what the decision records
	}{
		{"a client claiming a corporate address directly", outsideIP, []string{insideIP}, false, outsideIP, "peer"},
		{"the same claim from another untrusted peer, several headers", outsideIP, []string{insideIP, insideIP}, false, outsideIP, "peer"},
		{"a trusted proxy reports a corporate client", proxyIP, []string{insideIP}, true, insideIP, "x_forwarded_for"},
		{"a trusted proxy reports an outside client", proxyIP, []string{outsideIP}, false, outsideIP, "x_forwarded_for"},
		{"a corporate address prepended by the client is not the client", proxyIP, []string{insideIP + ", " + outsideIP}, false, outsideIP, "x_forwarded_for"},
		{"the proxy's append after the client's own header", proxyIP, []string{insideIP, outsideIP}, false, outsideIP, "x_forwarded_for"},
		{"a chain of trusted proxies is walked past", proxyIP, []string{insideIP + ", 10.255.0.2"}, true, insideIP, "x_forwarded_for"},
		{"a malformed hop stops the walk at the trusted peer", proxyIP, []string{insideIP + ", not-an-ip"}, false, proxyIP, "peer"},
		{"the header is ignored without a proxy even when it parses", insideIP, []string{outsideIP}, true, insideIP, "peer"},
		{"an IPv4-mapped peer is the IPv4 address", "[::ffff:" + insideIP + "]", nil, true, insideIP, "peer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(decisions(t, f, f.B))
			req := authed(l, "POST", fmt.Sprintf("/api/jit/requests/%d/approve", missingID), `{}`)
			req.RemoteAddr = tc.remote + ":40000"
			for _, x := range tc.xff {
				req.Header.Add("X-Forwarded-For", x)
			}
			rec := serve(h, req)
			if tc.allowed != ran(rec) {
				t.Fatalf("allowed=%v but %d %s", tc.allowed, rec.Code, rec.Body.String())
			}
			evs := decisions(t, f, f.B)
			if len(evs) != before+1 {
				t.Fatalf("%d decision events, want %d", len(evs), before+1)
			}
			in := asMap(evs[0]["inputs"])
			if in["client_ip"] != tc.ip || in["client_ip_via"] != tc.via {
				t.Errorf("inputs %v, want %s via %s", in, tc.ip, tc.via)
			}
		})
	}
}

// TestAccess_ClientIPHelper pins the address logic the rate limiter shares.
func TestAccess_ClientIPHelper(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := accessServer(f)
	for _, tc := range []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1", "198.51.100.7", "203.0.113.9"},
		{"10.255.0.1:1", "198.51.100.7", "198.51.100.7"},
		{"10.255.0.1:1", "", "10.255.0.1"},
		{"10.255.0.1:1", "198.51.100.7, 203.0.113.9", "203.0.113.9"},
		{"[2001:db8::1]:1", "198.51.100.7", "2001:db8::1"},
		{"garbage", "198.51.100.7", ""},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.xff != "" {
			req.Header.Set("X-Forwarded-For", tc.xff)
		}
		got, _ := s.clientIP(req)
		if (tc.want == "" && got.IsValid()) || (tc.want != "" && got.String() != tc.want) {
			t.Errorf("clientIP(%s, %q) = %v, want %q", tc.remote, tc.xff, got, tc.want)
		}
	}
}

// TestAccess_DeviceSignal: an admin-set device-compliance signal feeds the
// decision; a non-compliant signal overrides a compliant IdP claim, an
// expired one counts for nothing, and a CAEP-source signal (future receiver)
// is honored the same way.
func TestAccess_DeviceSignal(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedAccess(t, f, f.B, pspec{name: "posture", scope: store.AccessScopePrivileged, mode: store.AccessModeEnforce,
		outcome: "deny", device: store.DeviceNotCompliant})
	h := accessServer(f).Handler()
	good := authtest.Ctx{AAL: 2, Phr: true, Device: `{"managed":true,"compliant":true}`}
	l := signIn(t, f.DB, f.B.ID, testAdmin, good, storetest.Now)
	if rec := serve(h, privileged(l, insideIP)); !ran(rec) {
		t.Fatalf("a compliant claim passes: %d %s", rec.Code, rec.Body.String())
	}
	set := func(sig *store.DeviceSignal) {
		t.Helper()
		sig.UserID, sig.SetAt = l.UserID, storetest.Now
		if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.SetDeviceSignal(sig) }); err != nil {
			t.Fatal(err)
		}
	}
	exp := storetest.Now
	for _, tc := range []struct {
		name string
		sig  store.DeviceSignal
		deny bool
		src  string
	}{
		{"manual not compliant", store.DeviceSignal{Status: store.DeviceNonCompliant, Source: store.DeviceSourceManual}, true, "signal:manual"},
		{"caep not compliant", store.DeviceSignal{Status: store.DeviceNonCompliant, Source: store.DeviceSourceCAEP}, true, "signal:caep"},
		{"expired not compliant", store.DeviceSignal{Status: store.DeviceNonCompliant, Source: store.DeviceSourceManual, ExpiresAt: &exp}, false, ""},
		{"compliant signal", store.DeviceSignal{Status: store.DeviceCompliant, Source: store.DeviceSourceManual}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set(&tc.sig)
			rec := serve(h, privileged(l, insideIP))
			if tc.deny == ran(rec) {
				t.Fatalf("deny=%v but %d %s", tc.deny, rec.Code, rec.Body.String())
			}
			if tc.deny {
				in := asMap(decisions(t, f, f.B)[0]["inputs"])
				if in["device_compliance"] != "not_compliant" || in["device_compliance_source"] != tc.src {
					t.Errorf("inputs %v", in)
				}
			}
		})
	}
}

// TestAccess_ManagementRoutesNeverLockOut: a policy that denies every
// privileged action does not block the routes that edit policies, and the
// admin can still delete it; permission is checked before policies.
func TestAccess_ManagementRoutesNeverLockOut(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedAccess(t, f, f.B, pspec{name: "deny all", scope: store.AccessScopePrivileged, mode: store.AccessModeEnforce, outcome: "deny"})
	h := accessServer(f).Handler()
	admin := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	if rec := serve(h, privileged(admin, insideIP)); rec.Code != 403 || errorOf(rec) != "conditional_access_denied" {
		t.Fatalf("the privileged action is denied: %d %s", rec.Code, rec.Body.String())
	}
	var id string
	rec := serve(h, authed(admin, "GET", "/api/access/policies", ""))
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	id = list[0]["id"].(string)
	if rec := serve(h, authed(admin, "DELETE", "/api/access/policies/"+id, "")); rec.Code != 200 {
		t.Fatalf("delete the locking policy: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(h, privileged(admin, insideIP)); !ran(rec) {
		t.Fatalf("after the delete the action runs: %d %s", rec.Code, rec.Body.String())
	}
	// a caller without the permission never learns of the policies
	seedMore := func() {
		if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			return c.InsertAccessPolicy(&store.AccessPolicy{Name: "again", Scope: store.AccessScopePrivileged,
				Mode: store.AccessModeEnforce, Outcome: store.AccessDeny, NetworkOp: store.NetworkAny, Device: store.DeviceAny,
				Priority: 100, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	seedMore()
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "viewer@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := serve(h, privileged(viewer, insideIP)); rec.Code != 403 || errorOf(rec) != "forbidden" {
		t.Errorf("a viewer gets forbidden, not conditional_access_denied: %d %s", rec.Code, rec.Body.String())
	}
	// non-privileged routes are not touched by privileged-scope policies
	if rec := serve(h, authed(admin, "GET", "/api/identities", "")); rec.Code != 200 {
		t.Errorf("reads are unaffected: %d", rec.Code)
	}
}

// TestAccess_RevokeApplyDecisionKept: the in-handler check of an applying
// revoke is subject to the policies too, and a refusal keeps its audit event.
func TestAccess_RevokeApplyDecisionKept(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedAccess(t, f, f.B, pspec{name: "deny all", scope: store.AccessScopePrivileged, mode: store.AccessModeEnforce, outcome: "deny"})
	h := accessServer(f).Handler()
	l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	body := fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, f.B.IDs["edge:0"])
	if rec := serve(h, authed(l, "POST", "/api/least-privilege/revoke", body)); rec.Code != 403 || errorOf(rec) != "conditional_access_denied" {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	evs := decisions(t, f, f.B)
	if len(evs) != 1 || evs[0]["action"] != "POST /api/least-privilege/revoke" || evs[0]["_outcome"] != store.OutcomeDenied {
		t.Errorf("the refusal's decision event: %v", evs)
	}
	dry := fmt.Sprintf(`{"edge_id":%d}`, f.B.IDs["edge:0"])
	if rec := serve(h, authed(l, "POST", "/api/least-privilege/revoke", dry)); rec.Code != 200 {
		t.Errorf("a dry run is not privileged: %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------- management API

func TestAccess_ManagementCRUD(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := accessServer(f).Handler()
	admin := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	call := func(method, path, body string) (int, map[string]any) {
		rec := serve(h, authed(admin, method, path, body))
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return rec.Code, v
	}
	// network ranges: canonicalised, duplicates folded
	code, nr := call("POST", "/api/access/networks", `{"name":"HQ","description":"head office","cidrs":["198.51.100.77/24","192.0.2.5","198.51.100.0/24","2001:db8::/32"]}`)
	if code != 201 {
		t.Fatalf("create range: %d %v", code, nr)
	}
	cidrs, _ := json.Marshal(nr["cidrs"])
	if string(cidrs) != `["198.51.100.0/24","192.0.2.5/32","2001:db8::/32"]` {
		t.Errorf("cidrs %s", cidrs)
	}
	netID := nr["id"].(string)
	if code, v := call("POST", "/api/access/networks", `{"name":"HQ","cidrs":["10.0.0.0/8"]}`); code != 409 || v["error"] != "duplicate_name" {
		t.Errorf("duplicate name: %d %v", code, v)
	}
	for _, bad := range []string{`{"name":"","cidrs":["10.0.0.0/8"]}`, `{"name":"x","cidrs":[]}`, `{"name":"x","cidrs":["10.0.0.0/33"]}`,
		`{"name":"x","cidrs":["fe80::1%eth0"]}`, `{"name":"x","cidrs":["::ffff:10.0.0.0/104"]}`, `{"name":"x","cidrs":["nope"]}`,
		`{"name":"x","cidrs":["10.0.0.0/8"],"unknown":1}`, `{"name":"bad\u0007","cidrs":["10.0.0.0/8"]}`} {
		if code, v := call("POST", "/api/access/networks", bad); code != 422 {
			t.Errorf("%s: %d %v, want 422", bad, code, v)
		}
	}
	// policies
	pbody := func(extra string) string {
		return `{"name":"off-net","scope":"privileged","mode":"report_only","outcome":"step_up","step_up_max_age":300,` +
			`"network_op":"not_in","network_range_ids":["` + netID + `"]` + extra + `}`
	}
	code, pol := call("POST", "/api/access/policies", pbody(""))
	if code != 201 || pol["step_up_acr"] != accessPhr || pol["priority"] != float64(100) || pol["mode"] != "report_only" {
		t.Fatalf("create policy: %d %v", code, pol)
	}
	polID := pol["id"].(string)
	for name, bad := range map[string]string{
		"duplicate":         pbody(""),
		"unknown range":     `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","network_op":"in","network_range_ids":["00000000-0000-4000-8000-000000000001"]}`,
		"not a uuid":        `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","network_op":"in","network_range_ids":["x"]}`,
		"in without ranges": `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","network_op":"in"}`,
		"ranges with any":   `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","network_range_ids":["` + netID + `"]}`,
		"bad scope":         `{"name":"a","scope":"everywhere","mode":"enforce","outcome":"deny"}`,
		"bad mode":          `{"name":"a","scope":"signin","mode":"on","outcome":"deny"}`,
		"bad outcome":       `{"name":"a","scope":"signin","mode":"enforce","outcome":"maybe"}`,
		"acr on deny":       `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","step_up_acr":"urn:tessera:acr:phr"}`,
		"bad acr":           `{"name":"a","scope":"signin","mode":"enforce","outcome":"step_up","step_up_acr":"urn:tessera:acr:aal1"}`,
		"max age too long":  `{"name":"a","scope":"signin","mode":"enforce","outcome":"step_up","step_up_max_age":901}`,
		"bad priority":      `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","priority":10001}`,
		"bad device":        `{"name":"a","scope":"signin","mode":"enforce","outcome":"deny","device":"jailbroken"}`,
	} {
		if code, v := call("POST", "/api/access/policies", bad); code != 422 && !(name == "duplicate" && code == 409) {
			t.Errorf("%s: %d %v", name, code, v)
		}
	}
	// a range in use cannot be deleted
	if code, v := call("DELETE", "/api/access/networks/"+netID, ""); code != 409 || v["error"] != "range_in_use" {
		t.Errorf("delete range in use: %d %v", code, v)
	}
	if code, v := call("GET", "/api/access/networks", ""); code != 200 {
		t.Errorf("list ranges: %d", code)
	} else {
		_ = v
	}
	// enforce it, then the what-if evaluation answers with the policy
	if code, v := call("PUT", "/api/access/policies/"+polID, strings.Replace(pbody(""), "report_only", "enforce", 1)); code != 200 || v["mode"] != "enforce" {
		t.Fatalf("update: %d %v", code, v)
	}
	code, ev := call("POST", "/api/access/evaluate", `{"scope":"privileged","client_ip":"203.0.113.9","device_compliance":"compliant"}`)
	if code != 200 || ev["outcome"] != "step_up" || asMap(ev["decided_by"])["name"] != "off-net" || asMap(ev["inputs"])["client_ip"] != "203.0.113.9" {
		t.Errorf("evaluate: %d %v", code, ev)
	}
	if _, ev := call("POST", "/api/access/evaluate", `{"scope":"privileged","client_ip":"198.51.100.9"}`); ev["outcome"] != "allow" {
		t.Errorf("evaluate inside: %v", ev)
	}
	if code, v := call("POST", "/api/access/evaluate", `{"scope":"privileged","client_ip":"x"}`); code != 422 {
		t.Errorf("evaluate bad ip: %d %v", code, v)
	}
	// device signals
	if code, v := call("PUT", "/api/access/device-signals/"+admin.UserID.String(), `{"status":"not_compliant","reason":"lost laptop","expires_in_hours":24}`); code != 200 || v["source"] != "manual" || v["expires_at"] == nil {
		t.Errorf("set signal: %d %v", code, v)
	}
	if code, v := call("PUT", "/api/access/device-signals/"+admin.UserID.String(), `{"status":"bogus"}`); code != 422 {
		t.Errorf("bad status: %d %v", code, v)
	}
	req := authed(admin, "GET", "/api/access/device-signals", "")
	var sigs []map[string]any
	rec := serve(h, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &sigs)
	if len(sigs) != 1 || sigs[0]["user"] != testAdmin.Email || sigs[0]["active"] != true {
		t.Errorf("signals %s", rec.Body.String())
	}
	if code, v := call("DELETE", "/api/access/device-signals/"+admin.UserID.String(), ""); code != 200 {
		t.Errorf("clear: %d %v", code, v)
	}
	if code, _ := call("DELETE", "/api/access/device-signals/"+admin.UserID.String(), ""); code != 404 {
		t.Errorf("clear again: %d", code)
	}
	// delete the policy, then the range
	if code, _ := call("DELETE", "/api/access/policies/"+polID, ""); code != 200 {
		t.Errorf("delete policy: %d", code)
	}
	if code, _ := call("DELETE", "/api/access/networks/"+netID, ""); code != 200 {
		t.Errorf("delete range: %d", code)
	}
	// every change left its domain event in the chain
	got := map[string]int{}
	for _, ev := range ledger(t, f.DB, f.B.ID) {
		got[ev.Action]++
	}
	for _, a := range []string{"access.network.create", "access.network.delete", "access.policy.create", "access.policy.update",
		"access.policy.delete", "access.device_signal.set", "access.device_signal.clear"} {
		if got[a] != 1 {
			t.Errorf("%s events: %d, want 1", a, got[a])
		}
	}
	if got["access.decision"] != 0 {
		t.Errorf("management and what-if calls are not access decisions: %d", got["access.decision"])
	}
}

// TestAccess_PolicyLimit: a tenant's policy set is bounded.
func TestAccess_PolicyLimit(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := accessServer(f).Handler()
	admin := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		for i := 0; i < maxAccessPolicies; i++ {
			if err := c.InsertAccessPolicy(&store.AccessPolicy{Name: fmt.Sprint("p", i), Scope: store.AccessScopeSignin,
				Mode: store.AccessModeDisabled, Outcome: store.AccessAllow, NetworkOp: store.NetworkAny, Device: store.DeviceAny,
				Priority: 100, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rec := serve(h, authed(admin, "POST", "/api/access/policies", `{"name":"one more","scope":"signin","mode":"disabled","outcome":"allow"}`))
	if rec.Code != 409 || errorOf(rec) != "limit_reached" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

// TestAccess_RBAC: who may read and who may change.
func TestAccess_RBAC(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := accessServer(f).Handler()
	body := `{"name":"n","scope":"signin","mode":"disabled","outcome":"allow"}`
	stale := authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}
	for _, tc := range []struct {
		role           auth.Role
		ctx            authtest.Ctx
		read, mutation int
	}{
		{auth.RoleViewer, authtest.Phr, 403, 403},
		{auth.RoleOperator, authtest.Phr, 403, 403},
		{auth.RolePolicyAdmin, authtest.Phr, 403, 403},
		{auth.RoleAuditor, authtest.Phr, 200, 403},
		{auth.RoleTenantAdmin, authtest.Phr, 200, 201},
		{auth.RoleTenantAdmin, stale, 200, 401}, // a change needs a fresh phishing-resistant sign-in
		{auth.RoleTenantAdmin, authtest.AAL2, 403, 403},
	} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: fmt.Sprintf("%s-%d@b.example", tc.role, tc.mutation+tc.read), Roles: []auth.Role{tc.role}}, tc.ctx, storetest.Now)
		if rec := serve(h, authed(l, "GET", "/api/access/policies", "")); rec.Code != tc.read {
			t.Errorf("%s read: %d, want %d", tc.role, rec.Code, tc.read)
		}
		rec := serve(h, authed(l, "POST", "/api/access/policies", body))
		if rec.Code != tc.mutation {
			t.Errorf("%s create: %d %s, want %d", tc.role, rec.Code, rec.Body.String(), tc.mutation)
		}
		if tc.mutation == 201 {
			// a second create with the same name conflicts instead of duplicating
			if rec := serve(h, authed(l, "POST", "/api/access/policies", body)); rec.Code != 409 {
				t.Errorf("duplicate create: %d", rec.Code)
			}
		}
	}
}

// TestAccessCrossTenant: as tenant B, tenant A's ids look nonexistent on every
// route that takes one, and tenant A is left untouched; B's lists never show
// A's rows, and a policy cannot name A's network range.
func TestAccessCrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := accessServer(f)
	seedAccess(t, f, f.A, pspec{name: "a-policy", scope: store.AccessScopePrivileged, mode: store.AccessModeEnforce, outcome: "deny", netOp: "not_in"})
	seedAccess(t, f, f.B, pspec{name: "b-policy", scope: store.AccessScopePrivileged, mode: store.AccessModeDisabled, outcome: "allow"})
	var aPolicy, aNet, aUser uuid.UUID
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		ps, _ := c.AccessPolicies()
		ns, _ := c.NetworkRanges()
		us, err := c.PlatformUsers()
		aPolicy, aNet = ps[0].ID, ns[0].ID
		if len(us) > 0 {
			aUser = us[0].ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if aUser == uuid.Nil { // the fixture has no platform user: make one
		if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			u := &store.PlatformUser{DisplayName: "a-user", CreatedAt: storetest.Now}
			aUser = u.ID
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			aUser = u.ID
			return c.SetDeviceSignal(&store.DeviceSignal{UserID: u.ID, Status: store.DeviceNonCompliant, Source: store.DeviceSourceManual, SetAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	h := asAdmin(t, srv, f.DB, f.B.ID, storetest.Now).Handler()
	missing := "00000000-0000-4000-8000-00000000dead"
	pbody := `{"name":"renamed","scope":"signin","mode":"enforce","outcome":"deny"}`
	nbody := `{"name":"renamed","cidrs":["10.0.0.0/8"]}`
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/api/access/policies/%s", pbody},
		{"DELETE", "/api/access/policies/%s", ""},
		{"PUT", "/api/access/networks/%s", nbody},
		{"DELETE", "/api/access/networks/%s", ""},
		{"PUT", "/api/access/device-signals/%s", `{"status":"compliant"}`},
		{"DELETE", "/api/access/device-signals/%s", ""},
	} {
		ids := map[string]uuid.UUID{"policies": aPolicy, "networks": aNet, "device-signals": aUser}
		kind := strings.Split(tc.path, "/")[3]
		cross := serveOnce(h, tc.method, fmt.Sprintf(tc.path, ids[kind]), tc.body)
		none := serveOnce(h, tc.method, fmt.Sprintf(tc.path, missing), tc.body)
		if cross.Code != 404 || cross.Code != none.Code || cross.Body.String() != none.Body.String() {
			t.Errorf("%s %s: A's id %d %s, missing %d %s", tc.method, tc.path, cross.Code, cross.Body.String(), none.Code, none.Body.String())
		}
	}
	// a policy naming A's range is "unknown range", like any other unknown id
	rec := serveOnce(h, "POST", "/api/access/policies", `{"name":"x","scope":"signin","mode":"enforce","outcome":"deny","network_op":"in","network_range_ids":["`+aNet.String()+`"]}`)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "unknown_network_range") {
		t.Errorf("policy naming A's range: %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/api/access/policies", "/api/access/networks", "/api/access/device-signals"} {
		rec := serveOnce(h, "GET", path, "")
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "a-policy") || strings.Contains(rec.Body.String(), aNet.String()) ||
			strings.Contains(rec.Body.String(), aPolicy.String()) || strings.Contains(rec.Body.String(), aUser.String()) {
			t.Errorf("GET %s leaks tenant A: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("calls made as tenant B changed tenant A")
	}
	// A's policies never apply to B's requests: B has only a disabled one
	l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	if rec := serve(srv.Handler(), privileged(l, outsideIP)); !ran(rec) {
		t.Errorf("tenant A's deny policy applied to tenant B: %d %s", rec.Code, rec.Body.String())
	}
}
