package mfa_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

// idp is the tiny world with the registered methods of an IdP on top.
type idp struct {
	connectors.Tiny
	source  *connectors.AuthMethodSource
	methods []connectors.AuthMethodRecord
	signals []connectors.AuthSignals
}

func (w idp) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	r, err := w.Tiny.Discover(ctx)
	if err != nil {
		return nil, err
	}
	r.AuthSource, r.AuthMethods, r.AuthSignals = w.source, w.methods, w.signals
	return r, nil
}

func okta(account, id, strength, kind string) connectors.AuthMethodRecord {
	return connectors.AuthMethodRecord{Account: connectors.Ref{Kind: "account", System: "okta", ExternalID: account},
		ExternalID: id, Strength: strength, Kind: kind}
}

var oktaOK = &connectors.AuthMethodSource{System: "okta"}

func syncAt(t *testing.T, db *testkit.DB, now time.Time, w idp) {
	t.Helper()
	testkit.Write(t, db, func(c *store.TenantTx) error {
		_, err := ingest.Sync(c, now, []connectors.Connector{w}, nil)
		return err
	})
}

func evaluate(t *testing.T, db *testkit.DB, spec map[string]any) ([]policy.Violation, error) {
	t.Helper()
	spec["id"], spec["type"], spec["severity"] = "mfa-required", "mfa_required", "high"
	p, err := policy.Parse(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []policy.Violation
	err = db.ReadTenant(context.Background(), db.Tenant, func(c *store.TenantTx) error {
		g, err := graph.Build(c, testkit.Now)
		if err != nil {
			return err
		}
		out, err = policy.Evaluate([]*policy.Policy{p}, policy.NewContext(g, c, testkit.Now))
		return err
	})
	return out, err
}

func TestIngestStoresMethodsSourcesAndSnapshot(t *testing.T) {
	db, _ := testkit.Tiny(t)
	syncAt(t, db, testkit.Now, idp{source: oktaOK, methods: []connectors.AuthMethodRecord{
		okta("alice", "k1", "phishing_resistant", "passkey"), okta("carol", "t1", "otp", "totp"), okta("carol", "s1", "sms_voice", "sms"),
		okta("nobody", "x", "otp", "totp"), // no such account: skipped
		okta("bob", "bad", "bogus", "x"),   // not a class: skipped
	}})
	data := testkit.Get(t, db, func(c *store.TenantTx) (*mfa.Data, error) { return mfa.Load(c, testkit.Now) })
	byName := map[string]*mfa.Identity{}
	for _, v := range data.Identities {
		byName[strings.TrimSpace(v.Name)] = v
	}
	if len(data.Identities) != 3 { // alice, bob, carol: dave is terminated, the rest are not people
		t.Errorf("identities = %d, want 3", len(data.Identities))
	}
	if a := byName["Alice"]; a.Best != mfa.PhishingResistant || !a.Passkey || a.Privileged {
		t.Errorf("Alice = %+v", a)
	}
	if c := byName["Carol"]; c.Best != mfa.OTP || !c.Privileged || len(c.Methods) != 2 || c.Methods[0].Kind != "totp" {
		t.Errorf("Carol = %+v", c)
	}
	if b := byName["Bob"]; b.Best != mfa.None || len(b.Methods) != 0 {
		t.Errorf("Bob = %+v (covered by Okta, no method)", b)
	}
	if len(data.Sources) != 1 || data.Sources[0].System != "okta" || data.Sources[0].Status != mfa.SourceOK {
		t.Errorf("sources = %+v", data.Sources)
	}
	// today's snapshot: all + 2 departments + the privileged group
	snaps := testkit.Get(t, db, func(c *store.TenantTx) ([]*store.MFASnapshot, error) { return c.MFASnapshots("2026-10-08") })
	dims := map[string]int{}
	for _, s := range snaps {
		dims[s.Dimension]++
		if s.Dimension == mfa.DimAll && (s.Date != "2026-10-08" || s.Total != 3 || s.PhishingResistant != 1 || s.OTP != 1 ||
			s.NoMFA != 1 || s.PasskeyEnrolled != 1) {
			t.Errorf("all-snapshot = %+v", s)
		}
	}
	if dims[mfa.DimAll] != 1 || dims[mfa.DimDepartment] != 2 || dims[mfa.DimPrivilegedGroup] != 1 {
		t.Errorf("snapshot rows per dimension = %v", dims)
	}
	// a second sync the same day replaces the row; a later day adds one
	syncAt(t, db, testkit.Now.Add(time.Hour), idp{source: oktaOK, methods: []connectors.AuthMethodRecord{
		okta("alice", "k1", "phishing_resistant", "passkey"), okta("bob", "k2", "phishing_resistant", "passkey")}})
	syncAt(t, db, testkit.Now.Add(24*time.Hour), idp{source: oktaOK, methods: []connectors.AuthMethodRecord{okta("alice", "k1", "phishing_resistant", "passkey")}})
	snaps = testkit.Get(t, db, func(c *store.TenantTx) ([]*store.MFASnapshot, error) { return c.MFASnapshots("2026-10-08") })
	var trend []int
	for _, s := range snaps {
		if s.Dimension == mfa.DimAll {
			trend = append(trend, s.PasskeyEnrolled)
		}
	}
	if len(trend) != 2 || trend[0] != 2 || trend[1] != 1 {
		t.Errorf("passkey trend = %v, want [2 1] (same-day sync replaced, next day added)", trend)
	}
}

// A system that cannot read its methods keeps what was stored and is shown as
// unavailable; a later good read replaces the methods wholesale.
func TestUnavailableSourceKeepsStoredMethods(t *testing.T) {
	db, _ := testkit.Tiny(t)
	syncAt(t, db, testkit.Now, idp{source: oktaOK, methods: []connectors.AuthMethodRecord{okta("carol", "t1", "otp", "totp")}})
	syncAt(t, db, testkit.Now.Add(time.Hour), idp{source: &connectors.AuthMethodSource{System: "okta", Unavailable: true, Detail: "scope missing"}})
	read := func() ([]*store.AuthMethod, []*store.AuthMethodSource) {
		var ms []*store.AuthMethod
		var src []*store.AuthMethodSource
		testkit.Read(t, db, func(c *store.TenantTx) (err error) {
			if ms, err = c.AuthMethods(); err != nil {
				return err
			}
			src, err = c.AuthMethodSources()
			return err
		})
		return ms, src
	}
	ms, src := read()
	if len(ms) != 1 || len(src) != 1 || src[0].Status != mfa.SourceUnavailable || src[0].Detail != "scope missing" {
		t.Errorf("after an unavailable read: methods %+v, sources %+v", ms, src)
	}
	// a sync by a connector that reports no source at all leaves everything as it was
	syncAt(t, db, testkit.Now.Add(2*time.Hour), idp{})
	if ms, src = read(); len(ms) != 1 || len(src) != 1 || src[0].Status != mfa.SourceUnavailable {
		t.Errorf("after a sync without a source: methods %+v, sources %+v", ms, src)
	}
	syncAt(t, db, testkit.Now.Add(3*time.Hour), idp{source: oktaOK, methods: []connectors.AuthMethodRecord{okta("carol", "f1", "phishing_resistant", "passkey")}})
	if ms, src = read(); len(ms) != 1 || ms[0].ExternalID != "f1" || src[0].Status != mfa.SourceOK || src[0].Detail != "" {
		t.Errorf("after a good read: methods %+v, sources %+v", ms, src)
	}
}

func TestIngestStoresAppSignalsAsReported(t *testing.T) {
	db, _ := testkit.Tiny(t)
	acct := func(system, xid string) connectors.Ref {
		return connectors.Ref{Kind: "account", System: system, ExternalID: xid}
	}
	tr, fa := true, false
	syncAt(t, db, testkit.Now, idp{source: oktaOK, signals: []connectors.AuthSignals{
		{Account: acct("snowflake", "HELPER_BOT"), HasLocalPassword: &tr, MFAEnabled: &fa},
		{Account: acct("aws", "nope")}, // unknown account: skipped
	}})
	data := testkit.Get(t, db, func(c *store.TenantTx) (*mfa.Data, error) { return mfa.Load(c, testkit.Now) })
	if len(data.Findings) != 1 || data.Findings[0].System != "snowflake" || len(data.Findings[0].Issues) != 2 {
		t.Fatalf("findings = %+v", data.Findings)
	}
	rows := testkit.Get(t, db, func(c *store.TenantTx) ([]*store.AccountAuthSignals, error) { return c.AccountAuthSignalRows() })
	if len(rows) != 1 || rows[0].SSOEnforced != nil {
		t.Errorf("signal rows = %+v (an unreported flag must stay unknown)", rows)
	}
}

func TestMFARequiredPolicy(t *testing.T) {
	passkey := okta("carol", "k", "phishing_resistant", "passkey")
	for _, tc := range []struct {
		name    string
		source  *connectors.AuthMethodSource
		methods []connectors.AuthMethodRecord
		spec    map[string]any
		want    string // substring of the one violation's message, "" for none
	}{
		{"otp only", oktaOK, []connectors.AuthMethodRecord{okta("carol", "t", "otp", "totp"), okta("alice", "t", "otp", "totp")},
			map[string]any{}, "strongest mfa method is otp"},
		{"sms only", oktaOK, []connectors.AuthMethodRecord{okta("carol", "s", "sms_voice", "sms")}, map[string]any{}, "sms, voice or e-mail"},
		{"push with number match is not enough", oktaOK, []connectors.AuthMethodRecord{okta("carol", "p", "push_number_match", "app_push")},
			map[string]any{}, "push with number match"},
		{"no method registered", oktaOK, nil, map[string]any{}, "no mfa method registered"},
		{"passkey", oktaOK, []connectors.AuthMethodRecord{passkey}, map[string]any{}, ""},
		{"passkey among weaker methods", oktaOK, []connectors.AuthMethodRecord{okta("carol", "t", "otp", "totp"), passkey}, map[string]any{}, ""},
		{"methods unreadable is unknown, not a violation", &connectors.AuthMethodSource{System: "okta", Unavailable: true}, nil, map[string]any{}, ""},
		{"no source at all", nil, nil, map[string]any{}, ""},
		{"lower bar met", oktaOK, []connectors.AuthMethodRecord{okta("carol", "t", "otp", "totp")}, map[string]any{"require": "otp"}, ""},
		{"lower bar not met", oktaOK, []connectors.AuthMethodRecord{okta("carol", "s", "sms_voice", "sms")}, map[string]any{"require": "otp"}, "requires otp mfa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, ids := testkit.Tiny(t)
			syncAt(t, db, testkit.Now, idp{source: tc.source, methods: tc.methods})
			vs, err := evaluate(t, db, tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(vs) != 0 {
					t.Fatalf("violations = %+v, want none", vs)
				}
				return
			}
			// only Carol holds privileged access in the tiny world; Alice, Bob and the rest never violate
			if len(vs) != 1 || *vs[0].IdentityID != ids["carol"] || !strings.Contains(strings.ToLower(vs[0].Message), tc.want) {
				t.Fatalf("violations = %+v, want one for carol containing %q", vs, tc.want)
			}
			if vs[0].PolicyID != "mfa-required" || vs[0].Severity != "high" || len(vs[0].Evidence) == 0 ||
				vs[0].Key != fmt.Sprintf("mfa-required:%d", ids["carol"]) {
				t.Errorf("violation = %+v", vs[0])
			}
		})
	}
}

func TestMFARequiredRejectsAnUnknownClass(t *testing.T) {
	db, _ := testkit.Tiny(t)
	if _, err := evaluate(t, db, map[string]any{"require": "strong"}); err == nil || !strings.Contains(err.Error(), "require must be one of") {
		t.Errorf("err = %v, want a require error", err)
	}
}
