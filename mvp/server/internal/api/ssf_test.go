package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/ssf"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// ---------------------------------------------------------------- fixtures

const (
	ssfIssuer   = "https://larkspur.okta.com"
	ssfAudience = "https://tessera.example/ssf"
	awsUserID   = "c2a7e8f4-1031-70b2-9a64-0b5d8f6e3a11"
)

// oktaKey is the test transmitter's signing key.
type oktaKey struct {
	jwk jose.JSONWebKey
	s   jose.Signer
}

func newOktaKey(t testing.TB, kid string) *oktaKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("secevent+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	return &oktaKey{jwk: jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Use: "sig", Algorithm: "ES256"}, s: sg}
}

func (k *oktaKey) jwks() string {
	raw, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k.jwk}})
	return string(raw)
}

func (k *oktaKey) sign(t testing.TB, claims map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(claims)
	jws, err := k.s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sessionRevoked is a CAEP session-revoked SET for the Okta user sub.
func sessionRevoked(jti, sub string, mod func(map[string]any)) map[string]any {
	c := map[string]any{"iss": ssfIssuer, "aud": ssfAudience, "iat": storetest.Now.Add(-2 * time.Second).Unix(), "jti": jti,
		"events": map[string]any{ssf.EventSessionRevoked: map[string]any{
			"subject": map[string]any{"format": "iss_sub", "iss": ssfIssuer, "sub": sub}, "event_timestamp": storetest.Now.Unix()}}}
	if mod != nil {
		mod(c)
	}
	return c
}

// fakeAWS is a small stateful AWS: Organizations (the Deny SCP), the identity
// store and sso-admin, told apart by X-Amz-Target like the real ones.
type fakeAWS struct {
	srv *httptest.Server
	mu  sync.Mutex
	// state
	policy      string
	assignments []map[string]string
	calls       []string
	updates     []string // the content of every UpdatePolicy
	delay       time.Duration
	unattached  bool // the Deny policy has no target
}

func newFakeAWS(t *testing.T) *fakeAWS {
	t.Helper()
	a := &fakeAWS{policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["Add user ID here"]}}}]}`}
	for _, acct := range []string{"111122223333", "444455556666"} {
		a.assignments = append(a.assignments, map[string]string{"AccountId": acct, "PrincipalId": awsUserID, "PrincipalType": "USER",
			"PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-7223a1b2c3d4e5f6/ps-1111aaaa2222bbbb"})
	}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	target := r.Header.Get("X-Amz-Target")
	op := target[strings.Index(target, ".")+1:]
	a.calls = append(a.calls, op)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE1234567/") {
		http.Error(w, `{"__type":"UnrecognizedClientException"}`, 403)
		return
	}
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch op {
	case "DescribeUser":
		reply(map[string]any{"UserId": in["UserId"], "UserName": "alice@larkspur.example"})
	case "ListTargetsForPolicy":
		targets := []map[string]string{}
		if !a.unattached {
			targets = append(targets, map[string]string{"TargetId": "r-ab12", "Type": "ROOT"})
		}
		reply(map[string]any{"Targets": targets})
	case "DescribePolicy":
		reply(map[string]any{"Policy": map[string]any{"Content": a.policy}})
	case "UpdatePolicy":
		time.Sleep(a.delay)
		a.policy, _ = in["Content"].(string)
		a.updates = append(a.updates, a.policy)
		reply(map[string]any{})
	case "ListAccountAssignmentsForPrincipal":
		reply(map[string]any{"AccountAssignments": append([]map[string]string{}, a.assignments...)})
	case "DeleteAccountAssignment":
		kept := a.assignments[:0]
		for _, as := range a.assignments {
			if as["AccountId"] != in["TargetId"] {
				kept = append(kept, as)
			}
		}
		a.assignments = kept
		reply(map[string]any{"AccountAssignmentDeletionStatus": map[string]any{"Status": "SUCCEEDED", "RequestId": "r1"}})
	default:
		w.WriteHeader(400)
		reply(map[string]any{"__type": "UnknownOperationException"})
	}
}

func (a *fakeAWS) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

func (a *fakeAWS) SetDelay(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.delay = d
}

func (a *fakeAWS) Updates() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.updates...)
}

func (a *fakeAWS) Assignments() []map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]string(nil), a.assignments...)
}

func (a *fakeAWS) Count(op string) int {
	n := 0
	for _, c := range a.Calls() {
		if c == op {
			n++
		}
	}
	return n
}

type ssfEnv struct {
	t      *testing.T
	f      *storetest.Fixture
	srv    *Server
	h      http.Handler
	aws    *fakeAWS
	key    *oktaKey
	admin  authtest.Login // tenant admin: connections.manage
	pa     authtest.Login // policy admin: ssf.configure
	secret string
	id     string // the Okta transmitter
	path   string // its push path
}

func ssfServer(t *testing.T, f *storetest.Fixture, rl RateLimits) *Server {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	clock := timeutil.Frozen(storetest.Now)
	cs := &containment.Service{HTTP: hc, Sealer: sealer, Clock: clock, Sleep: func(context.Context, time.Duration) error { return nil }}
	return New(Config{
		Store: f.DB, Clock: clock, Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Containment: cs, SSF: &ssf.Service{HTTP: hc, Sealer: sealer, Clock: clock, Containment: cs, Dev: true},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Env:    "test", RateLimits: rl, AllowedOrigins: []string{"http://localhost:5173"},
	})
}

// newSSFEnv: tenant A with Alice linked to an aws_identity_center account
// (connection and credential set through the API), and an Okta push
// transmitter created through the API.
func newSSFEnv(t *testing.T) *ssfEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &ssfEnv{t: t, f: f, aws: newFakeAWS(t), key: newOktaKey(t, "okta-1")}
	e.srv = ssfServer(t, f, noRateLimits)
	e.h = e.srv.Handler()
	e.pa = policyAdmin(t, f, f.A.ID, "pa@a.example")
	e.admin = signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	var conn string
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		conn = store.NewID()
		if err := c.InsertConnection(&store.Connection{ID: conn, Name: "AWS IAM Identity Center", ConnectorType: "aws-identity-center",
			System: containment.AWSIdentityCenter, Role: "account_source", CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		alice := f.A.IDs["alice"]
		_, err := c.InsertAccount(&store.Account{System: containment.AWSIdentityCenter, ExternalID: awsUserID, IdentityID: &alice,
			Username: "alice@larkspur.example", Kind: "human", Status: "active"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rec := corrDo(e.h, e.admin, "PUT", "/api/connections/"+conn+"/containment-credential", fmt.Sprintf(`{"base_url":%q,"aws":{
		"access_key_id":"AKIDEXAMPLE1234567","secret_access_key":"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY","region":"us-east-1",
		"policy_id":"p-0a1b2c3d4e","identity_store_id":"d-1234567890","instance_arn":"arn:aws:sso:::instance/ssoins-7223a1b2c3d4e5f6"}}`, e.aws.srv.URL))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "wJalrXUtnFEMI") {
		t.Fatalf("aws credential: %d %s", rec.Code, rec.Body)
	}
	e.id, e.secret = e.createTransmitter("Okta", "push", e.key)
	e.path = "/public/t/" + f.A.Slug + "/ssf/" + e.id + "/events"
	return e
}

func (e *ssfEnv) createTransmitter(name, delivery string, key *oktaKey) (id, secret string) {
	e.t.Helper()
	body := map[string]any{"name": name, "issuer": ssfIssuer, "audience": ssfAudience, "jwks": json.RawMessage(key.jwks()),
		"delivery": delivery, "subject_system": "okta"}
	raw, _ := json.Marshal(body)
	rec := corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters", string(raw))
	var out struct {
		Transmitter struct {
			ID           string
			ReceiverPath string `json:"receiver_path"`
		} `json:"transmitter"`
		Secret string `json:"receiver_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 201 || out.Transmitter.ID == "" || out.Secret == "" {
		e.t.Fatalf("create transmitter: %d %s", rec.Code, rec.Body)
	}
	if want := "/public/t/" + e.f.A.Slug + "/ssf/" + out.Transmitter.ID + "/events"; out.Transmitter.ReceiverPath != want {
		e.t.Errorf("receiver path %q, want %q", out.Transmitter.ReceiverPath, want)
	}
	return out.Transmitter.ID, out.Secret
}

// push delivers a SET to the transmitter's push endpoint.
func (e *ssfEnv) push(path, bearer, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return serve(e.h, req)
}

func (e *ssfEnv) deliver(set string) *httptest.ResponseRecorder {
	return e.push(e.path, e.secret, "application/secevent+jwt", set)
}

type eventRow struct {
	ID, JTI, Via, Event, Subject, Status, Outcome string
	IdentityID                                    *int64 `json:"identity_id"`
	Steps                                         int
	StepsFailed                                   int     `json:"steps_failed"`
	LatencyMS                                     *int64  `json:"latency_ms"`
	IATLatencyMS                                  *int64  `json:"iat_latency_ms"`
	ActionedAt                                    *string `json:"actioned_at"`
}

func (e *ssfEnv) events(l authtest.Login, query string) []eventRow {
	e.t.Helper()
	rec := corrDo(e.h, l, "GET", "/api/ssf/events"+query, "")
	var out struct{ Events []eventRow }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		e.t.Fatalf("events: %d %s", rec.Code, rec.Body)
	}
	return out.Events
}

func (e *ssfEnv) audit(action string) []map[string]any {
	e.t.Helper()
	var out []map[string]any
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: action})
		for _, ev := range evs {
			var d map[string]any
			if err := json.Unmarshal(ev.Detail, &d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func b64s(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// seedSSFTransmitters gives each tenant a transmitter, tenant A's carrying the
// sentinel in its name, and returns their ids by slug.
func seedSSFTransmitters(t testing.TB, f *storetest.Fixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	key := newOktaKey(t, "seed")
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		name := "Okta " + tn.Slug
		if tn.ID == f.A.ID {
			name += " " + storetest.Sentinel
		}
		x := &store.SSFTransmitter{Name: name, Issuer: "https://" + tn.Slug + ".okta.example", Audience: "tessera", JWKSInline: key.jwks(),
			Delivery: store.SSFPush, SecretEnc: []byte("sealed"), SubjectSystem: "okta", Status: store.SSFEnabled, CreatedBy: "seed"}
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertSSFTransmitter(x, storetest.Now); err != nil {
				return err
			}
			return c.InsertSSFEvent(&store.SSFEvent{TransmitterID: x.ID, JTI: "seed-1", Via: store.SSFPush, EventType: ssf.EventSessionRevoked,
				SubjectFormat: "iss_sub", Subject: "alice " + name, ReceivedAt: storetest.Now, IATAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = x.ID
	}
	return out
}

// ---------------------------------------------------------------- the end-to-end test

// A revoked Okta session ends the matching AWS Identity Center session: the
// Okta transmitter push-delivers a CAEP session-revoked SET for Alice, Tessera
// denies her in the Identity Center SCP, deletes her assignments, re-reads
// both, and records the event with its latency.
func TestSSFEndToEnd_OktaSessionRevokedEndsAWSSession(t *testing.T) {
	e := newSSFEnv(t)
	e.aws.SetDelay(25 * time.Millisecond) // the provider takes a moment: the latency is real
	rec := e.deliver(e.key.sign(t, sessionRevoked("jti-e2e-1", "alice", nil)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	// the SCP was updated with her user id, next to the placeholder
	if updates := e.aws.Updates(); len(updates) != 1 || !strings.Contains(updates[0], `"identitystore:userId":["Add user ID here","`+awsUserID+`"]`) {
		t.Fatalf("SCP updates: %v", e.aws.Updates())
	}
	// her assignments were deleted
	if len(e.aws.Assignments()) != 0 || e.aws.Count("DeleteAccountAssignment") != 2 {
		t.Errorf("assignments left: %v (%d deletes)", e.aws.Assignments(), e.aws.Count("DeleteAccountAssignment"))
	}
	// verification passed: the policy and the assignments were read again after the revoke
	calls := e.aws.Calls()
	want := []string{"DescribeUser", "ListTargetsForPolicy", "DescribePolicy", "UpdatePolicy", "DescribePolicy",
		"ListAccountAssignmentsForPrincipal", "DeleteAccountAssignment", "DeleteAccountAssignment", "ListTargetsForPolicy",
		"DescribePolicy", "ListAccountAssignmentsForPrincipal"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Errorf("AWS calls\n got %v\nwant %v", calls, want)
	}
	run := e.audit("containment.run")
	if len(run) != 1 || run[0]["ok"] != true || run[0]["trigger"] != "ssf" {
		t.Fatalf("containment.run: %v", run)
	}
	steps, _ := run[0]["steps"].([]any)
	st, _ := steps[0].(map[string]any)
	if len(steps) != 1 || st["system"] != "aws_identity_center" || st["action"] != "revoke_sessions" || st["outcome"] != "done" || st["verified"] != true {
		t.Errorf("containment steps: %v", steps)
	}
	// the event row is actioned with the latency recorded
	evs := e.events(e.pa, "")
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	ev := evs[0]
	if ev.Status != "actioned" || ev.Event != "session-revoked" || ev.Via != "push" || ev.Steps != 1 || ev.StepsFailed != 0 ||
		ev.IdentityID == nil || *ev.IdentityID != e.f.A.IDs["alice"] || ev.ActionedAt == nil ||
		ev.LatencyMS == nil || *ev.LatencyMS < 25 || ev.IATLatencyMS == nil || *ev.IATLatencyMS < 2000 {
		t.Errorf("event %+v (latency %v, iat latency %v)", ev, ptrVal(ev.LatencyMS), ptrVal(ev.IATLatencyMS))
	}
	// the audit trail: received, run, actioned, with timings and no token
	for _, a := range []string{"ssf.event_received", "ssf.event_actioned"} {
		if got := e.audit(a); len(got) != 1 {
			t.Errorf("audit %s: %v", a, got)
		}
	}
	act := e.audit("ssf.event_actioned")[0]
	if act["status"] != "actioned" || act["latency_ms"] == nil || act["iat_latency_ms"] == nil || act["steps"] != float64(1) {
		t.Errorf("ssf.event_actioned detail %v", act)
	}
	e.noTokensInLedger()
	// the manual task AWS leaves (the access portal session) is reported, not claimed
	if m, _ := run[0]["manual_tasks"].(float64); m != 3 {
		t.Errorf("manual tasks %v, want 3", run[0]["manual_tasks"])
	}
	// the transmitter shows its last event and no error
	rec = corrDo(e.h, e.pa, "GET", "/api/ssf/transmitters/"+e.id, "")
	var one struct {
		Transmitter struct {
			Status      string
			LastEventAt *string `json:"last_event_at"`
			LastError   string  `json:"last_error"`
		}
		Events []eventRow
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil || one.Transmitter.Status != "enabled" || one.Transmitter.LastEventAt == nil ||
		one.Transmitter.LastError != "" || len(one.Events) != 1 {
		t.Errorf("transmitter detail: %d %s", rec.Code, rec.Body)
	}
	// delivering the same SET again is acknowledged and does nothing more (the jti is spent)
	again := e.deliver(e.key.sign(t, sessionRevoked("jti-e2e-1", "alice", nil)))
	if again.Code != http.StatusAccepted || e.aws.Count("UpdatePolicy") != 1 || e.aws.Count("DeleteAccountAssignment") != 2 || len(e.events(e.pa, "")) != 1 {
		t.Errorf("replay: %d, %d updates, %d events", again.Code, e.aws.Count("UpdatePolicy"), len(e.events(e.pa, "")))
	}
	if got := e.audit("ssf.event_replayed"); len(got) != 1 {
		t.Errorf("replay audit: %v", got)
	}
}

func ptrVal(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// noTokensInLedger: no audit event of the tenant holds a SET, a secret or an AWS credential.
func (e *ssfEnv) noTokensInLedger() {
	e.t.Helper()
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{IncludeHTTP: true})
		for _, ev := range evs {
			raw, _ := json.Marshal(ev)
			for _, bad := range []string{"eyJ", e.secret, "wJalrXUtnFEMI", "AKIDEXAMPLE1234567"} {
				if strings.Contains(string(raw), bad) {
					e.t.Errorf("audit event %s holds %q", ev.Action, bad)
				}
			}
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func TestSSFPush_RefusesBadSETs(t *testing.T) {
	e := newSSFEnv(t)
	stranger := newOktaKey(t, "okta-1") // same kid, another key
	cases := []struct {
		name string
		set  string
		err  string
	}{
		{"bad signature", stranger.sign(t, sessionRevoked("j-1", "alice", nil)), "invalid_key"},
		{"wrong audience", e.key.sign(t, sessionRevoked("j-2", "alice", func(c map[string]any) { c["aud"] = "https://other.example" })), "invalid_request"},
		{"wrong issuer", e.key.sign(t, sessionRevoked("j-3", "alice", func(c map[string]any) { c["iss"] = "https://evil.example" })), "invalid_request"},
		{"alg none", b64s(`{"alg":"none","typ":"secevent+jwt"}`) + "." + b64s(`{"iss":"`+ssfIssuer+`","aud":"`+ssfAudience+`","jti":"j-4","iat":1,"events":{}}`) + ".", "invalid_request"},
		{"HS256", b64s(`{"alg":"HS256"}`) + "." + b64s(`{}`) + ".c2ln", "invalid_request"},
		{"expired", e.key.sign(t, sessionRevoked("j-5", "alice", func(c map[string]any) { c["exp"] = storetest.Now.Add(-time.Minute).Unix() })), "invalid_request"},
		{"stale iat", e.key.sign(t, sessionRevoked("j-6", "alice", func(c map[string]any) { c["iat"] = storetest.Now.Add(-48 * time.Hour).Unix() })), "invalid_request"},
		{"no jti", e.key.sign(t, sessionRevoked("", "alice", nil)), "invalid_request"},
		{"empty body", "", "invalid_request"},
		{"garbage", "not a jwt", "invalid_request"},
	}
	for _, tc := range cases {
		rec := e.deliver(tc.set)
		var body struct{ Err, Description string }
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 400 || body.Err != tc.err || body.Description == "" {
			t.Errorf("%s: %d %s, want 400 %s", tc.name, rec.Code, rec.Body, tc.err)
		}
	}
	if len(e.events(e.pa, "")) != 0 || len(e.aws.Calls()) != 0 {
		t.Errorf("a refused SET must do nothing: %d events, AWS calls %v", len(e.events(e.pa, "")), e.aws.Calls())
	}
	if got := e.audit("ssf.event_rejected"); len(got) != len(cases) {
		t.Errorf("%d rejections audited, want %d", len(got), len(cases))
	}
	e.noTokensInLedger()
	// the content type and the size are checked too
	if rec := e.push(e.path, e.secret, "application/json", e.key.sign(t, sessionRevoked("j-7", "alice", nil))); rec.Code != 400 ||
		!strings.Contains(rec.Body.String(), `"invalid_request"`) {
		t.Errorf("wrong content type: %d %s", rec.Code, rec.Body)
	}
	if rec := e.deliver(strings.Repeat("a", ssf.MaxSETBytes+1)); rec.Code != 400 {
		t.Errorf("oversize: %d", rec.Code)
	}
	// a paused stream refuses everything (to an authenticated transmitter)
	rec := corrDo(e.h, e.pa, "PUT", "/api/ssf/transmitters/"+e.id, fmt.Sprintf(`{"name":"Okta","issuer":%q,"audience":%q,"delivery":"push","subject_system":"okta","status":"paused"}`, ssfIssuer, ssfAudience))
	if rec.Code != 200 {
		t.Fatalf("pause: %d %s", rec.Code, rec.Body)
	}
	if rec := e.deliver(e.key.sign(t, sessionRevoked("j-8", "alice", nil))); rec.Code != 400 || !strings.Contains(rec.Body.String(), `"access_denied"`) {
		t.Errorf("paused: %d %s", rec.Code, rec.Body)
	}
}

// An unknown tenant, an unknown transmitter and a wrong or missing secret get
// the same answer: byte for byte.
func TestSSFPush_RevealsNothing(t *testing.T) {
	e := newSSFEnv(t)
	set := e.key.sign(t, sessionRevoked("j-r", "alice", nil))
	bID := ""
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		x := &store.SSFTransmitter{Name: "B's", Issuer: ssfIssuer, Audience: ssfAudience, JWKSInline: e.key.jwks(), Delivery: store.SSFPush,
			SecretEnc: []byte("sealed"), SubjectSystem: "okta", Status: store.SSFEnabled, CreatedBy: "b"}
		if err := c.InsertSSFTransmitter(x, storetest.Now); err != nil {
			return err
		}
		bID = x.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const uuid = "00000000-0000-4000-8000-00000000dead"
	good := e.f.A.Slug
	responses := map[string]*httptest.ResponseRecorder{
		"unknown tenant":              e.push("/public/t/no-such-tenant/ssf/"+e.id+"/events", e.secret, "application/secevent+jwt", set),
		"invalid slug":                e.push("/public/t/NO_SUCH!/ssf/"+e.id+"/events", e.secret, "application/secevent+jwt", set),
		"platform tenant":             e.push("/public/t/_platform/ssf/"+e.id+"/events", e.secret, "application/secevent+jwt", set),
		"unknown transmitter":         e.push("/public/t/"+good+"/ssf/"+uuid+"/events", e.secret, "application/secevent+jwt", set),
		"malformed transmitter id":    e.push("/public/t/"+good+"/ssf/not-an-id/events", e.secret, "application/secevent+jwt", set),
		"another tenant's stream":     e.push("/public/t/"+good+"/ssf/"+bID+"/events", e.secret, "application/secevent+jwt", set),
		"wrong secret":                e.push(e.path, "wrong-secret-wrong-secret", "application/secevent+jwt", set),
		"secret with a suffix":        e.push(e.path, e.secret+"x", "application/secevent+jwt", set),
		"secret prefix":               e.push(e.path, e.secret[:10], "application/secevent+jwt", set),
		"no authorization":            e.push(e.path, "", "application/secevent+jwt", set),
		"empty bearer":                e.push(e.path, " ", "application/secevent+jwt", set),
		"wrong content type, no auth": e.push(e.path, "", "text/plain", set),
		"tenant B's slug":             e.push("/public/t/"+e.f.B.Slug+"/ssf/"+e.id+"/events", e.secret, "application/secevent+jwt", set),
	}
	var first *httptest.ResponseRecorder
	for name, rec := range responses {
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"authentication_failed"`) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if first == nil {
			first = rec
		}
		if rec.Code != first.Code || rec.Body.String() != first.Body.String() {
			t.Errorf("%s answers differently:\n %d %s\n %d %s", name, rec.Code, rec.Body, first.Code, first.Body)
		}
	}
	if len(e.events(e.pa, "")) != 0 || len(e.aws.Calls()) != 0 {
		t.Error("an unauthenticated delivery did something")
	}
	// the right secret works, and only the right secret
	if rec := e.deliver(set); rec.Code != 202 {
		t.Errorf("right secret: %d %s", rec.Code, rec.Body)
	}
	// a GET or another method is not a delivery
	if rec := serve(e.h, httptest.NewRequest("GET", e.path, nil)); rec.Code != 405 {
		t.Errorf("GET: %d", rec.Code)
	}
}

func TestSSFPush_UnmatchedSubjectIsRecordedAndShown(t *testing.T) {
	e := newSSFEnv(t)
	rec := e.deliver(e.key.sign(t, sessionRevoked("j-u", "00u-nobody", nil)))
	if rec.Code != 202 {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	evs := e.events(e.pa, "?transmitter_id="+e.id)
	if len(evs) != 1 || evs[0].Status != "unmatched" || !strings.Contains(evs[0].Outcome, "no okta account matches") ||
		evs[0].Subject != "00u-nobody" || evs[0].IdentityID != nil || evs[0].Steps != 0 {
		t.Fatalf("events %+v", evs)
	}
	if got := e.audit("ssf.event_unmatched"); len(got) != 1 || got[0]["subject"] != "00u-nobody" || got[0]["reason"] == nil {
		t.Errorf("audit %v", got)
	}
	if len(e.aws.Calls()) != 0 || len(e.audit("containment.run")) != 0 {
		t.Error("an unmatched subject triggered containment")
	}
	// an unknown event type is acknowledged and recorded as ignored
	rec = e.deliver(e.key.sign(t, sessionRevoked("j-x", "alice", func(c map[string]any) {
		c["events"] = map[string]any{"https://example.test/event/other": map[string]any{}}
	})))
	if rec.Code != 202 {
		t.Fatalf("unknown event: %d %s", rec.Code, rec.Body)
	}
	if evs = e.events(e.pa, ""); len(evs) != 2 || evs[0].Status != "ignored" || evs[0].Event != "unknown" {
		t.Errorf("events %+v", evs)
	}
	if got := e.audit("ssf.event_ignored"); len(got) != 1 {
		t.Errorf("ignored audit %v", got)
	}
}

func TestSSFPush_CredentialChangeAndAccountDisabled(t *testing.T) {
	e := newSSFEnv(t)
	set := func(jti, event string) string {
		return e.key.sign(t, sessionRevoked(jti, "alice", func(c map[string]any) {
			c["events"] = map[string]any{event: map[string]any{"subject": map[string]any{"format": "email", "email": "ignored@x"}}}
			c["sub_id"] = map[string]any{"format": "iss_sub", "iss": ssfIssuer, "sub": "alice"}
		}))
	}
	// the event's own subject wins: an email no account has
	if rec := e.deliver(set("j-c", ssf.EventCredentialChange)); rec.Code != 202 {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	if evs := e.events(e.pa, ""); len(evs) != 1 || evs[0].Status != "unmatched" {
		t.Errorf("events %+v", evs)
	}
	// an account-disabled event for Alice by her Okta id: sessions on AWS (AWS has no grants step)
	rec := e.deliver(e.key.sign(t, sessionRevoked("j-d", "alice", func(c map[string]any) {
		c["events"] = map[string]any{ssf.EventAccountDisabled: map[string]any{"subject": map[string]any{"format": "iss_sub", "iss": ssfIssuer, "sub": "alice"}}}
	})))
	if rec.Code != 202 {
		t.Fatalf("account-disabled: %d %s", rec.Code, rec.Body)
	}
	evs := e.events(e.pa, "")
	if len(evs) != 2 || evs[0].Event != "account-disabled" || evs[0].Status != "actioned" || evs[0].Steps != 1 || e.aws.Count("UpdatePolicy") != 1 {
		t.Errorf("events %+v, AWS calls %v", evs, e.aws.Calls())
	}
}

// A poll stream is polled by the sweeper loop; only the processed jtis are acknowledged.
func TestSSFPoll_SweeperPollsAndAcknowledgesOnlyProcessedJTIs(t *testing.T) {
	e := newSSFEnv(t)
	good := e.key.sign(t, sessionRevoked("poll-good", "alice", nil))
	stranger := newOktaKey(t, "okta-1").sign(t, sessionRevoked("poll-bad", "alice", nil))
	var mu sync.Mutex
	var reqs []map[string]any
	poll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["_auth"] = r.Header.Get("Authorization")
		mu.Lock()
		reqs = append(reqs, body)
		n := len(reqs)
		mu.Unlock()
		sets := map[string]string{}
		if n == 1 {
			sets = map[string]string{"poll-good": good, "poll-bad": stranger}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": sets, "moreAvailable": n == 1})
	}))
	t.Cleanup(poll.Close)
	raw, _ := json.Marshal(map[string]any{"name": "Okta poll", "issuer": ssfIssuer, "audience": ssfAudience, "jwks": json.RawMessage(e.key.jwks()),
		"delivery": "poll", "poll_url": poll.URL, "secret": "poll-bearer-secret-123456", "subject_system": "okta"})
	if rec := corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters", string(raw)); rec.Code != 201 || strings.Contains(rec.Body.String(), "receiver_secret") ||
		strings.Contains(rec.Body.String(), "poll-bearer-secret") || strings.Contains(rec.Body.String(), `"receiver_path"`) {
		t.Fatalf("create poll stream: %d %s", rec.Code, rec.Body)
	}
	// the ssf_poll queue job polls the stream; a tick starts four jobs at a time
	for range 4 {
		if err := e.srv.Queue().Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		e.srv.Queue().Wait()
		mu.Lock()
		n := len(reqs)
		mu.Unlock()
		if n >= 2 {
			break
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reqs) < 2 {
		t.Fatalf("the queue polled %d times", len(reqs))
	}
	if reqs[0]["_auth"] != "Bearer poll-bearer-secret-123456" || reqs[0]["returnImmediately"] != true || reqs[0]["maxEvents"] != float64(25) {
		t.Errorf("first poll %v", reqs[0])
	}
	acks, _ := reqs[1]["ack"].([]any)
	errs, _ := reqs[1]["setErrs"].(map[string]any)
	bad, _ := errs["poll-bad"].(map[string]any)
	if len(acks) != 1 || acks[0] != "poll-good" || len(errs) != 1 || bad["err"] != "invalid_key" {
		t.Errorf("second poll: ack %v setErrs %v", acks, errs)
	}
	evs := e.events(e.pa, "")
	if len(evs) != 1 || evs[0].JTI != "poll-good" || evs[0].Via != "poll" || evs[0].Status != "actioned" || e.aws.Count("UpdatePolicy") != 1 {
		t.Errorf("events %+v", evs)
	}
}

func TestSSFPush_RateLimited(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := ssfServer(t, f, RateLimits{Anonymous: RateLimit{Every: time.Hour, Burst: 3}})
	h := srv.Handler()
	var codes []int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/public/t/tenant-a/ssf/00000000-0000-4000-8000-00000000dead/events", strings.NewReader("x"))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		req.RemoteAddr = "198.51.100.7:4000"
		rec := serve(h, req)
		codes = append(codes, rec.Code)
		if rec.Code == 429 && (rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "rate_limited")) {
			t.Errorf("429 without Retry-After: %v %s", rec.Header(), rec.Body)
		}
	}
	if fmt.Sprint(codes) != "[400 400 400 429 429 429]" {
		t.Errorf("status codes %v", codes)
	}
	other := httptest.NewRequest("POST", "/public/t/tenant-a/ssf/00000000-0000-4000-8000-00000000dead/events", strings.NewReader("x"))
	other.RemoteAddr = "198.51.100.8:4000"
	if rec := serve(h, other); rec.Code != 400 {
		t.Errorf("another address is not limited: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- management API

func TestSSFManagementAPI(t *testing.T) {
	e := newSSFEnv(t)
	secret := e.secret
	// list and detail never carry a secret, and say how the stream is reached
	for _, path := range []string{"/api/ssf/transmitters", "/api/ssf/transmitters/" + e.id} {
		rec := corrDo(e.h, e.pa, "GET", path, "")
		body := rec.Body.String()
		if rec.Code != 200 || strings.Contains(body, secret) || !strings.Contains(body, `"secret_set":true`) ||
			!strings.Contains(body, `"receiver_path":"`+e.path+`"`) || !strings.Contains(body, `"status":"enabled"`) {
			t.Errorf("GET %s: %d %s", path, rec.Code, body)
		}
	}
	// validation
	for name, tc := range map[string]struct{ body, want string }{
		"no body":            {``, "invalid_body"},
		"unknown field":      {`{"x":1}`, "invalid_body"},
		"empty":              {`{}`, "invalid_transmitter"},
		"bad delivery":       {fmt.Sprintf(`{"name":"x","issuer":%q,"audience":"a","jwks_url":"https://j/x","delivery":"carrier-pigeon","subject_system":"okta"}`, ssfIssuer), "delivery must be"},
		"duplicate name":     {fmt.Sprintf(`{"name":"Okta","issuer":%q,"audience":"a","jwks_url":"https://j/x","delivery":"push","subject_system":"okta"}`, ssfIssuer), "exists"},
		"private jwks":       {fmt.Sprintf(`{"name":"p","issuer":%q,"audience":"a","jwks":{"keys":[{"kty":"oct","k":"c2VjcmV0c2VjcmV0"}]},"delivery":"push","subject_system":"okta"}`, ssfIssuer), "jwks:"},
		"foreign connection": {fmt.Sprintf(`{"name":"c","issuer":%q,"audience":"a","jwks_url":"https://j/x","delivery":"push","connection_id":%q}`, ssfIssuer, e.f.B.Refs["connection"]), "no such connection"},
	} {
		rec := corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters", tc.body)
		if rec.Code != 422 || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want 422 %s", name, rec.Code, rec.Body, tc.want)
		}
	}
	// update: a blank secret keeps it, rotating returns a new one once
	upd := fmt.Sprintf(`{"name":"Okta","issuer":%q,"audience":%q,"delivery":"push","subject_system":"okta"%%s}`, ssfIssuer, ssfAudience)
	rec := corrDo(e.h, e.pa, "PUT", "/api/ssf/transmitters/"+e.id, fmt.Sprintf(upd, ""))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "receiver_secret") {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if rec := e.deliver(e.key.sign(t, sessionRevoked("j-keep", "bob", nil))); rec.Code != 202 {
		t.Errorf("the old secret after an update that left it alone: %d", rec.Code)
	}
	rec = corrDo(e.h, e.pa, "PUT", "/api/ssf/transmitters/"+e.id, fmt.Sprintf(upd, `,"rotate_secret":true`))
	var rot struct {
		Secret string `json:"receiver_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rot); err != nil || rec.Code != 200 || rot.Secret == "" || rot.Secret == secret {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}
	if rec := e.deliver(e.key.sign(t, sessionRevoked("j-old", "bob", nil))); rec.Code != 400 {
		t.Errorf("the old secret after a rotation: %d", rec.Code)
	}
	if rec := e.push(e.path, rot.Secret, "application/secevent+jwt", e.key.sign(t, sessionRevoked("j-new", "bob", nil))); rec.Code != 202 {
		t.Errorf("the new secret: %d %s", rec.Code, rec.Body)
	}
	// unknown ids
	const uuid = "00000000-0000-4000-8000-00000000dead"
	for _, tc := range []struct{ method, path string }{{"GET", "/api/ssf/transmitters/" + uuid}, {"PUT", "/api/ssf/transmitters/" + uuid},
		{"DELETE", "/api/ssf/transmitters/" + uuid}, {"POST", "/api/ssf/transmitters/" + uuid + "/verify"},
		{"GET", "/api/ssf/transmitters/not-an-id"}, {"DELETE", "/api/ssf/transmitters/not-an-id"}} {
		body := ""
		if tc.method == "PUT" {
			body = fmt.Sprintf(upd, "")
		}
		if rec := corrDo(e.h, e.pa, tc.method, tc.path, body); rec.Code != 404 {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
	if rec := corrDo(e.h, e.pa, "GET", "/api/ssf/events?transmitter_id=nope", ""); rec.Code != 422 {
		t.Errorf("bad transmitter_id: %d", rec.Code)
	}
	if rec := corrDo(e.h, e.pa, "GET", "/api/ssf/events?limit=0", ""); rec.Code != 422 {
		t.Errorf("bad limit: %d", rec.Code)
	}
	// delete
	rec = corrDo(e.h, e.pa, "DELETE", "/api/ssf/transmitters/"+e.id, "")
	if rec.Code != 200 || len(e.events(e.pa, "")) != 0 {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := e.deliver(e.key.sign(t, sessionRevoked("j-after", "bob", nil))); rec.Code != 400 || !strings.Contains(rec.Body.String(), "authentication_failed") {
		t.Errorf("a deleted stream: %d %s", rec.Code, rec.Body)
	}
	for _, a := range []string{"ssf.transmitter_created", "ssf.transmitter_updated", "ssf.transmitter_deleted"} {
		if len(e.audit(a)) == 0 {
			t.Errorf("no %s audit event", a)
		}
	}
	e.noTokensInLedger()
	for _, d := range e.audit("ssf.transmitter_updated") {
		if raw, _ := json.Marshal(d); strings.Contains(string(raw), rot.Secret) {
			t.Error("the rotated secret is in the ledger")
		}
	}
}

func TestSSFDiscoveryAndVerifyAPI(t *testing.T) {
	e := newSSFEnv(t)
	var base string
	var mu sync.Mutex
	var verifyBody map[string]any
	var verifyAuth string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/.well-known/ssf-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": base, "jwks_uri": base + "/jwks", "verification_endpoint": base + "/verify"})
		case "/jwks":
			_, _ = io.WriteString(w, e.key.jwks())
		case "/verify":
			_ = json.NewDecoder(r.Body).Decode(&verifyBody)
			verifyAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	base = idp.URL
	body := fmt.Sprintf(`{"name":"Discovered","issuer":%q,"audience":%q,"delivery":"push","subject_system":"okta","discover":true,"api_token":"mgmt-token-1234567890"}`, base, ssfAudience)
	rec := corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters", body)
	var out struct {
		Transmitter struct {
			ID              string
			JWKSURL         string `json:"jwks_url"`
			VerificationURL string `json:"verification_url"`
			ReceiverPath    string `json:"receiver_path"`
		}
		Secret string `json:"receiver_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 201 || out.Transmitter.JWKSURL != base+"/jwks" ||
		out.Transmitter.VerificationURL != base+"/verify" || strings.Contains(rec.Body.String(), "mgmt-token") {
		t.Fatalf("discovery: %d %s", rec.Code, rec.Body)
	}
	// the keys come from the discovered JWKS endpoint; the issuer is the idp's
	path := "/public/t/" + e.f.A.Slug + "/ssf/" + out.Transmitter.ID + "/events"
	set := e.key.sign(t, sessionRevoked("j-disc", "bob", func(c map[string]any) { c["iss"] = base }))
	if rec := e.push(path, out.Secret, "application/secevent+jwt", set); rec.Code != 202 {
		t.Errorf("delivery with discovered keys: %d %s", rec.Code, rec.Body)
	}
	// a metadata document of another issuer is refused
	bad := fmt.Sprintf(`{"name":"Other","issuer":"https://elsewhere.example","audience":"a","delivery":"push","subject_system":"okta","discover":true}`)
	if rec := corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters", bad); rec.Code != 422 {
		t.Errorf("an unreachable issuer: %d %s", rec.Code, rec.Body)
	}
	// verify: the state goes out with the management token, and comes back as an event
	rec = corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters/"+out.Transmitter.ID+"/verify", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"requested":true`) {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	mu.Lock()
	state, _ := verifyBody["state"].(string)
	auth := verifyAuth
	mu.Unlock()
	if state == "" || auth != "Bearer mgmt-token-1234567890" {
		t.Fatalf("verification request: state %q auth %q", state, auth)
	}
	ver := e.key.sign(t, sessionRevoked("j-ver", "bob", func(c map[string]any) {
		c["iss"] = base
		c["events"] = map[string]any{ssf.EventVerification: map[string]any{"state": state}}
	}))
	if rec := e.push(path, out.Secret, "application/secevent+jwt", ver); rec.Code != 202 {
		t.Fatalf("verification event: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(e.h, e.pa, "GET", "/api/ssf/transmitters/"+out.Transmitter.ID, "")
	if !strings.Contains(rec.Body.String(), `"verified_at":"`) || !strings.Contains(rec.Body.String(), `"verification_pending":false`) {
		t.Errorf("verified: %s", rec.Body)
	}
	evs := e.events(e.pa, "?transmitter_id="+out.Transmitter.ID)
	if len(evs) != 2 || evs[0].Event != "verification" || evs[0].Status != "ignored" {
		t.Errorf("events %+v", evs)
	}
	// the original transmitter has no verification endpoint
	if rec := corrDo(e.h, e.pa, "POST", "/api/ssf/transmitters/"+e.id+"/verify", ""); rec.Code != 422 || !strings.Contains(rec.Body.String(), "no verification endpoint") {
		t.Errorf("no endpoint: %d %s", rec.Code, rec.Body)
	}
}

// ---------------------------------------------------------------- RBAC and isolation

func TestSSFRBAC(t *testing.T) {
	e := newSSFEnv(t)
	viewer := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "vic@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	operator := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "op@a.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	stale := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "pa2@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	body := fmt.Sprintf(`{"name":"X","issuer":%q,"audience":"a","jwks_url":"https://j/x","delivery":"push","subject_system":"okta"}`, ssfIssuer)
	writes := []struct{ method, path, body string }{
		{"POST", "/api/ssf/transmitters", body}, {"PUT", "/api/ssf/transmitters/" + e.id, body},
		{"DELETE", "/api/ssf/transmitters/" + e.id, ""}, {"POST", "/api/ssf/transmitters/" + e.id + "/verify", ""},
	}
	for _, w := range writes {
		for name, l := range map[string]authtest.Login{"viewer": viewer, "operator": operator, "tenant admin": e.admin} {
			if rec := corrDo(e.h, l, w.method, w.path, w.body); rec.Code != 403 {
				t.Errorf("%s %s as %s: %d, want 403", w.method, w.path, name, rec.Code)
			}
		}
		if rec := corrDo(e.h, stale, w.method, w.path, w.body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s with a stale sign-in: %d %s", w.method, w.path, rec.Code, rec.Body)
		}
	}
	// reads: every signed-in role
	for name, l := range map[string]authtest.Login{"viewer": viewer, "operator": operator, "tenant admin": e.admin, "policy admin": e.pa} {
		for _, p := range []string{"/api/ssf/transmitters", "/api/ssf/transmitters/" + e.id, "/api/ssf/events"} {
			if rec := corrDo(e.h, l, "GET", p, ""); rec.Code != 200 {
				t.Errorf("GET %s as %s: %d", p, name, rec.Code)
			}
		}
	}
	// nothing was changed by the refusals
	if len(e.audit("ssf.transmitter_updated"))+len(e.audit("ssf.transmitter_deleted")) != 0 {
		t.Error("a refused call changed a transmitter")
	}
	// the public endpoint takes no session: a policy admin's cookie is no secret
	req := httptest.NewRequest("POST", e.path, strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	e.pa.Apply(req)
	if rec := serve(e.h, req); rec.Code != 400 || !strings.Contains(rec.Body.String(), "authentication_failed") {
		t.Errorf("a session instead of the secret: %d %s", rec.Code, rec.Body)
	}
}

// Tenant B reaches nothing of tenant A's streams, and A's id looks like a missing one.
func TestSSFAPI_CrossTenant(t *testing.T) {
	e := newSSFEnv(t)
	bPA := policyAdmin(t, e.f, e.f.B.ID, "pa@b.example")
	const uuid = "00000000-0000-4000-8000-00000000dead"
	upd := fmt.Sprintf(`{"name":"hijack","issuer":%q,"audience":"a","jwks_url":"https://j/x","delivery":"push","subject_system":"okta"}`, ssfIssuer)
	e.deliver(e.key.sign(t, sessionRevoked("j-b", "alice", nil))) // A has an event too
	var aBefore string
	_ = e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		x, _ := c.SSFTransmitter(e.id)
		raw, _ := json.Marshal(x)
		aBefore = string(raw)
		return nil
	})
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/ssf/transmitters/%s", ""}, {"PUT", "/api/ssf/transmitters/%s", upd}, {"DELETE", "/api/ssf/transmitters/%s", ""},
		{"POST", "/api/ssf/transmitters/%s/verify", ""},
	} {
		cross := corrDo(e.h, bPA, tc.method, fmt.Sprintf(tc.path, e.id), tc.body)
		missing := corrDo(e.h, bPA, tc.method, fmt.Sprintf(tc.path, uuid), tc.body)
		norm := func(s, id string) string { return strings.ReplaceAll(s, id, "<id>") }
		if cross.Code != 404 || cross.Code != missing.Code || norm(cross.Body.String(), e.id) != norm(missing.Body.String(), uuid) {
			t.Errorf("%s %s: A's id %d %s, missing %d %s", tc.method, tc.path, cross.Code, cross.Body, missing.Code, missing.Body)
		}
	}
	for _, p := range []string{"/api/ssf/transmitters", "/api/ssf/events", "/api/ssf/events?transmitter_id=" + e.id} {
		rec := corrDo(e.h, bPA, "GET", p, "")
		if rec.Code != 200 || strings.Contains(rec.Body.String(), e.id) || strings.Contains(rec.Body.String(), "Okta") ||
			strings.Contains(rec.Body.String(), "j-b") || strings.Contains(rec.Body.String(), "alice") {
			t.Errorf("GET %s as B: %d %s", p, rec.Code, rec.Body)
		}
	}
	// B creating a transmitter naming A's connection
	aConn := e.f.A.Refs["connection"]
	body := fmt.Sprintf(`{"name":"b","issuer":%q,"audience":"a","jwks_url":"https://j/x","delivery":"push","connection_id":%q}`, ssfIssuer, aConn)
	if rec := corrDo(e.h, bPA, "POST", "/api/ssf/transmitters", body); rec.Code != 422 || !strings.Contains(rec.Body.String(), "no such connection") {
		t.Errorf("B naming A's connection: %d %s", rec.Code, rec.Body)
	}
	// B's own stream does not accept A's secret, and A's slug does not reach B's stream
	rec := corrDo(e.h, bPA, "POST", "/api/ssf/transmitters", fmt.Sprintf(`{"name":"b","issuer":%q,"audience":%q,"jwks":%s,"delivery":"push","subject_system":"okta"}`,
		ssfIssuer, ssfAudience, e.key.jwks()))
	var bt struct {
		Transmitter struct{ ID string }
		Secret      string `json:"receiver_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bt); err != nil || rec.Code != 201 {
		t.Fatalf("B create: %d %s", rec.Code, rec.Body)
	}
	set := e.key.sign(t, sessionRevoked("j-bb", "alice", nil))
	bPath := "/public/t/" + e.f.B.Slug + "/ssf/" + bt.Transmitter.ID + "/events"
	if rec := e.push(bPath, e.secret, "application/secevent+jwt", set); rec.Code != 400 {
		t.Errorf("A's secret at B's stream: %d", rec.Code)
	}
	if rec := e.push("/public/t/"+e.f.A.Slug+"/ssf/"+bt.Transmitter.ID+"/events", bt.Secret, "application/secevent+jwt", set); rec.Code != 400 {
		t.Errorf("B's secret at A's slug: %d", rec.Code)
	}
	if rec := e.push(bPath, bt.Secret, "application/secevent+jwt", set); rec.Code != 202 {
		t.Errorf("B's own delivery: %d %s", rec.Code, rec.Body)
	}
	// B's event is B's: alice is unknown there as an okta account id "alice"? (B has the same fixture) it ran in B only
	var aEvents int
	_ = e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		evs, _ := c.SSFEvents("", 100)
		aEvents = len(evs)
		return nil
	})
	if aEvents != 1 {
		t.Errorf("tenant A has %d events, want its own 1", aEvents)
	}
	// A's transmitter is untouched
	var aAfter string
	_ = e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		x, _ := c.SSFTransmitter(e.id)
		raw, _ := json.Marshal(x)
		aAfter = string(raw)
		return nil
	})
	if aAfter != aBefore {
		t.Errorf("tenant A's transmitter changed:\n%s\n%s", aBefore, aAfter)
	}
}

// The generic isolation checks also see an event list.
func TestSSFAPI_ListsNeverLeak(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedSSFTransmitters(t, f)
	srv := isolationServer(t, f, f.B.ID)
	h := srv.Handler()
	for _, p := range []string{"/api/ssf/transmitters", "/api/ssf/transmitters/" + ids[f.B.Slug], "/api/ssf/events"} {
		rec := serveOnce(h, "GET", p, "")
		if rec.Code != 200 || leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), ids[f.A.Slug]) {
			t.Errorf("GET %s: %d %.300s", p, rec.Code, rec.Body)
		}
	}
	// positive control: as A the sentinel is visible
	if rec := serveOnce(isolationServer(t, f, f.A.ID).Handler(), "GET", "/api/ssf/transmitters", ""); !leaks(rec.Body.String()) {
		t.Error("tenant A's own transmitter does not carry the sentinel; the leak check would never fire")
	}
	if rec := serveOnce(h, "GET", "/api/ssf/transmitters/"+ids[f.A.Slug], ""); rec.Code != 404 {
		t.Errorf("A's transmitter as B: %d", rec.Code)
	}
}
