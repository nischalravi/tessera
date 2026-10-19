package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// rig is tenant A of the two-tenant fixture with an Okta push transmitter
// (inline test JWKS) and Alice linked to an Okta account (the transmitter's
// own system) and an Entra account with a kill-switch connection.
type rig struct {
	t     *testing.T
	f     *storetest.Fixture
	svc   *Service
	sg    *signer
	tr    *store.SSFTransmitter
	alice int64
	// aliceEmail is the username of Alice's Okta account.
	aliceEmail string
}

func httpClient(t testing.TB) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	clock := timeutil.Frozen(now)
	svc := &Service{HTTP: httpClient(t), Sealer: sealer, Clock: clock,
		Containment: &containment.Service{Sealer: sealer, Clock: clock}} // no HTTP: provider calls fail
	r := &rig{t: t, f: f, svc: svc, sg: newSigner(t, jose.ES256, "k1"), alice: f.A.IDs["alice"]}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{r.sg.jwk}})
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		var err error
		r.tr, _, err = svc.Create(c, TransmitterInput{Name: "Okta", Issuer: testIssuer, Audience: testAudience,
			JWKS: jwks, Delivery: "push", SubjectSystem: "okta"}, "admin", now)
		if err != nil {
			return err
		}
		// Alice's Entra account, with a connection and a credential
		connID := store.NewID()
		if err := c.InsertConnection(&store.Connection{ID: connID, Name: "Entra", ConnectorType: "entra", System: "entra",
			Role: "account_source", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := svc.Containment.PutCredential(c, connID, containment.CredentialInput{Token: "entra-token"}, "admin", now); err != nil {
			return err
		}
		accts, err := c.AccountsByExternalID("okta", "alice")
		if err != nil || len(accts) != 1 {
			return errors.New("the fixture has no Okta account for alice")
		}
		r.aliceEmail = accts[0].Username
		a := r.alice
		_, err = c.InsertAccount(&store.Account{System: "entra", ExternalID: "alice-entra-id", IdentityID: &a, Username: "alice@a.example",
			Kind: "human", Status: "active"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// deliver signs a SET and hands it to Receive.
func (r *rig) deliver(jti, event string, subject map[string]any) (*store.SSFEvent, error) {
	r.t.Helper()
	return r.deliverRaw(jti, r.setFor(jti, event, subject))
}

func (r *rig) setFor(jti, event string, subject map[string]any) string {
	r.t.Helper()
	payload := map[string]any{}
	if subject != nil {
		payload["subject"] = subject
	}
	return r.sg.sign(r.t, claimsFor(func(c map[string]any) {
		c["jti"] = jti
		c["events"] = map[string]any{event: payload}
	}))
}

func (r *rig) deliverRaw(expectJTI, raw string) (*store.SSFEvent, error) {
	r.t.Helper()
	return r.svc.Receive(context.Background(), r.f.DB, r.f.A.ID, r.tr, store.SSFPush, raw, "")
}

func issSub(sub string) map[string]any {
	return map[string]any{"format": "iss_sub", "iss": testIssuer, "sub": sub}
}

func (r *rig) read(fn func(*store.TenantTx) error) {
	r.t.Helper()
	if err := r.f.DB.ReadTenant(context.Background(), r.f.A.ID, fn); err != nil {
		r.t.Fatal(err)
	}
}

// actions counts the tenant's audit events by action.
func (r *rig) actions() map[string]int {
	r.t.Helper()
	out := map[string]int{}
	r.read(func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			out[e.Action]++
		}
		return err
	})
	return out
}

func (r *rig) auditDetail(action string) map[string]any {
	r.t.Helper()
	var out map[string]any
	r.read(func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: action})
		if err == nil && len(evs) > 0 {
			err = json.Unmarshal(evs[0].Detail, &out)
		}
		return err
	})
	return out
}

// server is a test transmitter endpoint.
func server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

var _ = ojson.Object{}
var _ = time.Second
