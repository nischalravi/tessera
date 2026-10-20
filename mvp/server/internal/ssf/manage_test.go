package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (r *rig) inA(fn func(*store.TenantTx) error) error {
	return r.f.DB.InTenant(context.Background(), r.f.A.ID, fn)
}

func (r *rig) jwksJSON(extra ...*signer) json.RawMessage {
	keys := []jose.JSONWebKey{r.sg.jwk}
	for _, e := range extra {
		keys = append(keys, e.jwk)
	}
	raw, _ := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	return raw
}

func TestCreateValidation(t *testing.T) {
	r := newRig(t)
	good := func() TransmitterInput {
		return TransmitterInput{Name: "Entra", Issuer: "https://sts.windows.example/t1/", Audience: "tessera", JWKSURL: "https://x.example/jwks",
			Delivery: "push", SubjectSystem: "entra"}
	}
	aConn := ""
	r.read(func(c *store.TenantTx) error {
		cs, _ := c.Connections()
		for _, cn := range cs {
			if cn.System == "entra" {
				aConn = cn.ID
			}
		}
		return nil
	})
	for name, tc := range map[string]struct {
		mod  func(*TransmitterInput)
		want string
	}{
		"no name":              {func(i *TransmitterInput) { i.Name = " " }, "name is required"},
		"long name":            {func(i *TransmitterInput) { i.Name = strings.Repeat("n", 101) }, "name is required"},
		"no issuer":            {func(i *TransmitterInput) { i.Issuer = "" }, "issuer is required"},
		"issuer with a space":  {func(i *TransmitterInput) { i.Issuer = "a b" }, "issuer is required"},
		"no audience":          {func(i *TransmitterInput) { i.Audience = "" }, "audience is required"},
		"bad delivery":         {func(i *TransmitterInput) { i.Delivery = "webhook" }, "delivery must be"},
		"no keys":              {func(i *TransmitterInput) { i.JWKSURL = "" }, "jwks_url or jwks is required"},
		"jwks url scheme":      {func(i *TransmitterInput) { i.JWKSURL = "ftp://x" }, "jwks_url must be"},
		"jwks url with user":   {func(i *TransmitterInput) { i.JWKSURL = "https://u:p@x.example/jwks" }, "jwks_url must be"},
		"bad inline jwks":      {func(i *TransmitterInput) { i.JWKSURL = ""; i.JWKS = json.RawMessage(`{"keys":[]}`) }, "jwks:"},
		"bad status":           {func(i *TransmitterInput) { i.Status = "on" }, "status must be"},
		"short secret":         {func(i *TransmitterInput) { i.Secret = "short" }, "secret must be"},
		"secret with a space":  {func(i *TransmitterInput) { i.Secret = "aaaaaaaaaaaaaaaa bbbb" }, "secret must be"},
		"poll without url":     {func(i *TransmitterInput) { i.Delivery = "poll"; i.Secret = strings.Repeat("s", 20) }, "poll_url is required"},
		"poll without token":   {func(i *TransmitterInput) { i.Delivery = "poll"; i.PollURL = "https://t.example/poll" }, "secret (the bearer token"},
		"no subject system":    {func(i *TransmitterInput) { i.SubjectSystem = "" }, "subject_system is required"},
		"bad subject system":   {func(i *TransmitterInput) { i.SubjectSystem = "Okta!" }, "subject_system is required"},
		"unknown connection":   {func(i *TransmitterInput) { i.ConnectionID = "00000000-0000-4000-8000-00000000dead" }, "no such connection"},
		"another tenant's":     {func(i *TransmitterInput) { i.ConnectionID = r.f.B.Refs["connection"] }, "no such connection"},
		"system disagrees":     {func(i *TransmitterInput) { i.ConnectionID = aConn; i.SubjectSystem = "okta" }, "is not the system of the connection"},
		"duplicate name":       {func(i *TransmitterInput) { i.Name = "Okta" }, "exists"},
		"long verification":    {func(i *TransmitterInput) { i.VerificationURL = "https://x.example/" + strings.Repeat("a", 600) }, "verification_url must be"},
		"long api token":       {func(i *TransmitterInput) { i.APIToken = strings.Repeat("t", 9000) }, "api_token is too long"},
		"inline jwks too long": {func(i *TransmitterInput) { i.JWKSURL = ""; i.JWKS = json.RawMessage(strings.Repeat(" ", 70<<10)) }, "too large"},
	} {
		in := good()
		tc.mod(&in)
		err := r.inA(func(c *store.TenantTx) error {
			_, _, err := r.svc.Create(c, in, "admin", now)
			return err
		})
		var ce *ConfigError
		if !errors.As(err, &ce) || !strings.Contains(ce.Msg, tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// the connection implies the system
	in := good()
	in.SubjectSystem, in.ConnectionID = "", aConn
	var x *store.SSFTransmitter
	if err := r.inA(func(c *store.TenantTx) error {
		var err error
		x, _, err = r.svc.Create(c, in, "admin", now)
		return err
	}); err != nil || x.SubjectSystem != "entra" || x.ConnectionID == nil || *x.ConnectionID != aConn {
		t.Errorf("connection mapping: %+v %v", x, err)
	}
}

func TestSecretsAreSealedAndNeverAudited(t *testing.T) {
	r := newRig(t)
	var x *store.SSFTransmitter
	var generated string
	if err := r.inA(func(c *store.TenantTx) error {
		var err error
		x, generated, err = r.svc.Create(c, TransmitterInput{Name: "Push", Issuer: "https://p.example", Audience: "a", JWKSURL: "https://p.example/jwks",
			Delivery: "push", SubjectSystem: "okta", APIToken: "api-token-very-secret"}, "admin", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(generated) < 40 {
		t.Fatalf("a push stream without a secret gets a generated one: %q", generated)
	}
	r.read(func(c *store.TenantTx) error {
		got, _ := c.SSFTransmitter(x.ID)
		if strings.Contains(string(got.SecretEnc), generated) || strings.Contains(string(got.APITokenEnc), "api-token-very-secret") || len(got.SecretEnc) == 0 {
			t.Error("a secret is stored in the clear")
		}
		if s, err := r.svc.ReceiverSecret(c, got); err != nil || s != generated {
			t.Errorf("ReceiverSecret = %q, %v", s, err)
		}
		for name, aad := range map[string][]byte{
			"other tenant": seal.AAD(r.f.B.ID, "ssf_transmitters", "secret_enc", x.ID),
			"other row":    seal.AAD(r.f.A.ID, "ssf_transmitters", "secret_enc", r.tr.ID),
			"other column": seal.AAD(r.f.A.ID, "ssf_transmitters", "api_token_enc", x.ID),
		} {
			if _, err := r.svc.Sealer.Open(got.SecretEnc, aad); err == nil {
				t.Errorf("the secret opens under the AAD of %s", name)
			}
		}
		if _, err := r.svc.Sealer.Open(got.APITokenEnc, seal.AAD(r.f.A.ID, "ssf_transmitters", "api_token_enc", x.ID)); err != nil {
			t.Errorf("the api token does not open: %v", err)
		}
		v, _ := json.Marshal(ViewTransmitter(got, "tenant-a"))
		if strings.Contains(string(v), generated) || strings.Contains(string(v), "enc") && strings.Contains(string(v), "api-token") {
			t.Errorf("view leaks a secret: %s", v)
		}
		if !strings.Contains(string(v), `"receiver_path":"/public/t/tenant-a/ssf/`+x.ID+`/events"`) ||
			!strings.Contains(string(v), `"secret_set":true`) || !strings.Contains(string(v), `"api_token_set":true`) {
			t.Errorf("view %s", v)
		}
		evs, _ := c.AuditEvents(store.AuditFilter{IncludeHTTP: true})
		for _, e := range evs {
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), generated) || strings.Contains(string(raw), "api-token-very-secret") {
				t.Errorf("audit event %s carries a secret", e.Action)
			}
		}
		return nil
	})
	if r.actions()["ssf.transmitter_created"] != 2 { // the rig's and this one
		t.Errorf("audit %v", r.actions())
	}
}

func TestUpdate(t *testing.T) {
	r := newRig(t)
	other := newSigner(t, "ES256", "k9")
	update := func(id string, in TransmitterInput) (*store.SSFTransmitter, string, error) {
		var x *store.SSFTransmitter
		var gen string
		err := r.inA(func(c *store.TenantTx) error {
			var err error
			x, gen, err = r.svc.Update(c, id, in, "admin", now)
			return err
		})
		return x, gen, err
	}
	base := TransmitterInput{Name: "Okta", Issuer: testIssuer, Audience: testAudience, Delivery: "push", SubjectSystem: "okta"}
	secretOf := func(id string) string {
		var s string
		r.read(func(c *store.TenantTx) error {
			x, _ := c.SSFTransmitter(id)
			s, _ = r.svc.ReceiverSecret(c, x)
			return nil
		})
		return s
	}
	before := secretOf(r.tr.ID)
	// a blank secret and blank keys keep what is there; the status changes
	in := base
	in.Status = "paused"
	x, gen, err := update(r.tr.ID, in)
	if err != nil || gen != "" || x.Status != "paused" || x.JWKSInline == "" || secretOf(r.tr.ID) != before {
		t.Fatalf("update: %+v %q %v", x, gen, err)
	}
	// rotate
	in.RotateSecret = true
	_, gen, err = update(r.tr.ID, in)
	if err != nil || gen == "" || gen == before || secretOf(r.tr.ID) != gen {
		t.Fatalf("rotate: %q %v", gen, err)
	}
	// new inline keys replace the old ones
	in.JWKS = r.jwksJSON(other)
	if x, _, err = update(r.tr.ID, in); err != nil || !strings.Contains(x.JWKSInline, "k9") {
		t.Errorf("new keys: %v %v", x, err)
	}
	// switching to poll drops the push secret and demands a token
	in = base
	in.Delivery, in.PollURL = "poll", "https://t.example/poll"
	if _, _, err = update(r.tr.ID, in); err == nil || !strings.Contains(err.Error(), "bearer token") {
		t.Errorf("poll without a token: %v", err)
	}
	in.Secret = "poll-bearer-token-123456"
	if x, _, err = update(r.tr.ID, in); err != nil || x.Delivery != "poll" || secretOf(r.tr.ID) != "poll-bearer-token-123456" {
		t.Errorf("poll: %+v %v", x, err)
	}
	// and back to push: a fresh secret, not the poll token
	in = base
	if x, gen, err = update(r.tr.ID, in); err != nil || gen == "" || gen == "poll-bearer-token-123456" || x.PollURL != "" {
		t.Errorf("push again: %+v %q %v", x, gen, err)
	}
	// unknown id, another tenant's id
	if _, _, err := update("00000000-0000-4000-8000-00000000dead", base); !errors.Is(err, ErrNoSuchTransmitter) {
		t.Errorf("unknown: %v", err)
	}
	var bID string
	if err := r.f.DB.InTenant(context.Background(), r.f.B.ID, func(c *store.TenantTx) error {
		b, _, err := r.svc.Create(c, TransmitterInput{Name: "B", Issuer: "https://b", Audience: "a", JWKSURL: "https://b/jwks", Delivery: "push", SubjectSystem: "okta"}, "b", now)
		if b != nil {
			bID = b.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := update(bID, base); !errors.Is(err, ErrNoSuchTransmitter) {
		t.Errorf("another tenant's transmitter: %v", err)
	}
	if err := r.inA(func(c *store.TenantTx) error { return r.svc.Delete(c, bID, "admin", now) }); !errors.Is(err, ErrNoSuchTransmitter) {
		t.Errorf("delete another tenant's: %v", err)
	}
	if got := r.actions(); got["ssf.transmitter_updated"] != 5 {
		t.Errorf("audit %v", got)
	}
}

func TestDelete(t *testing.T) {
	r := newRig(t)
	if _, err := r.deliver("jti-d", EventSessionRevoked, issSub("bob")); err != nil {
		t.Fatal(err)
	}
	if err := r.inA(func(c *store.TenantTx) error { return r.svc.Delete(c, r.tr.ID, "admin", now) }); err != nil {
		t.Fatal(err)
	}
	r.read(func(c *store.TenantTx) error {
		if xs, _ := c.SSFTransmitters(); len(xs) != 0 {
			t.Errorf("transmitters %v", xs)
		}
		if evs, _ := c.SSFEvents("", 10); len(evs) != 0 {
			t.Errorf("events %v", evs)
		}
		return nil
	})
	if r.actions()["ssf.transmitter_deleted"] != 1 {
		t.Errorf("audit %v", r.actions())
	}
	if err := r.inA(func(c *store.TenantTx) error { return r.svc.Delete(c, r.tr.ID, "admin", now) }); !errors.Is(err, ErrNoSuchTransmitter) {
		t.Errorf("second delete: %v", err)
	}
}

func TestWithoutASealer(t *testing.T) {
	r := newRig(t)
	svc := &Service{Clock: r.svc.Clock}
	err := r.inA(func(c *store.TenantTx) error {
		_, _, err := svc.Create(c, TransmitterInput{Name: "x", Issuer: "https://x", Audience: "a", JWKSURL: "https://x/j", Delivery: "push", SubjectSystem: "okta"}, "a", now)
		return err
	})
	var ce *ConfigError
	if !errors.As(err, &ce) || !strings.Contains(ce.Msg, "sealing is not configured") {
		t.Errorf("create without a sealer: %v", err)
	}
}

func TestDiscoveryAndVerification(t *testing.T) {
	r := newRig(t)
	var srvURL string
	var gotBearer, gotState string
	verifyStatus := http.StatusNoContent
	srv := server(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/.well-known/ssf-configuration/tenant1":
			_ = json.NewEncoder(w).Encode(Metadata{Issuer: srvURL + "/tenant1", JWKSURI: srvURL + "/jwks",
				VerificationEndpoint: srvURL + "/verify", DeliveryMethods: []string{"urn:ietf:rfc:8935"}})
		case "/.well-known/ssf-configuration/other":
			_ = json.NewEncoder(w).Encode(Metadata{Issuer: "https://someone-else.example", JWKSURI: srvURL + "/jwks"})
		case "/verify":
			var b struct{ State string }
			_ = json.NewDecoder(req.Body).Decode(&b)
			gotBearer, gotState = req.Header.Get("Authorization"), b.State
			w.WriteHeader(verifyStatus)
		default:
			http.NotFound(w, req)
		}
	})
	srvURL = srv.URL
	if u, err := DiscoveryURL("https://idp.example/tenant1/"); err != nil || u != "https://idp.example/.well-known/ssf-configuration/tenant1" {
		t.Errorf("DiscoveryURL = %q %v", u, err)
	}
	if u, _ := DiscoveryURL("https://idp.example"); u != "https://idp.example/.well-known/ssf-configuration" {
		t.Errorf("DiscoveryURL without a path = %q", u)
	}
	if _, err := DiscoveryURL("not a url"); err == nil {
		t.Error("a non-URL issuer")
	}
	m, err := r.svc.Discover(context.Background(), srv.URL+"/tenant1")
	if err != nil || m.JWKSURI != srv.URL+"/jwks" || m.VerificationEndpoint != srv.URL+"/verify" {
		t.Fatalf("Discover = %+v, %v", m, err)
	}
	in := TransmitterInput{}
	ApplyDiscovery(&in, m)
	if in.JWKSURL != m.JWKSURI || in.VerificationURL != m.VerificationEndpoint {
		t.Errorf("ApplyDiscovery: %+v", in)
	}
	in = TransmitterInput{JWKSURL: "https://mine/jwks", VerificationURL: "https://mine/verify"}
	ApplyDiscovery(&in, m)
	if in.JWKSURL != "https://mine/jwks" || in.VerificationURL != "https://mine/verify" {
		t.Errorf("discovery must not overwrite: %+v", in)
	}
	for name, issuer := range map[string]string{"issuer mismatch": srv.URL + "/other", "no document": srv.URL + "/missing"} {
		if _, err := r.svc.Discover(context.Background(), issuer); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// verification: no endpoint, then a request, then the event that carries the state back
	if err := r.svc.RequestVerification(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID, "admin"); !errors.Is(err, ErrNoVerification) {
		t.Errorf("no endpoint: %v", err)
	}
	if err := r.svc.RequestVerification(context.Background(), r.f.DB, r.f.A.ID, "00000000-0000-4000-8000-00000000dead", "admin"); !errors.Is(err, ErrNoSuchTransmitter) {
		t.Errorf("unknown transmitter: %v", err)
	}
	if err := r.inA(func(c *store.TenantTx) error {
		_, _, err := r.svc.Update(c, r.tr.ID, TransmitterInput{Name: "Okta", Issuer: testIssuer, Audience: testAudience, Delivery: "push",
			SubjectSystem: "okta", VerificationURL: srv.URL + "/verify", APIToken: "mgmt-token-abcdef"}, "admin", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	verifyStatus = http.StatusInternalServerError
	if err := r.svc.RequestVerification(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID, "admin"); err == nil || !strings.Contains(err.Error(), "answered 500") {
		t.Errorf("a failing endpoint: %v", err)
	}
	r.read(func(c *store.TenantTx) error {
		if x, _ := c.SSFTransmitter(r.tr.ID); !strings.Contains(x.LastError, "verification request failed") || x.VerificationState != "" {
			t.Errorf("after a failed request: %+v", x)
		}
		return nil
	})
	verifyStatus = http.StatusNoContent
	if err := r.svc.RequestVerification(context.Background(), r.f.DB, r.f.A.ID, r.tr.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if gotBearer != "Bearer mgmt-token-abcdef" || len(gotState) < 20 {
		t.Errorf("verification request: bearer %q state %q", gotBearer, gotState)
	}
	r.read(func(c *store.TenantTx) error {
		r.tr, _ = c.SSFTransmitter(r.tr.ID)
		return nil
	})
	if r.tr.VerificationState != gotState || r.tr.VerificationRequestedAt == nil {
		t.Fatalf("state %q, want %q", r.tr.VerificationState, gotState)
	}
	raw := r.sg.sign(t, claimsFor(func(c map[string]any) {
		c["jti"] = "jti-verify"
		c["events"] = map[string]any{EventVerification: map[string]any{"state": gotState}}
	}))
	if _, err := r.deliverRaw("", raw); err != nil {
		t.Fatal(err)
	}
	r.read(func(c *store.TenantTx) error {
		x, _ := c.SSFTransmitter(r.tr.ID)
		if x.VerifiedAt == nil || x.VerificationState != "" {
			t.Errorf("verified: %+v", x)
		}
		return nil
	})
	if got := r.actions(); got["ssf.verification_requested"] != 1 || got["ssf.verification_received"] != 1 {
		t.Errorf("audit %v", got)
	}
}
