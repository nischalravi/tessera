package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen/fakerest"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func restConfig(base string) string {
	return `{"rest":{"base_url":"` + base + `","auth":{"type":"bearer"},
	  "users":{"path":"/offset/users","fields":{"id":"$.id","username":"$.login","email":"$.email","status":"$.state"},
	           "pagination":{"style":"offset","offset_param":"offset","size_param":"limit","page_size":10}}},
	  "technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"}`
}

func readyREST(t *testing.T, s *Service, st Scope, cfg string) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Acme REST", ConnectorType: "rest_generic", System: "acme", Config: json.RawMessage(cfg)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/acme"}, "admin", t0); err != nil {
			return err
		}
		if _, err := s.Attest(c, id, "base.owner", "both owners agreed in CHG-2001", "admin", t0); err != nil {
			return err
		}
		_, err = s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	return id
}

// A real rest_generic connection has no simulated results: without a client
// every live check errors; with the fake REST system the connectivity, auth,
// mapping and rate-limit checks run against it and pass.
func TestValidate_RESTLive(t *testing.T) {
	f := fakerest.NewTLS(25)
	defer f.Close()
	s, st := newSvc(t), newStore(t)
	id := readyREST(t, s, st, restConfig(f.URL))

	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(v, "rest.endpoint", "endpoint_reachable"); v.Simulated || r == nil || r.Status != "error" || r.Simulated {
		t.Fatalf("without a client: %+v", r)
	}

	s.Runner.REST = RESTLiveOptions{Client: f.Client(), Env: "dev",
		Secret: func(*Bundle) (string, error) { return fakerest.Bearer, nil }}
	v, err = s.Validate(context.Background(), st, id, "admin", clockAt(t0.Add(2*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("live run labelled simulated")
	}
	for _, c := range [][2]string{{"rest.endpoint", "endpoint_reachable"}, {"rest.auth", "auth_ok"},
		{"rest.users.mapped", "mapping_applied"}, {"rest.ratelimit", "rate_headroom"}} {
		r := resultFor(v, c[0], c[1])
		if r == nil || r.Status != "pass" || r.Simulated {
			t.Errorf("%s: %+v", c[1], r)
		}
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), fakerest.Bearer) {
		t.Error("the credential is in the run view")
	}

	// a wrong credential fails the auth check and the mapping check (nothing could be read)
	s.Runner.REST.Secret = func(*Bundle) (string, error) { return "wrong-token-value", nil }
	v, err = s.Validate(context.Background(), st, id, "admin", clockAt(t0.Add(4*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(v, "rest.auth", "auth_ok"); r == nil || r.Status != "fail" {
		t.Errorf("auth with a wrong credential: %+v", r)
	}

	// Demo connectors keep their simulated prober.
	if _, ok, _ := s.Runner.REST.prober(&Bundle{Conn: &store.Connection{ConnectorType: "demo-ad"}}, t0); ok {
		t.Error("a demo connection got the real REST prober")
	}
}

// The mapping check fails when the mapping reads nothing, and says why.
func TestValidate_RESTMappingFails(t *testing.T) {
	f := fakerest.NewTLS(5)
	defer f.Close()
	s, st := newSvc(t), newStore(t)
	cfg := strings.Replace(restConfig(f.URL), `"$.id"`, `"$.nope"`, 1)
	id := readyREST(t, s, st, cfg)
	s.Runner.REST = RESTLiveOptions{Client: f.Client(), Env: "dev", Secret: func(*Bundle) (string, error) { return fakerest.Bearer, nil }}
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	r := resultFor(v, "rest.users.mapped", "mapping_applied")
	if r == nil || r.Status != "fail" || !strings.Contains(r.Message, "no record the mapping could read") {
		t.Errorf("mapping check: %+v", r)
	}
}

func TestValidate_RESTConfigFields(t *testing.T) {
	reg := template.MustDefault()
	tmpl, _ := reg.Get("rest_generic")
	cfg, err := DecodeConfig([]byte(restConfig("https://api.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	cfg.CorrelationKey = "id"
	if errs := Validate(cfg, tmpl); len(errs) != 0 {
		t.Fatalf("a good config: %v", errs)
	}
	if errs := Validate(ConnConfig{CorrelationKey: "id"}, tmpl); len(errs) != 1 || errs[0].Field != "rest" {
		t.Errorf("no spec: %v", errs)
	}
	bad, err := DecodeConfig([]byte(`{"rest":{"base_url":"ftp://x","auth":{"type":"basic"},"users":{"path":"u","fields":{}}},"correlation_key":"id"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range Validate(bad, tmpl) {
		got[e.Field] = true
	}
	for _, want := range []string{"rest.base_url", "rest.auth.username", "rest.users.path", "rest.users.fields.id"} {
		if !got[want] {
			t.Errorf("no error on %s: %v", want, got)
		}
	}
	// strict decoding: a secret or an unknown key in the spec is refused
	for _, raw := range []string{`{"rest":{"base_url":"https://a.example.com","auth":{"type":"basic","username":"u","password":"p"}}}`,
		`{"rest":{"base_url":"https://a.example.com","oops":1}}`} {
		if _, err := DecodeConfig([]byte(raw)); err == nil {
			t.Errorf("decoded %s", raw)
		}
	}
	// the spec may be given as a YAML string
	y, err := DecodeConfig([]byte(`{"rest":"base_url: https://a.example.com\nauth: {type: bearer}\nusers:\n  path: /u\n  fields: {id: $.id, username: $.u}\n"}`))
	if err != nil || y.Rest == nil || y.Rest.Users.Path != "/u" {
		t.Errorf("yaml spec: %+v %v", y.Rest, err)
	}
}

// Saving a config applies the environment's URL policy: plain http is refused
// outside dev, and the errors say which field.
func TestPatchConfig_RESTEnvironmentPolicy(t *testing.T) {
	f := fakerest.New(1) // plain http on loopback
	defer f.Close()
	st := newStore(t)
	dev := NewService(template.MustDefault(), "dev")
	id := readyREST(t, dev, st, restConfig("https://api.example.com"))
	patch := `{"rest":{"base_url":"` + f.URL + `","auth":{"type":"bearer"},"users":{"path":"/u","fields":{"id":"$.id","username":"$.u"}}}}`
	for env, wantErr := range map[string]bool{"dev": false, "prod": true} {
		s := NewService(template.MustDefault(), env)
		err := st.Write(context.Background(), func(c *store.TenantTx) error {
			_, err := s.PatchConfig(c, id, []byte(patch), "admin", t0)
			return err
		})
		if (err != nil) != wantErr {
			t.Fatalf("env %s: err = %v", env, err)
		}
		if wantErr {
			var re *Error
			if !errors.As(err, &re) || len(re.Fields) == 0 || re.Fields[0].Field != "rest.base_url" {
				t.Errorf("env %s: %v", env, err)
			}
		}
	}
}
