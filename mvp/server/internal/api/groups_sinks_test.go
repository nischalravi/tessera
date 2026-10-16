package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Group event sinks API (issue #61, GR-18).

// sinkClient is a client for tenant `tenant` of the fixture on a server that
// can seal credentials.
func sinkClient(t *testing.T, f *storetest.Fixture, tenant tenancy.ID) grpClient {
	t.Helper()
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{
		Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{"http://localhost:5173"},
		Env: "test", RateLimits: noRateLimits, Sealer: sealer,
	})
	return grpClient{client{t, asAdmin(t, srv, f.DB, tenant, storetest.Now).Handler()}}
}

const kafkaSink = `{"name":"siem","kind":"kafka","config":{"brokers":["k1.example.com:9093"],"topic":"tessera.groups","sasl":"scram-sha-256"},` +
	`"credentials":{"username":"svc","password":"Sup3r-S3cret-Pw"},"event_types":["membership."]}`

func TestGroupsSinksAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	c := sinkClient(t, f, f.B.ID)
	// the outbox has two events before the sink exists
	err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		for _, g := range []string{"g1", "g2"} {
			if err := events.Append(tx, events.New(events.GroupCreated, g, storetest.Now, store.CauseAPI)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := c.do("POST", "/api/groups/event-sinks", kafkaSink)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "Sup3r-S3cret-Pw") || strings.Contains(rec.Body.String(), "secret_enc") {
		t.Fatalf("the create response leaks the credentials: %s", rec.Body)
	}
	got := c.call("GET", "/api/groups/event-sinks", "", 200)
	items := got["items"].([]any)
	if len(items) != 1 || got["max_sinks"] != float64(20) || got["allow_insecure"] != false || len(got["kinds"].([]any)) != 4 {
		t.Fatalf("list = %v", got)
	}
	s := items[0].(map[string]any)
	id := s["id"].(string)
	if s["name"] != "siem" || s["kind"] != "kafka" || s["enabled"] != true || s["credentials_set"] != true || s["state"] != "idle" ||
		s["cursor"] != float64(2) || s["lag"] != float64(0) || s["dead_letters"] != float64(0) || s["created_by"] == "" ||
		s["event_types"].([]any)[0] != "membership." {
		t.Errorf("sink = %v", s)
	}
	if cfg := s["config"].(map[string]any); cfg["topic"] != "tessera.groups" || cfg["sasl"] != "scram-sha-256" {
		t.Errorf("config = %v", cfg)
	}
	// no response carries the password, whatever the route
	for _, path := range []string{"/api/groups/event-sinks", "/api/groups/event-sinks/" + id} {
		if body := c.do("GET", path, "").Body.String(); strings.Contains(body, "Sup3r-S3cret-Pw") || strings.Contains(body, "password") {
			t.Errorf("GET %s leaks the credentials: %s", path, body)
		}
	}

	// the same name again, and refusals
	c.call("POST", "/api/groups/event-sinks", kafkaSink, 409)
	for name, body := range map[string]string{
		"plain amqp":    `{"name":"mq","kind":"rabbitmq","config":{"url":"amqp://mq.example.com/","exchange":"x"},"credentials":{"username":"u","password":"p"}}`,
		"userinfo":      `{"name":"mq","kind":"rabbitmq","config":{"url":"amqps://u:p@mq.example.com/","exchange":"x"},"credentials":{"username":"u","password":"p"}}`,
		"no creds":      `{"name":"q","kind":"sqs","config":{"region":"eu-west-1","queue_url":"https://sqs.eu-west-1.amazonaws.com/1/q"}}`,
		"bad kind":      `{"name":"q","kind":"nats","config":{}}`,
		"bad filter":    `{"name":"q","kind":"kafka","config":{"brokers":["k:9093"],"topic":"t"},"event_types":["nope"]}`,
		"unknown field": `{"name":"q","kind":"kafka","config":{"brokers":["k:9093"],"topic":"t"},"password":"x"}`,
		"unknown cfg":   `{"name":"q","kind":"kafka","config":{"brokers":["k:9093"],"topic":"t","tls":false}}`,
	} {
		if rec := c.do("POST", "/api/groups/event-sinks", body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: create = %d, want 422: %s", name, rec.Code, rec.Body)
		}
	}
	if got := c.call("POST", "/api/groups/event-sinks", `{"name":"mq","kind":"rabbitmq","config":{"url":"amqp://mq.example.com/","exchange":"x"},"credentials":{"username":"u","password":"p"}}`, 422); got["error"] != "invalid_url" {
		t.Errorf("plain amqp error = %v", got)
	}

	// change it: rename and switch off; the credentials stay
	got = c.call("PATCH", "/api/groups/event-sinks/"+id, `{"name":"siem-2","enabled":false}`, 200)
	if got["name"] != "siem-2" || got["enabled"] != false || got["credentials_set"] != true {
		t.Errorf("patch = %v", got)
	}
	c.call("PATCH", "/api/groups/event-sinks/"+id, `{"config":{"brokers":["k1.example.com:9093"],"topic":"t","sasl":"plain"},"credentials":{"username":"u"}}`, 422)
	got = c.call("PATCH", "/api/groups/event-sinks/"+id, `{"config":{"brokers":["k2.example.com:9093"],"topic":"t2"},"credentials":{}}`, 200)
	if got["credentials_set"] != false || got["config"].(map[string]any)["topic"] != "t2" {
		t.Errorf("replaced config = %v", got)
	}

	// dead letters: list, redeliver, discard
	err = f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		for seq := int64(1); seq <= 2; seq++ {
			if err := tx.InsertGrpDeadLetter(&store.GrpDeadLetter{SinkID: id, Seq: seq, EventType: "group.created", ObjectID: "g",
				Payload: `{"id":"x"}`, Attempts: 8, LastError: "boom", CreatedAt: storetest.Now}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dl := c.call("GET", "/api/groups/event-sinks/"+id+"/dead-letters", "", 200)
	rows := dl["items"].([]any)
	if dl["status"] != "dead" || len(rows) != 2 || rows[0].(map[string]any)["payload"].(map[string]any)["id"] != "x" {
		t.Fatalf("dead letters = %v", dl)
	}
	if one := c.call("GET", "/api/groups/event-sinks", "", 200)["items"].([]any)[0].(map[string]any); one["dead_letters"] != float64(2) {
		t.Errorf("dead_letters = %v", one["dead_letters"])
	}
	c.call("GET", "/api/groups/event-sinks/"+id+"/dead-letters?status=weird", "", 422)
	if got := c.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/1/redeliver", "", 200); got["status"] != "requeued" {
		t.Errorf("redeliver = %v", got)
	}
	c.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/1/redeliver", "", 409) // no longer dead
	c.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/2/discard", "", 200)
	c.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/9/discard", "", 404)
	c.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/x/discard", "", 404)
	if all := c.call("GET", "/api/groups/event-sinks/"+id+"/dead-letters?status=all", "", 200); len(all["items"].([]any)) != 2 {
		t.Errorf("all dead letters = %v", all)
	}

	// every change is audited, without the credentials
	err = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		all, err := tx.AuditEvents(store.AuditFilter{Limit: 200})
		seen := map[string]bool{}
		for _, e := range all {
			seen[e.Action] = true
		}
		for _, a := range []string{"groups.sink.created", "groups.sink.updated", "groups.sink.redelivery_requested", "groups.sink.dead_letter_discarded"} {
			if !seen[a] {
				t.Errorf("no %s audit event", a)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	c.call("DELETE", "/api/groups/event-sinks/"+id, "", 200)
	c.call("GET", "/api/groups/event-sinks/"+id, "", 404)
	c.call("DELETE", "/api/groups/event-sinks/"+id, "", 404)
	c.call("GET", "/api/groups/event-sinks/not-a-uuid", "", 404)
}

func TestGroupsSinksCredentialsNeedSealing(t *testing.T) {
	f := storetest.TwoTenants(t)
	c := grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}} // no sealer
	if got := c.call("POST", "/api/groups/event-sinks", kafkaSink, 503); got["error"] != "sealing_unavailable" {
		t.Errorf("create without a sealer = %v", got)
	}
	// a sink without credentials needs none
	c.call("POST", "/api/groups/event-sinks", `{"name":"open","kind":"kafka","config":{"brokers":["k:9093"],"topic":"t"}}`, 201)
}

func TestGroupsSinksTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := sinkClient(t, f, f.A.ID), sinkClient(t, f, f.B.ID)
	id := a.call("POST", "/api/groups/event-sinks", kafkaSink, 201)["id"].(string)
	b.call("POST", "/api/groups/event-sinks", kafkaSink, 201) // the same name is free in another tenant

	if items := b.call("GET", "/api/groups/event-sinks", "", 200)["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] == id {
		t.Errorf("B's list = %v", items)
	}
	b.call("GET", "/api/groups/event-sinks/"+id, "", 404)
	b.call("PATCH", "/api/groups/event-sinks/"+id, `{"name":"mine"}`, 404)
	b.call("DELETE", "/api/groups/event-sinks/"+id, "", 404)
	b.call("GET", "/api/groups/event-sinks/"+id+"/dead-letters", "", 404)
	b.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/1/redeliver", "", 404)
	b.call("POST", "/api/groups/event-sinks/"+id+"/dead-letters/1/discard", "", 404)
	if got := a.call("GET", "/api/groups/event-sinks/"+id, "", 200); got["name"] != "siem" || got["enabled"] != true {
		t.Errorf("A's sink after B's attempts = %v", got)
	}
}

func TestGroupsSinksRoutesRequireTenantAdmin(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	id := "00000000-0000-4000-8000-000000000000"
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		for _, tc := range [][3]string{
			{"GET", "/api/groups/event-sinks", ""}, {"POST", "/api/groups/event-sinks", kafkaSink},
			{"GET", "/api/groups/event-sinks/" + id, ""}, {"PATCH", "/api/groups/event-sinks/" + id, `{"enabled":false}`},
			{"DELETE", "/api/groups/event-sinks/" + id, ""}, {"GET", "/api/groups/event-sinks/" + id + "/dead-letters", ""},
			{"POST", "/api/groups/event-sinks/" + id + "/dead-letters/1/redeliver", ""},
			{"POST", "/api/groups/event-sinks/" + id + "/dead-letters/1/discard", ""},
		} {
			if rec := serve(h, authed(l, tc[0], tc[1], tc[2])); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want 403", role, tc[0], tc[1], rec.Code)
			}
		}
	}
}
