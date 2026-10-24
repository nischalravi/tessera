package wire_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam/pamfake"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// An end-to-end run of a governed connection against the vendor's fake: the
// same Service the API uses creates a CyberArk connection with a sealed
// credential, validates it (the real prober over the connector's client), dry-runs
// it (the real connector, staged and reconciled, the live graph untouched) and
// opens its connector for the sync from the live revision.
func TestEndToEnd_CyberArkConnection(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, store.TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var tn store.Tenant
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		var err error
		tn, err = s.CreateTenant(store.Tenant{Slug: "larkspur", Name: "Larkspur Labs"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	st := readiness.Scope{DB: db, Tenant: tn.ID}

	// the vault: a TLS fake the client reaches whatever host name the connection names
	fk := pamfake.New("cyberark", pamUser, pamSecret)
	fk.Set(pamSafe("cyberark", false))
	srv, _ := serve(t, fk)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := srv.Client()
	hc.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}

	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	svc := readiness.NewService(template.MustDefault(), "dev")
	svc.Runner.Live.Sealer = sealer
	svc.Runner.Gov = wire.Options(hc, connsynctest.Runtime, "", false)
	clock := func() time.Time { return t0 }

	var id string
	if err := st.Write(ctx, func(c *store.TenantTx) error {
		b, err := svc.Create(c, readiness.CreateInput{Name: "CyberArk production", ConnectorType: "cyberark",
			Config: json.RawMessage(`{"base_url":"https://example.com","settings":{"username":"` + pamUser + `"},` +
				`"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := svc.SetCredential(c, id, readiness.CredentialInput{Secret: pamSecret}, "admin", t0); err != nil {
			return err
		}
		for _, it := range b.Eval.Items {
			if it.Applicable && it.HasKind(template.Attestation) {
				if _, err := svc.Attest(c, id, it.ID, "confirmed with the vault owner", "admin", t0); err != nil {
					return err
				}
			}
		}
		_, err = svc.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	v, err := svc.Validate(ctx, st, id, "admin", clock)
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("a real connection's validation is labelled simulated")
	}
	for _, r := range v.Results {
		switch r.ItemID {
		case "pam.endpoint", "pam.auth", "pam.read", "pam.rights.readonly", "base.cred.sealed":
			if r.Status != "pass" || r.Simulated {
				t.Errorf("%s (%s): %s %s", r.ItemID, r.CheckID, r.Status, r.Message)
			}
		}
	}
	if raw, _ := json.Marshal(v); strings.Contains(string(raw), pamSecret) {
		t.Error("the vault password is in the run view")
	}
	if _, _, writes := fk.Counts(); writes != 0 {
		t.Errorf("validation wrote %d times to the vault", writes)
	}

	// the dry run discovers through the real connector and stages; the live graph is untouched
	stage := func(c *store.TenantTx, runID, system string, res *connectors.DiscoveryResult) error {
		_, err := ingest.Stage(c, runID, system, res)
		return err
	}
	var live store.SystemCounts
	if err := st.Read(ctx, func(c *store.TenantTx) (err error) { live, err = c.CountSystem("cyberark"); return err }); err != nil {
		t.Fatal(err)
	}
	// the dry run needs a validated revision: settle the recommended items the vault cannot answer
	if err := st.Write(ctx, func(c *store.TenantTx) error {
		b, err := svc.Current(c, id, t0)
		if err != nil {
			return err
		}
		for _, bl := range b.Gate(store.StateValidated, t0).Blocking {
			if bl.Level == "recommended" {
				if _, err := svc.Skip(c, id, bl.Item, "the vault reports no value for this", nil, "admin", t0); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, st, id, "admin", clock); err != nil {
		t.Fatal(err)
	}
	dr, err := svc.DryRun(ctx, st, id, "admin", clock, stage)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dr.Simulated {
		t.Error("a real connection's dry run is labelled simulated")
	}
	var after store.SystemCounts
	if err := st.Read(ctx, func(c *store.TenantTx) (err error) { after, err = c.CountSystem("cyberark"); return err }); err != nil {
		t.Fatal(err)
	}
	if after != live {
		t.Errorf("the dry run changed the live graph: %+v -> %+v", live, after)
	}
	var staged []*store.StagedAccount
	if err := st.Read(ctx, func(c *store.TenantTx) (err error) { staged, err = c.StagedAccounts(dr.ID); return err }); err != nil {
		t.Fatal(err)
	}
	if len(staged) == 0 {
		t.Error("nothing was staged by the real connector")
	}

	// The dry run's findings are real: the vault's members are not people Tessera knows yet,
	// so the correlation gate holds activation until they are (an HR id or an e-mail user name).
	if g := activationGate(t, ctx, st, svc, id); !strings.Contains(g, "base.correlation.rule") {
		t.Errorf("activation gate = %s; want the correlation rule to hold it", g)
	}

	// The sync reads the vault through the connector built from the connection (the worker's
	// and the on-demand sync do this for a live connection) into the graph, additively.
	n := governed.Net{RT: connsynctest.Runtime, HC: hc, Now: clock}
	cn, err := wire.Connector(governed.Params{Type: governed.CyberArk, BaseURL: "https://example.com",
		Settings: map[string]string{"username": pamUser}, Secret: pamSecret}, n)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Write(ctx, func(c *store.TenantTx) error {
		_, err := worker.RunSync(ctx, c, t0, []connectors.Connector{cn}, false, "test")
		return err
	}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := st.Read(ctx, func(c *store.TenantTx) (err error) { live, err = c.CountSystem("cyberark"); return err }); err != nil {
		t.Fatal(err)
	}
	if live.Accounts == 0 || live.Groups == 0 || live.Resources == 0 {
		t.Errorf("the sync read nothing into the graph: %+v", live)
	}
	if _, _, writes := fk.Counts(); writes != 0 {
		t.Errorf("reading the vault wrote %d times", writes)
	}
}

// activationGate renders the blockers of the activation gate of a connection.
func activationGate(t *testing.T, ctx context.Context, st readiness.Scope, svc *readiness.Service, id string) string {
	t.Helper()
	var out []string
	if err := st.Read(ctx, func(c *store.TenantTx) error {
		b, err := svc.Current(c, id, t0)
		if err != nil {
			return err
		}
		for _, bl := range b.Gate(store.StateActive, t0).Blocking {
			out = append(out, bl.Item+" "+bl.Finding)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, ", ")
}
