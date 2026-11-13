package transport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A bundle that carries the masked placeholder for a stored legacy attr_map or privileged_expected value keeps the
// stored value: the plan shows the connection unchanged and applying it leaves the config as it was (#975).
func TestImport_MaskedLegacyValuesAreKept(t *testing.T) {
	const cred = "https://u:pwSECRET@h.example"
	e := newEnv(t)
	legacy := `{"host":"dc01.corp.example","attr_map":[{"ldap":"` + cred + `","target":"x","scope":"account"}],` +
		`"privileged_expected":{"admins":["alice","` + cred + `"]}}`
	write(t, e.dst, func(tx *store.TenantTx) error {
		b, err := e.rd.Create(tx, readiness.CreateInput{Name: "Corp AD", ConnectorType: "demo-ad", System: "corp-ad",
			Config: json.RawMessage(`{"host":"dc01.corp.example"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		// a legacy row: Create and PATCH refuse a credentialed value now, so it is written as an old build did
		return tx.UpdateRevisionConfig(b.Rev.ID, legacy, "legacy-hash", "off", nil, t0)
	})
	mc := readiness.MaskText(cred)
	masked := `{"host":"dc01.corp.example","attr_map":[{"ldap":"` + mc + `","target":"x","scope":"account"}],` +
		`"privileged_expected":{"admins":["alice","` + mc + `"]}}`
	b := &Bundle{Version: 1, Connections: []Connection{{Name: "Corp AD", ConnectorType: "demo-ad", System: "corp-ad",
		Role: "authoritative", Config: json.RawMessage(masked), Credential: Credential{Kind: "none"}}}}
	p := planOf(t, e, b)
	if got := actions(p)["connections/Corp AD"]; got != Unchanged {
		t.Fatalf("plan %+v, want unchanged", p.Items)
	}
	err := e.dst.Write(context.Background(), func(tx *store.TenantTx) error {
		_, err := Apply(tx, e.rd, &Verified{Bundle: b, Hash: "h", Signer: &store.TrustedSigner{KID: "k", Label: "l"}}, Target{}, false, p.Digest, "admin", nil, t0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	write(t, e.dst, func(tx *store.TenantTx) error {
		live, err := liveConnections(tx, e.rd, t0)
		if err != nil {
			return err
		}
		if cfg := string(live["Corp AD"].cfg); !strings.Contains(cfg, "pwSECRET") || strings.Contains(cfg, "masked") {
			t.Errorf("stored config changed: %s", cfg)
		}
		return nil
	})

	// a real edit still shows as a change
	b.Connections[0].Config = json.RawMessage(`{"host":"dc01.corp.example","attr_map":[{"ldap":"mail","target":"x","scope":"account"}]}`)
	if got := actions(planOf(t, e, b))["connections/Corp AD"]; got == Unchanged {
		t.Errorf("an edited attr_map planned %s", got)
	}
}
