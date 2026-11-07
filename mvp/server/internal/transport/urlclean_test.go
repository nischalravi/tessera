package transport

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestCleanString(t *testing.T) {
	for _, c := range []struct {
		name, in, out string
		verdict       cleanVerdict
	}{
		{"plain text", "dc01.corp.example", "dc01.corp.example", verdictKeep},
		{"email", "ingrid@corp.example", "ingrid@corp.example", verdictKeep},
		{"clean url", "https://ok.example/path", "https://ok.example/path", verdictKeep},
		{"userinfo and query", "https://u:pw@api.example:8443/v1?token=abc#f", "https://api.example:8443/v1", verdictCleaned},
		{"query only", "https://x.example/a?k=v", "https://x.example/a", verdictCleaned},
		{"dsn url", "postgres://app:pw@db.example/tessera?sslmode=disable", "postgres://db.example/tessera", verdictCleaned},
		{"unparseable url", "https://u:pw@exa mple.example/%zz?token=1", "", verdictExcluded},
		{"bad port", "https://u:pw@host:notaport/x", "", verdictExcluded},
		{"jdbc", "jdbc:postgresql://db.example/app?user=a&password=b", "", verdictExcluded},
		{"jdbc no creds", "jdbc:mysql://db.example/app", "", verdictExcluded},
		{"odbc", "Driver={ODBC Driver 18};Server=db;Uid=a;Pwd=b", "", verdictExcluded},
		{"odbc scheme", "odbc:DSN=prod", "", verdictExcluded},
		{"embedded url", "see https://u:pw@api.example/v1 for details", "", verdictExcluded},
		{"embedded clean url", "use https://api.example/v1 here", "", verdictExcluded},
		{"keyword dsn", "host=db user=app password=hunter2 dbname=x", "", verdictExcluded},
		{"password pair", "password=hunter2", "", verdictExcluded},
		{"token query without scheme", "api.example/v1?token=abc", "", verdictExcluded},
		{"protocol relative", "//u:pw@api.example/v1", "", verdictExcluded},
		{"bearer", "Authorization: Bearer abcdef0123456789", "", verdictExcluded},
		{"path param", "https://api.example/v1;token=abc", "", verdictExcluded},
		{"ldap filter", "(&(objectClass=user)(uid=*)(cn=host))", "(&(objectClass=user)(uid=*)(cn=host))", verdictKeep},
		{"opaque", "https:opaque", "https:opaque", verdictKeep},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, v := cleanString(c.in)
			if v != c.verdict || got != c.out {
				t.Errorf("cleanString(%q) = %q, %d; want %q, %d", c.in, got, v, c.out, c.verdict)
			}
		})
	}
}

func TestCleanConfig(t *testing.T) {
	in := json.RawMessage(`{"host":"dc01","base_url":"https://u:pw@api.example:8443/v1?token=abc#f","list":["https://x.example/a?k=v","plain"],` +
		`"ok":"https://ok.example/path","user_filter":"jdbc:postgresql://db/app?password=x","nested":{"a":"text with http://h.example/x inside"},` +
		`"cmd":"run --password=hunter2","bind_password":"hunter2","secret_ref":"vault:kv/x"}`)
	out, cleaned, left := cleanConfig(in)
	if !cleaned || strings.Join(left, ",") != "bind_password,cmd,nested,user_filter" {
		t.Fatalf("cleaned=%v left=%v out=%s", cleaned, left, out)
	}
	for _, leak := range []string{"pw", "token", "k=v", "#f", "jdbc", "hunter2", "password=", "h.example"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("%q left in %s", leak, out)
		}
	}
	for _, want := range []string{"https://api.example:8443/v1", "https://ok.example/path", "secret_ref", "dc01"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("%q lost from %s", want, out)
		}
	}
	if _, cleaned, left := cleanConfig(json.RawMessage(`{"host":"dc01"}`)); cleaned || len(left) > 0 {
		t.Error("clean config reported changed")
	}
	if _, _, left := cleanConfig(json.RawMessage(`[1]`)); len(left) != 1 {
		t.Error("a config that is not an object must fail closed")
	}
}

func TestOverlayExportable(t *testing.T) {
	for body, want := range map[string]bool{
		`{"raise_levels":{"ad.svc.no_interactive":"required"}}`: true,
		"note: nothing to see":                true,
		"docs at https://docs.example/guide":  true,
		`{"hook":"https://u:pw@h.example/x"}`: false,
		`{"dsn":"jdbc:mysql://db/app"}`:       false,
		`{"bind_password":"x"}`:               false,
		"hook: https://h.example/x?token=abc": false,
		"password: hunter2":                   false,
		"dsn=host=db password=x":              false,
	} {
		if got := overlayExportable(body); got != want {
			t.Errorf("overlayExportable(%q) = %v, want %v", body, got, want)
		}
	}
}

func (e *env) seedUnsafe(t *testing.T, destToo bool) {
	write(t, e.src, func(tx *store.TenantTx) error {
		b, err := e.rd.Create(tx, readiness.CreateInput{Name: "Corp AD", ConnectorType: "demo-ad", System: "corp-ad",
			Config: json.RawMessage(`{"host":"dc01.corp.example","user_filter":"jdbc:postgresql://db/app?password=hunter2","base_url":"https://dc01.corp.example/x"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		// a value stored before saving a credentialed URL was refused (issue #908)
		dirty := strings.Replace(b.Rev.Config, "https://dc01.corp.example/x", "https://u:pw@dc01.corp.example/x?token=abc", 1)
		if err := tx.UpdateRevisionConfig(b.Rev.ID, dirty, b.Rev.ConfigHash, b.Rev.WriteMode, b.Rev.ExpectedCounts, t0); err != nil {
			return err
		}
		if _, err := e.rd.PutOverlay(tx, "ad", []byte(`{"add_items":[{"id":"custom.ticket","title":"Ticket","category":"ownership","level":"required",`+
			`"why":"see https://u:pw@h.example/x?token=abc","verify":[{"kind":"attestation"}],"remediation":{"hint":"do it"}}]}`), "admin", t0); err != nil {
			return err
		}
		return tx.InsertIdPConnection(&store.IdPConnection{TenantID: tx.Tenant(), Name: "Okta", Protocol: "oidc",
			Profile: store.ProfileOkta, Status: "active", Issuer: str("https://u:pw@larkspur.okta.com?token=abc"), DiscoveryURL: str("see https://x.example/.well-known"),
			MetadataURL: str("jdbc:x"), ClientID: str("0oa1"), CreatedAt: t0, UpdatedAt: t0})
	})
}

func TestExport_UnsafeValuesAreLeftOut(t *testing.T) {
	e := newEnv(t)
	e.seedUnsafe(t, false)
	b := e.bundleOf(t)
	raw, _ := json.Marshal(b)
	for _, leak := range []string{"hunter2", "pw@", "token=abc", "jdbc", "password", "x.example/.well-known"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the bundle carries %q: %s", leak, raw)
		}
	}
	if len(b.Overlays) != 0 || len(b.IdentityProviders) != 1 {
		t.Fatalf("overlays %d idps %d", len(b.Overlays), len(b.IdentityProviders))
	}
	got := map[string]string{}
	for _, x := range b.Excluded {
		got[x.Section+"/"+x.Name] += strings.Join(x.Fields, ",") + ";"
	}
	for k, want := range map[string]string{"overlays/ad": "body;", "connections/Corp AD": ";user_filter;", "identity_providers/Okta": ";discovery_url,metadata_url;"} {
		if !strings.Contains(got[k], strings.TrimSuffix(want, ";")) {
			t.Errorf("excluded %s = %q, want %q (all %v)", k, got[k], want, got)
		}
	}
}

func TestImport_ExcludedValuesKeepExistingAndFlagNew(t *testing.T) {
	e := newEnv(t)
	e.seedUnsafe(t, true)
	e.trust(t)
	raw := e.export(t).JWS

	// New objects: flagged, applied without the left-out values.
	p := e.plan(t, raw, Target{})
	flagged := map[string]bool{}
	for _, it := range p.Items {
		if it.NeedsValue {
			flagged[it.Section+"/"+it.Name] = true
		}
	}
	if !flagged["connections/Corp AD"] || !flagged["identity_providers/Okta"] || !flagged["overlays/ad"] {
		t.Fatalf("needs_value: %v; plan %+v", flagged, p.Items)
	}

	// Existing objects: the destination's own values stay.
	write(t, e.dst, func(tx *store.TenantTx) error {
		if _, err := e.rd.Create(tx, readiness.CreateInput{Name: "Corp AD", ConnectorType: "demo-ad", System: "corp-ad",
			Config: json.RawMessage(`{"host":"dc01.corp.example","user_filter":"keep-me"}`)}, "admin", t0); err != nil {
			return err
		}
		return tx.InsertIdPConnection(&store.IdPConnection{TenantID: tx.Tenant(), Name: "Okta", Protocol: "oidc",
			Profile: store.ProfileOkta, Status: "active", Issuer: str("https://larkspur.okta.com"), ClientID: str("0oa1"),
			DiscoveryURL: str("https://larkspur.okta.com/.well-known/openid-configuration"), MetadataURL: str("https://larkspur.okta.com/meta"), CreatedAt: t0, UpdatedAt: t0})
	})
	p = e.plan(t, raw, Target{})
	for _, it := range p.Items {
		if it.NeedsValue && it.Section != "overlays" {
			t.Errorf("existing object flagged: %+v", it)
		}
		if it.Section == "identity_providers" && it.Action == Manual {
			t.Errorf("a left-out IdP field shows as a difference: %+v", it)
		}
	}
	if _, err := e.apply(t, raw, false); err != nil {
		t.Fatal(err)
	}
	write(t, e.dst, func(tx *store.TenantTx) error {
		cur, err := e.rd.Current(tx, mustConnID(t, tx, "Corp AD"), t0)
		if err != nil {
			return err
		}
		if !strings.Contains(string(cur.Rev.Config), "keep-me") {
			t.Errorf("existing value lost: %s", cur.Rev.Config)
		}
		idps, _ := tx.IdPConnections()
		if len(idps) != 1 || idps[0].DiscoveryURL == nil || !strings.HasSuffix(*idps[0].DiscoveryURL, "openid-configuration") {
			t.Errorf("idp changed: %+v", idps)
		}
		return nil
	})
}

func mustConnID(t *testing.T, tx *store.TenantTx, name string) string {
	t.Helper()
	cs, err := tx.Connections()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Name == name {
			return c.ID
		}
	}
	t.Fatalf("no connection %q", name)
	return ""
}
