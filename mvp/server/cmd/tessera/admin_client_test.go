package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestAdminAddClient (design §9.5, §19 PR11): add-client registers a machine
// client from a PUBLIC key set, with the owner, roles and scopes it is given,
// audits it as the operator, and refuses what a machine client may never have.
func TestAdminAddClient(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	t.Setenv("USER", "op-jane")
	ctx := context.Background()
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if out, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Acme Corp"); err != nil {
		t.Fatalf("create-tenant: %v %s", err, out)
	}
	st, err = store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	var acme store.Tenant
	if err := st.ReadSystem(ctx, "test", func(s *store.SystemTx) error {
		var err error
		acme, err = s.TenantBySlug("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	t.Setenv("TESSERA_ENV", "test") // authtest refuses to create a session otherwise
	owner := authtest.LoginAs(t, st, acme.ID, authtest.User{Email: "owner@acme.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	_ = st.Close()
	t.Setenv("TESSERA_ENV", "dev")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubJWK := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}
	marshal := func(ks ...jose.JSONWebKey) string {
		b, err := json.Marshal(jose.JSONWebKeySet{Keys: ks})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	jwks := writeFile(t, dir, "pub.jwks", marshal(pubJWK))
	base := []string{"add-client", "-tenant", "acme", "-name", "Nightly ETL", "-owner", "owner@acme.example", "-jwks-file", jwks,
		"-scope", "tessera:read,tessera:audit", "-roles", "viewer,auditor"}
	with := func(args []string, replace ...string) []string {
		out := append([]string{}, args...)
		for i := 0; i < len(replace); i += 2 {
			for j := 0; j < len(out)-1; j++ {
				if out[j] == replace[i] {
					out[j+1] = replace[i+1]
				}
			}
		}
		return out
	}

	for name, args := range map[string][]string{
		"an admin role":           with(base, "-roles", "viewer,tenant_admin"),
		"policy_admin":            with(base, "-roles", "policy_admin"),
		"break_glass":             with(base, "-roles", "break_glass"),
		"an unknown role":         with(base, "-roles", "root"),
		"no roles":                with(base, "-roles", ""),
		"an unknown scope":        with(base, "-scope", "tessera:everything"),
		"no scope":                with(base, "-scope", ""),
		"no owner":                with(base, "-owner", ""),
		"an owner who is no user": with(base, "-owner", "nobody@acme.example"),
		"no name":                 with(base, "-name", " "),
		"no key file":             with(base, "-jwks-file", ""),
		"a missing key file":      with(base, "-jwks-file", filepath.Join(dir, "absent")),
		"a private key":           with(base, "-jwks-file", writeFile(t, dir, "priv.jwks", marshal(jose.JSONWebKey{Key: key, KeyID: "k1"}))),
		"a key without a kid":     with(base, "-jwks-file", writeFile(t, dir, "nokid.jwks", marshal(jose.JSONWebKey{Key: &key.PublicKey}))),
		"not a key set":           with(base, "-jwks-file", writeFile(t, dir, "bad.jwks", "{}")),
		"an unknown tenant":       with(base, "-tenant", "nobody"),
	} {
		if out, err := adminRun(t, db, args...); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}

	out, err := adminRun(t, db, base...)
	m := regexp.MustCompile(`added machine client (tsc_[a-z2-7]{16}) \(Nightly ETL\) to acme`).FindStringSubmatch(out)
	if err != nil || m == nil || !strings.Contains(out, "http://localhost:5173/t/acme/oauth/token") {
		t.Fatalf("add-client: %v %s", err, out)
	}
	if strings.Contains(out, "warning") {
		t.Errorf("a DPoP client warned: %s", out)
	}
	// by user id, without DPoP: allowed, with a warning
	out2, err := adminRun(t, db, append(with(base, "-owner", owner.UserID.String(), "-name", "Legacy job", "-roles", "viewer"), "-dpop=false")...)
	if err != nil || !strings.Contains(out2, "warning: DPoP is not required") {
		t.Fatalf("add-client -dpop=false: %v %s", err, out2)
	}

	st, err = store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ReadTenant(ctx, acme.ID, func(tx *store.TenantTx) error {
		c, err := tx.APIClientByClientID(m[1])
		if err != nil {
			return err
		}
		jkt, _ := dpop.Thumbprint(&pubJWK)
		if c.Kind != store.ClientMachine || c.Status != store.ClientActive || c.Name != "Nightly ETL" || !c.DPoPRequired ||
			c.TokenEndpointAuthMethod != "private_key_jwt" || strings.Join(c.GrantTypes, ",") != oauth.GrantClientCredentials ||
			strings.Join(c.Roles, ",") != "viewer,auditor" || strings.Join(c.AllowedScopes, ",") != "tessera:read,tessera:audit" ||
			c.OwnerUserID == nil || *c.OwnerUserID != owner.UserID {
			t.Errorf("client %+v", c)
		}
		if _, _, err := oauth.ParseClientJWKS(c.JWKS); err != nil || strings.Contains(string(c.JWKS), `"d"`) {
			t.Errorf("stored keys: %v %s", err, c.JWKS)
		}
		all, err := tx.APIClients()
		if err != nil || len(all) != 2 {
			t.Errorf("clients: %d %v", len(all), err)
		}
		events, err := tx.AuditLog(-1)
		if err != nil {
			return err
		}
		n := 0
		for _, e := range events {
			if e.Action != "oauth.client.created" {
				continue
			}
			n++
			if e.ActorType != store.ActorOperator || e.TargetType == nil || *e.TargetType != "api_client" {
				t.Errorf("event actor %s target %v", e.ActorType, e.TargetType)
			}
			if strings.Contains(string(e.Detail), m[1]) && (!strings.Contains(string(e.Detail), jkt) ||
				!strings.Contains(string(e.Detail), owner.UserID.String()) || strings.Contains(string(e.Detail), `"d"`)) {
				t.Errorf("event detail: %s", e.Detail)
			}
		}
		if n != 2 {
			t.Errorf("%d oauth.client.created events, want 2", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
