package identifiers_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestNormalize(t *testing.T) {
	for _, tc := range []struct {
		typ, in, want string
		bad           bool
	}{
		{store.IdentEmail, "  Ada.Lovelace@Example.COM ", "ada.lovelace@example.com", false},
		{store.IdentEmail, "no-at-sign", "", true},
		{store.IdentEmail, "two@@example.com", "", true},
		{store.IdentEmail, "a@b@c", "", true},
		{store.IdentEmail, "@example.com", "", true},
		{store.IdentEmail, "ada@", "", true},
		{store.IdentEmail, "a b@example.com", "", true},
		{store.IdentEPPN, "Ada@Uni.EDU", "ada@uni.edu", false},
		{store.IdentEPPN, "ada", "", true}, // unscoped eppn is refused
		{store.IdentPhone, "+1 (617) 555-0100", "+16175550100", false},
		{store.IdentPhone, "617.555.0100", "6175550100", false},
		{store.IdentPhone, "12345", "", true},
		{store.IdentPhone, "555-CALL-NOW", "", true},
		{store.IdentEmployeeID, " EMP-0042 ", "emp-0042", false},
		{store.IdentOIDCSub, " AbC123 ", "AbC123", false}, // subjects are case-sensitive
		{store.IdentSAMLSubject, "ABC@Idp.Example", "abc@idp.example", false},
		{store.IdentNationalHMAC, "123-45-6789", "123456789", false},
		{store.IdentNationalHMAC, "ab", "", true},
		{store.IdentNetID, "", "", true},
		{store.IdentNetID, "a\x00b", "", true},
		{"nonsense", "x", "", true},
		{store.IdentEmail, strings.Repeat("a", identifiers.MaxValue) + "@x.com", "", true},
	} {
		got, err := identifiers.Normalize(tc.typ, tc.in)
		if (err != nil) != tc.bad || got != tc.want {
			t.Errorf("Normalize(%s, %q) = %q, %v; want %q (bad=%v)", tc.typ, tc.in, got, err, tc.want, tc.bad)
		}
		if err != nil && strings.Contains(err.Error(), strings.TrimSpace(tc.in)) && len(strings.TrimSpace(tc.in)) > 3 {
			t.Errorf("error echoes the value: %v", err)
		}
	}
}

func TestCheckIssuer(t *testing.T) {
	for _, tc := range []struct {
		typ, issuer string
		bad         bool
	}{
		{store.IdentOIDCSub, "", true},
		{store.IdentSAMLPairwise, "", true},
		{store.IdentOIDCSub, "https://idp.example", false},
		{store.IdentEmail, "", false},
		{store.IdentOIDCSub, " https://idp.example", true},
		{store.IdentOIDCSub, "https://idp\x00.example", true},
	} {
		if err := identifiers.CheckIssuer(tc.typ, tc.issuer); (err != nil) != tc.bad {
			t.Errorf("CheckIssuer(%s, %q) = %v, bad=%v", tc.typ, tc.issuer, err, tc.bad)
		}
	}
}

func hash(t *testing.T, k *identifiers.Keyer, f *storetest.Fixture, tn storetest.Tenant, typ, issuer, v string) (*string, string) {
	t.Helper()
	norm, mac, err := k.Digest(tn.ID, typ, issuer, v)
	if err != nil {
		t.Fatalf("Digest(%s, %q): %v", typ, v, err)
	}
	return norm, mac
}

// TestIdentifiers_HMACUniqueness: the hash is stable, normalized, and
// separated by type, issuer and tenant, and the table refuses a second row
// with the same hash in the tenant, on any person.
func TestIdentifiers_HMACUniqueness(t *testing.T) {
	f := storetest.TwoTenants(t)
	k := storetest.IdentityKeyer(t)

	_, m1 := hash(t, k, f, f.A, store.IdentEmail, "", "New.Guest@Example.com")
	_, m2 := hash(t, k, f, f.A, store.IdentEmail, "", "  new.guest@example.com ")
	if m1 != m2 {
		t.Error("the same address in another case gives another hash")
	}
	if len(m1) != 64 || strings.Contains(m1, "guest") {
		t.Errorf("hash %q is not an opaque 256-bit hex value", m1)
	}
	_, other := hash(t, k, f, f.B, store.IdentEmail, "", "new.guest@example.com")
	if other == m1 {
		t.Error("tenant B hashes the same value to tenant A's hash: the key is not per tenant")
	}
	_, asEmpID := hash(t, k, f, f.A, store.IdentEmployeeID, "", "new.guest@example.com")
	_, asStuID := hash(t, k, f, f.A, store.IdentStudentID, "", "new.guest@example.com")
	if asEmpID == m1 || asEmpID == asStuID {
		t.Error("type is not part of the hash")
	}
	_, i1 := hash(t, k, f, f.A, store.IdentOIDCSub, "https://one.example", "abc")
	_, i2 := hash(t, k, f, f.A, store.IdentOIDCSub, "https://two.example", "abc")
	if i1 == i2 {
		t.Error("issuer is not part of the hash")
	}
	if n, _ := hash(t, k, f, f.A, store.IdentNationalHMAC, "", "123-45-6789"); n != nil {
		t.Error("a hashed-only identifier keeps its value")
	}
	if _, _, err := k.Digest(f.A.ID, store.IdentOIDCSub, "", "abc"); err == nil {
		t.Error("an oidc subject without an issuer was accepted")
	}
	if _, _, err := (*identifiers.Keyer)(nil).Digest(f.A.ID, store.IdentEmail, "", "a@b.c"); err == nil {
		t.Error("a nil keyer hashed")
	}

	insert := func(tn storetest.Tenant, who string, typ, issuer, mac string) error {
		return f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: tn.IDs[who], Type: typ,
				Issuer: issuer, ValueHMAC: mac, Status: store.RecordActive, CreatedAt: storetest.Now})
		})
	}
	if err := insert(f.A, "alice", store.IdentEmail, "", m1); err != nil {
		t.Fatal(err)
	}
	// the same value on another person of the same tenant: refused
	if err := insert(f.A, "bob", store.IdentEmail, "", m2); !errors.Is(err, store.ErrIdentifierTaken) {
		t.Errorf("duplicate on another person = %v, want ErrIdentifierTaken", err)
	}
	// the same person, the same value: refused too
	if err := insert(f.A, "alice", store.IdentEmail, "", m2); !errors.Is(err, store.ErrIdentifierTaken) {
		t.Errorf("duplicate on the same person = %v", err)
	}
	// another type or issuer with the same text is a different identifier
	if err := insert(f.A, "bob", store.IdentEmployeeID, "", asEmpID); err != nil {
		t.Errorf("other type: %v", err)
	}
	// and tenant B is free to hold its own
	if err := insert(f.B, "alice", store.IdentEmail, "", other); err != nil {
		t.Errorf("tenant B: %v", err)
	}
	// lookup by hash finds it in its own tenant only
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		x, err := c.IdentifierByHMAC(store.IdentEmail, "", m1)
		if err != nil || x.IdentityID != f.A.IDs["alice"] {
			t.Errorf("IdentifierByHMAC = %+v, %v", x, err)
		}
		if _, err := c.IdentifierByHMAC(store.IdentEmail, "", other); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's hash found in A: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
