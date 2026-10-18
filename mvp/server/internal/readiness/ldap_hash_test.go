package readiness

import (
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// TestLDAPItemHash_BindDNCABundlePortInvalidate: live results and attestations
// are keyed on the item hash, so changing only the bind DN, only the trusted CA
// or only the port must change the hash of exactly the items whose evidence
// depends on it (those declaring the field, plus items declaring none, which
// bind to the whole config) and of no other item.
func TestLDAPItemHash_BindDNCABundlePortInvalidate(t *testing.T) {
	reg, err := template.Default()
	if err != nil {
		t.Fatal(err)
	}
	res, ok := reg.Get("ldap")
	if !ok {
		t.Fatal("no ldap template")
	}
	base := HashInput{Config: ConnConfig{Host: "ldap.example.test", Port: 636, BindDN: "cn=tessera,dc=example,dc=test",
		CABundle: "pem-a", BaseDNs: []string{"dc=example,dc=test"}}, Role: "account_source",
		SecretRef: "sealed:1", SecretVersion: "1", TemplatePin: "ldap@1.0"}
	hashes := func(in HashInput) map[string]string {
		out := map[string]string{}
		for _, it := range res.Items {
			h, err := in.ItemHash(it.ConfigFields)
			if err != nil {
				t.Fatal(err)
			}
			out[it.ID] = h
		}
		return out
	}
	before := hashes(base)
	tests := []struct {
		field  string
		mutate func(*HashInput)
		// must lists items the review named; the full set is derived from the template.
		must []string
	}{
		{"bind_dn", func(in *HashInput) { in.Config.BindDN = "cn=other,dc=example,dc=test" },
			[]string{"ldap.svc.readonly", "ldap.svc.no_write", "ldap.svc.ppolicy", "ldap.bind", "ldap.scope.read_perms", "ldap.scope.limits"}},
		{"ca_bundle", func(in *HashInput) { in.Config.CABundle = "pem-b" },
			[]string{"ldap.tls.ldaps", "ldap.tls.chain", "ldap.tls.version", "ldap.bind", "ldap.svc.readonly"}},
		{"port", func(in *HashInput) { in.Config.Port = 389 },
			[]string{"ldap.svc.readonly", "ldap.tls.ldaps", "ldap.tls.chain", "ldap.tls.version", "ldap.bind", "ldap.scope.base_dns"}},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			after := hashes(in)
			var changed []string
			for _, it := range res.Items {
				depends := len(it.ConfigFields) == 0 || slices.Contains(it.ConfigFields, tc.field)
				if got := after[it.ID] != before[it.ID]; got != depends {
					t.Errorf("%s: hash changed=%v when only %s changed, declared dependency=%v (config_fields %v)",
						it.ID, got, tc.field, depends, it.ConfigFields)
				}
				if after[it.ID] != before[it.ID] {
					changed = append(changed, it.ID)
				}
			}
			for _, id := range tc.must {
				if !slices.Contains(changed, id) {
					t.Errorf("%s is not invalidated by a change to %s", id, tc.field)
				}
			}
			// Items that do not use a connection keep their evidence.
			for _, id := range []string{"ldap.replica", "ldap.key.hr_id"} {
				if slices.Contains(changed, id) {
					t.Errorf("%s was invalidated by an unrelated change to %s", id, tc.field)
				}
			}
		})
	}
}
