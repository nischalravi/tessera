//go:build ldapinteg

package ldap

// Real-server integration test, run by a human against their lab directory
// (LLDAP, OpenLDAP or 389-DS). It is read-only, like the probe, and never
// prints the password. Nothing here is committed with credentials; the
// target comes from the environment:
//
//	TESSERA_LDAP_TEST_URL      ldaps://host:636 or ldap://host:389 (StartTLS)
//	TESSERA_LDAP_TEST_BIND_DN  the read-only bind DN
//	TESSERA_LDAP_TEST_PASSWORD its password
//	TESSERA_LDAP_TEST_BASE_DN  base DNs to read, separated by ";"
//	                           (LLDAP: ou=people,dc=tessera,dc=test;ou=groups,dc=tessera,dc=test)
//	TESSERA_LDAP_TEST_CA       optional PEM file with the CA that signed the server certificate
//	TESSERA_LDAP_TEST_FILTER   optional people filter (default (objectClass=inetOrgPerson))
//
// Run: cd mvp/server && go test -tags ldapinteg -run TestLive -v ./internal/connectors/ldap
//
// The target host is allowlisted for safedial for this test only (it is the
// operator's explicit choice); the production policy is unchanged.

import (
	"context"
	"crypto/x509"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

func TestLive(t *testing.T) {
	raw := os.Getenv("TESSERA_LDAP_TEST_URL")
	if raw == "" {
		t.Skip("TESSERA_LDAP_TEST_URL is not set")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("TESSERA_LDAP_TEST_URL: %q", raw)
	}
	port := 636
	if u.Scheme == "ldap" {
		port = 389
	}
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			t.Fatal(err)
		}
	}
	var roots *x509.CertPool
	if ca := os.Getenv("TESSERA_LDAP_TEST_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("TESSERA_LDAP_TEST_CA has no certificate")
		}
	}
	allow, err := safedial.ParseAllow(u.Hostname() + ":" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	d, err := safedial.New(safedial.Options{Env: config.Dev, Allow: allow, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	bases := strings.Split(os.Getenv("TESSERA_LDAP_TEST_BASE_DN"), ";")
	filter := os.Getenv("TESSERA_LDAP_TEST_FILTER")
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}
	p, err := New(Config{Host: u.Hostname(), Port: port, BindDN: os.Getenv("TESSERA_LDAP_TEST_BIND_DN"),
		Password: Secret(os.Getenv("TESSERA_LDAP_TEST_PASSWORD")), BaseDNs: bases, UserFilter: filter, RootCAs: roots, Dialer: d})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ci, err := p.Connect(ctx)
	if err != nil || !ci.Reachable {
		t.Fatalf("connect: %+v %v", ci, err)
	}
	t.Logf("TLS %s, chain valid %v, host match %v, issuer %q, expires %s", ci.TLSVersion, ci.ChainValid, ci.HostnameMatch, ci.Issuer, ci.NotAfter.Format("2006-01-02"))
	a, err := p.Authenticate(ctx)
	if err != nil || !a.OK {
		t.Fatalf("bind: %+v %v", a, err)
	}
	t.Logf("bound as %q (root identity: %v, Who Am I unavailable: %v)", a.Identity, a.RootIdentity, a.IdentityUnverified)

	got := runChecks(t, p, bases, filter)
	ids := make([]string, 0, len(got))
	for id := range got {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := got[id]
		t.Logf("%-22s %-8s %s %v", id, r.Status, r.Message, r.Observed)
	}
	for _, id := range []string{"tls_handshake", "bind", "dn_exists", "sample_search"} {
		if got[id].Status != "pass" {
			t.Errorf("%s = %s: %s", id, got[id].Status, got[id].Message)
		}
	}
}
