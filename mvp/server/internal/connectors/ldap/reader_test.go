package ldap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

const readerBase = "dc=lab,dc=test"

// readerDir is a small directory: n people and two groups, paged.
func readerDir(n int) *fakeDir {
	d := &fakeDir{Name: "reader", Paged: true, Users: map[string]string{"cn=reader,dc=lab,dc=test": "reader-pw"}}
	d.Entries = append(d.Entries, fakeEntry{DN: readerBase, Attrs: map[string][]string{"objectClass": {"dc"}}})
	var members []string
	for i := 0; i < n; i++ {
		dn := fmt.Sprintf("uid=u%03d,ou=people,%s", i, readerBase)
		d.Entries = append(d.Entries, fakeEntry{DN: dn, Attrs: map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {fmt.Sprintf("u%03d", i)}, "mail": {fmt.Sprintf("u%03d@lab.test", i)}}})
		members = append(members, dn)
	}
	d.Entries = append(d.Entries,
		fakeEntry{DN: "cn=all,ou=groups," + readerBase, Attrs: map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"all"}, "member": members}},
		fakeEntry{DN: "cn=empty,ou=groups," + readerBase, Attrs: map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"empty"}}})
	return d
}

func openReader(t *testing.T, d *fakeDir, port int, bindDN, pw string) (*Reader, *fakeServer, error) {
	t.Helper()
	tcfg, pool := labCert(t, timeNowPlus())
	srv := startFake(t, d, tcfg)
	dialer, err := safedial.New(safedial.Options{Env: config.Prod, RootCAs: pool, Resolver: labResolver{}, TestDial: fakeTransport{srv}.dial})
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(context.Background(), ReadConfig{Host: labHost, Port: port, BindDN: bindDN, Password: Secret(pw), Dialer: dialer})
	if r != nil {
		t.Cleanup(r.Close)
	}
	return r, srv, err
}

func TestReader_SearchPagedOverLDAPSAndStartTLS(t *testing.T) {
	for _, port := range []int{636, 389} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			r, srv, err := openReader(t, readerDir(23), port, "cn=reader,dc=lab,dc=test", "reader-pw")
			if err != nil {
				t.Fatal(err)
			}
			es, err := r.Search(context.Background(), "ou=people,"+readerBase, ScopeSub, "(objectClass=inetOrgPerson)", []string{"uid", "mail"}, 5, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if len(es) != 23 {
				t.Fatalf("entries = %d, want 23 (pages of 5)", len(es))
			}
			if es[0].First("UID") != "u000" || es[22].First("mail") != "u022@lab.test" {
				t.Errorf("entries = %v ... %v", es[0], es[22])
			}
			g, err := r.Search(context.Background(), "ou=groups,"+readerBase, ScopeOne, "(&(objectClass=groupOfNames)(cn=all))", []string{"cn", "member"}, 10, 10)
			if err != nil || len(g) != 1 || len(g[0].Attrs["member"]) != 23 {
				t.Fatalf("groups = %v, %v", g, err)
			}
			_, writes := srv.snapshot()
			if len(writes) != 0 {
				t.Errorf("write operations sent: %v", writes)
			}
		})
	}
}

func TestReader_LimitAndErrors(t *testing.T) {
	r, _, err := openReader(t, readerDir(30), 636, "cn=reader,dc=lab,dc=test", "reader-pw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Search(context.Background(), readerBase, ScopeSub, "(objectClass=inetOrgPerson)", []string{"uid"}, 10, 10)
	if !errors.Is(err, ErrTooManyEntries) {
		t.Errorf("limit err = %v, want ErrTooManyEntries", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Search(ctx, readerBase, ScopeSub, "(uid=*)", nil, 10, 100); err == nil {
		t.Error("a cancelled search ran")
	}
}

func TestReader_BindRefusedAndNoAnonymous(t *testing.T) {
	_, _, err := openReader(t, readerDir(1), 636, "cn=reader,dc=lab,dc=test", "wrong")
	if !errors.Is(err, ErrBindRefused) {
		t.Errorf("wrong password err = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "wrong") {
		t.Errorf("the error says the password: %v", err)
	}
	for _, c := range [][2]string{{"", "pw"}, {"cn=reader,dc=lab,dc=test", ""}} {
		if _, _, err := openReader(t, readerDir(1), 636, c[0], c[1]); !errors.Is(err, ErrBindRefused) {
			t.Errorf("empty credential %q: err = %v", c[0], err)
		}
	}
}

func TestReader_RefusesPlainAndWrongPorts(t *testing.T) {
	d := readerDir(1)
	d.NoStartTLS = true
	if _, _, err := openReader(t, d, 389, "cn=reader,dc=lab,dc=test", "reader-pw"); !errors.Is(err, safedial.ErrNoTLS) {
		t.Errorf("a server without StartTLS: err = %v, want ErrNoTLS", err)
	}
	if _, _, err := openReader(t, readerDir(1), 3268, "cn=reader,dc=lab,dc=test", "reader-pw"); !errors.Is(err, safedial.ErrPort) {
		t.Errorf("port 3268: err = %v, want ErrPort", err)
	}
	// no bind was sent to the plain server
	d2 := readerDir(1)
	d2.NoStartTLS = true
	_, srv, _ := openReader(t, d2, 389, "cn=reader,dc=lab,dc=test", "reader-pw")
	if ops, _ := srv.snapshot(); slices.Contains(ops, "bind") {
		t.Errorf("a bind went over a connection with no TLS: %v", ops)
	}
}

func TestValidFilterDNAndRDN(t *testing.T) {
	for _, f := range []string{"(objectClass=person)", "(&(objectClass=person)(|(uid=a*)(mail=*@x.org)))", "(!(uid=bob))"} {
		if err := ValidFilter(f); err != nil {
			t.Errorf("ValidFilter(%q) = %v", f, err)
		}
	}
	for _, f := range []string{"", "objectClass=person", "(objectClass=person", "(&(a=b)", strings.Repeat("(", 3000)} {
		if err := ValidFilter(f); err == nil {
			t.Errorf("ValidFilter(%q) passed", f)
		}
	}
	if ValidDN("ou=people,dc=example,dc=org") != nil || ValidDN("nonsense") == nil || ValidDN("") == nil {
		t.Error("ValidDN")
	}
	if v, ok := RDNValue("uid=alice,ou=people,dc=x", "UID"); !ok || v != "alice" {
		t.Errorf("RDNValue = %q %v", v, ok)
	}
	if _, ok := RDNValue("cn=a\\,b,dc=x", "uid"); ok {
		t.Error("RDNValue found a missing attribute")
	}
	if v, _ := RDNValue(`cn=Smith\, Jo,dc=x`, "cn"); v != "Smith, Jo" {
		t.Errorf("escaped comma: %q", v)
	}
}

func timeNowPlus() time.Time { return time.Now().Add(90 * 24 * time.Hour) }
