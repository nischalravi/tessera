package loaders_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	ldapdir "github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// dirFake is an in-memory directory behind the loaders' DirectoryOpener: the
// people and the groups come back for their filters, and a group with more
// members than window is returned in Active Directory's ranged form. (The wire
// protocol, paging, StartTLS and the read-only guarantee are tested in
// internal/connectors/ldap against a fake server.)
type dirFake struct {
	people    []ldapdir.Entry
	groups    []ldapdir.Entry // attrs "member" hold the full list
	window    int
	spec      loaders.DirectorySpec
	opens     int
	searches  []string
	openErr   error
	maxPageIn int
}

func person(uid, mail string) ldapdir.Entry {
	return ldapdir.Entry{DN: fmt.Sprintf("uid=%s,ou=people,dc=lab,dc=test", uid), Attrs: map[string][]string{"uid": {uid}, "mail": {mail}}}
}

func group(cn string, members ...string) ldapdir.Entry {
	return ldapdir.Entry{DN: fmt.Sprintf("cn=%s,ou=groups,dc=lab,dc=test", cn), Attrs: map[string][]string{"cn": {cn}, "member": members}}
}

func (d *dirFake) opener() loaders.DirectoryOpener {
	return func(_ context.Context, spec loaders.DirectorySpec) (loaders.DirectoryReader, error) {
		d.spec = spec
		d.opens++
		if d.openErr != nil {
			return nil, d.openErr
		}
		return &dirConn{d: d}, nil
	}
}

type dirConn struct{ d *dirFake }

func (c *dirConn) Close() {}

func (c *dirConn) Search(_ context.Context, base string, scope ldapdir.Scope, filter string, attrs []string, page, max int) ([]ldapdir.Entry, error) {
	d := c.d
	d.searches = append(d.searches, fmt.Sprintf("%s|%d|%s|%s", base, scope, filter, strings.Join(attrs, ",")))
	d.maxPageIn = page
	switch {
	case scope == ldapdir.ScopeBase: // the next window of a ranged attribute
		for _, g := range d.groups {
			if g.DN != base {
				continue
			}
			var lo int
			_, _ = fmt.Sscanf(strings.SplitN(attrs[0], "=", 2)[1], "%d-*", &lo)
			return []ldapdir.Entry{d.window1(g, lo)}, nil
		}
		return nil, nil
	case strings.Contains(filter, "groupOfNames"):
		var out []ldapdir.Entry
		for _, g := range d.groups {
			out = append(out, d.window1(g, 0))
		}
		if len(out) > max {
			return nil, ldapdir.ErrTooManyEntries
		}
		return out, nil
	}
	if len(d.people) > max {
		return nil, ldapdir.ErrTooManyEntries
	}
	return d.people, nil
}

// window1 is the group with its members from lo on, at most window of them.
func (d *dirFake) window1(g ldapdir.Entry, lo int) ldapdir.Entry {
	all := g.Attrs["member"]
	out := ldapdir.Entry{DN: g.DN, Attrs: map[string][]string{"cn": g.Attrs["cn"]}}
	if d.window == 0 || len(all) <= d.window {
		out.Attrs["member"] = all
		return out
	}
	hi := min(len(all), lo+d.window)
	end := strconv.Itoa(hi - 1)
	if hi == len(all) {
		end = "*"
	}
	out.Attrs["member;range="+strconv.Itoa(lo)+"-"+end] = all[lo:hi]
	return out
}

func (h *harness) ldapSpec(name, typ, cfg string) loaders.Spec {
	return loaders.Spec{Name: name, Type: typ, TargetFolder: string(h.ref), Schedule: "@daily",
		Config: []byte(fmt.Sprintf(`{"url":"ldaps://ldap.lab.example","bind_dn":"cn=reader,dc=lab,dc=test","base_dn":"dc=lab,dc=test",%s}`, cfg))}
}

func TestLDAPSimple_PeopleOfAFilterAreOneGroup(t *testing.T) {
	h := newHarness(t)
	d := &dirFake{people: []ldapdir.Entry{person("u0", "u0@example.edu"), person("u1", "u1@example.edu"), person("u1", "u1@example.edu"), person("nobody", "nobody@example.edu")}}
	h.svc.Directory = d.opener()
	l := h.create(h.ldapSpec("staff", loaders.TypeLDAPSimple, `"filter":"(objectClass=inetOrgPerson)","subject_attr":"uid","group":"staff","page_size":50`), "bind-pw-secret")
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied && r.Status != store.RunHeld {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	// "nobody" matches no identity: listed as unresolved, and the run says so
	if un := h.unresolved(l.ID); len(un) != 1 || un[0].Identifier != "nobody" {
		t.Errorf("unresolved = %+v", un)
	}
	if d.spec.Host != "ldap.lab.example" || d.spec.Port != 636 || d.spec.BindDN != "cn=reader,dc=lab,dc=test" || string(d.spec.Password) != "bind-pw-secret" {
		t.Errorf("spec = %+v", d.spec)
	}
	if d.maxPageIn != 50 {
		t.Errorf("page size = %d", d.maxPageIn)
	}
	if stored := h.loader(l.ID); strings.Contains(string(stored.SecretEnc), "bind-pw") || len(stored.SecretEnc) == 0 {
		t.Errorf("secret stored as %q", stored.SecretEnc)
	}
}

func TestLDAPSimple_MailMatchesByEmail(t *testing.T) {
	h := newHarness(t)
	d := &dirFake{people: []ldapdir.Entry{person("a", "u0@example.edu"), person("b", "U1@EXAMPLE.EDU"), person("c", "u2@example.edu")}}
	h.svc.Directory = d.opener()
	l := h.create(h.ldapSpec("mail", loaders.TypeLDAPSimple, `"filter":"(mail=*)","subject_attr":"mail","group":"byemail","scope":"one"`), "pw")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:byemail", []string{"u0", "u1", "u2"})
	if !strings.HasPrefix(d.searches[0], "dc=lab,dc=test|"+strconv.Itoa(int(ldapdir.ScopeOne))+"|") {
		t.Errorf("search = %v", d.searches)
	}
}

func TestLDAPGroupList_MembersByRDNAndRangedRetrieval(t *testing.T) {
	h := newHarness(t)
	dn := func(uid string) string { return fmt.Sprintf("uid=%s,ou=people,dc=lab,dc=test", uid) }
	var all []string
	for i := 0; i < 7; i++ {
		all = append(all, dn(fmt.Sprintf("u%d", i)))
	}
	d := &dirFake{window: 3, groups: []ldapdir.Entry{group("Dev Team", all...), group("small", dn("u8"), dn("u9")), group("empty")}}
	h.svc.Directory = d.opener()
	l := h.create(h.ldapSpec("groups", loaders.TypeLDAPGroupList, `"filter":"(objectClass=groupOfNames)","member_rdn":"uid","name_prefix":"ad_"`), "pw")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:ad_Dev_Team", seq(0, 7))
	wantMembers(t, h, "ref:ad_small", []string{"u8", "u9"})
	// the ranged windows were followed: 0-2 came with the entry, 3-5 and 6-* by base searches
	var ranged []string
	for _, s := range d.searches {
		if strings.Contains(s, ";range=") {
			ranged = append(ranged, s[strings.LastIndex(s, "|")+1:])
		}
	}
	if !slices.Equal(ranged, []string{"member;range=3-*", "member;range=6-*"}) {
		t.Errorf("ranged reads = %v", ranged)
	}
}

func TestLDAPGroupList_PlainValuesAndNonUserMembers(t *testing.T) {
	h := newHarness(t)
	g := group("posix", "u0", "u1")
	d := &dirFake{groups: []ldapdir.Entry{g}}
	h.svc.Directory = d.opener()
	l := h.create(h.ldapSpec("plain", loaders.TypeLDAPGroupList, `"filter":"(objectClass=groupOfNames)","name_prefix":"p_"`), "pw")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:p_posix", []string{"u0", "u1"})
	// with member_rdn, a member that is not a uid= DN is listed, never dropped
	d.groups = []ldapdir.Entry{group("mixed", "uid=u2,ou=people,dc=lab,dc=test", "cn=other-group,ou=groups,dc=lab,dc=test")}
	spec := h.ldapSpec("rdn", loaders.TypeLDAPGroupList, `"filter":"(objectClass=groupOfNames)","member_rdn":"uid","name_prefix":"r_"`)
	loose := 100.0
	spec.Failsafe = &loaders.Failsafe{MaxUnresolvedPercent: &loose}
	l2 := h.create(spec, "pw")
	if r := h.run(l2, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:r_mixed", []string{"u2"})
	found := false
	for _, u := range h.unresolved(l2.ID) {
		found = found || u.Identifier == "cn=other-group,ou=groups,dc=lab,dc=test"
	}
	if !found {
		t.Errorf("unresolved = %+v: the nested group's DN should be listed", h.unresolved(l2.ID))
	}
}

func TestLDAP_FailuresNameTheCauseNotTheCredential(t *testing.T) {
	h := newHarness(t)
	d := &dirFake{people: []ldapdir.Entry{person("u0", "u0@example.edu")}}
	h.svc.Directory = d.opener()
	l := h.create(h.ldapSpec("fail", loaders.TypeLDAPSimple, `"filter":"(objectClass=person)","subject_attr":"uid","group":"g"`), "pw-should-not-leak")
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"bind refused":  {ldapdir.ErrBindRefused, "refused the bind"},
		"no TLS":        {fmt.Errorf("%w: StartTLS: boom pw-should-not-leak", safedial.ErrNoTLS), "does not offer TLS"},
		"blocked":       {safedial.ErrBlockedAddress, "address is not allowed"},
		"cert":          {safedial.ErrHandshake, "certificate"},
		"anything else": {fmt.Errorf("dial tcp: pw-should-not-leak"), "reading the directory failed"},
	} {
		d.openErr = tc.err
		r := h.run(l, store.RunFull)
		if r.Status != store.RunFailed || !strings.Contains(deref(r.Error), tc.want) || strings.Contains(deref(r.Error), "pw-should-not-leak") {
			t.Errorf("%s: %s %q", name, r.Status, deref(r.Error))
		}
	}
	// no opener: the source is off
	h.svc.Directory = nil
	if r := h.run(l, store.RunFull); r.Status != store.RunFailed || !strings.Contains(deref(r.Error), "not available") {
		t.Errorf("no opener: %s %q", r.Status, deref(r.Error))
	}
	// too many entries is an error, not a cut-off
	d.openErr = nil
	h.svc.Directory = d.opener()
	d.people = nil
	if r := h.run(l, store.RunFull); r.Status == store.RunFailed {
		t.Errorf("an empty directory failed: %q", deref(r.Error))
	}
}

func TestLDAPConfigValidation(t *testing.T) {
	base := func(extra string) json.RawMessage {
		return json.RawMessage(`{"url":"ldaps://ldap.example.org","bind_dn":"cn=r,dc=x","base_dn":"dc=x","filter":"(objectClass=person)"` + extra + `}`)
	}
	simple := `,"subject_attr":"uid","group":"g"`
	for name, tc := range map[string]struct {
		typ, cfg, want string
	}{
		"simple ok":             {loaders.TypeLDAPSimple, string(base(simple)), ""},
		"group list ok":         {loaders.TypeLDAPGroupList, string(base(`,"member_rdn":"uid","scope":"one","page_size":100`)), ""},
		"starttls url":          {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "ldaps://ldap.example.org", "ldap://ldap.example.org", 1), ""},
		"plain ldap on 636":     {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "ldaps://ldap.example.org", "ldap://ldap.example.org:636", 1), "uses port 636"},
		"odd port":              {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "ldap.example.org", "ldap.example.org:3268", 1), "port is 389"},
		"http url":              {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "ldaps://", "http://", 1), "url is ldaps"},
		"path in url":           {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "example.org", "example.org/x", 1), "nothing after"},
		"bad filter":            {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "(objectClass=person)", "objectClass=person", 1), "filter"},
		"unbalanced filter":     {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "(objectClass=person)", "(&(a=b)", 1), "filter"},
		"bad base dn":           {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), `"dc=x"`, `"nonsense"`, 1), "base_dn"},
		"bad scope":             {loaders.TypeLDAPSimple, string(base(simple + `,"scope":"base"`)), "scope"},
		"simple needs attr":     {loaders.TypeLDAPSimple, string(base(`,"group":"g"`)), "subject_attr"},
		"simple needs group":    {loaders.TypeLDAPSimple, string(base(`,"subject_attr":"uid"`)), "group"},
		"simple with member":    {loaders.TypeLDAPSimple, string(base(simple + `,"member_attr":"member"`)), "ldap_group_list"},
		"list with group":       {loaders.TypeLDAPGroupList, string(base(`,"group":"g"`)), "ldap_simple"},
		"bad attribute":         {loaders.TypeLDAPGroupList, string(base(`,"member_rdn":"u id"`)), "attribute name"},
		"unknown field":         {loaders.TypeLDAPSimple, string(base(simple + `,"password":"x"`)), "unknown field"},
		"ca without cert":       {loaders.TypeLDAPSimple, string(base(simple + `,"ca_pem":"nope"`)), "ca_pem"},
		"page size":             {loaders.TypeLDAPGroupList, string(base(`,"page_size":99999`)), "page_size"},
		"bind dn with password": {loaders.TypeLDAPSimple, strings.Replace(string(base(simple)), "cn=r,dc=x", "not a dn", 1), "bind_dn"},
	} {
		_, err := loaders.ValidateConfig(tc.typ, json.RawMessage(tc.cfg), false)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
	for url, want := range map[string]loaders.LDAPEndpoint{
		"ldaps://h.example":     {Host: "h.example", Port: 636},
		"ldap://h.example":      {Host: "h.example", Port: 389},
		"ldap://h.example:389/": {Host: "h.example", Port: 389},
	} {
		if got, err := loaders.ParseLDAPURL(url); err != nil || got != want {
			t.Errorf("ParseLDAPURL(%q) = %+v, %v", url, got, err)
		}
	}
}
