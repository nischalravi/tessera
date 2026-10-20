package provisioning

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// fakeDir is an in-memory LDAP directory. With rangeSize > 0 it behaves like
// Active Directory: a multi-valued attribute with more values than that is
// returned as member;range=0-N and the rest is fetched with member;range=N+1-*.
type fakeDir struct {
	mu        sync.Mutex
	entries   map[string]*dirEntry // by lower-cased DN
	rangeSize int
	clock     int
	searches  int
	modifies  int
	adds      int
	log       []string
}

type dirEntry struct {
	dn    string
	attrs map[string][]string // by lower-cased attribute name
	names map[string]string   // lower-cased -> as given
	mod   int
}

func newDir(rangeSize int) *fakeDir {
	return &fakeDir{entries: map[string]*dirEntry{}, rangeSize: rangeSize}
}

func (d *fakeDir) put(dn string, attrs ...ldapAttr) *dirEntry {
	e := &dirEntry{dn: dn, attrs: map[string][]string{}, names: map[string]string{}}
	for _, a := range attrs {
		k := strings.ToLower(a.Name)
		e.attrs[k] = slices.Clone(a.Vals)
		e.names[k] = a.Name
	}
	d.clock++
	e.mod = d.clock
	d.entries[strings.ToLower(dn)] = e
	return e
}

func (d *fakeDir) Close() error { return nil }

var filterTerm = regexp.MustCompile(`\(([A-Za-z]+)=((?:[^()\\]|\\[0-9a-fA-F]{2})*)\)`)

func unescapeFilter(s string) string {
	return regexp.MustCompile(`\\([0-9a-fA-F]{2})`).ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 16, 8)
		return string(rune(n))
	})
}

func (e *dirEntry) matches(filter string) bool {
	for _, m := range filterTerm.FindAllStringSubmatch(filter, -1) {
		want := unescapeFilter(m[2])
		if want == "*" {
			continue
		}
		ok := false
		for _, v := range e.attrs[strings.ToLower(m[1])] {
			if strings.EqualFold(v, want) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (d *fakeDir) Search(base string, scope int, filter string, attrs []string) ([]ldapEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searches++
	d.log = append(d.log, "search "+base)
	var hits []*dirEntry
	if scope == ldapScopeBase {
		e := d.entries[strings.ToLower(base)]
		if e == nil {
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
		}
		hits = []*dirEntry{e}
	} else {
		for _, e := range d.entries {
			if strings.HasSuffix(strings.ToLower(e.dn), strings.ToLower(base)) {
				hits = append(hits, e)
			}
		}
		slices.SortFunc(hits, func(a, b *dirEntry) int { return strings.Compare(a.dn, b.dn) })
	}
	var out []ldapEntry
	for _, e := range hits {
		if !e.matches(filter) {
			continue
		}
		le := ldapEntry{DN: e.dn}
		for _, want := range attrs {
			name, opt, hasOpt := strings.Cut(want, ";")
			k := strings.ToLower(name)
			vals, ok := e.attrs[k]
			if k == "modifytimestamp" {
				vals, ok = []string{fmt.Sprintf("20260101%06d.0Z", e.mod)}, true
			}
			if !ok {
				continue
			}
			if d.rangeSize > 0 && len(vals) > 0 && k != "modifytimestamp" {
				lo := 0
				if hasOpt {
					lo, _, _ = parseRange(opt)
				}
				if hasOpt || len(vals) > d.rangeSize {
					hi := lo + d.rangeSize
					if hi >= len(vals) {
						le.Attrs = append(le.Attrs, ldapAttr{Name: fmt.Sprintf("%s;range=%d-*", name, lo), Vals: vals[min(lo, len(vals)):]})
					} else {
						le.Attrs = append(le.Attrs, ldapAttr{Name: fmt.Sprintf("%s;range=%d-%d", name, lo, hi-1), Vals: vals[lo:hi]})
					}
					continue
				}
			}
			le.Attrs = append(le.Attrs, ldapAttr{Name: name, Vals: slices.Clone(vals)})
		}
		out = append(out, le)
	}
	return out, nil
}

func (d *fakeDir) Add(dn string, attrs []ldapAttr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.adds++
	d.log = append(d.log, "add "+dn)
	if d.entries[strings.ToLower(dn)] != nil {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("exists"))
	}
	d.put(dn, attrs...)
	return nil
}

func (d *fakeDir) Modify(dn string, changes []ldapChange) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.modifies++
	e := d.entries[strings.ToLower(dn)]
	if e == nil {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	for _, ch := range changes {
		k := strings.ToLower(ch.Attr)
		d.log = append(d.log, fmt.Sprintf("%s %s %d", ch.Op, ch.Attr, len(ch.Vals)))
		switch ch.Op {
		case "add":
			for _, v := range ch.Vals {
				if slices.ContainsFunc(e.attrs[k], func(x string) bool { return strings.EqualFold(x, v) }) {
					return ldap.NewError(ldap.LDAPResultAttributeOrValueExists, errors.New("exists"))
				}
			}
			e.attrs[k] = append(e.attrs[k], ch.Vals...)
			e.names[k] = ch.Attr
		case "delete":
			for _, v := range ch.Vals {
				if !slices.ContainsFunc(e.attrs[k], func(x string) bool { return strings.EqualFold(x, v) }) {
					return ldap.NewError(ldap.LDAPResultNoSuchAttribute, errors.New("no such value"))
				}
			}
			e.attrs[k] = slices.DeleteFunc(e.attrs[k], func(x string) bool {
				return slices.ContainsFunc(ch.Vals, func(v string) bool { return strings.EqualFold(x, v) })
			})
		default:
			e.attrs[k] = slices.Clone(ch.Vals)
			e.names[k] = ch.Attr
		}
	}
	d.clock++
	e.mod = d.clock
	return nil
}

func (d *fakeDir) Del(dn string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.entries[strings.ToLower(dn)] == nil {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	delete(d.entries, strings.ToLower(dn))
	return nil
}

func (d *fakeDir) values(dn, attr string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.entries[strings.ToLower(dn)]
	if e == nil {
		return nil
	}
	return slices.Clone(e.attrs[strings.ToLower(attr)])
}

// ---------------------------------------------------------------- tests

const base = "ou=groups,dc=example,dc=com"

func ldapTargetOf(t *testing.T, typ string, d *fakeDir, target string, attrs map[string]string) *ldapTarget {
	t.Helper()
	cfgJSON := map[string]any{"account_system": "dir", "attrs": attrs, "target": map[string]any{}}
	tg := cfgJSON["target"].(map[string]any)
	tg["url"], tg["security"], tg["base_dn"], tg["bind_dn"] = "ldaps://ldap.example.com", "ldaps", base, "cn=svc,dc=example,dc=com"
	if target != "" {
		for _, kv := range strings.Split(target, ";") {
			k, v, _ := strings.Cut(kv, "=")
			if n, err := strconv.Atoi(v); err == nil {
				tg[k] = n
			} else {
				tg[k] = v
			}
		}
	}
	raw := mustJSON(t, cfgJSON)
	c, err := ParseCommon(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseLDAPConfig(typ, c, Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return newLDAPTarget(typ, cfg, c, d)
}

func TestLDAP_ADRangedAttributes(t *testing.T) {
	d := newDir(4)
	var members []string
	for i := 0; i < 11; i++ {
		members = append(members, fmt.Sprintf("CN=user%02d,OU=People,DC=example,DC=com", i))
	}
	dn := "cn=Big,ou=groups,dc=example,dc=com"
	d.put(dn, ldapAttr{"objectClass", []string{"top", "group"}}, ldapAttr{"cn", []string{"Big"}},
		ldapAttr{"sAMAccountName", []string{"Big"}}, ldapAttr{"member", members})
	d.put("cn=Small,ou=groups,dc=example,dc=com", ldapAttr{"objectClass", []string{"top", "group"}}, ldapAttr{"sAMAccountName", []string{"Small"}},
		ldapAttr{"member", members[:3]})
	d.put("cn=Empty,ou=groups,dc=example,dc=com", ldapAttr{"objectClass", []string{"top", "group"}}, ldapAttr{"sAMAccountName", []string{"Empty"}})
	tg := ldapTargetOf(t, TypeAD, d, "", nil)
	if tg.Capabilities().MaxBatch == 0 || !tg.Capabilities().Readable {
		t.Fatalf("capabilities = %+v", tg.Capabilities())
	}

	st, err := tg.ReadAll(context.Background(), Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Groups) != 3 {
		t.Fatalf("groups = %d", len(st.Groups))
	}
	if got := st.Groups["big"].Members; len(got) != 11 || got[10] != members[10] || got[4] != members[4] {
		t.Errorf("ranged members = %d %v, want all 11 in order", len(got), got)
	}
	if got := len(st.Groups["small"].Members); got != 3 {
		t.Errorf("small = %d members, want 3", got)
	}
	if got := len(st.Groups["empty"].Members); got != 0 {
		t.Errorf("empty = %d members", got)
	}
	if st.Groups["big"].Ref.ID != dn {
		t.Errorf("target id = %q, want the DN", st.Groups["big"].Ref.ID)
	}

	// the targeted read follows the ranges too, by DN and by name
	for _, ref := range []TargetRef{{Name: "Big", ID: dn}, {Name: "big"}} {
		d.searches = 0
		got, err := tg.Read(context.Background(), []TargetRef{ref})
		if err != nil || len(got.Groups["big"].Members) != 11 {
			t.Fatalf("Read(%+v) = %v, %v", ref, got.Groups, err)
		}
		if d.searches < 3 { // the entry, then range 4-* hits 8-*, then the end
			t.Errorf("%d searches for 11 members at 4 per range", d.searches)
		}
	}
	if got, err := tg.Read(context.Background(), []TargetRef{{Name: "Missing", ID: "cn=Missing," + base}}); err != nil || len(got.Groups) != 0 {
		t.Errorf("Read of a missing group = %v, %v; want it absent", got.Groups, err)
	}

	// a server that never ends the ranges does not loop forever
	loop := &loopDir{fakeDir: d}
	lt := newLDAPTarget(TypeAD, tg.cfg, mustCompile(t, nil), loop)
	if _, err := lt.Read(context.Background(), []TargetRef{{Name: "Big", ID: dn}}); err == nil {
		t.Error("a ranged retrieval that makes no progress was accepted")
	}
}

// loopDir answers every range request with the same window.
type loopDir struct{ *fakeDir }

func (l *loopDir) Search(b string, scope int, filter string, attrs []string) ([]ldapEntry, error) {
	if scope == ldapScopeBase {
		return []ldapEntry{{DN: b, Attrs: []ldapAttr{{Name: "sAMAccountName", Vals: []string{"Big"}},
			{Name: "member;range=0-1", Vals: []string{"a", "b"}}}}}, nil
	}
	return l.fakeDir.Search(b, scope, filter, attrs)
}

func mustCompile(t *testing.T, attrs map[string]string) *Compiled {
	t.Helper()
	c, err := ParseCommon(mustJSON(t, map[string]any{"account_system": "dir", "attrs": attrs}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLDAP_ApplyAndRead(t *testing.T) {
	ctx := context.Background()
	d := newDir(0)
	tg := ldapTargetOf(t, TypeLDAP, d, "write_chunk=3;empty_member=cn=nobody,dc=example,dc=com", map[string]string{"description": "{{.Name}}"})
	op := func(id string, o Op) OpResult {
		o.ID = id
		res, err := tg.Apply(ctx, []Op{o})
		if err != nil || len(res) != 1 {
			t.Fatalf("apply: %v %v", res, err)
		}
		return res[0]
	}
	var add []string
	for i := 0; i < 7; i++ {
		add = append(add, fmt.Sprintf("uid=u%d,ou=people,dc=example,dc=com", i))
	}
	res := op("1", Op{Kind: OpCreate, Ref: TargetRef{Name: "Eng, Core"}, Attrs: map[string][]string{"description": {"Eng: Core"}}, Add: add})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	dn := `cn=Eng\, Core,` + base
	if res.Ref.ID != dn {
		t.Errorf("created %q, want %q", res.Ref.ID, dn)
	}
	if d.adds != 1 || d.modifies != 2 { // 3 in the add, 3 and 1 in modifies
		t.Errorf("%d adds and %d modifies for 7 members at chunk 3", d.adds, d.modifies)
	}
	if got := d.values(dn, "objectClass"); !slices.Equal(got, []string{"top", "groupOfNames"}) {
		t.Errorf("objectClass = %v", got)
	}
	if got := d.values(dn, "member"); len(got) != 7 {
		t.Errorf("members = %v", got)
	}

	st, err := tg.Read(ctx, []TargetRef{{Name: "Eng, Core"}})
	if err != nil {
		t.Fatal(err)
	}
	g := st.Groups["eng, core"]
	if g == nil || len(g.Members) != 7 || g.Attrs["description"][0] != "Eng: Core" || g.Token == "" {
		t.Fatalf("read = %+v", g)
	}

	// attributes are replaced, members added and removed; the placeholder keeps a group from being emptied
	if r := op("2", Op{Kind: OpUpdate, Ref: res.Ref, Attrs: map[string][]string{"description": {"renamed"}}}); r.Err != nil {
		t.Fatal(r.Err)
	}
	if got := d.values(dn, "description"); !slices.Equal(got, []string{"renamed"}) {
		t.Errorf("description = %v", got)
	}
	if r := op("3", Op{Kind: OpMembers, Ref: res.Ref, Remove: add}); r.Err != nil {
		t.Fatal(r.Err)
	}
	if got := d.values(dn, "member"); !slices.Equal(got, []string{"cn=nobody,dc=example,dc=com"}) {
		t.Errorf("members after removing all = %v, want only the placeholder", got)
	}
	st, _ = tg.Read(ctx, []TargetRef{res.Ref})
	if got := st.Groups["eng, core"].Members; len(got) != 0 {
		t.Errorf("the placeholder is visible: %v", got)
	}
	// adding what is there and removing what is not are not errors
	if r := op("4", Op{Kind: OpMembers, Ref: res.Ref, Add: add[:1], Remove: add[:1]}); r.Err != nil {
		t.Errorf("idempotent members op: %v", r.Err)
	}
	if r := op("4b", Op{Kind: OpMembers, Ref: res.Ref, Add: add[:1], Remove: add[1:2]}); r.Err != nil {
		t.Errorf("removing an absent member: %v", r.Err)
	}
	// delete twice
	if r := op("5", Op{Kind: OpDelete, Ref: res.Ref}); r.Err != nil {
		t.Fatal(r.Err)
	}
	if r := op("6", Op{Kind: OpDelete, Ref: res.Ref}); r.Err != nil {
		t.Errorf("deleting a deleted group: %v", r.Err)
	}
	if got := d.values(dn, "member"); got != nil {
		t.Errorf("group still there: %v", got)
	}
}

func TestLDAP_ADCreate(t *testing.T) {
	d := newDir(0)
	tg := ldapTargetOf(t, TypeAD, d, "group_scope=universal", nil)
	long := strings.Repeat("n", 65)
	if r, _ := tg.Apply(context.Background(), []Op{{ID: "1", Kind: OpCreate, Ref: TargetRef{Name: long}}}); r[0].Err == nil || !strings.Contains(r[0].Err.Error(), "truncateHash") {
		t.Errorf("a 65-character sAMAccountName: %v, want an error pointing at truncateHash", r[0].Err)
	}
	if r, _ := tg.Apply(context.Background(), []Op{{ID: "1", Kind: OpCreate, Ref: TargetRef{Name: "a=b"}}}); r[0].Err == nil {
		t.Error("a sAMAccountName with = was accepted")
	}
	short, err := TruncateHash(64, long+"zz")
	if err != nil || len(short) != 64 {
		t.Fatalf("TruncateHash = %q, %v", short, err)
	}
	r, _ := tg.Apply(context.Background(), []Op{{ID: "1", Kind: OpCreate, Ref: TargetRef{Name: short}, Add: []string{"CN=a,DC=x"}}})
	if r[0].Err != nil {
		t.Fatal(r[0].Err)
	}
	dn := r[0].Ref.ID
	if got := d.values(dn, "sAMAccountName"); !slices.Equal(got, []string{short}) {
		t.Errorf("sAMAccountName = %v", got)
	}
	if got := d.values(dn, "groupType"); !slices.Equal(got, []string{"-2147483640"}) {
		t.Errorf("groupType = %v, want a universal security group", got)
	}
	if got := d.values(dn, "objectClass"); !slices.Equal(got, []string{"top", "group"}) {
		t.Errorf("objectClass = %v", got)
	}
}

func TestLDAP_Config(t *testing.T) {
	good := map[string]any{"url": "ldaps://ldap.example.com", "base_dn": base, "bind_dn": "cn=svc,dc=example,dc=com"}
	with := func(kv ...any) map[string]any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(m, kv[i].(string))
			} else {
				m[kv[i].(string)] = kv[i+1]
			}
		}
		return m
	}
	parse := func(typ string, target map[string]any, deps Deps, attrs map[string]string) (ldapCfg, error) {
		c, err := ParseCommon(mustJSON(t, map[string]any{"account_system": "dir", "attrs": attrs, "target": target}))
		if err != nil {
			t.Fatal(err)
		}
		return parseLDAPConfig(typ, c, deps)
	}
	cfg, err := parse(TypeLDAP, good, Deps{}, nil)
	if err != nil || cfg.Security != "ldaps" || cfg.ObjectClass != "groupOfNames" || cfg.MemberAttr != "member" || cfg.WriteChunk != 500 {
		t.Errorf("defaults = %+v, %v", cfg, err)
	}
	if cfg, _ := parse(TypeLDAP, with("url", "ldap://ldap.example.com:389"), Deps{}, nil); cfg.Security != "starttls" {
		t.Errorf("ldap:// defaults to %q, want starttls", cfg.Security)
	}
	if cfg, _ := parse(TypeLDAP, with("object_class", "groupOfUniqueNames"), Deps{}, nil); cfg.MemberAttr != "uniqueMember" {
		t.Errorf("member attr = %q", cfg.MemberAttr)
	}
	if cfg, _ := parse(TypeLDAP, with("object_class", "posixGroup"), Deps{}, nil); cfg.MemberAttr != "memberUid" {
		t.Errorf("member attr = %q", cfg.MemberAttr)
	}
	if cfg, err := parse(TypeAD, with("object_class", nil), Deps{}, nil); err != nil || cfg.ObjectClass != "group" || cfg.GroupScope != "global" {
		t.Errorf("ad defaults = %+v, %v", cfg, err)
	}
	for name, c := range map[string]struct {
		typ    string
		target map[string]any
		deps   Deps
		attrs  map[string]string
	}{
		"plain LDAP in production":  {TypeLDAP, with("url", "ldap://ldap.example.com", "security", "none"), Deps{}, nil},
		"no tls to ldaps url":       {TypeLDAP, with("security", "none"), Deps{AllowPlainLDAP: true}, nil},
		"starttls on ldaps url":     {TypeLDAP, with("security", "starttls"), Deps{}, nil},
		"ldaps on ldap url":         {TypeLDAP, with("url", "ldap://h", "security", "ldaps"), Deps{}, nil},
		"unknown security":          {TypeLDAP, with("security", "tls"), Deps{}, nil},
		"http url":                  {TypeLDAP, with("url", "http://h"), Deps{}, nil},
		"user info":                 {TypeLDAP, with("url", "ldaps://u:p@h"), Deps{}, nil},
		"a path":                    {TypeLDAP, with("url", "ldaps://h/dc=x"), Deps{}, nil},
		"no base":                   {TypeLDAP, with("base_dn", nil), Deps{}, nil},
		"no bind dn (anonymous)":    {TypeLDAP, with("bind_dn", nil), Deps{}, nil},
		"ad with another class":     {TypeAD, with("object_class", "groupOfNames"), Deps{}, nil},
		"ad scope":                  {TypeAD, with("group_scope", "forest"), Deps{}, nil},
		"scope on ldap":             {TypeLDAP, with("group_scope", "global"), Deps{}, nil},
		"filter injection in class": {TypeLDAP, with("object_class", "x)(uid=*"), Deps{}, nil},
		"bad chunk":                 {TypeLDAP, with("write_chunk", 0, "page_size", 9999), Deps{}, nil},
		"bad ca":                    {TypeLDAP, with("ca_pem", "not pem"), Deps{}, nil},
		"unknown field":             {TypeLDAP, with("password", "x"), Deps{}, nil},
		"protected attribute":       {TypeLDAP, good, Deps{}, map[string]string{"member": "x"}},
		"protected attribute case":  {TypeLDAP, good, Deps{}, map[string]string{"ObjectClass": "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			if cfg, err := parse(c.typ, c.target, c.deps, c.attrs); err == nil {
				t.Errorf("accepted: %+v", cfg)
			} else if !errors.Is(err, ErrConfig) {
				t.Errorf("error %v is not an ErrConfig", err)
			}
		})
	}
	if _, err := parse(TypeLDAP, with("url", "ldap://ldap.example.com", "security", "none"), Deps{AllowPlainLDAP: true}, nil); err != nil {
		t.Errorf("plain LDAP is refused in dev: %v", err)
	}
}

func TestLDAP_OpenNeedsGuardedDialerAndPassword(t *testing.T) {
	c := mustCompile(t, nil)
	c.Target = mustJSON(t, map[string]any{"url": "ldaps://ldap.example.com", "base_dn": base, "bind_dn": "cn=svc,dc=x"})
	spec := TargetSpec{Type: TypeLDAP, Common: c, Secret: map[string]string{"bind_password": "pw"}}
	if _, err := openLDAP(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "dialer") {
		t.Errorf("open without a dialer: %v", err)
	}
	spec.Deps.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("must not dial") }
	spec.Secret = nil
	if _, err := openLDAP(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "bind_password") {
		t.Errorf("open without a password: %v", err)
	}
}

// the full path: a sync through the LDAP target, with change tokens.
func TestLDAP_SyncThroughService(t *testing.T) {
	x := newHarness(t, 4)
	g := x.group(x.root, "eng")
	x.add(g, x.idents[0])
	x.add(g, x.idents[1])
	d := newDir(2)
	extra := map[string]any{"member_ref": "uid={{.Username | ldapEscape}},ou=people,dc=example,dc=com", "group_name": "{{.Extension}}",
		"attrs":  map[string]string{"description": "{{.DisplayName}}"},
		"target": map[string]any{"url": "ldaps://ldap.example.com", "base_dn": base, "bind_dn": "cn=svc,dc=x", "write_chunk": 1}}
	var tgt *ldapTarget
	x.svc.Open = func(_ context.Context, spec TargetSpec) (Provisioner, error) {
		tgt = newLDAPTarget(spec.Type, mustLDAPCfg(t, spec), spec.Common, d)
		return tgt, nil
	}
	var p *store.Provisioner
	x.must(func(e model.Env) error {
		var err error
		p, err = x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "ldap", TargetType: TypeLDAP, Config: scimConfig(extra),
			Secret: map[string]string{"bind_password": "pw"}})
		return err
	})
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive)

	rep := x.full(p.ID)
	if rep.Summary.Verified != 1 || rep.Run.Status != store.RunDone {
		t.Fatalf("run %s, summary %+v", rep.Run.Status, rep.Summary)
	}
	dn := "cn=eng," + base
	if got := d.values(dn, "member"); len(got) != 2 || !slices.Contains(got, "uid=u0,ou=people,dc=example,dc=com") {
		t.Fatalf("members = %v", got)
	}
	if got := d.values(dn, "description"); !slices.Equal(got, []string{"eng"}) {
		t.Errorf("description = %v", got)
	}
	// nothing changed: a second full sync asks only for tokens and reads nothing
	d.searches = 0
	rep = x.full(p.ID)
	if rep.Summary.CacheHits != 1 || rep.Summary.Verified != 0 || rep.Summary.Skipped != 0 {
		t.Errorf("second run: %+v, want one cache hit and no ops", rep.Summary)
	}
	if d.searches != 1 { // the tokens
		t.Errorf("%d searches, want 1 (tokens only)", d.searches)
	}
	// someone changes the group on the directory: its token moves and the full sync repairs it
	d.mu.Lock()
	d.entries[strings.ToLower(dn)].attrs["member"] = append(d.entries[strings.ToLower(dn)].attrs["member"], "uid=intruder,dc=x")
	d.clock++
	d.entries[strings.ToLower(dn)].mod = d.clock
	d.mu.Unlock()
	rep = x.full(p.ID)
	if rep.Summary.CacheHits != 0 || rep.Summary.Verified != 1 {
		t.Errorf("third run: %+v, want a re-read and a repair", rep.Summary)
	}
	if got := d.values(dn, "member"); len(got) != 2 || slices.Contains(got, "uid=intruder,dc=x") {
		t.Errorf("members = %v, want the intruder removed", got)
	}
	// the cache can be bypassed
	rep, err := x.svc.Run(context.Background(), tid, p.ID, RunOptions{Kind: store.RunFull, IgnoreCache: true})
	if err != nil || rep.Summary.CacheHits != 0 {
		t.Errorf("ignore-cache run: %+v, %v", rep, err)
	}
}

func mustLDAPCfg(t *testing.T, spec TargetSpec) ldapCfg {
	t.Helper()
	cfg, err := parseLDAPConfig(spec.Type, spec.Common, Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
