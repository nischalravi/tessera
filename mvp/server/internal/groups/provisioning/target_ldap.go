package provisioning

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// The LDAP and Active Directory targets (design §9.2). Groups are
// groupOfNames, groupOfUniqueNames or posixGroup entries (ldap) or AD groups
// (ad) under one base DN. A member reference is whatever the member_ref
// template makes of the account: a DN for member and uniqueMember, a uid for
// memberUid.
//
// Connections are made through the safehttp dialer (private, loopback and
// metadata addresses are refused after DNS resolution) and are always
// protected: ldaps:// or StartTLS. Plain ldap:// ("none") exists for the dev
// directory only and is refused unless the server runs with TESSERA_ENV=dev
// or test.
//
// Active Directory returns at most 1,500 values of a multi-valued attribute
// per request and hides the rest behind ranged retrieval: member;range=0-1499
// in the entry, then member;range=1500-* asks for the next window. members()
// follows that until the server answers "*".
//
// Not done: entity attributes on people (isMemberOf, eduPersonEntitlement), and
// renaming a group in place (a rename creates the new group and deletes the old
// one, which the group-deletion failsafe holds for approval).

type ldapCfg struct {
	URL      string `json:"url"`
	Security string `json:"security"` // ldaps | starttls | none
	BaseDN   string `json:"base_dn"`
	BindDN   string `json:"bind_dn"`
	// ObjectClass is groupOfNames (default), groupOfUniqueNames or posixGroup for ldap, and group for ad.
	ObjectClass string `json:"object_class"`
	// MemberAttr defaults by class: member, uniqueMember, memberUid.
	MemberAttr string `json:"member_attr"`
	// EmptyMember is a placeholder DN kept in a group so that it is never
	// empty (groupOfNames requires a member). It is hidden when reading.
	EmptyMember string `json:"empty_member"`
	// WriteChunk is the most values of one modify request (default 500).
	WriteChunk int `json:"write_chunk"`
	PageSize   int `json:"page_size"`
	// GroupScope is the AD group scope: global (default), universal or domain_local.
	GroupScope string `json:"group_scope"`
	// CAPEM is a PEM bundle that replaces the system roots (a private CA).
	CAPEM      string `json:"ca_pem"`
	ServerName string `json:"server_name"`
}

var (
	ldapClassRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
	protectedAttr = []string{"objectclass", "cn", "member", "uniquemember", "memberuid", "samaccountname", "grouptype",
		"modifytimestamp", "dn", "entrydn"}
)

// groupType values of AD security groups by scope (ADS_GROUP_TYPE_* | SECURITY_ENABLED).
var adGroupType = map[string]string{"global": "-2147483646", "domain_local": "-2147483644", "universal": "-2147483640"}

func parseLDAPConfig(typ string, c *Compiled, deps Deps) (ldapCfg, error) {
	var cfg ldapCfg
	if err := strictJSON(c.Target, &cfg); err != nil {
		return cfg, cfgErr("target: %v", err)
	}
	u, err := url.Parse(cfg.URL)
	switch {
	case err != nil || u.Host == "" || u.Hostname() == "" || len(cfg.URL) > 512:
		return cfg, cfgErr("target.url must be an ldaps:// or ldap:// URL with a host")
	case u.Scheme != "ldaps" && u.Scheme != "ldap":
		return cfg, cfgErr("target.url must be an ldaps:// or ldap:// URL")
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "":
		return cfg, cfgErr("target.url must be only a scheme, host and port")
	}
	if cfg.Security == "" {
		cfg.Security = "starttls"
		if u.Scheme == "ldaps" {
			cfg.Security = "ldaps"
		}
	}
	switch {
	case cfg.Security == "ldaps" && u.Scheme != "ldaps", cfg.Security == "starttls" && u.Scheme != "ldap":
		return cfg, cfgErr("target.security %q does not match the %s:// URL", cfg.Security, u.Scheme)
	case cfg.Security == "none":
		if !deps.AllowPlainLDAP {
			return cfg, cfgErr("target.security none (no TLS) is not allowed on this server: use ldaps or starttls")
		}
		if u.Scheme != "ldap" {
			return cfg, cfgErr("target.security none needs an ldap:// URL")
		}
	case cfg.Security != "ldaps" && cfg.Security != "starttls":
		return cfg, cfgErr("target.security is ldaps, starttls or none")
	}
	if cfg.BaseDN == "" || len(cfg.BaseDN) > 512 || cfg.BindDN == "" || len(cfg.BindDN) > 512 {
		return cfg, cfgErr("target.base_dn and target.bind_dn are required")
	}
	switch typ {
	case TypeAD:
		if cfg.ObjectClass != "" && !strings.EqualFold(cfg.ObjectClass, "group") {
			return cfg, cfgErr("target.object_class of an ad target is group")
		}
		cfg.ObjectClass, cfg.MemberAttr = "group", "member"
		if cfg.GroupScope == "" {
			cfg.GroupScope = "global"
		}
		if _, ok := adGroupType[cfg.GroupScope]; !ok {
			return cfg, cfgErr("target.group_scope is global, universal or domain_local")
		}
	default:
		if cfg.ObjectClass == "" {
			cfg.ObjectClass = "groupOfNames"
		}
		if !ldapClassRE.MatchString(cfg.ObjectClass) {
			return cfg, cfgErr("target.object_class is not an object class name")
		}
		if cfg.MemberAttr == "" {
			switch cfg.ObjectClass {
			case "groupOfUniqueNames":
				cfg.MemberAttr = "uniqueMember"
			case "posixGroup":
				cfg.MemberAttr = "memberUid"
			default:
				cfg.MemberAttr = "member"
			}
		}
		if !ldapClassRE.MatchString(cfg.MemberAttr) {
			return cfg, cfgErr("target.member_attr is not an attribute name")
		}
		if cfg.GroupScope != "" {
			return cfg, cfgErr("target.group_scope is for ad targets")
		}
	}
	if cfg.WriteChunk == 0 {
		cfg.WriteChunk = 500
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 500
	}
	if cfg.WriteChunk < 1 || cfg.WriteChunk > 5000 || cfg.PageSize < 1 || cfg.PageSize > 5000 {
		return cfg, cfgErr("target.write_chunk and target.page_size are from 1 to 5000")
	}
	if len(cfg.EmptyMember) > 512 {
		return cfg, cfgErr("target.empty_member is too long")
	}
	if cfg.CAPEM != "" {
		if len(cfg.CAPEM) > 64<<10 || !x509.NewCertPool().AppendCertsFromPEM([]byte(cfg.CAPEM)) {
			return cfg, cfgErr("target.ca_pem holds no PEM certificate")
		}
	}
	for k := range c.Attrs {
		if slices.Contains(protectedAttr, strings.ToLower(k)) {
			return cfg, cfgErr("attrs: %q is set by the target and cannot be configured", k)
		}
	}
	return cfg, nil
}

// ---------------------------------------------------------------- connection

const (
	ldapScopeBase = ldap.ScopeBaseObject
	ldapScopeSub  = ldap.ScopeWholeSubtree
)

type ldapAttr struct {
	Name string
	Vals []string
}

type ldapEntry struct {
	DN    string
	Attrs []ldapAttr
}

// ldapChange is one modification: Op is "add", "delete" or "replace".
type ldapChange struct {
	Op   string
	Attr string
	Vals []string
}

// ldapConn is the part of an LDAP connection the target uses. The real one
// wraps go-ldap; tests use an in-memory directory.
type ldapConn interface {
	Search(base string, scope int, filter string, attrs []string) ([]ldapEntry, error)
	Add(dn string, attrs []ldapAttr) error
	Modify(dn string, changes []ldapChange) error
	Del(dn string) error
	Close() error
}

type goLDAP struct {
	l        *ldap.Conn
	pageSize uint32
}

func (c *goLDAP) Search(base string, scope int, filter string, attrs []string) ([]ldapEntry, error) {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	var res *ldap.SearchResult
	var err error
	if scope == ldapScopeBase {
		res, err = c.l.Search(req)
	} else {
		res, err = c.l.SearchWithPaging(req, c.pageSize)
	}
	if err != nil {
		return nil, err
	}
	out := make([]ldapEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		le := ldapEntry{DN: e.DN}
		for _, a := range e.Attributes {
			le.Attrs = append(le.Attrs, ldapAttr{Name: a.Name, Vals: a.Values})
		}
		out = append(out, le)
	}
	return out, nil
}

func (c *goLDAP) Add(dn string, attrs []ldapAttr) error {
	req := ldap.NewAddRequest(dn, nil)
	for _, a := range attrs {
		req.Attribute(a.Name, a.Vals)
	}
	return c.l.Add(req)
}

func (c *goLDAP) Modify(dn string, changes []ldapChange) error {
	req := ldap.NewModifyRequest(dn, nil)
	for _, ch := range changes {
		switch ch.Op {
		case "add":
			req.Add(ch.Attr, ch.Vals)
		case "delete":
			req.Delete(ch.Attr, ch.Vals)
		default:
			req.Replace(ch.Attr, ch.Vals)
		}
	}
	return c.l.Modify(req)
}

func (c *goLDAP) Del(dn string) error { return c.l.Del(ldap.NewDelRequest(dn, nil)) }
func (c *goLDAP) Close() error        { return c.l.Close() }

const ldapTimeout = 30 * time.Second

// dialLDAP connects through the safehttp dialer, secures the connection (LDAPS
// or StartTLS) and binds. A password is required: an empty one would make the
// directory treat the bind as anonymous.
func dialLDAP(ctx context.Context, spec TargetSpec, cfg ldapCfg) (ldapConn, error) {
	if spec.Deps.Dial == nil {
		return nil, errors.New("LDAP targets are unavailable: no address-checked dialer is configured")
	}
	password := spec.Secret["bind_password"]
	if password == "" {
		return nil, cfgErr("secret.bind_password is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, cfgErr("target.url is invalid")
	}
	port := u.Port()
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}
	if cfg.CAPEM != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(cfg.CAPEM))
		tlsCfg.RootCAs = pool
	}
	raw, err := spec.Deps.Dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	var nc net.Conn = raw
	isTLS := false
	if cfg.Security == "ldaps" {
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		nc, isTLS = tc, true
	}
	l := ldap.NewConn(nc, isTLS)
	l.Start()
	l.SetTimeout(ldapTimeout)
	if cfg.Security == "starttls" {
		if err := l.StartTLS(tlsCfg); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	}
	if err := l.Bind(cfg.BindDN, password); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("bind: %w", err)
	}
	return &goLDAP{l: l, pageSize: uint32(cfg.PageSize)}, nil // #nosec G115 -- PageSize is validated to 1..5000
}

func openLDAP(ctx context.Context, spec TargetSpec) (Provisioner, error) {
	cfg, err := parseLDAPConfig(spec.Type, spec.Common, spec.Deps)
	if err != nil {
		return nil, err
	}
	conn, err := dialLDAP(ctx, spec, cfg)
	if err != nil {
		return nil, err
	}
	return newLDAPTarget(spec.Type, cfg, spec.Common, conn), nil
}

// ---------------------------------------------------------------- the target

type ldapTarget struct {
	typ      string
	cfg      ldapCfg
	conn     ldapConn
	attrKeys []string
	nameAttr string
}

func newLDAPTarget(typ string, cfg ldapCfg, c *Compiled, conn ldapConn) *ldapTarget {
	t := &ldapTarget{typ: typ, cfg: cfg, conn: conn, attrKeys: c.AttrKeys(), nameAttr: "cn"}
	if typ == TypeAD {
		t.nameAttr = "sAMAccountName"
	}
	return t
}

func (t *ldapTarget) Capabilities() Capabilities {
	return Capabilities{Groups: true, Memberships: true, Incremental: true, MaxBatch: 50, Readable: true, ChangeTokens: true}
}

func (t *ldapTarget) Close() error { return t.conn.Close() }

func (t *ldapTarget) classFilter() string {
	return "(objectClass=" + ldap.EscapeFilter(t.cfg.ObjectClass) + ")"
}

func (t *ldapTarget) wanted(extra ...string) []string {
	out := []string{t.nameAttr, t.cfg.MemberAttr, "modifyTimestamp"}
	out = append(out, t.attrKeys...)
	return append(out, extra...)
}

func (t *ldapTarget) dn(name string) string { return "cn=" + EscapeDN(name) + "," + t.cfg.BaseDN }

func attrVals(e ldapEntry, name string) []string {
	for _, a := range e.Attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Vals
		}
	}
	return nil
}

// parseRange reads the "lo-hi" of an attribute option "range=lo-hi" (hi may be "*").
func parseRange(opt string) (lo int, hi string, ok bool) {
	v, found := strings.CutPrefix(strings.ToLower(opt), "range=")
	if !found {
		return 0, "", false
	}
	l, h, found := strings.Cut(v, "-")
	if !found {
		return 0, "", false
	}
	n, err := strconv.Atoi(l)
	if err != nil || n < 0 {
		return 0, "", false
	}
	if h != "*" {
		if m, err := strconv.Atoi(h); err != nil || m < n {
			return 0, "", false
		}
	}
	return n, h, true
}

// members returns every value of the member attribute of e, following ranged
// retrieval until the server says "*".
func (t *ldapTarget) members(e ldapEntry) ([]string, error) {
	var out []string
	next := -1
	collect := func(a ldapAttr) error {
		base, opt, hasOpt := strings.Cut(a.Name, ";")
		if !strings.EqualFold(base, t.cfg.MemberAttr) {
			return nil
		}
		out = append(out, a.Vals...)
		if !hasOpt {
			return nil
		}
		_, hi, ok := parseRange(opt)
		if !ok {
			return fmt.Errorf("%s: unexpected attribute option %q", e.DN, opt)
		}
		if hi != "*" {
			n, _ := strconv.Atoi(hi)
			next = n + 1
		}
		return nil
	}
	for _, a := range e.Attrs {
		if err := collect(a); err != nil {
			return nil, err
		}
	}
	for rounds := 0; next >= 0; rounds++ {
		if rounds > 100_000 {
			return nil, fmt.Errorf("%s: ranged retrieval does not end", e.DN)
		}
		prev := next
		next = -1
		es, err := t.conn.Search(e.DN, ldapScopeBase, "(objectClass=*)", []string{fmt.Sprintf("%s;range=%d-*", t.cfg.MemberAttr, prev)})
		if err != nil {
			return nil, err
		}
		if len(es) != 1 {
			return nil, fmt.Errorf("%s: ranged retrieval returned %d entries", e.DN, len(es))
		}
		before := len(out)
		for _, a := range es[0].Attrs {
			if err := collect(a); err != nil {
				return nil, err
			}
		}
		if next >= 0 && (next <= prev || len(out) == before) {
			return nil, fmt.Errorf("%s: ranged retrieval made no progress at %d", e.DN, prev)
		}
	}
	if t.cfg.EmptyMember != "" {
		out = slices.DeleteFunc(out, func(m string) bool { return NormMember(m) == NormMember(t.cfg.EmptyMember) })
	}
	return out, nil
}

func (t *ldapTarget) toGroup(e ldapEntry) (*TargetGroup, error) {
	names := attrVals(e, t.nameAttr)
	if len(names) == 0 {
		return nil, nil
	}
	ms, err := t.members(e)
	if err != nil {
		return nil, err
	}
	g := &TargetGroup{Ref: TargetRef{Name: names[0], ID: e.DN}, Members: ms}
	if ts := attrVals(e, "modifyTimestamp"); len(ts) > 0 {
		g.Token = ts[0]
	}
	for _, k := range t.attrKeys {
		if v := attrVals(e, k); len(v) > 0 {
			if g.Attrs == nil {
				g.Attrs = map[string][]string{}
			}
			g.Attrs[k] = v
		}
	}
	return g, nil
}

func (t *ldapTarget) ReadAll(ctx context.Context, _ Scope) (TargetState, error) {
	st := NewState()
	es, err := t.conn.Search(t.cfg.BaseDN, ldapScopeSub, t.classFilter(), t.wanted())
	if err != nil {
		return st, err
	}
	for _, e := range es {
		g, err := t.toGroup(e)
		if err != nil {
			return st, err
		}
		if g != nil {
			st.Groups[Key(g.Ref.Name)] = g
		}
	}
	return st, ctx.Err()
}

func (t *ldapTarget) Read(ctx context.Context, refs []TargetRef) (TargetState, error) {
	st := NewState()
	for _, r := range refs {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		var es []ldapEntry
		if r.ID != "" {
			var err error
			es, err = t.conn.Search(r.ID, ldapScopeBase, t.classFilter(), t.wanted())
			if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return st, err
			}
		}
		if len(es) == 0 {
			var err error
			filter := "(&" + t.classFilter() + "(" + t.nameAttr + "=" + ldap.EscapeFilter(r.Name) + "))"
			if es, err = t.conn.Search(t.cfg.BaseDN, ldapScopeSub, filter, t.wanted()); err != nil {
				return st, err
			}
		}
		for _, e := range es {
			g, err := t.toGroup(e)
			if err != nil {
				return st, err
			}
			if g != nil && Key(g.Ref.Name) == Key(r.Name) {
				st.Groups[Key(r.Name)] = g
				break
			}
		}
	}
	return st, nil
}

// Tokens implements TokenReader with modifyTimestamp.
func (t *ldapTarget) Tokens(ctx context.Context, _ Scope) (map[string]string, error) {
	es, err := t.conn.Search(t.cfg.BaseDN, ldapScopeSub, t.classFilter(), []string{t.nameAttr, "modifyTimestamp"})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(es))
	for _, e := range es {
		if n := attrVals(e, t.nameAttr); len(n) > 0 {
			tok := ""
			if ts := attrVals(e, "modifyTimestamp"); len(ts) > 0 {
				tok = ts[0]
			}
			out[Key(n[0])] = tok
		}
	}
	return out, ctx.Err()
}

func (t *ldapTarget) Apply(ctx context.Context, ops []Op) ([]OpResult, error) {
	out := make([]OpResult, len(ops))
	for i, op := range ops {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		out[i] = OpResult{ID: op.ID, Ref: op.Ref}
		ref, err := t.apply(op)
		if ref.ID != "" {
			out[i].Ref = ref
		}
		out[i].Err = err
	}
	return out, nil
}

var adBadName = regexp.MustCompile(`["/\\\[\]:;|=,+*?<>]`)

func (t *ldapTarget) apply(op Op) (TargetRef, error) {
	ref := op.Ref
	dn := ref.ID
	if dn == "" {
		dn = t.dn(ref.Name)
	}
	switch op.Kind {
	case OpCreate:
		if t.typ == TypeAD && (len(ref.Name) > 64 || adBadName.MatchString(ref.Name)) {
			return ref, fmt.Errorf("%q is not a valid sAMAccountName (at most 64 characters, none of \" / \\ [ ] : ; | = , + * ? < >): shorten it with truncateHash in group_name", ref.Name)
		}
		classes := []string{"top", t.cfg.ObjectClass}
		attrs := []ldapAttr{{"objectClass", classes}, {"cn", []string{ref.Name}}}
		switch {
		case t.typ == TypeAD:
			attrs = append(attrs, ldapAttr{"sAMAccountName", []string{ref.Name}}, ldapAttr{"groupType", []string{adGroupType[t.cfg.GroupScope]}})
		case t.nameAttr != "cn":
			attrs = append(attrs, ldapAttr{t.nameAttr, []string{ref.Name}})
		}
		keys := make([]string, 0, len(op.Attrs))
		for k := range op.Attrs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			attrs = append(attrs, ldapAttr{k, op.Attrs[k]})
		}
		n := min(len(op.Add), t.cfg.WriteChunk)
		initial, rest := op.Add[:n], op.Add[n:]
		if len(initial) == 0 && t.cfg.EmptyMember != "" {
			initial = []string{t.cfg.EmptyMember}
		}
		if len(initial) > 0 {
			attrs = append(attrs, ldapAttr{t.cfg.MemberAttr, initial})
		}
		if err := t.conn.Add(dn, attrs); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return ref, err
		}
		ref.ID = dn
		return ref, t.changeMembers(dn, rest, nil)
	case OpUpdate:
		var changes []ldapChange
		keys := make([]string, 0, len(op.Attrs))
		for k := range op.Attrs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			changes = append(changes, ldapChange{Op: "replace", Attr: k, Vals: op.Attrs[k]})
		}
		if len(changes) == 0 {
			return ref, nil
		}
		return ref, t.conn.Modify(dn, changes)
	case OpMembers:
		return ref, t.changeMembers(dn, op.Add, op.Remove)
	case OpDelete:
		if err := t.conn.Del(dn); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return ref, err
		}
		return ref, nil
	}
	return ref, fmt.Errorf("unknown op %q", op.Kind)
}

// changeMembers adds and removes members in modify requests of at most
// WriteChunk values (range-limited writes for large groups). Adds go first; a
// value that is already there, or already gone, is not an error.
func (t *ldapTarget) changeMembers(dn string, add, remove []string) error {
	for chunk := range slices.Chunk(add, t.cfg.WriteChunk) {
		err := t.conn.Modify(dn, []ldapChange{{Op: "add", Attr: t.cfg.MemberAttr, Vals: chunk}})
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
			return err
		}
	}
	if len(remove) > 0 && t.cfg.EmptyMember != "" {
		err := t.conn.Modify(dn, []ldapChange{{Op: "add", Attr: t.cfg.MemberAttr, Vals: []string{t.cfg.EmptyMember}}})
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
			return err
		}
	}
	for chunk := range slices.Chunk(remove, t.cfg.WriteChunk) {
		err := t.conn.Modify(dn, []ldapChange{{Op: "delete", Attr: t.cfg.MemberAttr, Vals: chunk}})
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
			return err
		}
	}
	return nil
}
