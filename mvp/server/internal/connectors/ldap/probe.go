// Package ldap is the real connectors.Prober for the generic LDAP readiness
// template (OpenLDAP, 389-DS, LLDAP; design
// docs/design/deployment-readiness.md §3.8 and §5.4).
//
// It is read-only by construction. Every operation goes through the narrow
// client in client.go, which can only simple-bind, search, ask Who Am I
// (RFC 4532), negotiate StartTLS and close. It has no Add, Modify, Delete,
// ModifyDN, Compare or arbitrary extended operation, and
// TestProbers_ReadOnly scans the package for them. Attribute reads that only
// count use the LDAP "types only" flag, so values never leave the server.
//
// The network path is internal/safedial: address policy, ports 389 and 636
// only, TLS 1.2 or later. A password is sent only on a connection that
// safedial reports as Secure; a server that refuses StartTLS is never sent
// credentials.
//
// What it does not do: reach private directories from a cloud deployment (the
// Directory Agent, DR-11, runs this same Prober inside the customer network
// with its own allowlist, and Tessera sends it typed operations), or verify
// what the server cannot answer. LLDAP and OpenLDAP have no Get Effective
// Rights control, and a server may have no Who Am I; those checks report
// "unsupported" (skipped) and need an attestation, never a pass.
package ldap

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// Bounds (design §5.2).
const (
	CheckTimeout   = 10 * time.Second
	MaxConcurrent  = 2
	pageSize       = 100
	maxPages       = connectors.MaxSample / pageSize
	searchTimeSecs = 8
)

// Well-known OIDs.
const (
	oidPagedResults = "1.2.840.113556.1.4.319"
	oidSyncRequest  = "1.3.6.1.4.1.4203.1.9.1.1" // syncrepl, RFC 4533
	oidGER          = "1.3.6.1.4.1.42.2.27.9.5.2"
	oidWhoAmI       = "1.3.6.1.4.1.4203.1.11.3"
)

// Secret holds the bind password. It never prints, logs or marshals.
type Secret string

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "ldap.Secret([redacted])" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Config is one connection's non-secret settings plus its credential.
type Config struct {
	Host   string
	Port   int // 636 (LDAPS) or 389 (StartTLS required)
	BindDN string
	// Password is the bind password, opened from the sealed secret just for
	// this run.
	Password Secret
	BaseDNs  []string
	// UserFilter selects people for the sample search. Empty means
	// (objectClass=inetOrgPerson).
	UserFilter string
	// RootCAs is the connection's CA bundle (nil: system roots).
	RootCAs *x509.CertPool
	// RootDNs are extra bind DNs to treat as root (the site's rootDN).
	RootDNs []string
	// Dialer is the safedial dialer; required.
	Dialer *safedial.Dialer
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Prober implements connectors.Prober against one LDAP server.
type Prober struct {
	cfg Config
	sem chan struct{}

	mu   sync.Mutex
	root *rootDSE
}

var _ connectors.Prober = (*Prober)(nil)

// New returns a Prober. It validates the config and opens nothing.
func New(cfg Config) (*Prober, error) {
	if cfg.Dialer == nil {
		return nil, errors.New("ldap: a safedial.Dialer is required")
	}
	if cfg.Host == "" {
		return nil, errors.New("ldap: host is required")
	}
	if cfg.Port != safedial.PortLDAPS && cfg.Port != safedial.PortStartTLS {
		return nil, fmt.Errorf("ldap: port must be %d (StartTLS) or %d (LDAPS)", safedial.PortStartTLS, safedial.PortLDAPS)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Prober{cfg: cfg, sem: make(chan struct{}, MaxConcurrent)}, nil
}

// ---------------------------------------------------------------- sessions

type session struct {
	c    *client
	conn *safedial.Conn
	stop func() bool
	rel  func()
}

func (s *session) close() {
	s.stop()
	s.c.close()
	s.rel()
}

// open dials and secures a connection. With bind it also binds as the
// configured identity (only ever over a secure connection). inspect opens a
// connection whose chain is not verified, for reading the handshake only.
func (p *Prober) open(ctx context.Context, bind, inspect bool) (*session, error) {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	rel := func() { <-p.sem }
	conn, err := p.cfg.Dialer.Dial(ctx, p.cfg.Host, p.cfg.Port, inspect)
	if err != nil {
		rel()
		if errors.Is(err, safedial.ErrBlockedAddress) || errors.Is(err, safedial.ErrPort) || errors.Is(err, safedial.ErrHost) {
			return nil, fmt.Errorf("%w: %v", connectors.ErrTargetNotAllowed, err)
		}
		return nil, err
	}
	c := newClient(conn.Conn, conn.Secure())
	s := &session{c: c, conn: conn, rel: rel}
	s.stop = context.AfterFunc(ctx, c.close) // a cancelled check closes the socket
	if conn.StartTLSPort {
		if err := c.startTLS(conn.TLSConfig()); err != nil {
			s.close()
			return nil, fmt.Errorf("%w: StartTLS: %w", safedial.ErrNoTLS, err)
		}
		st, ok := c.tlsState()
		if !ok {
			s.close()
			return nil, safedial.ErrNoTLS
		}
		if err := conn.SetTLS(st); err != nil {
			s.close()
			return nil, err
		}
	}
	if !conn.Secure() { // never send a credential in clear text
		s.close()
		return nil, safedial.ErrNoTLS
	}
	if bind {
		if p.cfg.BindDN == "" || p.cfg.Password == "" {
			s.close()
			return nil, errBind
		}
		if err := c.bind(p.cfg.BindDN, string(p.cfg.Password)); err != nil {
			s.close()
			if isCode(err, goldap.LDAPResultInvalidCredentials, goldap.LDAPResultInappropriateAuthentication,
				goldap.LDAPResultInsufficientAccessRights, goldap.LDAPResultNoSuchObject, goldap.LDAPResultAuthMethodNotSupported) {
				return nil, errBind
			}
			return nil, err
		}
	}
	return s, nil
}

var errBind = errors.New("ldap: bind refused")

func isCode(err error, codes ...uint16) bool {
	var le *goldap.Error
	if !errors.As(err, &le) {
		return false
	}
	return slices.Contains(codes, le.ResultCode)
}

// answered reports whether err is the server's LDAP result (it answered and
// refused) rather than a transport failure.
func answered(err error) bool {
	var le *goldap.Error
	return errors.As(err, &le)
}

// ---------------------------------------------------------------- Connect

// Connect opens TCP and TLS and reports the handshake. A server with no TLS
// on the port is reachable with an empty TLS version, which fails the TLS
// checks; an address the policy refuses is an error.
func (p *Prober) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	s, err := p.open(ctx, false, true)
	switch {
	case errors.Is(err, safedial.ErrHandshake), errors.Is(err, safedial.ErrNoTLS):
		return connectors.ConnInfo{Reachable: true}, nil
	case err != nil:
		return connectors.ConnInfo{}, err
	}
	defer s.close()
	st, ok := s.conn.TLSState()
	if !ok {
		return connectors.ConnInfo{Reachable: true}, nil
	}
	rep := safedial.Inspect(st, p.cfg.Host, p.cfg.RootCAs, p.cfg.Now())
	return connectors.ConnInfo{Reachable: true, TLSVersion: rep.TLSVersion, ChainValid: rep.ChainValid,
		HostnameMatch: rep.HostnameMatch, NotAfter: rep.NotAfter, Issuer: rep.Issuer}, nil
}

// ---------------------------------------------------------------- Authenticate

// lldapAdminGroup is the LLDAP group that grants full write access; a service
// account belongs in lldap_strict_readonly instead.
const lldapAdminGroup = "lldap_admin"

// Authenticate simple-binds and reports who the server says we are. An empty
// password is never sent (it would be an anonymous bind that "succeeds").
func (p *Prober) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	info := connectors.AuthInfo{Mode: "simple_bind", Identity: p.cfg.BindDN}
	s, err := p.open(ctx, true, false)
	if errors.Is(err, errBind) {
		return info, nil
	}
	if err != nil {
		return info, err
	}
	defer s.close()
	info.OK = true

	identity := p.cfg.BindDN
	authz, err := s.c.whoAmI()
	switch {
	case err == nil:
		switch {
		case strings.HasPrefix(strings.ToLower(authz), "dn:"):
			identity = strings.TrimSpace(authz[3:])
		case authz == "":
			info.OK = false // bound anonymously: the credential was not honoured
		}
		info.Identity = identity
	case answered(err):
		info.IdentityUnverified = true // no Who Am I on this server
	default:
		return info, err
	}
	if !info.OK {
		return info, nil
	}

	roots := p.rootDNs(s)
	if slices.ContainsFunc(roots, func(r string) bool { return sameDN(r, identity) }) {
		info.RootIdentity = true
	}
	// The bound entry's own group membership and password expiry: a read of
	// one base-scope entry.
	if e := s.c.readOne(identity, "memberOf", "pwdEndTime", "passwordExpirationTime"); e != nil {
		for _, m := range e.GetEqualFoldAttributeValues("memberOf") {
			if isGroupCN(m, lldapAdminGroup) {
				info.RootIdentity = true
			}
		}
		for _, a := range []string{"pwdEndTime", "passwordExpirationTime"} {
			if t, ok := parseGeneralized(e.GetEqualFoldAttributeValue(a)); ok {
				info.ExpiresAt = &t
				break
			}
		}
	}
	if info.RootIdentity {
		info.IdentityUnverified = false // the verdict does not depend on Who Am I
	}
	return info, nil
}

// rootDNs lists identities that bypass access control: the 389-DS Directory
// Manager, configured root DNs, and the rootDN the server reports in its
// configuration (readable only by the root itself or an administrator).
func (p *Prober) rootDNs(s *session) []string {
	roots := append([]string{"cn=Directory Manager"}, p.cfg.RootDNs...)
	for _, a := range []string{"olcRootDN", "nsslapd-rootdn"} {
		res, _ := s.c.search(&goldap.SearchRequest{BaseDN: "cn=config", Scope: goldap.ScopeWholeSubtree, SizeLimit: 20,
			TimeLimit: searchTimeSecs, Filter: "(" + a + "=*)", Attributes: []string{a}})
		if res == nil {
			continue
		}
		for _, e := range res.Entries {
			roots = append(roots, e.GetEqualFoldAttributeValues(a)...)
		}
	}
	return roots
}

func sameDN(a, b string) bool {
	da, err1 := goldap.ParseDN(a)
	db, err2 := goldap.ParseDN(b)
	if err1 != nil || err2 != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return da.EqualFold(db)
}

// isGroupCN reports whether a group DN's first RDN is cn=name.
func isGroupCN(dn, name string) bool {
	d, err := goldap.ParseDN(dn)
	if err != nil || len(d.RDNs) == 0 || len(d.RDNs[0].Attributes) == 0 {
		return false
	}
	a := d.RDNs[0].Attributes[0]
	return strings.EqualFold(a.Type, "cn") && strings.EqualFold(a.Value, name)
}

func parseGeneralized(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	if i := strings.IndexAny(v, ".,"); i > 0 {
		v = v[:i] + "Z"
	}
	for _, l := range []string{"20060102150405Z", "20060102150405Z0700"} {
		if t, err := time.Parse(l, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------- root DSE

type rootDSE struct {
	NamingContexts  []string
	Controls        []string
	Extensions      []string
	Subschema       string
	Vendor, Version string
	Changelog       string
}

func (r *rootDSE) hasControl(oid string) bool   { return slices.Contains(r.Controls, oid) }
func (r *rootDSE) hasExtension(oid string) bool { return slices.Contains(r.Extensions, oid) }

// rootDSE reads (once per run) the server's root DSE.
func (p *Prober) rootDSE(ctx context.Context) (*rootDSE, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.root != nil {
		return p.root, nil
	}
	s, err := p.bound(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	res, err := s.c.search(&goldap.SearchRequest{BaseDN: "", Scope: goldap.ScopeBaseObject, SizeLimit: 1, TimeLimit: searchTimeSecs,
		Filter: "(objectClass=*)", Attributes: []string{"namingContexts", "supportedControl", "supportedExtension",
			"subschemaSubentry", "vendorName", "vendorVersion", "changelog"}})
	if err != nil {
		return nil, err
	}
	r := &rootDSE{}
	if len(res.Entries) > 0 {
		e := res.Entries[0]
		r.NamingContexts = e.GetEqualFoldAttributeValues("namingContexts")
		r.Controls = e.GetEqualFoldAttributeValues("supportedControl")
		r.Extensions = e.GetEqualFoldAttributeValues("supportedExtension")
		r.Subschema = e.GetEqualFoldAttributeValue("subschemaSubentry")
		r.Vendor = e.GetEqualFoldAttributeValue("vendorName")
		r.Version = e.GetEqualFoldAttributeValue("vendorVersion")
		r.Changelog = e.GetEqualFoldAttributeValue("changelog")
	}
	p.root = r
	return r, nil
}

// bound opens a secure, bound session; a refused bind is an error here
// (Authenticate is where it is reported).
func (p *Prober) bound(ctx context.Context) (*session, error) { return p.open(ctx, true, false) }

// RootInfo reads the root DSE and, when advertised, counts the schema's
// custom attribute types.
func (p *Prober) RootInfo(ctx context.Context) (connectors.RootInfo, error) {
	r, err := p.rootDSE(ctx)
	if err != nil {
		return connectors.RootInfo{}, err
	}
	info := connectors.RootInfo{Servers: 1, Domains: slices.Clone(r.NamingContexts), ConfiguredDomains: slices.Clone(r.NamingContexts)}
	if r.Vendor != "" {
		info.Capabilities = append(info.Capabilities, "vendor:"+r.Vendor)
	}
	if r.Subschema == "" {
		return info, nil
	}
	s, err := p.bound(ctx)
	if err != nil {
		return info, err
	}
	defer s.close()
	res, err := s.c.search(&goldap.SearchRequest{BaseDN: r.Subschema, Scope: goldap.ScopeBaseObject, SizeLimit: 1,
		TimeLimit: searchTimeSecs, Filter: "(objectClass=*)", Attributes: []string{"attributeTypes"}})
	if err != nil {
		if answered(err) { // schema not readable by this identity: nothing to count
			return info, nil
		}
		return info, err
	}
	if len(res.Entries) > 0 {
		for _, def := range res.Entries[0].GetEqualFoldAttributeValues("attributeTypes") {
			if isCustomAttributeType(def) {
				info.CustomAttributes++
			}
		}
	}
	return info, nil
}

// standardArcs are OID prefixes of attribute types that ship with directory
// servers or standards (X.500, cosine, nis, entryUUID, ppolicy, Netscape,
// OpenLDAP, Sun, Novell, Microsoft, Samba). Anything else counts as custom.
var standardArcs = []string{
	"2.5.", "0.9.2342.19200300.", "1.3.6.1.1.", "1.3.6.1.4.1.1466.", "1.3.6.1.4.1.4203.", "1.3.6.1.4.1.42.2.27.",
	"2.16.840.1.113730.", "2.16.840.1.113719.", "1.3.6.1.4.1.250.", "1.2.840.113556.", "1.3.6.1.4.1.7165.",
	"1.3.6.1.4.1.2428.", "1.3.6.1.4.1.5322.", "2.16.840.1.113894.", "1.3.6.1.4.1.453.", "2.16.840.1.113549.",
	"1.3.18.0.2.4.", "1.2.840.113549.", "1.3.6.1.4.1.18060.", "1.3.6.1.4.1.6572.", "2.16.840.1.113556.",
}

func isCustomAttributeType(def string) bool {
	def = strings.TrimSpace(def)
	i := strings.Index(def, "(")
	if i < 0 {
		return false
	}
	fields := strings.Fields(def[i+1:])
	if len(fields) == 0 {
		return false
	}
	oid := strings.Trim(fields[0], "'")
	if oid == "" || (oid[0] < '0' || oid[0] > '9') {
		return false
	}
	for _, a := range standardArcs {
		if strings.HasPrefix(oid+".", a) || strings.HasPrefix(oid, a) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- ObjectExists

// ObjectExists is a base-scope read of one DN that requests no attributes.
// A DN the bind identity cannot read answers the same as a missing one.
func (p *Prober) ObjectExists(ctx context.Context, ref string) (bool, error) {
	if _, err := goldap.ParseDN(ref); err != nil {
		return false, nil
	}
	s, err := p.bound(ctx)
	if err != nil {
		return false, err
	}
	defer s.close()
	res, err := s.c.search(&goldap.SearchRequest{BaseDN: ref, Scope: goldap.ScopeBaseObject, SizeLimit: 1, TimeLimit: searchTimeSecs,
		Filter: "(objectClass=*)", Attributes: []string{"1.1"}})
	if err != nil {
		if isCode(err, goldap.LDAPResultNoSuchObject, goldap.LDAPResultInsufficientAccessRights) {
			return false, nil
		}
		return false, err
	}
	return len(res.Entries) > 0, nil
}

// ---------------------------------------------------------------- Sample

// Object classes by role. Group classes name the attribute that holds
// members; LLDAP's groupOfUniqueNames answers member as well as uniqueMember.
var (
	personClasses = map[string]bool{"inetorgperson": true, "posixaccount": true, "person": true, "organizationalperson": true}
	groupMembers  = map[string][]string{
		"groupofnames":       {"member"},
		"groupofuniquenames": {"uniqueMember", "member"},
		"posixgroup":         {"memberUid"},
	}
	// aliases are attributes that satisfy a required one (389-DS nsUniqueId
	// may stand in for entryUUID).
	aliases = map[string][]string{"entryuuid": {"nsUniqueId"}}
	// hostClasses are entries a people filter must not select.
	hostClasses = []string{"computer", "device", "ipHost"}
)

// Sample reads at most MaxSample objects per class and returns counts only.
func (p *Prober) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	limit := q.Limit
	if limit <= 0 || limit > connectors.MaxSample {
		limit = connectors.MaxSample
	}
	stats := connectors.SampleStats{PerClass: map[string]int{}, AttrFill: map[string]int{}}
	switch q.Op {
	case "search", "classes", "attr", "page":
	default:
		return stats, connectors.ErrUnsupported
	}
	s, err := p.bound(ctx)
	if err != nil {
		return stats, err
	}
	defer s.close()
	if len(p.cfg.BaseDNs) == 0 {
		return stats, nil
	}
	switch q.Op {
	case "search":
		return p.sampleSearch(s, q, limit, stats)
	case "classes":
		return p.sampleClasses(s, q, limit, stats)
	case "attr":
		return p.sampleAttr(s, q, limit, stats)
	}
	return p.samplePage(s, q, limit, stats)
}

// count searches every base DN and returns the entries with only attrs (types
// only: no values), at most limit in total. Unreadable bases count as empty.
func (p *Prober) count(s *session, filter string, attrs []string, limit int) ([]*goldap.Entry, bool, error) {
	var out []*goldap.Entry
	hit := false
	for _, base := range p.cfg.BaseDNs {
		if len(out) >= limit {
			break
		}
		res, err := s.c.search(&goldap.SearchRequest{BaseDN: base, Scope: goldap.ScopeWholeSubtree, SizeLimit: limit - len(out),
			TimeLimit: searchTimeSecs, TypesOnly: true, Filter: filter, Attributes: attrs})
		if res != nil {
			out = append(out, res.Entries...)
		}
		if err != nil {
			switch {
			case isCode(err, goldap.LDAPResultSizeLimitExceeded):
				hit = true
			case isCode(err, goldap.LDAPResultNoSuchObject, goldap.LDAPResultInsufficientAccessRights):
			default:
				return out, hit, err
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, hit, nil
}

func (p *Prober) sampleSearch(s *session, q connectors.SampleQuery, limit int, st connectors.SampleStats) (connectors.SampleStats, error) {
	filter := q.Filter
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}
	if limit > 50 {
		limit = 50 // design §5.4: one search with sizeLimit 50
	}
	if _, err := goldap.CompileFilter(filter); err != nil {
		return st, nil // the filter check reports syntax; nothing to sample
	}
	es, hit, err := p.count(s, filter, []string{"1.1"}, limit)
	if err != nil {
		return st, err
	}
	st.Objects, st.SizeLimitHit = len(es), hit
	var hosts strings.Builder
	for _, c := range hostClasses {
		hosts.WriteString("(objectClass=" + c + ")")
	}
	hs, _, err := p.count(s, "(&"+filter+"(|"+hosts.String()+"))", []string{"1.1"}, limit)
	if err != nil {
		return st, err
	}
	st.PerClass["computer"] = len(hs)
	return st, nil
}

func (p *Prober) sampleClasses(s *session, q connectors.SampleQuery, limit int, st connectors.SampleStats) (connectors.SampleStats, error) {
	userAttrs := q.Attrs
	missing := map[string]bool{}
	seenClass := false
	for _, class := range q.Classes {
		lc := strings.ToLower(class)
		var want []string
		switch {
		case personClasses[lc]:
			want = userAttrs
		case groupMembers[lc] != nil:
			want = append([]string{"entryUUID", "cn"}, groupMembers[lc]...)
		default:
			want = []string{"entryUUID"}
		}
		req := attrsWithAliases(want)
		es, hit, err := p.count(s, "(objectClass="+goldap.EscapeFilter(class)+")", req, limit)
		if err != nil {
			return st, err
		}
		st.SizeLimitHit = st.SizeLimitHit || hit
		st.PerClass[class] = len(es)
		st.Objects += len(es)
		if len(es) == 0 {
			continue
		}
		seenClass = true
		fill := map[string]int{}
		for _, e := range es {
			for _, a := range want {
				if hasAttr(e, a) {
					fill[a]++
					st.AttrFill[a]++
				}
			}
		}
		if members := groupMembers[lc]; members != nil {
			// Any one membership attribute satisfies the group's member
			// requirement (LLDAP: member or uniqueMember).
			any := 0
			for _, m := range members {
				any += fill[m]
			}
			for _, m := range members {
				delete(fill, m)
			}
			if any == 0 {
				missing[members[0]] = true
			}
		}
		for _, a := range want {
			if groupMembers[lc] != nil && slices.Contains(groupMembers[lc], a) {
				continue
			}
			if fill[a] == 0 {
				missing[a] = true
			}
		}
	}
	if !seenClass {
		missing["(no entries readable in the listed classes)"] = true
	}
	for a := range missing {
		st.Missing = append(st.Missing, a)
	}
	slices.Sort(st.Missing)
	return st, nil
}

func (p *Prober) sampleAttr(s *session, q connectors.SampleQuery, limit int, st connectors.SampleStats) (connectors.SampleStats, error) {
	if len(q.Attrs) == 0 || q.Attrs[0] == "" {
		return st, nil
	}
	attr := q.Attrs[0]
	filter := q.Filter
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}
	es, hit, err := p.count(s, filter, attrsWithAliases([]string{attr}), limit)
	if err != nil {
		return st, err
	}
	st.Objects, st.SizeLimitHit = len(es), hit
	for _, e := range es {
		if hasAttr(e, attr) {
			st.AttrFill[attr]++
		}
	}
	return st, nil
}

// samplePage reads up to maxPages pages of pageSize with the paged-results
// control (RFC 2696), within the 500-object bound. SizeLimitHit is the
// server's sizeLimitExceeded; PagedBeyond is true when the read was not cut
// short: it ended normally, or more pages were still coming at the bound.
func (p *Prober) samplePage(s *session, q connectors.SampleQuery, limit int, st connectors.SampleStats) (connectors.SampleStats, error) {
	filter := q.Filter
	if filter == "" {
		filter = "(objectClass=*)"
	}
	base := p.cfg.BaseDNs[0]
	var cookie []byte
	for page := 0; page < maxPages && st.Objects < limit; page++ {
		pc := goldap.NewControlPaging(pageSize)
		pc.SetCookie(cookie)
		res, err := s.c.search(&goldap.SearchRequest{BaseDN: base, Scope: goldap.ScopeWholeSubtree, TimeLimit: searchTimeSecs,
			TypesOnly: true, Filter: filter, Attributes: []string{"1.1"}, Controls: []goldap.Control{pc}})
		if res != nil {
			st.Objects += len(res.Entries)
		}
		if err != nil {
			if isCode(err, goldap.LDAPResultSizeLimitExceeded) {
				st.SizeLimitHit = true
				return st, nil
			}
			if isCode(err, goldap.LDAPResultNoSuchObject, goldap.LDAPResultInsufficientAccessRights) {
				return st, nil
			}
			return st, err
		}
		next := []byte(nil)
		if rc, ok := goldap.FindControl(res.Controls, goldap.ControlTypePaging).(*goldap.ControlPaging); ok {
			next = rc.Cookie
		}
		if len(next) == 0 {
			st.PagedBeyond = true // read to the end without truncation
			return st, nil
		}
		cookie = next
	}
	st.PagedBeyond = true // the bound was reached with pages still available
	return st, nil
}

func attrsWithAliases(want []string) []string {
	out := slices.Clone(want)
	for _, a := range want {
		out = append(out, aliases[strings.ToLower(a)]...)
	}
	return out
}

func hasAttr(e *goldap.Entry, attr string) bool {
	names := append([]string{attr}, aliases[strings.ToLower(attr)]...)
	for _, n := range names {
		for _, a := range e.Attributes {
			if strings.EqualFold(a.Name, n) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- EffectiveRights

// EffectiveRights reads the Get Effective Rights control (389-DS, Sun/Oracle
// DSEE) on up to ten sampled entries: what the bound identity could write,
// read from the server, never tried. Servers without the control report
// Unsupported.
func (p *Prober) EffectiveRights(ctx context.Context, _ string) (connectors.Rights, error) {
	var r connectors.Rights
	root, err := p.rootDSE(ctx)
	if err != nil {
		return r, err
	}
	if !root.hasControl(oidGER) || len(p.cfg.BaseDNs) == 0 {
		r.Unsupported = true
		return r, nil
	}
	s, err := p.bound(ctx)
	if err != nil {
		return r, err
	}
	defer s.close()
	// GetEffectiveRightsRequest ::= SEQUENCE { gerAuthzID OCTET STRING }
	req := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "GER request")
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dn: "+p.cfg.BindDN, "authzId"))
	ger := goldap.NewControlString(oidGER, false, string(req.Bytes()))
	writable := map[string]bool{}
	answeredAny := false
	for _, base := range p.cfg.BaseDNs {
		res, err := s.c.search(&goldap.SearchRequest{BaseDN: base, Scope: goldap.ScopeWholeSubtree, SizeLimit: 10,
			TimeLimit: searchTimeSecs, TypesOnly: false, Filter: "(objectClass=*)",
			Attributes: []string{"1.1", "entryLevelRights", "attributeLevelRights"}, Controls: []goldap.Control{ger}})
		if res == nil && err != nil && !isCode(err, goldap.LDAPResultSizeLimitExceeded) {
			if answered(err) {
				continue
			}
			return r, err
		}
		for _, e := range res.Entries {
			el := e.GetEqualFoldAttributeValue("entryLevelRights")
			al := e.GetEqualFoldAttributeValue("attributeLevelRights")
			if el == "" && al == "" {
				continue
			}
			answeredAny = true
			for _, c := range el {
				switch c {
				case 'a':
					writable["entry:add"] = true
				case 'd':
					writable["entry:delete"] = true
				case 'n':
					writable["entry:rename"] = true
				}
			}
			for _, pair := range strings.Split(al, ",") {
				name, rights, ok := strings.Cut(strings.TrimSpace(pair), ":")
				if ok && strings.ContainsAny(rights, "wo") { // write or obliterate
					writable["attr:"+strings.ToLower(name)] = true
				}
			}
		}
	}
	if !answeredAny { // the control was advertised but not honoured
		r.Unsupported = true
		return r, nil
	}
	for k := range writable {
		r.Writable = append(r.Writable, k)
	}
	slices.Sort(r.Writable)
	return r, nil
}

// ---------------------------------------------------------------- ChangeFeed

// ChangeFeed reports how incremental sync can work: syncrepl (RFC 4533) from
// the root DSE's supported controls, the OpenLDAP accesslog database or the
// 389-DS retro changelog when its DN is readable. Otherwise only
// modifyTimestamp polling is left, which is not reported as supported.
func (p *Prober) ChangeFeed(ctx context.Context) (connectors.FeedInfo, error) {
	r, err := p.rootDSE(ctx)
	if err != nil {
		return connectors.FeedInfo{}, err
	}
	if r.hasControl(oidSyncRequest) {
		return connectors.FeedInfo{Supported: true, Mechanism: "syncrepl"}, nil
	}
	s, err := p.bound(ctx)
	if err != nil {
		return connectors.FeedInfo{}, err
	}
	defer s.close()
	cands := []struct{ dn, mech string }{}
	if r.Changelog != "" {
		cands = append(cands, struct{ dn, mech string }{r.Changelog, "retro_changelog"})
	}
	cands = append(cands, struct{ dn, mech string }{"cn=changelog", "retro_changelog"})
	for _, nc := range r.NamingContexts {
		if strings.EqualFold(strings.ReplaceAll(nc, " ", ""), "cn=accesslog") {
			cands = append(cands, struct{ dn, mech string }{nc, "accesslog"})
		}
	}
	for _, c := range cands {
		res, err := s.c.search(&goldap.SearchRequest{BaseDN: c.dn, Scope: goldap.ScopeBaseObject, SizeLimit: 1, TimeLimit: searchTimeSecs,
			Filter: "(objectClass=*)", Attributes: []string{"1.1"}})
		if err == nil && len(res.Entries) > 0 {
			return connectors.FeedInfo{Supported: true, Mechanism: c.mech}, nil
		}
		if err != nil && !answered(err) {
			return connectors.FeedInfo{}, err
		}
	}
	return connectors.FeedInfo{Supported: false, Mechanism: "modifytimestamp_polling"}, nil
}

// ---------------------------------------------------------------- RateLimits and Time

// RateLimits: LDAP servers expose no rate-limit headers.
func (p *Prober) RateLimits(context.Context) (connectors.RateInfo, error) {
	return connectors.RateInfo{}, connectors.ErrUnsupported
}

// Time reads currentTime from cn=Monitor where the server exposes it
// (OpenLDAP, 389-DS); LLDAP and others do not.
func (p *Prober) Time(ctx context.Context) (time.Time, error) {
	s, err := p.bound(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer s.close()
	res, err := s.c.search(&goldap.SearchRequest{BaseDN: "cn=Monitor", Scope: goldap.ScopeBaseObject, SizeLimit: 1, TimeLimit: searchTimeSecs,
		Filter: "(objectClass=*)", Attributes: []string{"currentTime"}})
	if err != nil {
		if answered(err) {
			return time.Time{}, connectors.ErrUnsupported
		}
		return time.Time{}, err
	}
	if len(res.Entries) > 0 {
		if t, ok := parseGeneralized(res.Entries[0].GetEqualFoldAttributeValue("currentTime")); ok {
			return t, nil
		}
	}
	return time.Time{}, connectors.ErrUnsupported
}
