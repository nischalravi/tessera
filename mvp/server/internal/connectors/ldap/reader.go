package ldap

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// Reader is a read-only connection that returns directory entries (not
// statistics, as the Prober does). The group loaders use it to read people and
// groups from LDAP and Active Directory (GR-10, design
// docs/design/groups-grouper-parity.md §9.1). It goes through the same narrow
// client as the Prober, which has no Add, Modify, Delete, ModifyDN or
// arbitrary extended operation, and through safedial: ports 389 (StartTLS
// required) and 636 (LDAPS) only, TLS 1.2 or later, blocked addresses
// refused, and the bind password is sent only on a connection safedial calls
// Secure.

// Scope is how deep a search reaches.
type Scope int

// The scopes a loader may use. Base reads one entry (the ranged retrieval of
// a long member list).
const (
	ScopeBase Scope = iota
	ScopeOne
	ScopeSub
)

// ErrTooManyEntries: a search returned more entries than the limit. It is an
// error, never a cut-off, which would look like people who left.
var ErrTooManyEntries = errors.New("ldap: the search returned more entries than the limit")

// ErrBindRefused: the directory refused the bind (wrong DN or password, or an
// account that may not bind). The message never says which.
var ErrBindRefused = errBind

// Entry is one directory entry. Attribute names are lower-case; an AD ranged
// attribute keeps its option ("member;range=0-1499").
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// First returns the first value of an attribute, or "".
func (e Entry) First(attr string) string {
	if v := e.Attrs[strings.ToLower(attr)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// ReadConfig is what a Reader needs. Password is opened from the sealed secret
// for the run and is never logged.
type ReadConfig struct {
	Host     string
	Port     int // 636 (LDAPS) or 389 (StartTLS)
	BindDN   string
	Password Secret
	// Dialer is the safedial dialer, built with the loader's CA bundle.
	Dialer *safedial.Dialer
}

// Reader reads entries over one bound connection.
type Reader struct {
	c    *client
	stop func() bool
}

// OpenReader dials, secures and binds.
func OpenReader(ctx context.Context, cfg ReadConfig) (*Reader, error) {
	if cfg.Dialer == nil {
		return nil, errors.New("ldap: a safedial.Dialer is required")
	}
	if cfg.BindDN == "" || cfg.Password == "" {
		return nil, errBind // go-ldap would send an empty password as an anonymous bind
	}
	conn, err := cfg.Dialer.Dial(ctx, cfg.Host, cfg.Port, false)
	if err != nil {
		return nil, err
	}
	c := newClient(conn.Conn, conn.Secure())
	r := &Reader{c: c}
	r.stop = context.AfterFunc(ctx, c.close) // a cancelled run closes the socket
	if conn.StartTLSPort {
		if err := c.startTLS(conn.TLSConfig()); err != nil {
			r.Close()
			return nil, fmt.Errorf("%w: StartTLS: %w", safedial.ErrNoTLS, err)
		}
		st, ok := c.tlsState()
		if !ok {
			r.Close()
			return nil, safedial.ErrNoTLS
		}
		if err := conn.SetTLS(st); err != nil {
			r.Close()
			return nil, err
		}
	}
	if !conn.Secure() { // never send a credential in clear text
		r.Close()
		return nil, safedial.ErrNoTLS
	}
	if err := c.bind(cfg.BindDN, string(cfg.Password)); err != nil {
		r.Close()
		if isCode(err, goldap.LDAPResultInvalidCredentials, goldap.LDAPResultInappropriateAuthentication,
			goldap.LDAPResultInsufficientAccessRights, goldap.LDAPResultNoSuchObject, goldap.LDAPResultAuthMethodNotSupported) {
			return nil, errBind
		}
		return nil, err
	}
	return r, nil
}

// Close ends the connection.
func (r *Reader) Close() {
	if r.stop != nil {
		r.stop()
	}
	r.c.close()
}

// Search returns the entries under base that match filter, with the named
// attributes (none: all user attributes), a page at a time (RFC 2696), and an
// error if there are more than max.
func (r *Reader) Search(ctx context.Context, base string, scope Scope, filter string, attrs []string, page, max int) ([]Entry, error) {
	if page < 1 || page > 5000 {
		page = 500
	}
	if max < 1 {
		max = 1_000_000
	}
	var s int
	switch scope {
	case ScopeBase:
		s = goldap.ScopeBaseObject
	case ScopeOne:
		s = goldap.ScopeSingleLevel
	default:
		s = goldap.ScopeWholeSubtree
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := goldap.NewSearchRequest(base, s, goldap.NeverDerefAliases, max+1, int(time.Hour/time.Second), false, filter, attrs, nil)
	res, err := r.c.l.SearchWithPaging(req, uint32(page)) // #nosec G115 -- page is 1..5000
	if res == nil && err != nil {
		if isCode(err, goldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrTooManyEntries
		}
		return nil, err
	}
	if err != nil && !isCode(err, goldap.LDAPResultSizeLimitExceeded) {
		return nil, err
	}
	if len(res.Entries) > max || isCode(err, goldap.LDAPResultSizeLimitExceeded) {
		return nil, ErrTooManyEntries
	}
	out := make([]Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		ent := Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attributes))}
		for _, a := range e.Attributes {
			ent.Attrs[strings.ToLower(a.Name)] = a.Values
		}
		out = append(out, ent)
	}
	return out, nil
}

// ValidFilter checks an LDAP search filter (RFC 4515) without sending it.
func ValidFilter(f string) error {
	if len(f) == 0 || len(f) > 2048 {
		return errors.New("a filter is 1 to 2048 characters")
	}
	if !strings.HasPrefix(f, "(") {
		return errors.New("a filter is in parentheses, such as (objectClass=person)")
	}
	if _, err := goldap.CompileFilter(f); err != nil {
		return fmt.Errorf("not a valid LDAP filter: %v", err)
	}
	return nil
}

// ValidDN checks a distinguished name (RFC 4514) without sending it.
func ValidDN(dn string) error {
	if dn == "" || len(dn) > 1024 {
		return errors.New("a DN is 1 to 1024 characters")
	}
	if _, err := goldap.ParseDN(dn); err != nil {
		return fmt.Errorf("not a valid DN: %v", err)
	}
	return nil
}

// RDNValue returns the value of the first RDN of dn whose attribute is attr
// (case-insensitive): "uid=alice,ou=people,dc=x" with "uid" is "alice". The
// bool is false if the DN is invalid or has no such RDN.
func RDNValue(dn, attr string) (string, bool) {
	p, err := goldap.ParseDN(dn)
	if err != nil {
		return "", false
	}
	for _, rdn := range p.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, attr) {
				return a.Value, true
			}
		}
	}
	return "", false
}

// CAPool parses a PEM bundle for a loader's private CA.
func CAPool(pem string) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("the CA bundle holds no PEM certificate")
	}
	return p, nil
}
