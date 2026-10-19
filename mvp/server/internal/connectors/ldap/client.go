package ldap

import (
	"crypto/tls"
	"net"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// client is the only way this package talks LDAP. It wraps go-ldap's
// connection and exposes exactly the read-only operations the probe needs:
// StartTLS, simple bind, search, Who Am I and close. The write operations of
// the underlying library (Add, Modify, Del, ModifyDN, PasswordModify, the
// generic Extended and the other bind mechanisms) are not reachable from
// here, and TestProbers_ReadOnly scans the package to keep it that way.
type client struct {
	l *goldap.Conn
}

func newClient(c net.Conn, isTLS bool) *client {
	l := goldap.NewConn(c, isTLS)
	l.SetTimeout(CheckTimeout)
	l.Start()
	return &client{l: l}
}

func (c *client) close() { _ = c.l.Close() }

// startTLS negotiates StartTLS (RFC 4511 §4.14) on a 389 connection.
func (c *client) startTLS(cfg *tls.Config) error { return c.l.StartTLS(cfg) }

func (c *client) tlsState() (tls.ConnectionState, bool) { return c.l.TLSConnectionState() }

// bind is a simple bind with a non-empty password; go-ldap itself refuses an
// empty one (an unauthenticated bind), and the caller checks first.
func (c *client) bind(dn, password string) error {
	_, err := c.l.SimpleBind(&goldap.SimpleBindRequest{Username: dn, Password: password})
	return err
}

// whoAmI is the RFC 4532 extended operation. It reads and changes nothing.
func (c *client) whoAmI() (string, error) {
	r, err := c.l.WhoAmI(nil)
	if err != nil {
		return "", err
	}
	return r.AuthzID, nil
}

// search runs one search. Callers set SizeLimit and TimeLimit.
func (c *client) search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if req.TimeLimit == 0 {
		req.TimeLimit = int(CheckTimeout / time.Second)
	}
	return c.l.Search(req)
}

// readOne base-scope reads one entry's named attributes; nil if unreadable.
func (c *client) readOne(dn string, attrs ...string) *goldap.Entry {
	res, err := c.search(&goldap.SearchRequest{BaseDN: dn, Scope: goldap.ScopeBaseObject, SizeLimit: 1,
		Filter: "(objectClass=*)", Attributes: attrs})
	if err != nil || res == nil || len(res.Entries) == 0 {
		return nil
	}
	return res.Entries[0]
}
