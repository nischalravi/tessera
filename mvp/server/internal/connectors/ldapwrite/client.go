package ldapwrite

import (
	"context"
	"errors"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// callTimeout bounds one LDAP request.
const callTimeout = 30 * time.Second

// conn is one bound, encrypted connection. It exists only inside one Apply or Verify call.
type conn struct {
	l    *goldap.Conn
	stop func() bool
}

func (c *conn) close() {
	if c.stop != nil {
		c.stop()
	}
	_ = c.l.Close()
}

// open dials through safedial (the SSRF and port policy), completes StartTLS on 389 and refuses to
// bind on any connection that is not TLS 1.2 or later: the bind password and every password set
// travel only on an encrypted connection.
func open(ctx context.Context, d *safedial.Dialer, cfg *Config, pw connsync.Secret) (*conn, error) {
	if d == nil {
		return nil, target.Permanent("no directory dialer is configured")
	}
	if pw.Empty() || cfg.BindDN == "" {
		return nil, target.Permanent("the directory bind credential is missing") // go-ldap would send an anonymous bind
	}
	sc, err := d.Dial(ctx, cfg.Host, cfg.Port, false)
	if err != nil {
		return nil, unreachable("connect")
	}
	l := goldap.NewConn(sc, sc.Secure())
	l.SetTimeout(callTimeout)
	l.Start()
	c := &conn{l: l}
	if sc.StartTLSPort {
		if err := l.StartTLS(sc.TLSConfig()); err != nil {
			c.close()
			return nil, unreachable("StartTLS")
		}
		st, ok := l.TLSConnectionState()
		if !ok || sc.SetTLS(st) != nil {
			c.close()
			return nil, unreachable("StartTLS")
		}
	}
	if !sc.Secure() {
		c.close()
		return nil, unreachable("TLS")
	}
	c.stop = context.AfterFunc(ctx, func() { _ = l.Close() }) // a cancelled call closes the socket
	if _, err := l.SimpleBind(&goldap.SimpleBindRequest{Username: cfg.BindDN, Password: pw.Reveal()}); err != nil {
		c.close()
		var le *goldap.Error
		if errors.As(err, &le) && le.ResultCode == goldap.LDAPResultInvalidCredentials {
			return nil, target.Permanent("bind: the directory refused the bind credential")
		}
		return nil, unreachable("bind")
	}
	return c, nil
}

func unreachable(op string) *target.Error {
	return &target.Error{Retryable: true, Msg: op + ": the directory could not be reached or did not complete the exchange"}
}

// fail turns a go-ldap error into a target error with fixed text: the server's own diagnostic can
// carry names and values from the request, so it is never copied.
func fail(op string, err error) error {
	if err == nil {
		return nil
	}
	var le *goldap.Error
	if !errors.As(err, &le) {
		return unreachable(op)
	}
	var msg string
	switch le.ResultCode {
	case goldap.LDAPResultInsufficientAccessRights:
		msg = "the bind account has no right to make this change"
	case goldap.LDAPResultNoSuchObject:
		msg = "the entry or its parent does not exist"
	case goldap.LDAPResultEntryAlreadyExists:
		msg = "an entry with this name already exists"
	case goldap.LDAPResultUnwillingToPerform:
		msg = "the directory is unwilling to perform it (a password policy or a rule of the directory)"
	case goldap.LDAPResultConstraintViolation:
		msg = "the change breaks a constraint of the directory (for example its password policy)"
	case goldap.LDAPResultInvalidAttributeSyntax, goldap.LDAPResultUndefinedAttributeType, goldap.LDAPResultObjectClassViolation,
		goldap.LDAPResultNoSuchAttribute, goldap.LDAPResultAttributeOrValueExists, goldap.LDAPResultNotAllowedOnNonLeaf,
		goldap.LDAPResultNamingViolation, goldap.LDAPResultObjectClassModsProhibited:
		msg = "the directory's schema refused the change"
	case goldap.LDAPResultBusy, goldap.LDAPResultUnavailable, goldap.ErrorNetwork, goldap.LDAPResultTimeLimitExceeded:
		return unreachable(op)
	default:
		msg = "the directory answered with an error"
	}
	return &target.Error{Msg: op + ": " + msg}
}

func (c *conn) search(base string, scope int, filter string, attrs []string, size int) ([]*goldap.Entry, error) {
	req := goldap.NewSearchRequest(base, scope, goldap.NeverDerefAliases, size, int(callTimeout/time.Second), false, filter, attrs, nil)
	res, err := c.l.Search(req)
	var le *goldap.Error
	if err != nil && errors.As(err, &le) && le.ResultCode == goldap.LDAPResultSizeLimitExceeded && res != nil {
		return res.Entries, nil
	}
	if err != nil {
		var le *goldap.Error
		if errors.As(err, &le) && le.ResultCode == goldap.LDAPResultNoSuchObject {
			return nil, nil
		}
		return nil, fail("search", err)
	}
	return res.Entries, nil
}

func (c *conn) add(dn string, attrs map[string][]string, order []string) error {
	req := goldap.NewAddRequest(dn, nil)
	for _, k := range order {
		req.Attribute(k, attrs[k])
	}
	return fail("add entry", c.l.Add(req))
}

type change struct {
	op   string // "add", "delete", "replace"
	attr string
	vals []string
}

func (c *conn) modify(dn string, changes []change) error {
	req := goldap.NewModifyRequest(dn, nil)
	for _, ch := range changes {
		switch ch.op {
		case "add":
			req.Add(ch.attr, ch.vals)
		case "delete":
			req.Delete(ch.attr, ch.vals)
		default:
			req.Replace(ch.attr, ch.vals)
		}
	}
	return fail("modify entry", c.l.Modify(req))
}

func (c *conn) del(dn string) error {
	return fail("delete entry", c.l.Del(goldap.NewDelRequest(dn, nil)))
}

func (c *conn) move(dn, rdn, newSuperior string) error {
	return fail("move entry", c.l.ModifyDN(goldap.NewModifyDNRequest(dn, rdn, true, newSuperior)))
}

// oidPasswordModify is the Password Modify extended operation (RFC 3062).
const oidPasswordModify = "1.3.6.1.4.1.4203.1.11.1"

// supportsPasswordModify reads the root DSE for the RFC 3062 operation.
func (c *conn) supportsPasswordModify() bool {
	es, err := c.search("", goldap.ScopeBaseObject, "(objectClass=*)", []string{"supportedExtension"}, 1)
	if err != nil || len(es) == 0 {
		return false
	}
	for _, v := range es[0].GetEqualFoldAttributeValues("supportedExtension") {
		if v == oidPasswordModify {
			return true
		}
	}
	return false
}

// passwordModify sets the password through the extended operation, so the directory hashes it
// under its own password policy instead of storing what was sent as an attribute value.
func (c *conn) passwordModify(dn, pw string) error {
	_, err := c.l.PasswordModify(&goldap.PasswordModifyRequest{UserIdentity: dn, NewPassword: pw})
	return fail("set password", err)
}
