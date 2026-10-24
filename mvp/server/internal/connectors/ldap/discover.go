package ldap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// ErrTooLarge: the directory holds more than the limits of a sync; nothing
// partial is returned.
var ErrTooLarge = errors.New("ldap: the directory is larger than the sync limits")

// Account is a person (or service) entry read for a sync. ExternalID is the
// entry's DN, which is what group membership values name.
type Account struct {
	ExternalID, Username, Email string
	Disabled                    bool
	// Extra holds the values of the connection's attribute map (the first
	// value of each mapped LDAP attribute).
	Extra []ExtraValue
}

// ExtraValue is one mapped attribute value of an account.
type ExtraValue struct{ Scope, Target, Value string }

// AttrMap maps one LDAP attribute to a Tessera account or identity attribute.
type AttrMap struct{ LDAP, Target, Scope string }

// Paged-search page size of a sync.
const (
	DefaultPageSize = 500
	MaxPageSize     = 10000
)

var descrRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,127}$`)

// ValidAttrName reports whether s is an attribute description name (RFC 4512
// descr: a letter, then letters, digits and hyphens).
func ValidAttrName(s string) bool { return descrRE.MatchString(s) }

// Group is a group entry read for a sync.
type Group struct{ ExternalID, Name string }

// Member says Account (a DN) is a member of Group (a DN).
type Member struct{ Account, Group string }

// Listing is the result of Discover.
type Listing struct {
	Accounts []Account
	Groups   []Group
	Members  []Member
}

const (
	userFilterDefault  = "(objectClass=inetOrgPerson)"
	groupFilterDefault = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group))"
	uacDisabled        = 0x2
	maxSyncPages       = 10000
)

// Discover lists the accounts, groups and group memberships under the base
// DNs: one paged, read-only search for people and one for groups, over the
// connection's own bind. It reads names and membership, plus the attributes of the connection's attribute map.
// More than the limits is ErrTooLarge. Memberships whose account or group is
// not in the listing are dropped (they point outside the base DNs).
func (p *Prober) Discover(ctx context.Context, maxAccounts, maxGroups, maxMembers int) (*Listing, error) {
	if len(p.cfg.BaseDNs) == 0 {
		return nil, errors.New("ldap: no base DN is configured")
	}
	userFilter := p.cfg.UserFilter
	if userFilter == "" {
		userFilter = userFilterDefault
	}
	if _, err := goldap.CompileFilter(userFilter); err != nil {
		return nil, fmt.Errorf("ldap: the user filter is not valid: %w", err)
	}
	s, err := p.bound(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	out := &Listing{}
	accts := map[string]string{} // normalised DN -> DN
	attrs := []string{"uid", "sAMAccountName", "cn", "mail", "userAccountControl", "nsAccountLock"}
	for _, m := range p.cfg.AttrMap {
		if !ValidAttrName(m.LDAP) {
			return nil, fmt.Errorf("ldap: %q is not an attribute name", m.LDAP)
		}
		attrs = append(attrs, m.LDAP)
	}
	err = p.paged(s, userFilter, attrs, func(e *goldap.Entry) error {
		if len(out.Accounts) >= maxAccounts {
			return ErrTooLarge
		}
		name := firstOf(e, "uid", "sAMAccountName", "cn")
		if name == "" {
			return nil
		}
		dis := strings.EqualFold(e.GetAttributeValue("nsAccountLock"), "true")
		if uac, err := strconv.Atoi(e.GetAttributeValue("userAccountControl")); err == nil && uac&uacDisabled != 0 {
			dis = true
		}
		if _, dup := accts[normalDN(e.DN)]; dup {
			return nil
		}
		accts[normalDN(e.DN)] = e.DN
		acct := Account{ExternalID: e.DN, Username: name, Email: e.GetAttributeValue("mail"), Disabled: dis}
		for _, m := range p.cfg.AttrMap {
			if v := e.GetAttributeValue(m.LDAP); v != "" {
				acct.Extra = append(acct.Extra, ExtraValue{Scope: m.Scope, Target: m.Target, Value: v})
			}
		}
		out.Accounts = append(out.Accounts, acct)
		return nil
	})
	if err != nil {
		return nil, err
	}
	groups := map[string]string{}
	seen := map[[2]string]bool{} // a group often lists a member twice (member, uniqueMember)
	err = p.paged(s, groupFilterDefault, []string{"cn", "member", "uniqueMember"}, func(e *goldap.Entry) error {
		if _, dup := groups[normalDN(e.DN)]; dup {
			return nil
		}
		if len(out.Groups) >= maxGroups {
			return ErrTooLarge
		}
		groups[normalDN(e.DN)] = e.DN
		name := firstOf(e, "cn")
		if name == "" {
			name = e.DN
		}
		out.Groups = append(out.Groups, Group{ExternalID: e.DN, Name: name})
		for _, attr := range []string{"member", "uniqueMember"} {
			for _, v := range e.GetAttributeValues(attr) {
				acct, ok := accts[normalDN(v)]
				if !ok {
					continue
				}
				if k := [2]string{acct, e.DN}; seen[k] {
					continue
				} else {
					seen[k] = true
				}
				if len(out.Members) >= maxMembers {
					return ErrTooLarge
				}
				out.Members = append(out.Members, Member{Account: acct, Group: e.DN})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// paged runs a paged subtree search (RFC 2696) of every base DN and calls fn
// for each entry. A base that does not exist or cannot be read counts as empty.
func (p *Prober) paged(s *session, filter string, attrs []string, fn func(*goldap.Entry) error) error {
	size := p.cfg.PageSize
	if size == 0 {
		size = DefaultPageSize
	}
	for _, base := range p.cfg.BaseDNs {
		var cookie []byte
		for page := 0; page < maxSyncPages; page++ {
			pc := goldap.NewControlPaging(uint32(size)) // #nosec G115 -- New bounds it to 1..MaxPageSize
			pc.SetCookie(cookie)
			res, err := s.c.search(&goldap.SearchRequest{BaseDN: base, Scope: goldap.ScopeWholeSubtree, TimeLimit: searchTimeSecs,
				Filter: filter, Attributes: attrs, Controls: []goldap.Control{pc}})
			if res != nil {
				for _, e := range res.Entries {
					if err := fn(e); err != nil {
						return err
					}
				}
			}
			if err != nil {
				if isCode(err, goldap.LDAPResultNoSuchObject, goldap.LDAPResultInsufficientAccessRights) {
					break
				}
				return err
			}
			next := []byte(nil)
			if rc, ok := goldap.FindControl(res.Controls, goldap.ControlTypePaging).(*goldap.ControlPaging); ok {
				next = rc.Cookie
			}
			if len(next) == 0 {
				break
			}
			cookie = next
		}
	}
	return nil
}

func firstOf(e *goldap.Entry, attrs ...string) string {
	for _, a := range attrs {
		if v := e.GetAttributeValue(a); v != "" {
			return v
		}
	}
	return ""
}

// normDN is a DN as compared: parsed (so spacing and attribute case do not
// matter) and lower-cased; an unparsable DN compares as its trimmed lower case.
func normalDN(dn string) string {
	if d, err := goldap.ParseDN(dn); err == nil {
		return strings.ToLower(d.String())
	}
	return strings.ToLower(strings.TrimSpace(dn))
}
