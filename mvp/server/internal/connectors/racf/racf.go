// Package racf is the Directory Agent module that reads RACF (IBM z/OS) through
// the z/OS LDAP server's SDBM backend (issue #561).
//
// SDBM presents the RACF database as a directory: a user is
// racfid=ID,profiletype=USER,<suffix>, a group racfid=ID,profiletype=GROUP,<suffix>.
// The module is read-only. It runs on the Directory Agent, inside the customer
// network that reaches the mainframe, through the agent's own safedial Dialer
// (so the target must be on the agent's local allowlist) and the shared LDAP
// reader, which has no write operation, sends the bind password only on a TLS
// connection and refuses blocked addresses.
//
// What it reads, as the typed agent.SyncResult:
//
//   - users (racfid), disabled when racfAttributes holds REVOKE;
//   - groups (racfid) and connects, from the user's racfConnectGroupName and
//     the group's racfGroupUserids (the union, once each);
//   - the user attributes SPECIAL, OPERATIONS and AUDITOR, as three synthetic
//     privileged groups ("racf-attr:SPECIAL" ...), so the system-wide
//     authorities appear as entitlements reviewers can certify;
//   - the owner, default group and programmer name, as account attributes.
//
// Not covered yet: group-level authorities (group-SPECIAL and so on), the
// connect authority (USE, CREATE, CONNECT, JOIN), dataset and general resource
// profiles. ACF2 and Top Secret use their own modules.
package racf

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
)

// Fixed errors. Their text never contains the job's input or a directory
// value.
var (
	ErrNoBase   = errors.New("racf: no SDBM suffix is configured")
	ErrBadBase  = errors.New("racf: an SDBM suffix is not a distinguished name")
	ErrTooLarge = errors.New("racf: the RACF database is larger than the sync limits")
	ErrRead     = errors.New("racf: the z/OS LDAP server could not be read")
	ErrNoDriver = errors.New("racf: no LDAP reader is configured")
)

// The SDBM object classes and attributes read (lower case: ldap.Entry keys).
const (
	userFilter  = "(objectclass=racfUser)"
	groupFilter = "(objectclass=racfGroup)"

	attrID        = "racfid"
	attrAttrs     = "racfattributes"
	attrConnects  = "racfconnectgroupname"
	attrDefGroup  = "racfdefaultgroup"
	attrOwner     = "racfowner"
	attrProgrName = "racfprogrammername"
	attrMembers   = "racfgroupuserids"

	pageSize = 500
)

// privileged are the system-wide authorities of a user (RACF SPECIAL,
// OPERATIONS, AUDITOR); each becomes a privileged group.
var privileged = []string{"SPECIAL", "OPERATIONS", "AUDITOR"}

// Searcher is the read-only slice of the LDAP reader the module uses.
// *ldap.Reader satisfies it; tests supply an in-process fake.
type Searcher interface {
	Search(ctx context.Context, base string, scope ldap.Scope, filter string, attrs []string, page, max int) ([]ldap.Entry, error)
	Close()
}

// Opener connects and binds for a job.
type Opener func(ctx context.Context, s agent.ProberSpec) (Searcher, error)

// OpenLDAP is the production Opener: the shared LDAP reader over the agent's
// safedial Dialer.
func OpenLDAP(ctx context.Context, s agent.ProberSpec) (Searcher, error) {
	return ldap.OpenReader(ctx, ldap.ReadConfig{Host: s.Target.Host, Port: s.Target.Port, TLSMode: s.Target.TLSMode,
		BindDN: s.Config.BindDN, Password: ldap.Secret(s.Password), Dialer: s.Dialer})
}

// Module is the plug-in to register with the agent.
func Module(open Opener) agent.Module {
	return agent.Module{Name: agent.ModuleRACF, New: func(s agent.ProberSpec) (agent.Syncer, error) {
		if open == nil {
			return nil, ErrNoDriver
		}
		for _, b := range s.Config.BaseDNs {
			if ldap.ValidDN(b) != nil {
				return nil, ErrBadBase
			}
		}
		if len(s.Config.BaseDNs) == 0 {
			return nil, ErrNoBase
		}
		return &syncer{spec: s, open: open}, nil
	}}
}

type syncer struct {
	spec agent.ProberSpec
	open Opener
}

// Discover reads every SDBM suffix of the job. More than a limit is
// ErrTooLarge and nothing partial is returned.
func (y *syncer) Discover(ctx context.Context, lim agent.SyncLimits) (*agent.SyncResult, error) {
	s, err := y.open(ctx, y.spec)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	extra := y.spec.Config.AttrMap
	attrs := []string{attrID, attrAttrs, attrConnects, attrDefGroup, attrOwner, attrProgrName}
	for _, m := range extra {
		if !ldap.ValidAttrName(m.LDAP) {
			return nil, ErrRead
		}
		attrs = append(attrs, strings.ToLower(m.LDAP))
	}

	out := &agent.SyncResult{Accounts: []agent.SyncAccount{}, Groups: []agent.SyncGroup{}, Members: []agent.SyncMember{}}
	userDN := map[string]string{}  // racfid -> account DN
	groupDN := map[string]string{} // racfid -> group DN
	connects := map[[2]string]bool{}
	addMember := func(acct, grp string) error {
		k := [2]string{acct, grp}
		if connects[k] {
			return nil
		}
		if len(out.Members) >= lim.Members {
			return ErrTooLarge
		}
		connects[k] = true
		out.Members = append(out.Members, agent.SyncMember{Account: acct, Group: grp})
		return nil
	}
	synthetic := map[string]bool{}
	type pendingConnect struct{ acct, group string }
	var userConnects []pendingConnect

	for _, suffix := range y.spec.Config.BaseDNs {
		users, err := s.Search(ctx, "profiletype=USER,"+suffix, ldap.ScopeSub, userFilter, attrs, pageSize, lim.Accounts+1)
		if err != nil {
			return nil, readErr(err)
		}
		for _, e := range users {
			id := e.First(attrID)
			if id == "" || userDN[strings.ToUpper(id)] != "" {
				continue
			}
			if len(out.Accounts) >= lim.Accounts {
				return nil, ErrTooLarge
			}
			userDN[strings.ToUpper(id)] = e.DN
			acct := agent.SyncAccount{ExternalID: e.DN, Username: id, Status: "active"}
			flags := upper(e.Attrs[attrAttrs])
			if slices.Contains(flags, "REVOKE") || slices.Contains(flags, "REVOKED") {
				acct.Status = "disabled"
			}
			for name, target := range map[string]string{attrDefGroup: "racfDefaultGroup", attrOwner: "racfOwner", attrProgrName: "racfProgrammerName"} {
				if v := e.First(name); v != "" {
					acct.Extra = append(acct.Extra, agent.SyncExtra{Scope: "account", Target: target, Value: v})
				}
			}
			for _, m := range extra {
				if v := e.First(m.LDAP); v != "" {
					acct.Extra = append(acct.Extra, agent.SyncExtra{Scope: m.Scope, Target: m.Target, Value: v})
				}
			}
			slices.SortFunc(acct.Extra, func(a, b agent.SyncExtra) int { return strings.Compare(a.Target, b.Target) })
			out.Accounts = append(out.Accounts, acct)
			for _, p := range privileged {
				if slices.Contains(flags, p) {
					synthetic[p] = true
					if err := addMember(e.DN, attrGroupID(p)); err != nil {
						return nil, err
					}
				}
			}
			for _, g := range e.Attrs[attrConnects] {
				userConnects = append(userConnects, pendingConnect{e.DN, strings.ToUpper(g)})
			}
		}
	}

	groupMembers := map[string][]string{} // group DN -> user ids
	for _, suffix := range y.spec.Config.BaseDNs {
		groups, err := s.Search(ctx, "profiletype=GROUP,"+suffix, ldap.ScopeSub, groupFilter, []string{attrID, attrMembers}, pageSize, lim.Groups+1)
		if err != nil {
			return nil, readErr(err)
		}
		for _, e := range groups {
			id := e.First(attrID)
			if id == "" || groupDN[strings.ToUpper(id)] != "" {
				continue
			}
			if len(out.Groups) >= lim.Groups-len(privileged) { // room for the synthetic groups
				return nil, ErrTooLarge
			}
			groupDN[strings.ToUpper(id)] = e.DN
			out.Groups = append(out.Groups, agent.SyncGroup{ExternalID: e.DN, Name: id})
			groupMembers[e.DN] = e.Attrs[attrMembers]
		}
	}
	for _, c := range userConnects {
		if g, ok := groupDN[c.group]; ok {
			if err := addMember(c.acct, g); err != nil {
				return nil, err
			}
		}
	}
	for g, ids := range groupMembers {
		for _, id := range ids {
			if a, ok := userDN[strings.ToUpper(id)]; ok {
				if err := addMember(a, g); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, p := range privileged {
		if synthetic[p] {
			out.Groups = append(out.Groups, agent.SyncGroup{ExternalID: attrGroupID(p), Name: "RACF " + p + " attribute", Privileged: true})
		}
	}
	// Map iteration above is unordered; a sync result is deterministic.
	slices.SortFunc(out.Members, func(a, b agent.SyncMember) int {
		if c := strings.Compare(a.Group, b.Group); c != 0 {
			return c
		}
		return strings.Compare(a.Account, b.Account)
	})
	return out, nil
}

func attrGroupID(attr string) string { return "racf-attr:" + attr }

func upper(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.ToUpper(strings.TrimSpace(v))
	}
	return out
}

// readErr maps a search failure to a fixed error: a directory's own message
// can echo a DN, a filter or a value.
func readErr(err error) error {
	if errors.Is(err, ldap.ErrTooManyEntries) {
		return ErrTooLarge
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrRead
}
