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
//   - users (racfid), disabled when racfAttributes holds REVOKED (the
//     permanent revoke flag only: a pending racfRevokeDate or racfResumeDate is
//     not evaluated, RACF decides it at logon);
//   - groups (racfid) and connects, from the user's racfConnectGroupName and
//     the group's racfGroupUserids (the union, once each), minus the connects
//     whose CONNECT profile (racfuserid=U+racfgroupid=G,profiletype=CONNECT)
//     carries REVOKED (again the flag only, not the connect's dates);
//   - the user attributes SPECIAL, OPERATIONS, AUDITOR and ROAUDIT, as synthetic
//     privileged groups ("racf-attr:SPECIAL" ...), so the system-wide
//     authorities appear as entitlements reviewers can certify;
//   - the group-level SPECIAL, OPERATIONS and AUDITOR of a connect
//     (racfConnectAttributes), as one privileged group per group and attribute
//     ("racf-group-attr:SPECIAL:<group DN>"), kept even when the connect is
//     revoked so a dormant authority stays visible;
//   - the owner, default group and programmer name, as account attributes.
//
// A listing in which no user carries racfAttributes at all is refused
// (ErrNoAttributes): it means the bind user cannot read them, and a sync that
// reported no privileged holder would be wrong, not empty.
//
// Each SDBM suffix is its own RACF database: users, groups and connects are
// matched within their suffix only.
//
// Not covered yet: the connect group authority (USE, CREATE, CONNECT, JOIN),
// CLAUTH, dataset and general resource profiles. ACF2 and Top Secret use their
// own modules.
package racf

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// Fixed errors. Their text never contains the job's input or a directory
// value.
var (
	ErrNoBase   = errors.New("racf: no SDBM suffix is configured")
	ErrBadBase  = errors.New("racf: an SDBM suffix is not a distinguished name")
	ErrTooLarge = errors.New("racf: the RACF database is larger than the sync limits")
	ErrRead     = errors.New("racf: the z/OS LDAP server could not be read")
	ErrNoDriver = errors.New("racf: no LDAP reader is configured")
	// ErrNoAttributes: users were listed but none carries racfAttributes, so
	// the bind user cannot read them and the privileged holders are unknown.
	ErrNoAttributes = errors.New("racf: no user carries racfAttributes: the bind user cannot read the RACF attributes")
	ErrConnect      = errors.New("racf: the z/OS LDAP server could not be reached or refused the connection")
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

	connectFilter = "(objectclass=racfConnect)"
	attrConnUser  = "racfuserid"
	attrConnGroup = "racfgroupid"
	attrConnAttrs = "racfconnectattributes"

	// maxText is the protocol's limit on an external id or a name.
	maxText = 256

	pageSize = 500
)

// privileged are the system-wide authorities of a user (RACF SPECIAL,
// OPERATIONS, AUDITOR and ROAUDIT, the read-only auditor that can list every
// profile and the audit settings); each becomes a privileged group.
var privileged = []string{"SPECIAL", "OPERATIONS", "AUDITOR", "ROAUDIT"}

// groupPrivileged are the group-level authorities of a connect: SPECIAL,
// OPERATIONS and AUDITOR within the scope of one group.
var groupPrivileged = []string{"SPECIAL", "OPERATIONS", "AUDITOR"}

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
		return nil, openErr(err)
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
	// Profiles are keyed by suffix and upper-case racfid: two suffixes are two
	// RACF databases, and the same id in each is two accounts.
	type key struct {
		suffix int
		id     string
	}
	userDN := map[key]string{}
	groupDN := map[key]string{}
	type pair struct{ acct, group string }
	connects := map[pair]bool{}
	addMember := func(acct, grp string) error {
		k := pair{acct, grp}
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
	synthetic := map[string]agent.SyncGroup{} // external id -> privileged group
	addPriv := func(acct, id, name string) error {
		if _, ok := synthetic[id]; !ok {
			if len(id) > maxText || len(name) > maxText {
				return ErrTooLarge
			}
			synthetic[id] = agent.SyncGroup{ExternalID: id, Name: name, Privileged: true}
		}
		return addMember(acct, id)
	}
	type pendingConnect struct {
		suffix      int
		acct, group string
	}
	var userConnects []pendingConnect
	sawAttrs := false

	for si, suffix := range y.spec.Config.BaseDNs {
		users, err := s.Search(ctx, "profiletype=USER,"+suffix, ldap.ScopeSub, userFilter, attrs, pageSize, lim.Accounts+1)
		if err != nil {
			return nil, readErr(err)
		}
		for _, e := range users {
			id := strings.ToUpper(e.First(attrID))
			if id == "" || userDN[key{si, id}] != "" {
				continue
			}
			if len(out.Accounts) >= lim.Accounts {
				return nil, ErrTooLarge
			}
			userDN[key{si, id}] = e.DN
			acct := agent.SyncAccount{ExternalID: e.DN, Username: e.First(attrID), Status: "active"}
			if _, ok := e.Attrs[attrAttrs]; ok {
				sawAttrs = true
			}
			flags := upper(e.Attrs[attrAttrs])
			if revoked(flags) {
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
					if err := addPriv(e.DN, attrGroupID(p), "RACF "+p+" attribute"); err != nil {
						return nil, err
					}
				}
			}
			for _, g := range e.Attrs[attrConnects] {
				userConnects = append(userConnects, pendingConnect{si, e.DN, strings.ToUpper(g)})
			}
		}
	}
	if len(out.Accounts) > 0 && !sawAttrs {
		return nil, ErrNoAttributes
	}

	groupMembers := map[string][]string{} // group DN -> user ids
	groupSuffix := map[string]int{}
	for si, suffix := range y.spec.Config.BaseDNs {
		groups, err := s.Search(ctx, "profiletype=GROUP,"+suffix, ldap.ScopeSub, groupFilter, []string{attrID, attrMembers}, pageSize, lim.Groups+1)
		if err != nil {
			return nil, readErr(err)
		}
		for _, e := range groups {
			id := strings.ToUpper(e.First(attrID))
			if id == "" || groupDN[key{si, id}] != "" {
				continue
			}
			if len(out.Groups) >= lim.Groups {
				return nil, ErrTooLarge
			}
			groupDN[key{si, id}] = e.DN
			groupSuffix[e.DN] = si
			out.Groups = append(out.Groups, agent.SyncGroup{ExternalID: e.DN, Name: e.First(attrID)})
			groupMembers[e.DN] = e.Attrs[attrMembers]
		}
	}

	// CONNECT profiles: the revoke flag of a connect and its group-level
	// authorities.
	revokedConnect := map[pair]bool{}
	for si, suffix := range y.spec.Config.BaseDNs {
		conns, err := s.Search(ctx, "profiletype=CONNECT,"+suffix, ldap.ScopeSub, connectFilter,
			[]string{attrConnUser, attrConnGroup, attrConnAttrs}, pageSize, lim.Members+1)
		if err != nil {
			return nil, readErr(err)
		}
		for _, e := range conns {
			a, okA := userDN[key{si, strings.ToUpper(e.First(attrConnUser))}]
			g, okG := groupDN[key{si, strings.ToUpper(e.First(attrConnGroup))}]
			if !okA || !okG {
				continue
			}
			flags := upper(e.Attrs[attrConnAttrs])
			if revoked(flags) {
				revokedConnect[pair{a, g}] = true
			}
			gid := strings.ToUpper(e.First(attrConnGroup))
			for _, p := range groupPrivileged {
				if slices.Contains(flags, p) {
					if err := addPriv(a, groupAttrID(p, g), "RACF group-"+p+" in "+gid); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	for _, c := range userConnects {
		if g, ok := groupDN[key{c.suffix, c.group}]; ok && !revokedConnect[pair{c.acct, g}] {
			if err := addMember(c.acct, g); err != nil {
				return nil, err
			}
		}
	}
	for g, ids := range groupMembers {
		for _, id := range ids {
			if a, ok := userDN[key{groupSuffix[g], strings.ToUpper(id)}]; ok && !revokedConnect[pair{a, g}] {
				if err := addMember(a, g); err != nil {
					return nil, err
				}
			}
		}
	}
	// The synthetic groups count against the group limit only when emitted.
	if len(out.Groups)+len(synthetic) > lim.Groups {
		return nil, ErrTooLarge
	}
	ids := make([]string, 0, len(synthetic))
	for id := range synthetic {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		out.Groups = append(out.Groups, synthetic[id])
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

func revoked(flags []string) bool {
	return slices.Contains(flags, "REVOKED") || slices.Contains(flags, "REVOKE")
}

func groupAttrID(attr, groupDN string) string { return "racf-group-attr:" + attr + ":" + groupDN }

func attrGroupID(attr string) string { return "racf-attr:" + attr }

// upper returns the RACF attribute keywords of a racfAttributes value list,
// upper-cased. SDBM sends one keyword per value, but a server that packs
// several into one value (space or comma separated) must not hide a SPECIAL.
func upper(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			out = append(out, strings.ToUpper(f))
		}
	}
	return out
}

// openErr maps a dial or bind failure to a fixed error. The policy and TLS
// refusals keep their sentinel (the agent turns them into its error codes);
// anything else, which can carry the server's diagnostic text, a DN or an
// address, becomes ErrConnect.
func openErr(err error) error {
	for _, s := range []error{context.Canceled, context.DeadlineExceeded, ldap.ErrBindRefused, connectors.ErrTargetNotAllowed,
		safedial.ErrBlockedAddress, safedial.ErrPort, safedial.ErrHost, safedial.ErrTLSMode, safedial.ErrNoTLS, safedial.ErrHandshake} {
		if errors.Is(err, s) {
			return s
		}
	}
	return ErrConnect
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
