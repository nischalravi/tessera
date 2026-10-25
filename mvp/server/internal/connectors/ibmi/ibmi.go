// Package ibmi is the Directory Agent module for IBM i user profiles and
// special authorities (issue #561).
//
// IBM i has no LDAP view of its user profiles. They are read from the Db2 for i
// catalog (QSYS2.USER_INFO) or the system APIs, over IBM's host servers
// (DRDA/JDBC), which the Go standard library cannot speak. So this package
// holds the plug-in contract and the module, and leaves the transport behind
// one narrow interface:
//
//   - Source is the read-only contract a transport implements: list the user
//     profiles, bounded. It has no operation that changes anything.
//   - The module maps profiles to the typed agent.SyncResult: each profile is an
//     account (disabled when its status is *DISABLED); each group profile and
//     supplemental group is a group; each special authority (*ALLOBJ, *SECADM,
//     *AUDIT, *IOSYSCFG, *SERVICE, *SAVSYS, *JOBCTL, *SPLCTL) and the *SECOFR
//     and *SECADM user classes is a synthetic group, privileged for the
//     authorities that give control of the system.
//   - NoTransport is the transport of this build: it answers "unsupported". The
//     live transport is a follow-up; it plugs in as an Opener and gets the
//     agent's safedial Dialer in agent.ProberSpec, like every module.
package ibmi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

// Fixed errors. Their text never contains the job's input or a system value.
var (
	// ErrNoTransport: this build has no live IBM i transport. It wraps
	// connectors.ErrUnsupported, so the agent reports the code "unsupported".
	ErrNoTransport = fmt.Errorf("ibmi: the live IBM i transport is not built into this agent: %w", connectors.ErrUnsupported)
	ErrTooLarge    = errors.New("ibmi: the system has more user profiles than the sync limits")
	ErrBadProfile  = errors.New("ibmi: the system returned a user profile that is not valid")
	ErrNoDriver    = errors.New("ibmi: no transport is configured")
)

// Profile is one IBM i user profile, as read from QSYS2.USER_INFO.
type Profile struct {
	Name string // USER_NAME, 1 to 10 characters
	// Status is STATUS: *ENABLED or *DISABLED.
	Status string
	// UserClass is USER_CLASS_NAME: *SECOFR, *SECADM, *PGMR, *SYSOPR or *USER.
	UserClass string
	// SpecialAuthorities is SPECIAL_AUTHORITIES: *ALLOBJ, *SECADM, ...
	SpecialAuthorities []string
	// GroupProfile is GROUP_PROFILE_NAME ("" or *NONE for none).
	GroupProfile string
	// SupplementalGroups is SUPPLEMENTAL_GROUP_LIST.
	SupplementalGroups []string
	// Text is TEXT_DESCRIPTION.
	Text string
}

// Source is the read-only contract of a transport.
type Source interface {
	// Profiles lists up to max user profiles. More than max is an error
	// (ErrTooLarge), never a cut-off list.
	Profiles(ctx context.Context, max int) ([]Profile, error)
	Close()
}

// Opener connects to the system of a job. A transport reaches the system only
// through s.Dialer.
type Opener func(ctx context.Context, s agent.ProberSpec) (Source, error)

// NoTransport is the Opener of this build.
func NoTransport(context.Context, agent.ProberSpec) (Source, error) { return nil, ErrNoTransport }

// Module is the plug-in to register with the agent.
func Module(open Opener) agent.Module {
	return agent.Module{Name: agent.ModuleIBMi, New: func(s agent.ProberSpec) (agent.Syncer, error) {
		if open == nil {
			return nil, ErrNoDriver
		}
		return &syncer{spec: s, open: open}, nil
	}}
}

type syncer struct {
	spec agent.ProberSpec
	open Opener
}

var nameRE = regexp.MustCompile(`^[A-Za-z#$@][A-Za-z0-9#$@_.]{0,9}$`)

// authorities that give control of the system.
var privilegedAuth = map[string]bool{"*ALLOBJ": true, "*SECADM": true, "*AUDIT": true, "*IOSYSCFG": true, "*SERVICE": true}

var privilegedClass = map[string]bool{"*SECOFR": true, "*SECADM": true}

// Discover lists the profiles and maps them. Nothing partial is returned.
func (y *syncer) Discover(ctx context.Context, lim agent.SyncLimits) (*agent.SyncResult, error) {
	src, err := y.open(ctx, y.spec)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	profiles, err := src.Profiles(ctx, lim.Accounts)
	if err != nil {
		if errors.Is(err, ErrTooLarge) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, errRead
	}
	return Map(profiles, lim)
}

var errRead = errors.New("ibmi: the system could not be read")

// Map turns profiles into the typed result.
func Map(profiles []Profile, lim agent.SyncLimits) (*agent.SyncResult, error) {
	if len(profiles) > lim.Accounts {
		return nil, ErrTooLarge
	}
	out := &agent.SyncResult{Accounts: []agent.SyncAccount{}, Groups: []agent.SyncGroup{}, Members: []agent.SyncMember{}}
	seen := map[string]bool{}
	groups := map[string]agent.SyncGroup{}
	type edge struct{ acct, group string }
	var edges []edge
	for _, p := range profiles {
		if !nameRE.MatchString(p.Name) {
			return nil, ErrBadProfile
		}
		name := strings.ToUpper(p.Name)
		if seen[name] {
			continue
		}
		seen[name] = true
		st := "active"
		if strings.EqualFold(p.Status, "*DISABLED") {
			st = "disabled"
		}
		acct := agent.SyncAccount{ExternalID: name, Username: name, Status: st}
		if p.UserClass != "" {
			acct.Extra = append(acct.Extra, agent.SyncExtra{Scope: "account", Target: "userClass", Value: clip(p.UserClass)})
		}
		if t := strings.TrimSpace(p.Text); t != "" && !strings.ContainsAny(t, "\r\n\x00") {
			acct.Extra = append(acct.Extra, agent.SyncExtra{Scope: "account", Target: "description", Value: clip(t)})
		}
		out.Accounts = append(out.Accounts, acct)

		addGroup := func(id, label string, priv bool) {
			if _, ok := groups[id]; !ok {
				groups[id] = agent.SyncGroup{ExternalID: id, Name: label, Privileged: priv}
			}
			edges = append(edges, edge{name, id})
		}
		var gnames []string
		if g := strings.ToUpper(p.GroupProfile); g != "" && g != "*NONE" {
			gnames = append(gnames, g)
		}
		for _, g := range p.SupplementalGroups {
			gnames = append(gnames, strings.ToUpper(g))
		}
		for _, g := range gnames {
			if !nameRE.MatchString(g) {
				return nil, ErrBadProfile
			}
			addGroup("group:"+g, g, false)
		}
		for _, a := range p.SpecialAuthorities {
			a = strings.ToUpper(strings.TrimSpace(a))
			if !strings.HasPrefix(a, "*") || !nameRE.MatchString(a[1:]) {
				return nil, ErrBadProfile
			}
			addGroup("authority:"+a, "IBM i special authority "+a, privilegedAuth[a])
		}
		if c := strings.ToUpper(p.UserClass); privilegedClass[c] {
			addGroup("class:"+c, "IBM i user class "+c, true)
		}
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) > lim.Groups {
		return nil, ErrTooLarge
	}
	for _, id := range ids {
		out.Groups = append(out.Groups, groups[id])
	}
	done := map[edge]bool{}
	for _, e := range edges {
		if done[e] {
			continue
		}
		done[e] = true
		if len(out.Members) >= lim.Members {
			return nil, ErrTooLarge
		}
		out.Members = append(out.Members, agent.SyncMember{Account: e.acct, Group: e.group})
	}
	return out, nil
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
