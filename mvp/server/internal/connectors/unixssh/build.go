package unixssh

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

// noLogin are the shells that refuse an interactive login.
var noLogin = map[string]bool{"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true, "/bin/nologin": true}

func (c *Connector) build(s *Snapshot) *connectors.DiscoveryResult {
	h := c.host
	res := &connectors.DiscoveryResult{System: System}
	if s.Bad > 0 { // a dropped line may be an account: the deletion guard holds removals
		res.Partial = strconv.Itoa(s.Bad) + " passwd or group lines could not be read"
	}
	tags := []string{"unix", "ssh"}
	switch {
	case !s.SudoersRead:
		tags = append(tags, "sudoers:unreadable")
	case s.SudoersSkipped > 0:
		tags = append(tags, "sudoers-skipped:"+strconv.Itoa(s.SudoersSkipped))
	}
	res.Resources = []connectors.ResourceRecord{{System: System, ExternalID: h, Name: h, Kind: "unix_host", Tags: tags}}

	acct := func(name string) connectors.Ref {
		return connectors.Ref{Kind: "account", System: System, ExternalID: name + "@" + h}
	}
	grp := func(name string) connectors.Ref {
		return connectors.Ref{Kind: "group", System: System, ExternalID: name + "@" + h}
	}
	haveAccount, haveGroup := map[string]bool{}, map[string]bool{}
	for _, a := range s.Accounts {
		haveAccount[a.Name] = true
	}
	for _, g := range s.Groups {
		haveGroup[g.Name] = true
	}

	// sudoers: one permission per rule, granted to the users and groups it names
	privGroup := map[string]bool{}
	var edges []connectors.EdgeRecord
	permSeen := map[string]bool{}
	for _, r := range s.Rules {
		id := h + "|sudo|" + r.ID
		if !permSeen[id] {
			permSeen[id] = true
			// every sudo rule lets its principal run commands as another user: none is below privileged
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: id,
				Action: "sudo " + r.Text, ResourceExternalID: h, Privileged: true})
		}
		perm := connectors.Ref{Kind: "perm", System: System, ExternalID: id}
		for _, p := range r.Principals {
			switch {
			case strings.HasPrefix(p, "u:") && haveAccount[p[2:]]:
				edges = append(edges, connectors.EdgeRecord{Src: acct(p[2:]), Dst: perm, Relation: "direct_grant"})
			case strings.HasPrefix(p, "g:") && haveGroup[p[2:]]:
				privGroup[p[2:]] = true
				edges = append(edges, connectors.EdgeRecord{Src: grp(p[2:]), Dst: perm, Relation: "grants"})
			}
		}
	}

	// uid 0 is root whatever its name
	root := connectors.PermissionRecord{System: System, ExternalID: h + "|uid0", Action: "uid 0 (root)", ResourceExternalID: h, Privileged: true}
	rootRef := connectors.Ref{Kind: "perm", System: System, ExternalID: root.ExternalID}
	rootUsed := false

	byGID := map[uint32]string{}
	for _, g := range s.Groups {
		if _, ok := byGID[g.GID]; !ok {
			byGID[g.GID] = g.Name
		}
		res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: g.Name + "@" + h, Name: g.Name, Kind: "unix_group",
			Privileged: privGroup[g.Name] || g.GID == 0})
	}
	for _, a := range s.Accounts {
		kind, status := "user", "active"
		if a.UID != 0 && a.UID < HumanUID || a.UID == 65534 {
			kind = "service"
		} else if noLogin[a.Shell] {
			status = "disabled" // a login account whose shell refuses logins
		}
		rec := connectors.AccountRecord{System: System, ExternalID: a.Name + "@" + h, Username: a.Name, Kind: kind, Status: status,
			Attributes: map[string]string{"uid": strconv.FormatUint(uint64(a.UID), 10), "gid": strconv.FormatUint(uint64(a.GID), 10), "shell": a.Shell, "home": a.Home}}
		if t, ok := s.LastLogin[a.Name]; ok {
			rec.LastLoginAt = &t
		}
		res.Accounts = append(res.Accounts, rec)
		if a.Privileged {
			rootUsed = true
			edges = append(edges, connectors.EdgeRecord{Src: acct(a.Name), Dst: rootRef, Relation: "direct_grant"})
		}
		if g, ok := byGID[a.GID]; ok { // the primary group
			edges = append(edges, connectors.EdgeRecord{Src: acct(a.Name), Dst: grp(g), Relation: "member_of"})
		}
	}
	for _, g := range s.Groups {
		for _, m := range g.Members {
			if haveAccount[m] {
				edges = append(edges, connectors.EdgeRecord{Src: acct(m), Dst: grp(g.Name), Relation: "member_of"})
			}
		}
	}
	if rootUsed {
		res.Permissions = append(res.Permissions, root)
	}
	res.Edges = dedupe(edges)
	return res
}

// dedupe drops repeated edges (a primary group that also lists the member) and orders them.
func dedupe(in []connectors.EdgeRecord) []connectors.EdgeRecord {
	seen := map[[3]string]bool{}
	var out []connectors.EdgeRecord
	for _, e := range in {
		k := [3]string{e.Src.Kind + ":" + e.Src.ExternalID, e.Dst.Kind + ":" + e.Dst.ExternalID, e.Relation}
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Src.ExternalID != b.Src.ExternalID {
			return a.Src.ExternalID < b.Src.ExternalID
		}
		return a.Dst.ExternalID < b.Dst.ExternalID
	})
	return out
}
