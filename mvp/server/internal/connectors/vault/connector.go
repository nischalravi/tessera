package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the connector's system name.
const System = "vault"

// Resource and group kinds.
const (
	KindPath          = "vault_path"
	KindPolicy        = "vault_policy"
	KindLDAPGroup     = "vault_ldap_group"
	KindIdentityGroup = "vault_identity_group"
)

// ConfigFromEnv reads TESSERA_VAULT_*:
//
//	TESSERA_VAULT_BASE_URL   https://vault.example.com:8200
//	TESSERA_VAULT_TOKEN      reference (file:/abs/path or env:NAME) to the read-only Vault token
//	TESSERA_VAULT_NAMESPACE  optional: the Vault Enterprise namespace
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_VAULT_"
	secret, err := connsync.ResolveSecret(getenv(p+"TOKEN"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "TOKEN: " + err.Error())
	}
	return Config{BaseURL: getenv(p + "BASE_URL"), Token: secret, Namespace: strings.TrimSpace(getenv(p + "NAMESPACE"))}, nil
}

// Connector is the read connector (connectors.Connector).
type Connector struct{ c *Client }

// NewConnector wraps a client.
func NewConnector(c *Client) *Connector { return &Connector{c} }

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "HashiCorp Vault" }
func (*Connector) TypeName() string    { return "VaultConnector" }

// StreamEvents: no usage is read here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// FromEnv builds the read connector from TESSERA_VAULT_* (ConfigFromEnv).
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	c, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(c), nil
}

// mountKinds says, per auth method type, which collections hold identities: role and certs are machine
// roles, users are people, groups are LDAP groups.
var mountKinds = map[string][]struct{ path, kind string }{
	"approle":    {{"role", "role"}},
	"kubernetes": {{"role", "role"}},
	"jwt":        {{"role", "role"}},
	"oidc":       {{"role", "role"}},
	"aws":        {{"role", "role"}},
	"gcp":        {{"role", "role"}},
	"azure":      {{"role", "role"}},
	"cert":       {{"certs", "role"}},
	"userpass":   {{"users", "user"}},
	"ldap":       {{"users", "user"}, {"groups", "ldapgroup"}},
}

// machineAuth are the auth method types whose identities are workloads.
var machineAuth = map[string]bool{"approle": true, "kubernetes": true, "aws": true, "gcp": true, "azure": true, "cert": true, "jwt": true}

type policyDoc struct {
	Policy string `json:"policy"`
}

type authItem struct {
	Policies      []string `json:"policies"`
	TokenPolicies []string `json:"token_policies"`
	Allowed       []string `json:"allowed_policies"`
	Groups        any      `json:"groups"`
}

func (a authItem) all() []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range [][]string{a.Policies, a.TokenPolicies, a.Allowed} {
		for _, p := range l {
			if validPolicy(p) && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// groups reads an LDAP user's groups, which Vault answers as a list (or a comma separated string in old versions).
func (a authItem) groupNames() []string {
	var out []string
	switch g := a.Groups.(type) {
	case []any:
		for _, e := range g {
			if s, ok := e.(string); ok && validName(s) {
				out = append(out, s)
			}
		}
	case string:
		for _, s := range strings.Split(g, ",") {
			if s = strings.TrimSpace(s); validName(s) {
				out = append(out, s)
			}
		}
	}
	return out
}

type entityDoc struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Disabled bool              `json:"disabled"`
	Policies []string          `json:"policies"`
	GroupIDs []string          `json:"group_ids"`
	Metadata map[string]string `json:"metadata"`
	Aliases  []struct {
		MountType string `json:"mount_type"`
	} `json:"aliases"`
}

type groupDoc struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Policies []string `json:"policies"`
	Members  []string `json:"member_entity_ids"`
	Groups   []string `json:"member_group_ids"`
}

// Discover reads policies, auth method roles and users, entities and identity groups, and maps them.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	cl := c.c
	res := &connectors.DiscoveryResult{System: System}
	var partial []string
	note := func(why string) {
		for _, p := range partial {
			if p == why {
				return
			}
		}
		partial = append(partial, why)
	}
	ref := func(kind, id string) connectors.Ref {
		return connectors.Ref{Kind: kind, System: System, ExternalID: id}
	}
	edgeSeen := map[string]bool{}
	edge := func(src, dst connectors.Ref, rel string) {
		if k := src.Kind + ":" + src.ExternalID + ">" + rel + ">" + dst.Kind + ":" + dst.ExternalID; !edgeSeen[k] {
			edgeSeen[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: dst, Relation: rel})
		}
	}
	// readable tells a skipped class (the token may not read it) from a failed one.
	skip := func(err error) bool {
		s := connsync.Status(err)
		return s == http.StatusForbidden || s == http.StatusNotFound
	}

	// policies
	names, err := cl.list(ctx, "sys", "policies", "acl")
	if err != nil {
		return nil, wrap("policies", err)
	}
	sort.Strings(names)
	if len(names) > MaxItems {
		names = names[:MaxItems]
		note("more policies than the connector reads")
	}
	known := map[string]bool{}
	resSeen := map[string]bool{}
	for _, n := range names {
		if !validPolicy(n) {
			continue
		}
		known[n] = true
		g := connectors.GroupRecord{System: System, ExternalID: "policy:" + n, Name: n, Kind: KindPolicy, Privileged: n == "root"}
		var rules []PathRule
		if n != "root" { // the root policy is not readable and holds everything
			var doc policyDoc
			if err := cl.get(ctx, &doc, "sys", "policies", "acl", n); err != nil {
				if !skip(err) {
					return nil, wrap("policy", err)
				}
				note("a policy could not be read")
			} else if rules, err = ParsePolicy(doc.Policy); err != nil {
				note("a policy could not be parsed")
			}
		}
		for _, r := range rules {
			if r.Path == "" || len(r.Capabilities) == 0 {
				continue
			}
			rid := "path:" + r.Path
			if !resSeen[rid] {
				resSeen[rid] = true
				res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: rid, Name: r.Path, Kind: KindPath, Tags: []string{"vault"}})
			}
			priv := RulePrivileged(r)
			pid := "policy:" + n + "|" + r.Path
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: pid, Action: strings.Join(r.Capabilities, ","),
				ResourceExternalID: rid, Privileged: priv})
			edge(ref("group", g.ExternalID), ref("perm", pid), "grants")
			g.Privileged = g.Privileged || priv
		}
		res.Groups = append(res.Groups, g)
	}
	member := func(src connectors.Ref, policies []string) {
		for _, p := range policies {
			if known[p] {
				edge(src, ref("group", "policy:"+p), "member_of")
			}
		}
	}
	addAccount := func(id, name, kind, status string, attrs map[string]string) {
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: id, Username: name, Kind: kind, Status: status, Attributes: attrs})
	}

	// auth methods: roles, users and LDAP groups
	var auth map[string]struct {
		Type string `json:"type"`
	}
	if err := cl.get(ctx, &auth, "sys", "auth"); err != nil {
		return nil, wrap("auth methods", err)
	}
	mounts := make([]string, 0, len(auth))
	for m := range auth {
		if mountRE.MatchString(m) {
			mounts = append(mounts, m)
		}
	}
	sort.Strings(mounts)
	if len(mounts) > MaxMounts {
		mounts = mounts[:MaxMounts]
		note("more auth methods than the connector reads")
	}
	for _, m := range mounts {
		mount := strings.TrimSuffix(m, "/")
		typ := auth[m].Type
		kinds := mountKinds[typ]
		if typ == "token" {
			mount, kinds = "token", []struct{ path, kind string }{{"roles", "role"}}
		}
		for _, k := range kinds {
			segs := []string{"auth", mount, k.path}
			if typ == "token" {
				segs = []string{"auth", "token", "roles"}
			}
			keys, err := cl.list(ctx, segs...)
			if err != nil {
				if !skip(err) {
					return nil, wrap("auth method", err)
				}
				note("an auth method could not be listed")
				continue
			}
			sort.Strings(keys)
			if len(keys) > MaxItems {
				keys = keys[:MaxItems]
				note("more roles than the connector reads")
			}
			for _, key := range keys {
				if !validName(key) {
					continue
				}
				var it authItem
				if err := cl.get(ctx, &it, append(append([]string(nil), segs...), key)...); err != nil {
					if !skip(err) {
						return nil, wrap("auth role", err)
					}
					note("an auth role could not be read")
					continue
				}
				switch k.kind {
				case "role":
					id := "role:" + mount + "/" + key
					addAccount(id, mount+"/"+key, "service", "active", map[string]string{"auth_type": typ, "mount": mount, "name": key})
					member(ref("account", id), it.all())
				case "user":
					id := "user:" + mount + "/" + key
					addAccount(id, mount+"/"+key, "user", "active", map[string]string{"auth_type": typ, "mount": mount, "name": key})
					member(ref("account", id), it.all())
					for _, g := range it.groupNames() {
						edge(ref("account", id), ref("group", "ldapgroup:"+mount+"/"+g), "member_of")
					}
				case "ldapgroup":
					id := "ldapgroup:" + mount + "/" + key
					res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: id, Name: mount + "/" + key, Kind: KindLDAPGroup})
					member(ref("group", id), it.all())
				}
			}
		}
	}

	// identity entities and groups
	ents, err := cl.list(ctx, "identity", "entity", "id")
	if err != nil {
		if !skip(err) {
			return nil, wrap("entities", err)
		}
		note("entities could not be listed")
	}
	sort.Strings(ents)
	if len(ents) > MaxItems {
		ents = ents[:MaxItems]
		note("more entities than the connector reads")
	}
	for _, id := range ents {
		if !idRE.MatchString(id) {
			continue
		}
		var e entityDoc
		if err := cl.get(ctx, &e, "identity", "entity", "id", id); err != nil {
			if !skip(err) {
				return nil, wrap("entity", err)
			}
			note("an entity could not be read")
			continue
		}
		name := e.Name
		if !validName(name) {
			name = id
		}
		kind := "user"
		if len(e.Aliases) > 0 {
			kind = "service"
			for _, a := range e.Aliases {
				if !machineAuth[a.MountType] {
					kind = "user"
				}
			}
		}
		status := "active"
		if e.Disabled {
			status = "disabled"
		}
		aid := "entity:" + id
		addAccount(aid, name, kind, status, map[string]string{"id": id, "name": name})
		if mail := strings.ToLower(strings.TrimSpace(e.Metadata["email"])); mail != "" && strings.Contains(mail, "@") && kind == "user" {
			res.Accounts[len(res.Accounts)-1].Identity = &connectors.IdentityRef{Email: mail}
		}
		member(ref("account", aid), e.Policies)
		for _, g := range e.GroupIDs {
			if idRE.MatchString(g) {
				edge(ref("account", aid), ref("group", "idgroup:"+g), "member_of")
			}
		}
	}
	gids, err := cl.list(ctx, "identity", "group", "id")
	if err != nil {
		if !skip(err) {
			return nil, wrap("identity groups", err)
		}
		note("identity groups could not be listed")
	}
	sort.Strings(gids)
	if len(gids) > MaxItems {
		gids = gids[:MaxItems]
		note("more identity groups than the connector reads")
	}
	for _, id := range gids {
		if !idRE.MatchString(id) {
			continue
		}
		var g groupDoc
		if err := cl.get(ctx, &g, "identity", "group", "id", id); err != nil {
			if !skip(err) {
				return nil, wrap("identity group", err)
			}
			note("an identity group could not be read")
			continue
		}
		name := g.Name
		if !validName(name) {
			name = id
		}
		gid := "idgroup:" + id
		res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: gid, Name: name, Kind: KindIdentityGroup})
		member(ref("group", gid), g.Policies)
		for _, m := range g.Members {
			if idRE.MatchString(m) {
				edge(ref("account", "entity:"+m), ref("group", gid), "member_of")
			}
		}
		for _, p := range g.Groups {
			if idRE.MatchString(p) {
				edge(ref("group", gid), ref("group", "idgroup:"+p), "member_of")
			}
		}
	}
	res.Partial = strings.Join(partial, "; ")
	pruneEdges(res)
	return res, nil
}

// pruneEdges drops the edges whose ends this read did not produce (a member of a group or an LDAP group the
// token could not read), so ingest never sees a dangling reference.
func pruneEdges(res *connectors.DiscoveryResult) {
	have := map[string]bool{}
	for _, a := range res.Accounts {
		have["account:"+a.ExternalID] = true
	}
	for _, g := range res.Groups {
		have["group:"+g.ExternalID] = true
	}
	for _, p := range res.Permissions {
		have["perm:"+p.ExternalID] = true
	}
	out := res.Edges[:0]
	for _, e := range res.Edges {
		if have[e.Src.Kind+":"+e.Src.ExternalID] && have[e.Dst.Kind+":"+e.Dst.ExternalID] {
			out = append(out, e)
		}
	}
	res.Edges = out
}

// wrap names the class that failed; the cause is the connsync error, which never carries a response body.
func wrap(what string, err error) error { return fmt.Errorf("vault: reading %s: %w", what, err) }
