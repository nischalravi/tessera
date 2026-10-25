package kubernetes

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
const System = "kubernetes"

// Resource and group kinds.
const (
	KindCluster     = "k8s_cluster"
	KindNamespace   = "k8s_namespace"
	KindGroup       = "k8s_group"
	KindOpenShift   = "openshift_group"
	clusterScopeKey = "cluster"
)

// ConfigFromEnv reads TESSERA_KUBERNETES_*:
//
//	TESSERA_KUBERNETES_BASE_URL    https://api.cluster.example.com:6443
//	TESSERA_KUBERNETES_TOKEN       reference (file:/abs/path or env:NAME) to the ServiceAccount bearer token
//	TESSERA_KUBERNETES_NAMESPACES  optional: comma separated namespaces to read roles, bindings and service accounts of
//	TESSERA_KUBERNETES_OPENSHIFT   true to read the groups of user.openshift.io
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_KUBERNETES_"
	secret, err := connsync.ResolveSecret(getenv(p+"TOKEN"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "TOKEN: " + err.Error())
	}
	var ns []string
	for _, s := range strings.Split(getenv(p+"NAMESPACES"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			ns = append(ns, s)
		}
	}
	return Config{BaseURL: getenv(p + "BASE_URL"), Token: secret, Namespaces: ns,
		OpenShift: strings.EqualFold(strings.TrimSpace(getenv(p+"OPENSHIFT")), "true")}, nil
}

// Connector is the read connector (connectors.Connector).
type Connector struct{ c *Client }

// NewConnector wraps a client.
func NewConnector(c *Client) *Connector { return &Connector{c} }

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Kubernetes and OpenShift" }
func (*Connector) TypeName() string    { return "KubernetesConnector" }

// StreamEvents: no usage is read here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// FromEnv builds the read connector from TESSERA_KUBERNETES_* (ConfigFromEnv).
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

func in(list []string, want ...string) bool {
	for _, s := range list {
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
}

// Privileged reports whether rules give broad or escalating power: every verb on every resource, the
// escalate, bind or impersonate verbs, reading secrets, writing RBAC objects or tokens, or running commands
// in pods.
func Privileged(rules []Rule) bool {
	for _, r := range rules {
		if len(r.Resources) == 0 {
			continue // a non-resource URL rule
		}
		allVerbs := in(r.Verbs, "*")
		write := allVerbs || in(r.Verbs, "create", "update", "patch", "delete", "deletecollection")
		switch {
		case allVerbs && in(r.Resources, "*"):
			return true
		case in(r.Verbs, "escalate", "bind", "impersonate"):
			return true
		case (allVerbs || in(r.Verbs, "get", "list", "watch")) && in(r.Resources, "secrets", "*"):
			return true
		case write && in(r.Resources, "roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts/token", "pods/exec", "pods/attach"):
			return true
		case write && in(r.Resources, "*") && len(r.APIGroups) > 0 && in(r.APIGroups, "*", "rbac.authorization.k8s.io"):
			return true
		}
	}
	return false
}

// snapshot is what Discover read.
type snapshot struct {
	clusterRoles map[string]bool // name -> privileged
	roles        map[string]bool // namespace/name -> privileged
	bindings     []binding
	sas          []saObj
	osGroups     []osGroupObj
	openshift    bool
}

// binding is a (Cluster)RoleBinding in one scope: namespace is empty for a ClusterRoleBinding.
type binding struct {
	namespace string
	ref       roleRef
	subjects  []subject
}

func (c *Client) read(ctx context.Context) (*snapshot, error) {
	s := &snapshot{clusterRoles: map[string]bool{}, roles: map[string]bool{}, openshift: c.cfg.OpenShift}
	wrap := func(what string, err error) error { return fmt.Errorf("%s: %w", what, err) }
	if err := listAll(ctx, c, rbacAPI+"/clusterroles", pageSize, func(r roleObj) {
		if nameRE.MatchString(r.Metadata.Name) {
			s.clusterRoles[r.Metadata.Name] = Privileged(r.Rules)
		}
	}); err != nil {
		return nil, wrap("cluster roles", err)
	}
	if err := listAll(ctx, c, rbacAPI+"/clusterrolebindings", pageSize, func(b bindingObj) {
		s.bindings = append(s.bindings, binding{ref: b.RoleRef, subjects: b.Subjects})
	}); err != nil {
		return nil, wrap("cluster role bindings", err)
	}
	if err := scoped(ctx, c, rbacAPI, "roles", func(r roleObj) {
		if nameRE.MatchString(r.Metadata.Name) && nsRE.MatchString(r.Metadata.Namespace) {
			s.roles[r.Metadata.Namespace+"/"+r.Metadata.Name] = Privileged(r.Rules)
		}
	}); err != nil {
		return nil, wrap("roles", err)
	}
	if err := scoped(ctx, c, rbacAPI, "rolebindings", func(b bindingObj) {
		if nsRE.MatchString(b.Metadata.Namespace) {
			s.bindings = append(s.bindings, binding{namespace: b.Metadata.Namespace, ref: b.RoleRef, subjects: b.Subjects})
		}
	}); err != nil {
		return nil, wrap("role bindings", err)
	}
	if err := scoped(ctx, c, "/api/v1", "serviceaccounts", func(a saObj) { s.sas = append(s.sas, a) }); err != nil {
		return nil, wrap("service accounts", err)
	}
	if c.cfg.OpenShift {
		if err := listAll(ctx, c, osGroupsAPI, pageSize, func(g osGroupObj) { s.osGroups = append(s.osGroups, g) }); err != nil {
			return nil, wrap("OpenShift groups", err)
		}
	}
	return s, nil
}

// Discover reads the cluster's RBAC objects and maps them.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	s, err := c.c.read(ctx)
	if err != nil {
		return nil, err
	}
	return build(s), nil
}

func emailOf(name string) *connectors.IdentityRef {
	if i := strings.LastIndex(name, ":"); i >= 0 {
		name = name[i+1:]
	}
	if at := strings.Index(name, "@"); at > 0 && at < len(name)-1 && !strings.ContainsAny(name, " \t") {
		return &connectors.IdentityRef{Email: strings.ToLower(name)}
	}
	return nil
}

func build(s *snapshot) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{System: System}
	resSeen, permSeen, acctSeen, groupSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	edgeSeen := map[string]bool{}
	edge := func(src, dst connectors.Ref, rel string) {
		if k := src.Kind + ":" + src.ExternalID + ">" + rel + ">" + dst.Kind + ":" + dst.ExternalID; !edgeSeen[k] {
			edgeSeen[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: dst, Relation: rel})
		}
	}
	ref := func(kind, id string) connectors.Ref {
		return connectors.Ref{Kind: kind, System: System, ExternalID: id}
	}
	scope := func(ns string) string {
		key, name, kind := clusterScopeKey, "cluster", KindCluster
		if ns != "" {
			key, name, kind = "namespace:"+ns, ns, KindNamespace
		}
		if !resSeen[key] {
			resSeen[key] = true
			res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: key, Name: name, Kind: kind,
				Tags: []string{"kubernetes", strings.TrimPrefix(kind, "k8s_")}})
		}
		return key
	}
	osKnown := map[string]bool{}
	for _, g := range s.osGroups {
		if nameRE.MatchString(g.Metadata.Name) {
			osKnown[g.Metadata.Name] = true
		}
	}
	addGroup := func(name string) string {
		id := "group:" + name
		if !groupSeen[id] {
			groupSeen[id] = true
			kind := KindGroup
			if osKnown[name] {
				kind = KindOpenShift
			}
			res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: id, Name: name, Kind: kind})
		}
		return id
	}
	addAccount := func(id, name, kind string) {
		if !acctSeen[id] {
			acctSeen[id] = true
			a := connectors.AccountRecord{System: System, ExternalID: id, Username: name, Kind: kind, Status: "active",
				Attributes: map[string]string{"name": name}}
			if kind == "user" {
				a.Identity = emailOf(name)
			}
			res.Accounts = append(res.Accounts, a)
		}
	}

	scope("")
	nsOfSA := map[string]string{} // account id -> namespace
	sas := append([]saObj(nil), s.sas...)
	sort.SliceStable(sas, func(i, j int) bool {
		return sas[i].Metadata.Namespace+"/"+sas[i].Metadata.Name < sas[j].Metadata.Namespace+"/"+sas[j].Metadata.Name
	})
	for _, a := range sas {
		if !nsRE.MatchString(a.Metadata.Namespace) || !nameRE.MatchString(a.Metadata.Name) {
			continue
		}
		id := "sa:" + a.Metadata.Namespace + "/" + a.Metadata.Name
		addAccount(id, a.Metadata.Namespace+"/"+a.Metadata.Name, "service")
		nsOfSA[id] = a.Metadata.Namespace
		scope(a.Metadata.Namespace)
	}

	for _, b := range s.bindings {
		if !nameRE.MatchString(b.ref.Name) || (b.ref.Kind != "ClusterRole" && b.ref.Kind != "Role") {
			continue
		}
		sk := scope(b.namespace)
		var priv bool
		var rk string
		if b.ref.Kind == "ClusterRole" {
			priv, rk = s.clusterRoles[b.ref.Name], "clusterrole:"+b.ref.Name
		} else if b.namespace != "" { // a ClusterRoleBinding names a ClusterRole only
			priv, rk = s.roles[b.namespace+"/"+b.ref.Name], "role:"+b.ref.Name
		} else {
			continue
		}
		id := sk + "|" + rk
		if !permSeen[id] {
			permSeen[id] = true
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: id,
				Action: strings.Replace(rk, ":", " ", 1), ResourceExternalID: sk, Privileged: priv})
		}
		perm := ref("perm", id)
		for _, sub := range b.subjects {
			if !nameRE.MatchString(sub.Name) {
				continue
			}
			switch sub.Kind {
			case "User":
				aid := "user:" + sub.Name
				addAccount(aid, sub.Name, "user")
				edge(ref("account", aid), perm, "direct_grant")
			case "Group":
				edge(ref("group", addGroup(sub.Name)), perm, "grants")
			case "ServiceAccount":
				ns := sub.Namespace
				if ns == "" {
					ns = b.namespace
				}
				if !nsRE.MatchString(ns) {
					continue
				}
				aid := "sa:" + ns + "/" + sub.Name
				addAccount(aid, ns+"/"+sub.Name, "service")
				nsOfSA[aid] = ns
				edge(ref("account", aid), perm, "direct_grant")
			}
		}
	}

	// a service account is a member of the groups the API server adds it to
	ids := make([]string, 0, len(nsOfSA))
	for id := range nsOfSA {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, g := range []string{"system:serviceaccounts", "system:serviceaccounts:" + nsOfSA[id], "system:authenticated"} {
			if groupSeen["group:"+g] {
				edge(ref("account", id), ref("group", "group:"+g), "member_of")
			}
		}
	}

	groups := append([]osGroupObj(nil), s.osGroups...)
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Metadata.Name < groups[j].Metadata.Name })
	for _, g := range groups {
		if !nameRE.MatchString(g.Metadata.Name) {
			continue
		}
		gid := addGroup(g.Metadata.Name)
		for _, u := range g.Users {
			if !nameRE.MatchString(u) {
				continue
			}
			aid := "user:" + u
			addAccount(aid, u, "user")
			edge(ref("account", aid), ref("group", gid), "member_of")
		}
	}
	return res
}
