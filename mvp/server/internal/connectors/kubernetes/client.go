// Package kubernetes reads a Kubernetes or OpenShift cluster's RBAC model into Tessera's graph, read-only
// (issue #560): ClusterRoles and Roles with what their rules allow, ClusterRoleBindings and RoleBindings,
// ServiceAccounts and, on OpenShift, the groups of user.openshift.io with their members.
//
// Authentication is a bearer token (a ServiceAccount token) sent to the API server. The server's address is the
// connection's base URL: https, a well-formed domain name, no path; private and link-local addresses are refused
// by internal/safehttp, which every call goes through. Only fixed API paths are requested: a response never
// chooses a URL (a list continues with the continue token in the query, not with a link).
//
// The ServiceAccount needs list on clusterroles, clusterrolebindings, roles, rolebindings and serviceaccounts
// (the built-in "view" role does not cover RBAC objects; bind a ClusterRole with only those verbs) and, on
// OpenShift, list on groups.user.openshift.io. It never needs a write verb and none is ever sent.
//
// Mapping onto Tessera's graph (Discover):
//
//	cluster, namespace                   -> resource (kinds k8s_cluster, k8s_namespace)
//	(Cluster)Role bound at a scope       -> permission "scope|role"; privileged by the role's rules (see Privileged)
//	subject User                         -> account "user:NAME", direct_grant (correlated by e-mail when the name has one)
//	subject Group                        -> group "group:NAME" (k8s_group, or openshift_group when OpenShift lists it), grants
//	subject ServiceAccount, and every
//	ServiceAccount listed                -> account "sa:NAMESPACE/NAME" (kind service); member of the implicit
//	                                        system:serviceaccounts groups a binding names
//	OpenShift group members              -> accounts "user:NAME", member_of the group
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const (
	pageSize = "500"
	maxPages = 4000
	// MaxNamespaces bounds the namespaces a connection may restrict the read to (each costs three calls).
	MaxNamespaces = 100
	rbacAPI       = "/apis/rbac.authorization.k8s.io/v1"
	osGroupsAPI   = "/apis/user.openshift.io/v1/groups"
)

// allowedPorts are the ports the base URL may name (none: 443); the connection's own port is the only one
// the safehttp client is opened to.
var allowedPorts = []string{"443", "6443", "8443"}

// loopback reports the dev loopback exception: a test fake on an arbitrary local port.
func loopback(u *url.URL, rt connsync.Runtime) bool {
	if rt.Env == config.Prod || !rt.AllowLoopback {
		return false
	}
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.IsLoopback()
}

var (
	nsRE   = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	nameRE = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,253}$`)
)

// IsNamespace reports whether s is a namespace name (a DNS-1123 label).
func IsNamespace(s string) bool { return nsRE.MatchString(s) }

// Config configures one cluster.
type Config struct {
	// BaseURL is the API server: https://api.cluster.example.com:6443.
	BaseURL string
	// Token is the bearer token of the reading ServiceAccount.
	Token connsync.Secret
	// Namespaces restricts roles, role bindings and service accounts to these namespaces (none: all).
	Namespaces []string
	// OpenShift also reads the groups of user.openshift.io.
	OpenShift bool
}

// Client is a retrying REST client of one cluster.
type Client struct {
	api  *connsync.Client
	base *url.URL
	cfg  Config
}

// Open validates cfg and returns the client. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("kubernetes: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	tok := cfg.Token.Reveal()
	if tok == "" || len(tok) > 8<<10 || strings.ContainsAny(tok, " \t\r\n\x00") {
		return nil, errors.New("kubernetes: the credential is the ServiceAccount bearer token")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: base URL: %w", err)
	}
	if port := base.Port(); port != "" && !slices.Contains(allowedPorts, port) && !loopback(base, rt) {
		return nil, errors.New("kubernetes: the base URL port is not one of the supported ports")
	}
	if base.Path != "" {
		return nil, errors.New("kubernetes: the base URL is a host without a path")
	}
	if len(cfg.Namespaces) > MaxNamespaces {
		return nil, fmt.Errorf("kubernetes: at most %d namespaces", MaxNamespaces)
	}
	for _, n := range cfg.Namespaces {
		if !nsRE.MatchString(n) {
			return nil, errors.New("kubernetes: a namespace is not a valid name")
		}
	}
	bearer := "Bearer " + tok
	hdr := http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/kubernetes"}}
	hc = safehttp.WithConfiguredPorts(hc, base.String()) // the connection's own port, and no other
	return &Client{base: base, cfg: cfg,
		api: &connsync.Client{HC: hc, Now: now, Header: hdr, Authorize: func(context.Context) (string, error) { return bearer, nil }}}, nil
}

// Mode names how the client authenticates, for a prober.
func (c *Client) Mode() string { return "bearer_token" }

// Identity is the API server's host, for a prober (the token's own name is not read).
func (c *Client) Identity() string { return c.base.Hostname() }

// OpenShift reports whether the OpenShift groups are read.
func (c *Client) OpenShift() bool { return c.cfg.OpenShift }

func (c *Client) url(path string, q url.Values) string {
	x := *c.base
	x.Path = path
	x.RawQuery = q.Encode()
	return x.String()
}

type objectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type Rule struct {
	Verbs           []string `json:"verbs"`
	Resources       []string `json:"resources"`
	APIGroups       []string `json:"apiGroups"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type roleObj struct {
	Metadata objectMeta `json:"metadata"`
	Rules    []Rule     `json:"rules"`
}

type roleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type bindingObj struct {
	Metadata objectMeta `json:"metadata"`
	RoleRef  roleRef    `json:"roleRef"`
	Subjects []subject  `json:"subjects"`
}

type saObj struct {
	Metadata objectMeta `json:"metadata"`
}

type osGroupObj struct {
	Metadata objectMeta `json:"metadata"`
	Users    []string   `json:"users"`
}

// listAll walks a list endpoint with limit and the continue token and calls fn for every item.
func listAll[T any](ctx context.Context, c *Client, path string, limit string, fn func(T)) error {
	cont := ""
	for i := 0; ; i++ {
		if i >= maxPages {
			return fmt.Errorf("kubernetes: more than %d pages; stopping", maxPages)
		}
		q := url.Values{"limit": {limit}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var p struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if _, err := c.api.GetJSON(ctx, c.url(path, q), nil, &p); err != nil {
			return err
		}
		for _, it := range p.Items {
			fn(it)
		}
		if p.Metadata.Continue == "" || len(p.Items) == 0 {
			return nil
		}
		cont = p.Metadata.Continue
	}
}

// scoped lists a namespaced kind: cluster wide, or once per configured namespace.
func scoped[T any](ctx context.Context, c *Client, group, kind string, fn func(T)) error {
	if len(c.cfg.Namespaces) == 0 {
		return listAll(ctx, c, group+"/"+kind, pageSize, fn)
	}
	for _, ns := range c.cfg.Namespaces {
		if err := listAll(ctx, c, group+"/namespaces/"+ns+"/"+kind, pageSize, fn); err != nil {
			return err
		}
	}
	return nil
}

// ProbeResult is what one bounded read found (first page sizes only).
type ProbeResult struct {
	ClusterRoles, ClusterRoleBindings, ServiceAccounts, Groups int
}

// Probe reads the first few ClusterRoles, ClusterRoleBindings and ServiceAccounts (and OpenShift groups). It
// keeps counts only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	var r ProbeResult
	n := func(path string, into *int) error {
		var p struct {
			Items []struct{} `json:"items"`
		}
		if _, err := c.api.GetJSON(ctx, c.url(path, url.Values{"limit": {"5"}}), nil, &p); err != nil {
			return err
		}
		*into = len(p.Items)
		return nil
	}
	if err := n(rbacAPI+"/clusterroles", &r.ClusterRoles); err != nil {
		return r, err
	}
	if err := n(rbacAPI+"/clusterrolebindings", &r.ClusterRoleBindings); err != nil {
		return r, err
	}
	sa := "/api/v1/serviceaccounts"
	if len(c.cfg.Namespaces) > 0 {
		sa = "/api/v1/namespaces/" + c.cfg.Namespaces[0] + "/serviceaccounts"
	}
	if err := n(sa, &r.ServiceAccounts); err != nil {
		return r, err
	}
	if c.cfg.OpenShift {
		if err := n(osGroupsAPI, &r.Groups); err != nil {
			return r, fmt.Errorf("OpenShift groups: %w", err)
		}
	}
	return r, nil
}
