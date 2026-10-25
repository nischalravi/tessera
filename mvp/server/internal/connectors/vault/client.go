// Package vault reads a HashiCorp Vault (or OpenBao) server's access model into Tessera's graph, read-only
// (issue #560): ACL policies with the paths and capabilities they grant, the auth methods' roles (AppRole,
// Kubernetes, JWT/OIDC, AWS, GCP, Azure, TLS certificate, token roles) and users (userpass, LDAP and its
// groups), identity entities and identity groups.
//
// Authentication is a Vault token (X-Vault-Token) held sealed as the connection's credential. Use a
// periodic token of a dedicated read-only policy (see below), not a root token. The server's address is the
// connection's base URL: https, a well-formed domain name, no path; every call goes through internal/safehttp
// and only fixed API paths under /v1 are requested (list calls are GET with list=true). Secret engines are
// never read: no path under a secret mount is requested, and no secret value, role secret id or token is
// read.
//
// The token's policy needs read on sys/policies/acl/*, list on sys/policies/acl, read on sys/auth, list and
// read on auth/+/role/*, auth/+/users/*, auth/+/groups/*, auth/+/certs/* and auth/token/roles/*, list and
// read on identity/entity/id/* and identity/group/id/*, and read on auth/token/lookup-self. It never needs
// create, update or delete.
//
// Mapping onto Tessera's graph (Discover):
//
//	ACL policy                       -> group "policy:NAME" (vault_policy); privileged when a path block is (RulePrivileged)
//	path block of a policy           -> resource "path:PATH" (vault_path) and permission "policy:NAME|PATH" (capabilities as action)
//	auth role / token role           -> account "role:MOUNT/NAME" (kind service), member_of its policies
//	userpass and LDAP user           -> account "user:MOUNT/NAME", member_of its policies (and its LDAP groups)
//	LDAP group                       -> group "ldapgroup:MOUNT/NAME" (vault_ldap_group), member_of its policies
//	identity entity                  -> account "entity:ID" (service when every alias is a machine auth method), member_of its
//	                                    policies and identity groups
//	identity group                   -> group "idgroup:ID" (vault_identity_group), member_of its policies and parent groups
package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const (
	// MaxItems bounds each class read one call at a time (policies, roles of a mount, entities, groups).
	MaxItems = 20000
	// MaxMounts bounds the auth methods whose roles are read.
	MaxMounts = 100
)

var (
	nameRE      = regexp.MustCompile(`^[^\x00-\x1f\x7f/]{1,256}$`)
	policyRE    = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,128}$`)
	mountRE     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}(?:/[A-Za-z0-9._-]{1,64}){0,3}/?$`)
	namespaceRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}(?:/[A-Za-z0-9._-]{1,64}){0,7}$`)
	idRE        = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// IsNamespace reports whether s is a well-formed Vault Enterprise namespace path.
func IsNamespace(s string) bool { return namespaceRE.MatchString(s) && !strings.Contains(s, "..") }

// Config configures one Vault server.
type Config struct {
	// BaseURL is the server: https://vault.example.com:8200.
	BaseURL string
	// Token is the Vault token of the read-only policy.
	Token connsync.Secret
	// Namespace is the Vault Enterprise namespace (empty: the root namespace).
	Namespace string
}

// Client is a retrying REST client of one Vault server.
type Client struct {
	api  *connsync.Client
	base *url.URL
	cfg  Config
}

// Open validates cfg and returns the client. hc is the server's safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("vault: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	tok := cfg.Token.Reveal()
	if tok == "" || len(tok) > 4<<10 || strings.ContainsAny(tok, " \t\r\n\x00") {
		return nil, errors.New("vault: the credential is a Vault token")
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("vault: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("vault: the base URL is a host without a path")
	}
	if cfg.Namespace != "" && !IsNamespace(cfg.Namespace) {
		return nil, errors.New("vault: the namespace is not valid")
	}
	hdr := http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/vault"}, "X-Vault-Token": {tok}}
	if cfg.Namespace != "" {
		hdr.Set("X-Vault-Namespace", cfg.Namespace)
	}
	return &Client{base: base, cfg: cfg, api: &connsync.Client{HC: hc, Now: now, Header: hdr}}, nil
}

// Mode names how the client authenticates, for a prober.
func (c *Client) Mode() string { return "token" }

// url builds /v1/<segments...> with each segment escaped, so a name from a response cannot add path
// elements, and refuses "." and "..".
func (c *Client) url(list bool, segs ...string) (string, error) {
	var plain, esc []string
	for _, s := range segs {
		for _, p := range strings.Split(strings.Trim(s, "/"), "/") {
			if p == "" || p == "." || p == ".." {
				return "", errors.New("vault: invalid path element")
			}
			plain, esc = append(plain, p), append(esc, url.PathEscape(p))
		}
	}
	x := *c.base
	x.Path, x.RawPath = "/v1/"+strings.Join(plain, "/"), "/v1/"+strings.Join(esc, "/")
	if list {
		x.RawQuery = "list=true"
	}
	return x.String(), nil
}

// get reads one document and decodes its data member into v.
func (c *Client) get(ctx context.Context, v any, segs ...string) error {
	u, err := c.url(false, segs...)
	if err != nil {
		return err
	}
	var env struct {
		Data any `json:"data"`
	}
	env.Data = v
	_, err = c.api.GetJSON(ctx, u, nil, &env)
	return err
}

// list returns the keys under a path. Vault answers 404 for a path with no keys: that is an empty list.
func (c *Client) list(ctx context.Context, segs ...string) ([]string, error) {
	u, err := c.url(true, segs...)
	if err != nil {
		return nil, err
	}
	var env struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if _, err := c.api.GetJSON(ctx, u, nil, &env); err != nil {
		if connsync.Status(err) == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return env.Data.Keys, nil
}

// ProbeResult is what one bounded read found.
type ProbeResult struct {
	Identity                        string
	Policies, AuthMethods, Entities int
}

// Probe proves the token (its own display name), then lists policies, auth methods and entities. It keeps
// counts only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	var r ProbeResult
	var me struct {
		DisplayName string `json:"display_name"`
	}
	if err := c.get(ctx, &me, "auth", "token", "lookup-self"); err != nil {
		return r, err
	}
	r.Identity = me.DisplayName
	if r.Identity == "" {
		r.Identity = "token"
	}
	pol, err := c.list(ctx, "sys", "policies", "acl")
	if err != nil {
		return r, err
	}
	r.Policies = len(pol)
	var auth map[string]struct {
		Type string `json:"type"`
	}
	if err := c.get(ctx, &auth, "sys", "auth"); err != nil {
		return r, err
	}
	r.AuthMethods = len(auth)
	ents, err := c.list(ctx, "identity", "entity", "id")
	if err != nil {
		return r, err
	}
	r.Entities = len(ents)
	return r, nil
}

// validName and validPolicy admit a name the server returned into a path or an id: well formed, and never "."
// or "..".
func validName(s string) bool { return nameRE.MatchString(s) && s != "." && s != ".." }

func validPolicy(s string) bool { return policyRE.MatchString(s) && s != "." && s != ".." }
