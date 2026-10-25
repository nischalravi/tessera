package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the graph system name.
const System = "mcp"

// riskyName marks a tool with no destructive annotation whose name says it runs commands or deletes.
var riskyName = regexp.MustCompile(`(?i)(^|[_.:/-])(exec|execute|shell|bash|run_command|eval|delete|drop|destroy|rm|admin|sudo)([_.:/-]|$)`)

// Connector is the read connector (connectors.Connector).
type Connector struct {
	c   *Client
	now func() time.Time
}

// NewConnector wraps a client.
func NewConnector(c *Client, now func() time.Time) *Connector {
	if now == nil {
		now = time.Now
	}
	return &Connector{c, now}
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "MCP server" }
func (*Connector) TypeName() string    { return "MCPServerConnector" }

// StreamEvents: no usage is read.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// ConfigFromEnv reads TESSERA_MCP_*:
//
//	TESSERA_MCP_URL          the MCP endpoint, https
//	TESSERA_MCP_NAME         optional display name
//	TESSERA_MCP_OWNER        optional e-mail address of the accountable person
//	TESSERA_MCP_AUTH_HEADER  optional header name for an API key (default: Authorization: Bearer)
//	TESSERA_MCP_TOKEN        reference to the token or key: file:/abs/path or env:NAME
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_MCP_"
	secret, err := connsync.ResolveSecret(getenv(p+"TOKEN"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "TOKEN: " + err.Error())
	}
	return Config{URL: getenv(p + "URL"), Name: strings.TrimSpace(getenv(p + "NAME")), Owner: strings.TrimSpace(getenv(p + "OWNER")),
		AuthHeader: strings.TrimSpace(getenv(p + "AUTH_HEADER")), Secret: secret}, nil
}

// FromEnv builds the read connector from TESSERA_MCP_* (ConfigFromEnv).
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	c, err := Open(cfg, rt, hc)
	if err != nil {
		return nil, err
	}
	return NewConnector(c, now), nil
}

// slug turns the endpoint into an id fragment: host and path, lower case, anything else a hyphen.
func slug(host, path string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(host + path) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

func privileged(t Tool) bool {
	if t.Destructive != nil {
		return *t.Destructive
	}
	if t.ReadOnly != nil && *t.ReadOnly {
		return false
	}
	return riskyName.MatchString(t.Name)
}

// Discover reads the server and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	info, err := c.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	host, path := c.c.Host(), c.c.Path()
	id := slug(host, path)
	xid := "mcp:" + id
	name := c.c.cfg.Name
	if name == "" {
		name = info.ServerName
	}
	if name == "" {
		name = host
	}
	auth := "required"
	if info.Anonymous {
		auth = "anonymous"
	}
	var owner *connectors.IdentityRef
	if o := strings.ToLower(c.c.cfg.Owner); o != "" {
		owner = &connectors.IdentityRef{Email: o}
	}
	desc := "MCP server " + host + path
	res := &connectors.DiscoveryResult{AgentSnapshotOf: []string{System}}
	res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "service", Status: "active",
		Description: &desc, Owner: owner})
	attrs := map[string]string{"host": host, "path": path, "auth_mode": auth, "protocol_version": info.ProtocolVersion,
		"server_name": info.ServerName, "server_version": info.ServerVersion}
	created := c.now().UTC()
	res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: id, Username: name,
		Identity: &connectors.IdentityRef{ExternalID: xid}, Kind: "service", Status: "active", CreatedAt: &created, Attributes: attrs})
	sum := sha256.Sum256([]byte(host + path))
	finding := connectors.MCPFindingRecord{System: System, Kind: "mcp_server", Org: host, Path: path, Location: "tools/list", Server: name,
		Transport: "http", Target: host, Fingerprint: hex.EncodeToString(sum[:6]), OwnerSource: "none", Owner: owner}
	if owner != nil {
		finding.OwnerRef, finding.OwnerSource = owner.Email, "configured"
	}
	res.MCPFindings = append(res.MCPFindings, finding)

	acct := connectors.Ref{Kind: "account", System: System, ExternalID: id}
	sort.SliceStable(info.Tools, func(i, j int) bool { return info.Tools[i].Name < info.Tools[j].Name })
	seen := map[string]bool{}
	for _, t := range info.Tools {
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		rid := id + "/" + t.Name
		tags := []string{"mcp"}
		switch {
		case t.Destructive != nil && *t.Destructive:
			tags = append(tags, "destructive")
		case t.ReadOnly != nil && *t.ReadOnly:
			tags = append(tags, "read_only")
		}
		if info.Anonymous {
			tags = append(tags, "anonymous_access")
		}
		res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: rid, Name: t.Name, Kind: "mcp_tool", Tags: tags})
		perm := rid + "#call"
		res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: perm, Action: "call",
			ResourceExternalID: rid, Privileged: privileged(t)})
		res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acct, Dst: connectors.Ref{Kind: "perm", System: System, ExternalID: perm}, Relation: "direct_grant"})
	}
	return res, nil
}
