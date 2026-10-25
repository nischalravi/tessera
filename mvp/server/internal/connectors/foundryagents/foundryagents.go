// Package foundryagents inventories the agents of an Azure AI Foundry project (issue #562): each agent of the
// Agent Service, its tools and the data they reach, as an ai_agent non-human identity linked to its owner. It
// is read-only: only the agents list (a GET) is sent.
//
// Authentication is the Entra client-credentials flow of the azurerbac connector (a client secret or a
// certificate; scope https://ai.azure.com/.default, the application needs the Azure AI User role on the
// project). There is no Azure SDK.
//
// Mapping, per agent:
//
//	identity  foundry:<agent id>, type ai_agent, owned by its "sponsor" (else "owner") metadata value or, when
//	          that is no e-mail address, the connection's owner setting
//	account   <agent id>, kind agent; an agent record of kind foundry_agent (creator: the "creator" metadata)
//	access    each tool: a function (invoke), the code interpreter (privileged), file search over its vector
//	          stores (file_search), Azure AI Search indexes (search), an OpenAPI tool, another agent
//	          (invoke_agent), an MCP server, or any other tool type by name
//
// Instructions, tool definitions, schemas and descriptions are never read into the result: only a tool's type,
// its name and the ids of the data it points at.
package foundryagents

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentmap"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name; AgentKind the agent profile kind.
const (
	System    = "azure-foundry"
	AgentKind = "foundry_agent"
	// Scope is the token audience of the Foundry data plane.
	Scope      = "https://ai.azure.com/.default"
	apiVersion = "2025-05-01"
)

const (
	pageSize  = 100
	maxPages  = 100
	maxAgents = 5000
	maxItems  = 100
)

var (
	// hostSuffixes are the domains a Foundry project endpoint lives under. The token goes only to these.
	hostSuffixes = []string{".services.ai.azure.com", ".cognitiveservices.azure.com", ".openai.azure.com"}
	pathRE       = regexp.MustCompile(`^/api/projects/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	agentIDRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
	typeRE       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	nameRE       = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	emailRE      = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)
)

// ErrCredential is Entra refusing the application.
var ErrCredential = azurerbac.ErrCredential

// Config configures one project.
type Config struct {
	// BaseURL is the project endpoint: https://<account>.services.ai.azure.com/api/projects/<project>.
	BaseURL            string
	TenantID, ClientID string
	// Credential is a client secret or a PEM with the certificate and its RSA key.
	Credential connsync.Secret
	// Owner is the e-mail address of the person accountable for agents that name no sponsor.
	Owner string
	// AuthorityURL overrides the Entra login endpoint. Dev and test only; Open refuses it outside dev.
	AuthorityURL string
}

// Client is a retrying Foundry client.
type Client struct {
	cfg  Config
	base *url.URL
	api  *connsync.Client
	auth *azurerbac.Auth
}

// CheckURL parses the project endpoint and refuses a host that is not an Azure AI one (loopback only in the dev
// runtime, for a local fake), a port, a query and a path other than /api/projects/<name>.
func CheckURL(raw string, rt connsync.Runtime) (*url.URL, error) {
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, err
	}
	if !pathRE.MatchString(u.Path) || u.RawQuery != "" {
		return nil, errors.New("the endpoint ends in /api/projects/<project>")
	}
	host := strings.ToLower(u.Hostname())
	if rt.Env != config.Prod && rt.AllowLoopback {
		if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
			return u, nil
		}
	}
	for _, suf := range hostSuffixes {
		if strings.HasSuffix(host, suf) && len(host) > len(suf) && u.Port() == "" {
			return u, nil
		}
	}
	return nil, errors.New("the host must be an Azure AI Foundry endpoint (*.services.ai.azure.com)")
}

// Open validates cfg and returns the client. hc must be the server's shared safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("foundryagents: an internal/safehttp client is required")
	}
	if cfg.Owner != "" && !emailRE.MatchString(cfg.Owner) {
		return nil, errors.New("foundryagents: the owner is an e-mail address")
	}
	base, err := CheckURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("foundryagents: endpoint: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	auth, err := azurerbac.NewAuth(cfg.TenantID, cfg.ClientID, cfg.Credential, Scope, cfg.AuthorityURL, rt, hc, now)
	if err != nil {
		return nil, err
	}
	hc = safehttp.WithConfiguredPorts(hc, base.String())
	c := &Client{cfg: cfg, base: base, auth: auth}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/foundry-agents"}},
		Authorize: auth.Authorize, OnUnauthorized: auth.Invalidate}
	return c, nil
}

// Identity is the application the client signs in as, for a prober.
func (c *Client) Identity() string { return c.cfg.ClientID }

// Mode is client_secret or certificate.
func (c *Client) Mode() string { return c.auth.Mode() }

// Format prints the client without its credential (every verb).
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "foundryagents.Client{"+c.base.Hostname()+"}")
}

type tool struct {
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
	OpenAPI struct {
		Name string `json:"name"`
	} `json:"openapi"`
	MCP struct {
		Label string `json:"server_label"`
	} `json:"mcp"`
	Connected struct {
		ID string `json:"id"`
	} `json:"connected_agent"`
}

type assistant struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	CreatedAt int64             `json:"created_at"`
	Metadata  map[string]string `json:"metadata"`
	Tools     []tool            `json:"tools"`
	Resources struct {
		FileSearch struct {
			VectorStoreIDs []string `json:"vector_store_ids"`
		} `json:"file_search"`
		AISearch struct {
			Indexes []struct {
				Connection string `json:"index_connection_id"`
				Name       string `json:"index_name"`
			} `json:"indexes"`
		} `json:"azure_ai_search"`
	} `json:"tool_resources"`
}

type agentsPage struct {
	Data    []assistant `json:"data"`
	HasMore bool        `json:"has_more"`
	LastID  string      `json:"last_id"`
}

func (c *Client) page(ctx context.Context, size int, after string) (agentsPage, error) {
	q := url.Values{"api-version": {apiVersion}, "limit": {strconv.Itoa(size)}, "order": {"asc"}}
	if after != "" {
		q.Set("after", after)
	}
	u := *c.base
	u.Path += "/assistants"
	u.RawQuery = q.Encode()
	var p agentsPage
	_, err := c.api.GetJSON(ctx, u.String(), nil, &p)
	return p, err
}

// ProbeResult is what one bounded read found.
type ProbeResult struct{ Agents int }

// Probe lists the first page, for the readiness checks, and keeps a count only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	p, err := c.page(ctx, 10, "")
	return ProbeResult{Agents: len(p.Data)}, err
}

// Read lists every agent of the project and maps it.
func (c *Client) Read(ctx context.Context) ([]agentmap.Agent, error) {
	var out []agentmap.Agent
	after := ""
	for i := 0; ; i++ {
		if i >= maxPages {
			return nil, errors.New("foundryagents: more pages than the connector reads")
		}
		p, err := c.page(ctx, pageSize, after)
		if err != nil {
			return nil, err
		}
		for _, x := range p.Data {
			if !agentIDRE.MatchString(x.ID) {
				continue
			}
			if len(out) >= maxAgents {
				return nil, errors.New("foundryagents: more agents than the connector reads")
			}
			out = append(out, c.agent(x))
		}
		if !p.HasMore || !agentIDRE.MatchString(p.LastID) || p.LastID == after {
			return out, nil
		}
		after = p.LastID
	}
}

func (c *Client) agent(x assistant) agentmap.Agent {
	md := map[string]string{}
	for k, v := range x.Metadata {
		if len(md) < 64 {
			md[strings.ToLower(agentmap.Clip(k, 64))] = agentmap.Clip(v, 256)
		}
	}
	a := agentmap.Agent{ID: x.ID, Name: agentmap.Clip(x.Name, 128), Kind: AgentKind, Creator: md["creator"],
		Attributes: map[string]string{"project": strings.TrimPrefix(c.base.Path, "/api/projects/")}, PII: strings.EqualFold(md["pii"], "true")}
	if x.CreatedAt > 0 {
		a.Created = time.Unix(x.CreatedAt, 0).UTC()
	}
	a.Owner = agentmap.First(md, "sponsor", "owner")
	if ref, _ := agentmap.Person(a.Owner); ref == nil {
		if c.cfg.Owner != "" {
			if a.Owner != "" {
				a.Attributes["sponsor_text"] = a.Owner
			}
			a.Owner = c.cfg.Owner
		}
	}
	add := func(res, name, kind, action string, priv bool, tags ...string) {
		if len(a.Access) < maxItems {
			a.Access = append(a.Access, agentmap.Access{Resource: res, Name: name, Kind: kind, Action: action, Privileged: priv, Tags: tags})
		}
	}
	for _, t := range x.Tools {
		if !typeRE.MatchString(t.Type) {
			continue
		}
		switch t.Type {
		case "function":
			if n := t.Function.Name; nameRE.MatchString(n) {
				add("foundry-function:"+x.ID+"/"+n, n, "foundry_function", "invoke", false)
			}
		case "code_interpreter":
			add("foundry-tool:code_interpreter", "code interpreter", "foundry_tool", "invoke", true, "code_execution")
		case "file_search":
			for _, v := range x.Resources.FileSearch.VectorStoreIDs {
				if agentIDRE.MatchString(v) {
					add("foundry-vector-store:"+v, v, "foundry_vector_store", "file_search", false)
				}
			}
		case "azure_ai_search":
			for _, ix := range x.Resources.AISearch.Indexes {
				if nameRE.MatchString(ix.Connection) {
					n := ix.Connection
					if nameRE.MatchString(ix.Name) {
						n += "/" + ix.Name
					}
					add("foundry-search-index:"+n, n, "foundry_search_index", "search", false)
				}
			}
		case "openapi":
			if n := t.OpenAPI.Name; nameRE.MatchString(n) {
				add("foundry-openapi:"+x.ID+"/"+n, n, "foundry_openapi_tool", "invoke", false)
			}
		case "connected_agent":
			if n := t.Connected.ID; agentIDRE.MatchString(n) {
				add("foundry-agent:"+n, n, "foundry_agent", "invoke_agent", false)
			}
		case "mcp":
			if n := t.MCP.Label; nameRE.MatchString(n) {
				add("foundry-mcp:"+n, n, "foundry_mcp_server", "invoke", false)
			}
		default:
			add("foundry-tool:"+t.Type, t.Type, "foundry_tool", "invoke", false)
		}
	}
	return a
}
