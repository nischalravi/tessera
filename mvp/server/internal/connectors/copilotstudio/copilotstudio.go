// Package copilotstudio inventories the agents of Microsoft Copilot Studio (issue #562) through the Dataverse
// Web API of one Power Platform environment: each agent (the bots table), its tool and knowledge components,
// as an ai_agent non-human identity linked to its owner. It is read-only: only GET requests are sent, and the
// application user needs a read-only Dataverse role (read on Chatbot, Chatbot Subcomponent and User).
//
// Authentication is the Entra client-credentials flow of the azurerbac connector (a client secret or a
// certificate; scope <environment url>/.default). There is no Microsoft SDK.
//
// Mapping, per agent:
//
//	identity  copilot:<bot id>, type ai_agent, owned by the Dataverse owner of the bot (read from systemusers:
//	          the internal e-mail address; a team owner is kept as text), creator likewise
//	account   <bot id>, kind agent (disabled when the bot is inactive); an agent record of kind copilot_studio_agent
//	access    each tool component (an action or skill: invoke) and each knowledge source (retrieve). A bot that
//	          requires no authentication of its callers carries the anonymous_access tag on everything it reaches.
//
// A component is classified by the segment of its schema name (<bot schema>.<segment>.<name>): action and skill
// are tools, knowledge and file are knowledge sources; topics and the rest are conversation content and are
// not read. The component's data (its YAML: instructions, prompts, descriptions) is never selected.
package copilotstudio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
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
	System    = "copilot-studio"
	AgentKind = "copilot_studio_agent"
	apiPath   = "/api/data/v9.2/"
)

const (
	maxPages  = 200
	maxAgents = 5000
	maxItems  = 200
	maxOwners = 500
)

var (
	// hostSuffixes are the domains a Dataverse environment lives under. The token goes only to these.
	hostSuffixes = []string{".dynamics.com", ".microsoftdynamics.us", ".dynamics.cn", ".appsplatform.us"}
	guidRE       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	schemaRE     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,200}$`)
	emailRE      = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)
)

// ErrCredential is Entra refusing the application.
var ErrCredential = azurerbac.ErrCredential

// Config configures one environment.
type Config struct {
	// BaseURL is the environment's Dataverse URL: https://<org>.crm.dynamics.com.
	BaseURL            string
	TenantID, ClientID string
	// Credential is a client secret or a PEM with the certificate and its RSA key.
	Credential connsync.Secret
	// AuthorityURL overrides the Entra login endpoint. Dev and test only; Open refuses it outside dev.
	AuthorityURL string
}

// Client is a retrying Dataverse client.
type Client struct {
	cfg  Config
	base *url.URL
	api  *connsync.Client
	auth *azurerbac.Auth
}

// CheckURL parses the environment URL and refuses a host that is not a Dataverse one (loopback only in the dev
// runtime, for a local fake), a port, a path and a query.
func CheckURL(raw string, rt connsync.Runtime) (*url.URL, error) {
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, errors.New("the environment URL is a host without a path")
	}
	u.Path = ""
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
	return nil, errors.New("the host must be a Dataverse environment (*.crm.dynamics.com)")
}

// Open validates cfg and returns the client. hc must be the server's shared safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("copilotstudio: an internal/safehttp client is required")
	}
	base, err := CheckURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("copilotstudio: environment URL: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	auth, err := azurerbac.NewAuth(cfg.TenantID, cfg.ClientID, cfg.Credential, base.Scheme+"://"+base.Host+"/.default", cfg.AuthorityURL, rt, hc, now)
	if err != nil {
		return nil, err
	}
	hc = safehttp.WithConfiguredPorts(hc, base.String())
	c := &Client{cfg: cfg, base: base, auth: auth}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/copilot-studio"},
		"OData-MaxVersion": {"4.0"}, "OData-Version": {"4.0"}, "Prefer": {"odata.maxpagesize=100"}},
		Authorize: auth.Authorize, OnUnauthorized: auth.Invalidate}
	return c, nil
}

// Identity is the application the client signs in as, for a prober.
func (c *Client) Identity() string { return c.cfg.ClientID }

// Mode is client_secret or certificate.
func (c *Client) Mode() string { return c.auth.Mode() }

// Format prints the client without its credential (every verb).
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "copilotstudio.Client{"+c.base.Hostname()+"}")
}

type row map[string]any

func (r row) str(k string) string { s, _ := r[k].(string); return s }
func (r row) num(k string) (int, bool) {
	f, ok := r[k].(float64)
	return int(f), ok
}

// query reads an entity set with the OData options in q, following @odata.nextLink (same origin, under the
// Web API path) and calling each for every row.
func (c *Client) query(ctx context.Context, set string, q url.Values, each func(row) error) error {
	u := *c.base
	u.Path = apiPath + set
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	next := u.String()
	for i := 0; next != ""; i++ {
		if i >= maxPages {
			return errors.New("copilotstudio: more pages than the connector reads")
		}
		var page struct {
			Value []row  `json:"value"`
			Next  string `json:"@odata.nextLink"`
		}
		if _, err := c.api.GetJSON(ctx, next, nil, &page); err != nil {
			return err
		}
		for _, r := range page.Value {
			if err := each(r); err != nil {
				return err
			}
		}
		next = ""
		if page.Next != "" {
			n, err := url.Parse(page.Next)
			if err != nil || n.Scheme != c.base.Scheme || n.Host != c.base.Host || !strings.HasPrefix(n.Path, apiPath) || strings.Contains(n.Path, "..") {
				return errors.New("copilotstudio: page link leaves the Web API")
			}
			next = page.Next
		}
	}
	return nil
}

// ProbeResult is what one bounded read found.
type ProbeResult struct{ Agents int }

// Probe reads the first agents, for the readiness checks, and keeps a count only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	var got struct {
		Value []row `json:"value"`
	}
	u := *c.base
	u.Path = apiPath + "bots"
	u.RawQuery = "$select=botid&$top=10"
	if _, err := c.api.GetJSON(ctx, u.String(), nil, &got); err != nil {
		return ProbeResult{}, err
	}
	return ProbeResult{Agents: len(got.Value)}, nil
}

type bot struct {
	id, name, schema  string
	owner, creator    string // systemuser or team ids
	active            bool
	authMode          string
	created           time.Time
	tools, knowledges []component
}

type component struct{ id, name string }

func authModeName(n int) string {
	switch n {
	case 1:
		return "none"
	case 2:
		return "integrated"
	case 3:
		return "custom_aad"
	case 4:
		return "generic_oauth"
	}
	return "unknown"
}

// Read reads every agent of the environment and maps it.
func (c *Client) Read(ctx context.Context) ([]agentmap.Agent, error) {
	var bots []*bot
	byID := map[string]*bot{}
	err := c.query(ctx, "bots", url.Values{"$select": {"botid,name,schemaname,statecode,authenticationmode,createdon,_ownerid_value,_createdby_value"}},
		func(r row) error {
			id := strings.ToLower(r.str("botid"))
			if !guidRE.MatchString(id) {
				return nil
			}
			if len(bots) >= maxAgents {
				return errors.New("copilotstudio: more agents than the connector reads")
			}
			b := &bot{id: id, name: agentmap.Clip(r.str("name"), 128), owner: strings.ToLower(r.str("_ownerid_value")), creator: strings.ToLower(r.str("_createdby_value"))}
			if s := r.str("schemaname"); schemaRE.MatchString(s) {
				b.schema = s
			}
			st, _ := r.num("statecode")
			b.active = st == 0
			n, _ := r.num("authenticationmode")
			b.authMode = authModeName(n)
			if t, err := time.Parse(time.RFC3339, r.str("createdon")); err == nil {
				b.created = t
			}
			bots = append(bots, b)
			byID[id] = b
			return nil
		})
	if err != nil {
		return nil, err
	}
	if len(bots) > 0 {
		err = c.query(ctx, "botcomponents", url.Values{"$select": {"botcomponentid,name,schemaname,_parentbotid_value"}, "$filter": {"statecode eq 0"}},
			func(r row) error {
				b := byID[strings.ToLower(r.str("_parentbotid_value"))]
				id := strings.ToLower(r.str("botcomponentid"))
				if b == nil || !guidRE.MatchString(id) || len(b.tools)+len(b.knowledges) >= maxItems {
					return nil
				}
				cp := component{id: id, name: agentmap.Clip(r.str("name"), 128)}
				if cp.name == "" {
					cp.name = id
				}
				switch segment(r.str("schemaname")) {
				case "action", "skill":
					b.tools = append(b.tools, cp)
				case "knowledge", "file":
					b.knowledges = append(b.knowledges, cp)
				}
				return nil
			})
		if err != nil {
			return nil, err
		}
	}
	people := c.people(ctx, bots)
	out := make([]agentmap.Agent, 0, len(bots))
	for _, b := range bots {
		a := agentmap.Agent{ID: b.id, Name: b.name, Kind: AgentKind, Disabled: !b.active, Owner: people[b.owner], Creator: people[b.creator], Created: b.created,
			Attributes: map[string]string{"auth_mode": b.authMode, "schema": b.schema}}
		if b.authMode == "none" {
			a.Tags = []string{"anonymous_access"}
		}
		for _, t := range b.tools {
			a.Access = append(a.Access, agentmap.Access{Resource: "copilot-tool:" + b.id + "/" + t.id, Name: t.name, Kind: "copilot_tool", Action: "invoke"})
		}
		for _, k := range b.knowledges {
			a.Access = append(a.Access, agentmap.Access{Resource: "copilot-knowledge:" + b.id + "/" + k.id, Name: k.name, Kind: "copilot_knowledge_source", Action: "retrieve"})
		}
		out = append(out, a)
	}
	return out, nil
}

// segment is the middle part of <bot schema>.<segment>.<name>.
func segment(schema string) string {
	parts := strings.Split(strings.ToLower(schema), ".")
	if len(parts) < 3 {
		return ""
	}
	return parts[len(parts)-2]
}

// people resolves the owners and creators of the bots to e-mail addresses, one lookup each. A team, a
// disabled or application user and a failed lookup resolve to nothing; the id is then the text kept.
func (c *Client) people(ctx context.Context, bots []*bot) map[string]string {
	out := map[string]string{}
	for _, b := range bots {
		for _, id := range []string{b.owner, b.creator} {
			if _, done := out[id]; done || !guidRE.MatchString(id) || len(out) >= maxOwners {
				continue
			}
			out[id] = id
			var u struct {
				Email string `json:"internalemailaddress"`
			}
			x := *c.base
			x.Path = apiPath + "systemusers(" + id + ")"
			x.RawQuery = "$select=internalemailaddress"
			if _, err := c.api.GetJSON(ctx, x.String(), nil, &u); err == nil && emailRE.MatchString(u.Email) {
				out[id] = u.Email
			}
		}
	}
	return out
}
