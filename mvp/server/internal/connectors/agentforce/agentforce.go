// Package agentforce inventories the agents of Salesforce Agentforce (issue #562): each agent definition
// (BotDefinition) of an org, the user it runs as and the actions it can invoke, as an ai_agent non-human
// identity linked to its owner. It is read-only: only SOQL queries (GETs) are sent.
//
// Authentication is the JWT bearer flow of the salesforce connector (a connected app's certificate, no
// password), through that package's client: the API host is the configured My Domain URL and the instance_url
// of a token response is never followed. The integration user needs read access to BotDefinition, the GenAi
// planner and function objects, and User.
//
// Mapping, per agent:
//
//	identity  agentforce:<BotDefinition id>, type ai_agent, owned by its Salesforce owner (the user's e-mail
//	          address), creator likewise
//	account   <BotDefinition id>, kind agent; an agent record of kind agentforce_agent
//	access    the user the agent runs as (run_as; what that user may do is the Salesforce connection's job, the
//	          agent links to it by user id) and each action of its planner (invoke on the Apex class, flow or
//	          prompt template it targets)
//
// Instructions, topics, descriptions and prompt templates are never queried: only names and ids.
//
// The object and field names (BotDefinition, GenAiPlannerDefinition, GenAiPlannerFunctionDef,
// GenAiFunctionDefinition) follow Salesforce's Einstein Agent data model; the tests run against a fake.
package agentforce

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentmap"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
)

// System is the graph system name; AgentKind the agent profile kind.
const (
	System    = "salesforce-agentforce"
	AgentKind = "agentforce_agent"
)

const (
	maxAgents = 5000
	maxItems  = 200
	chunk     = 100
)

var (
	devNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,255}$`)
	targetRE  = regexp.MustCompile(`^[A-Za-z0-9_.:/ -]{1,255}$`)
	typeRE    = regexp.MustCompile(`^[A-Za-z]{1,40}$`)
	emailRE   = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)
)

// ErrCredential is Salesforce refusing the sign-in (the token endpoint answers 400 invalid_grant). A probe
// reports it as "not authenticated".
var ErrCredential = errors.New("agentforce: the credential was refused")

// Config configures one org.
type Config struct {
	// BaseURL is the org's My Domain URL (https://acme.my.salesforce.com).
	BaseURL string
	// Credential is the JSON of the JWT bearer flow (salesforce.Credential): client_id, username, private_key
	// and optionally login_url.
	Credential connsync.Secret
	// APIVersion is "v61.0" and the like; empty: the salesforce package's default.
	APIVersion string
}

// Client reads the agents of one org.
type Client struct {
	sf   *salesforce.Client
	cfg  Config
	host string
}

// Open validates cfg and returns the client. hc must be the server's shared safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	cred, err := salesforce.ParseCredential(cfg.Credential.Reveal())
	if err != nil {
		return nil, err
	}
	sf, err := salesforce.Open(salesforce.Config{BaseURL: cfg.BaseURL, LoginURL: cred.LoginURL, ClientID: cred.ClientID, Username: cred.Username,
		PrivateKey: connsync.NewSecret(cred.PrivateKey), APIVersion: cfg.APIVersion}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	u, _ := salesforce.CheckURL(cfg.BaseURL, rt)
	return &Client{sf: sf, cfg: cfg, host: u.Hostname()}, nil
}

// Identity is the integration user the client signs in as, for a prober.
func (c *Client) Identity() string { return c.sf.Identity() }

// Mode names how the client authenticates, for a prober.
func (*Client) Mode() string { return "jwt_bearer" }

// Format prints the client without its credential (every verb).
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "agentforce.Client{"+c.host+"}")
}

const agentSOQL = "SELECT Id, DeveloperName, MasterLabel, Type, BotUserId, OwnerId, CreatedById, CreatedDate, IsDeleted FROM BotDefinition " +
	"WHERE Type IN ('ExternalCopilot','InternalCopilot') ORDER BY Id"

// ProbeResult is what one bounded read found.
type ProbeResult struct{ Agents int }

// Probe reads the first agent definitions, for the readiness checks, and keeps a count only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	rows, err := c.sf.SOQL(ctx, "SELECT Id FROM BotDefinition WHERE Type IN ('ExternalCopilot','InternalCopilot') LIMIT 10")
	if connsync.Status(err) == http.StatusBadRequest {
		// the query is fixed, so a 400 is the token endpoint refusing the connected app, the user or the key
		return ProbeResult{}, fmt.Errorf("%w: %v", ErrCredential, err)
	}
	return ProbeResult{Agents: len(rows)}, err
}

func str(r map[string]any, k string) string { s, _ := r[k].(string); return s }

func inList(ids []string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = "'" + id + "'" // ids are validated by IDValid: no quote can be in one
	}
	return strings.Join(q, ",")
}

// Read reads every agent of the org and maps it.
func (c *Client) Read(ctx context.Context) ([]agentmap.Agent, error) {
	rows, err := c.sf.SOQL(ctx, agentSOQL)
	if err != nil {
		return nil, err
	}
	type bot struct {
		id, dev, name, typ, user, owner, creator string
		created                                  time.Time
	}
	var bots []bot
	users := map[string]bool{}
	for _, r := range rows {
		id := str(r, "Id")
		if !salesforce.IDValid(id) {
			continue
		}
		if len(bots) >= maxAgents {
			return nil, errors.New("agentforce: more agents than the connector reads")
		}
		b := bot{id: id, name: agentmap.Clip(str(r, "MasterLabel"), 128), user: str(r, "BotUserId"), owner: str(r, "OwnerId"), creator: str(r, "CreatedById")}
		if d := str(r, "DeveloperName"); devNameRE.MatchString(d) {
			b.dev = d
		}
		if t := str(r, "Type"); typeRE.MatchString(t) {
			b.typ = t
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000-0700", str(r, "CreatedDate")); err == nil {
			b.created = t
		}
		bots = append(bots, b)
		for _, u := range []string{b.user, b.owner, b.creator} {
			if salesforce.IDValid(u) {
				users[u] = true
			}
		}
	}
	emails, err := c.emails(ctx, users)
	if err != nil {
		return nil, err
	}
	actions := map[string][]action{}
	if len(bots) > 0 {
		if actions, err = c.actions(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]agentmap.Agent, 0, len(bots))
	for _, b := range bots {
		a := agentmap.Agent{ID: b.id, Name: b.name, Kind: AgentKind, Created: b.created, Owner: emails[b.owner], Creator: emails[b.creator],
			Attributes: map[string]string{"developer_name": b.dev, "agent_type": b.typ}}
		if a.Owner == "" && salesforce.IDValid(b.owner) {
			a.Owner = b.owner
		}
		if salesforce.IDValid(b.user) {
			a.Attributes["run_as_user_id"] = b.user
			a.Access = append(a.Access, agentmap.Access{Resource: "sf-user:" + b.user, Name: coalesce(emails[b.user], b.user), Kind: "salesforce_user", Action: "run_as"})
		}
		for _, x := range actions[b.dev] {
			a.Access = append(a.Access, agentmap.Access{Resource: "sf-action:" + x.kind + ":" + x.target, Name: x.name, Kind: "salesforce_action", Action: "invoke",
				Tags: []string{"target_" + strings.ToLower(x.kind)}})
		}
		out = append(out, a)
	}
	return out, nil
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// emails resolves user ids to e-mail addresses. An inactive user still resolves: the agent keeps its owner.
func (c *Client) emails(ctx context.Context, ids map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	for len(list) > 0 {
		n := min(chunk, len(list))
		rows, err := c.sf.SOQL(ctx, "SELECT Id, Email FROM User WHERE Id IN ("+inList(list[:n])+")")
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if e := str(r, "Email"); emailRE.MatchString(e) {
				out[str(r, "Id")] = e
			}
		}
		list = list[n:]
	}
	return out, nil
}

type action struct{ name, kind, target string }

// actions reads the actions of every planner, keyed by the planner's developer name (the agent's).
func (c *Client) actions(ctx context.Context) (map[string][]action, error) {
	planners, err := c.sf.SOQL(ctx, "SELECT Id, DeveloperName FROM GenAiPlannerDefinition ORDER BY Id")
	if err != nil {
		return nil, err
	}
	funcs, err := c.sf.SOQL(ctx, "SELECT Id, DeveloperName, InvocationTarget, InvocationTargetType FROM GenAiFunctionDefinition ORDER BY Id")
	if err != nil {
		return nil, err
	}
	links, err := c.sf.SOQL(ctx, "SELECT PlannerId, FunctionId FROM GenAiPlannerFunctionDef ORDER BY Id")
	if err != nil {
		return nil, err
	}
	pname := map[string]string{}
	for _, p := range planners {
		if d := str(p, "DeveloperName"); devNameRE.MatchString(d) {
			pname[str(p, "Id")] = d
		}
	}
	fn := map[string]action{}
	for _, f := range funcs {
		t, k := str(f, "InvocationTarget"), str(f, "InvocationTargetType")
		if n := str(f, "DeveloperName"); devNameRE.MatchString(n) && targetRE.MatchString(t) && typeRE.MatchString(k) {
			fn[str(f, "Id")] = action{name: n, kind: k, target: t}
		}
	}
	out := map[string][]action{}
	for _, l := range links {
		p, f := pname[str(l, "PlannerId")], fn[str(l, "FunctionId")]
		if p != "" && f.name != "" && len(out[p]) < maxItems {
			out[p] = append(out[p], f)
		}
	}
	return out, nil
}
