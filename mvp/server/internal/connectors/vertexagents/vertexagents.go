// Package vertexagents inventories the agents of Google Vertex AI Agent Engine (issue #562): the reasoning
// engines of one project and location, each as an ai_agent non-human identity linked to its owner, with the
// identity it runs as and the secrets it reads as grants. It is read-only: only the reasoningEngines list
// (a GET) is sent.
//
// Authentication is the service account key of the gcpiam connector (a signed JWT exchanged for an access
// token, scope cloud-platform; the account needs only roles/aiplatform.viewer). There is no Google SDK.
//
// Mapping, per reasoning engine:
//
//	identity  vertex:<engine id>, type ai_agent, owned by the connection's owner setting (a label "sponsor" or
//	          "owner" is kept as the source's own word)
//	account   <engine id>, kind agent; an agent record of kind vertex_agent_engine
//	access    the service account or agent identity it runs as (run_as) and each Secret Manager secret its
//	          deployment reads (secretmanager.versions.access)
//
// Environment variable values, the package, class methods, prompts and descriptions are never read into the
// result. What the service account can do is the Google Cloud IAM connection's job: the agent links to it by
// e-mail address.
package vertexagents

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentmap"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name; AgentKind the agent profile kind.
const (
	System    = "gcp-vertex"
	AgentKind = "vertex_agent_engine"
)

const (
	pageSize  = 100
	maxPages  = 200
	maxAgents = 5000
	maxSecret = 50
)

var (
	projectRE   = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$`)
	locationRE  = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]{1,2}$`)
	engineRE    = regexp.MustCompile(`^[0-9]{1,30}$`)
	emailRE     = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)
	secretRE    = regexp.MustCompile(`^(projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})/secrets/)?[A-Za-z0-9_-]{1,255}$`)
	principalRE = regexp.MustCompile(`^principal(Set)?://[A-Za-z0-9._~:/@+=-]{1,500}$`)
)

// Config configures one project and location.
type Config struct {
	Key                 connsync.Secret
	ProjectID, Location string
	// Owner is the e-mail address of the person accountable for the project's agents.
	Owner string
	// APIURL and TokenURL override the Google endpoints. Dev and test only; Open refuses them outside dev.
	APIURL, TokenURL string
}

// Client is a retrying Vertex AI client.
type Client struct {
	cfg  Config
	base *url.URL
	api  *connsync.Client
	auth *gcpiam.Auth
}

// Open validates cfg and returns the client. hc must be the server's shared safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("vertexagents: an internal/safehttp client is required")
	}
	if !projectRE.MatchString(cfg.ProjectID) {
		return nil, errors.New("vertexagents: the project is a project id or number")
	}
	if !locationRE.MatchString(cfg.Location) {
		return nil, errors.New("vertexagents: the location is a Google Cloud region such as us-central1")
	}
	if cfg.Owner != "" && !emailRE.MatchString(cfg.Owner) {
		return nil, errors.New("vertexagents: the owner is an e-mail address")
	}
	def := DefaultURL(cfg.Location)
	override := cfg.APIURL != "" && strings.TrimRight(cfg.APIURL, "/") != def
	if override && rt.Env != config.Dev {
		return nil, errors.New("vertexagents: an endpoint override is a dev setting and is refused outside dev")
	}
	raw := cfg.APIURL
	if raw == "" {
		raw = def
	}
	base, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, fmt.Errorf("vertexagents: endpoint: %w", err)
	}
	if !override && (base.Hostname() != strings.TrimPrefix(def, "https://") || base.Port() != "" || base.Path != "") {
		return nil, errors.New("vertexagents: the host is not the Vertex AI endpoint of the location")
	}
	if now == nil {
		now = time.Now
	}
	auth, err := gcpiam.NewAuth(cfg.Key, cfg.TokenURL, rt, hc, now)
	if err != nil {
		return nil, err
	}
	hc = safehttp.WithConfiguredPorts(hc, base.String())
	c := &Client{cfg: cfg, base: base, auth: auth}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/vertex-agents"}},
		RetryOn: connsync.IsGoogleRateLimit, Authorize: auth.Authorize, OnUnauthorized: auth.Invalidate}
	return c, nil
}

// DefaultURL is the public Vertex AI endpoint of a location.
func DefaultURL(location string) string { return "https://" + location + "-aiplatform.googleapis.com" }

// Identity is the service account the client signs in as, for a prober.
func (c *Client) Identity() string { return c.auth.Identity() }

// Mode names how the client authenticates, for a prober.
func (*Client) Mode() string { return "json_key" }

// Format prints the client without its credential (every verb).
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "vertexagents.Client{"+c.cfg.ProjectID+"/"+c.cfg.Location+"}")
}

type engine struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"displayName"`
	CreateTime  string            `json:"createTime"`
	Labels      map[string]string `json:"labels"`
	Spec        struct {
		ServiceAccount    string `json:"serviceAccount"`
		IdentityType      string `json:"identityType"`
		EffectiveIdentity string `json:"effectiveIdentity"`
		Deployment        struct {
			SecretEnv []struct {
				Ref struct {
					Secret string `json:"secret"`
				} `json:"secretRef"`
			} `json:"secretEnv"`
		} `json:"deploymentSpec"`
	} `json:"spec"`
}

type enginesPage struct {
	Engines []engine `json:"reasoningEngines"`
	Next    string   `json:"nextPageToken"`
}

func (c *Client) page(ctx context.Context, size int, token string) (enginesPage, error) {
	q := url.Values{"pageSize": {strconv.Itoa(size)}}
	if token != "" {
		q.Set("pageToken", token)
	}
	u := *c.base
	u.Path = "/v1/projects/" + c.cfg.ProjectID + "/locations/" + c.cfg.Location + "/reasoningEngines"
	u.RawQuery = q.Encode()
	var p enginesPage
	_, err := c.api.GetJSON(ctx, u.String(), nil, &p)
	return p, err
}

// ProbeResult is what one bounded read found.
type ProbeResult struct{ Agents int }

// Probe lists the first page, for the readiness checks: it proves the credential, the right and the shape of
// the answer, and keeps a count only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	p, err := c.page(ctx, 10, "")
	return ProbeResult{Agents: len(p.Engines)}, err
}

// Read lists every reasoning engine and maps it.
func (c *Client) Read(ctx context.Context) ([]agentmap.Agent, error) {
	var out []agentmap.Agent
	token := ""
	for i := 0; ; i++ {
		if i >= maxPages {
			return nil, errors.New("vertexagents: more pages than the connector reads")
		}
		p, err := c.page(ctx, pageSize, token)
		if err != nil {
			return nil, err
		}
		for _, e := range p.Engines {
			if a, ok := c.agent(e); ok {
				if len(out) >= maxAgents {
					return nil, errors.New("vertexagents: more agents than the connector reads")
				}
				out = append(out, a)
			}
		}
		if p.Next == "" || len(p.Next) > 2048 {
			return out, nil
		}
		token = p.Next
	}
}

func (c *Client) agent(e engine) (agentmap.Agent, bool) {
	i := strings.LastIndex(e.Name, "/")
	id := e.Name[i+1:]
	if i < 0 || !engineRE.MatchString(id) {
		return agentmap.Agent{}, false
	}
	labels := map[string]string{}
	for k, v := range e.Labels {
		if len(labels) < 64 {
			labels[strings.ToLower(agentmap.Clip(k, 64))] = agentmap.Clip(v, 128)
		}
	}
	a := agentmap.Agent{ID: id, Name: agentmap.Clip(e.DisplayName, 128), Kind: AgentKind, Owner: c.cfg.Owner,
		Attributes: map[string]string{"identity_type": agentmap.Clip(e.Spec.IdentityType, 40), "resource": "projects/" + c.cfg.ProjectID + "/locations/" + c.cfg.Location + "/reasoningEngines/" + id},
		PII:        strings.EqualFold(labels["pii"], "true")}
	if a.Owner == "" {
		a.Owner = agentmap.First(labels, "sponsor", "owner")
	} else if ref := agentmap.First(labels, "sponsor", "owner"); ref != "" {
		a.Attributes["sponsor_label"] = ref
	}
	a.Creator = agentmap.First(labels, "creator")
	if t, err := time.Parse(time.RFC3339, e.CreateTime); err == nil {
		a.Created = t
	}
	if sa := e.Spec.ServiceAccount; emailRE.MatchString(sa) {
		a.Attributes["service_account"] = sa
		a.Access = append(a.Access, agentmap.Access{Resource: "gcp-sa:" + sa, Name: sa, Kind: "gcp_service_account", Action: "run_as"})
	} else if p := e.Spec.EffectiveIdentity; principalRE.MatchString(p) {
		a.Attributes["agent_identity"] = p
		a.Access = append(a.Access, agentmap.Access{Resource: "gcp-agent-identity:" + p, Name: p, Kind: "gcp_agent_identity", Action: "run_as"})
	}
	n := 0
	for _, s := range e.Spec.Deployment.SecretEnv {
		sec := s.Ref.Secret
		if !secretRE.MatchString(sec) || n >= maxSecret {
			continue
		}
		if !strings.HasPrefix(sec, "projects/") {
			sec = "projects/" + c.cfg.ProjectID + "/secrets/" + sec
		}
		n++
		a.Access = append(a.Access, agentmap.Access{Resource: "gcp-secret:" + sec, Name: sec, Kind: "gcp_secret", Action: "secretmanager.versions.access"})
	}
	return a, true
}

// ErrCredential is Google refusing the service account.
var ErrCredential = gcpiam.ErrCredential
