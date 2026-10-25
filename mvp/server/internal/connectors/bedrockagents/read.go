package bedrockagents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Agent is one Bedrock agent and what is known about it.
type Agent struct {
	ID, Name, ARN, Status, Description string
	RoleARN, Model                     string
	CreatedAt                          time.Time
	Tags                               map[string]string
	ActionGroups                       []ActionGroup
	KnowledgeBases                     []string
}

// ActionGroup is one enabled action group: a tool the agent can call.
type ActionGroup struct {
	ID, Name string
	// Lambda is the executor's ARN; empty when the caller runs the action (return of control).
	Lambda string
	// Signature is the built-in capability ("AMAZON.CodeInterpreter", "AMAZON.UserInput"), empty for a custom one.
	Signature string
	Functions int
}

type nextPage struct {
	Next string `json:"nextToken"`
}

func (c *Client) pages(ctx context.Context, op string, segs []string, each func(raw any) (more bool, err error), page func() any) error {
	token := ""
	for i := 0; ; i++ {
		if i >= maxPages {
			return errors.New("bedrockagents: " + op + " lists more pages than the connector reads")
		}
		body := map[string]any{"maxResults": pageSize}
		if token != "" {
			body["nextToken"] = token
		}
		p := page()
		if err := c.do(ctx, op, http.MethodPost, segs, body, p); err != nil {
			return err
		}
		more, err := each(p)
		if err != nil {
			return err
		}
		next := p.(interface{ token() string }).token()
		if !more || next == "" || len(next) > 2048 {
			return nil
		}
		token = next
	}
}

type agentsPage struct {
	nextPage
	Agents []struct {
		ID string `json:"agentId"`
	} `json:"agentSummaries"`
}

func (p *agentsPage) token() string { return p.Next }

// agentIDs lists every agent id, up to limit.
func (c *Client) agentIDs(ctx context.Context, limit int) ([]string, error) {
	var ids []string
	err := c.pages(ctx, "ListAgents", []string{"agents", ""}, func(raw any) (bool, error) {
		for _, a := range raw.(*agentsPage).Agents {
			if !idRE.MatchString(a.ID) {
				continue
			}
			if len(ids) >= limit {
				return false, nil
			}
			ids = append(ids, a.ID)
		}
		return len(ids) < limit, nil
	}, func() any { return &agentsPage{} })
	return ids, err
}

type groupsPage struct {
	nextPage
	Groups []struct {
		ID    string `json:"actionGroupId"`
		State string `json:"actionGroupState"`
	} `json:"actionGroupSummaries"`
}

func (p *groupsPage) token() string { return p.Next }

type kbPage struct {
	nextPage
	KBs []struct {
		ID    string `json:"knowledgeBaseId"`
		State string `json:"knowledgeBaseState"`
	} `json:"agentKnowledgeBaseSummaries"`
}

func (p *kbPage) token() string { return p.Next }

func printable(s string, n int) string { return clip(s, n) }

func clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// agent reads one agent: its definition, tags, enabled action groups and knowledge bases.
func (c *Client) agent(ctx context.Context, id string) (Agent, error) {
	var got struct {
		Agent struct {
			ID          string      `json:"agentId"`
			Name        string      `json:"agentName"`
			ARN         string      `json:"agentArn"`
			Status      string      `json:"agentStatus"`
			Description string      `json:"description"`
			RoleARN     string      `json:"agentResourceRoleArn"`
			Model       string      `json:"foundationModel"`
			CreatedAt   json.Number `json:"createdAt"`
		} `json:"agent"`
	}
	if err := c.do(ctx, "GetAgent", http.MethodGet, []string{"agents", id, ""}, nil, &got); err != nil {
		return Agent{}, err
	}
	g := got.Agent
	a := Agent{ID: id, Name: printable(g.Name, 128), Status: g.Status, Description: printable(g.Description, 200), Model: printable(g.Model, 256)}
	if arnRE.MatchString(g.ARN) {
		a.ARN = g.ARN
	}
	if arnRE.MatchString(g.RoleARN) {
		a.RoleARN = g.RoleARN
	}
	if f, err := g.CreatedAt.Float64(); err == nil && f > 0 {
		a.CreatedAt = time.Unix(int64(f), 0).UTC()
	}
	if a.ARN != "" {
		var tg struct {
			Tags map[string]string `json:"tags"`
		}
		if err := c.do(ctx, "ListTagsForResource", http.MethodGet, []string{"tags", a.ARN}, nil, &tg); err != nil {
			return Agent{}, err
		}
		a.Tags = map[string]string{}
		for k, v := range tg.Tags {
			if len(a.Tags) < 50 {
				a.Tags[strings.ToLower(printable(k, 128))] = printable(v, 256)
			}
		}
	}
	var groupIDs []string
	err := c.pages(ctx, "ListAgentActionGroups", []string{"agents", id, "agentversions", "DRAFT", "actiongroups", ""}, func(raw any) (bool, error) {
		for _, x := range raw.(*groupsPage).Groups {
			if idRE.MatchString(x.ID) && x.State == "ENABLED" {
				groupIDs = append(groupIDs, x.ID)
			}
		}
		return true, nil
	}, func() any { return &groupsPage{} })
	if err != nil {
		return Agent{}, err
	}
	for _, gid := range groupIDs {
		var ag struct {
			Group struct {
				Name     string `json:"actionGroupName"`
				Executor struct {
					Lambda string `json:"lambda"`
				} `json:"actionGroupExecutor"`
				Signature string `json:"parentActionGroupSignature"`
				Schema    struct {
					Functions []struct {
						Name string `json:"name"`
					} `json:"functions"`
				} `json:"functionSchema"`
			} `json:"agentActionGroup"`
		}
		if err := c.do(ctx, "GetAgentActionGroup", http.MethodGet, []string{"agents", id, "agentversions", "DRAFT", "actiongroups", gid, ""}, nil, &ag); err != nil {
			return Agent{}, err
		}
		x := ActionGroup{ID: gid, Name: printable(ag.Group.Name, 128), Signature: printable(ag.Group.Signature, 64), Functions: len(ag.Group.Schema.Functions)}
		if arnRE.MatchString(ag.Group.Executor.Lambda) {
			x.Lambda = ag.Group.Executor.Lambda
		}
		a.ActionGroups = append(a.ActionGroups, x)
	}
	err = c.pages(ctx, "ListAgentKnowledgeBases", []string{"agents", id, "agentversions", "DRAFT", "knowledgebases", ""}, func(raw any) (bool, error) {
		for _, x := range raw.(*kbPage).KBs {
			if idRE.MatchString(x.ID) && x.State == "ENABLED" {
				a.KnowledgeBases = append(a.KnowledgeBases, x.ID)
			}
		}
		return true, nil
	}, func() any { return &kbPage{} })
	return a, err
}

// ProbeResult is what one bounded read found.
type ProbeResult struct{ Agents int }

// Probe lists the first page of agents, for the readiness checks: it proves the credential, the list right and
// the shape of the answer, and keeps a count only.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	var got agentsPage
	if err := c.do(ctx, "ListAgents", http.MethodPost, []string{"agents", ""}, map[string]any{"maxResults": 10}, &got); err != nil {
		return ProbeResult{}, err
	}
	return ProbeResult{Agents: len(got.Agents)}, nil
}

// Read reads every agent in the region.
func (c *Client) Read(ctx context.Context) ([]Agent, error) {
	ids, err := c.agentIDs(ctx, maxAgents)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	var out []Agent
	for _, id := range ids {
		a, err := c.agent(ctx, id)
		if err != nil {
			// an agent deleted while the read ran is gone, not a failure
			if Status(err) == http.StatusNotFound {
				continue
			}
			return nil, fmt.Errorf("agent %s: %w", id, err)
		}
		out = append(out, a)
	}
	return out, nil
}
