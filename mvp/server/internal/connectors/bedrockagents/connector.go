package bedrockagents

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the graph system name.
const System = "aws-bedrock"

// AgentKind is the AgentRecord kind of a Bedrock agent.
const AgentKind = "bedrock_agent"

var emailRE = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)

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
func (*Connector) DisplayName() string { return "Amazon Bedrock Agents" }
func (*Connector) TypeName() string    { return "BedrockAgentsConnector" }

// StreamEvents: no usage is read.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// ConfigFromEnv reads TESSERA_BEDROCK_*:
//
//	TESSERA_BEDROCK_REGION     the region whose agents are read
//	TESSERA_BEDROCK_CREDENTIAL reference to the credential JSON: file:/abs/path or env:NAME
//	TESSERA_BEDROCK_AGENT_URL  dev and test endpoint override; refused outside dev
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_BEDROCK_"
	secret, err := connsync.ResolveSecret(getenv(p+"CREDENTIAL"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "CREDENTIAL: " + err.Error())
	}
	return Config{Region: strings.TrimSpace(getenv(p + "REGION")), Secret: secret, AgentURL: getenv(p + "AGENT_URL")}, nil
}

// FromEnv builds the read connector from TESSERA_BEDROCK_* (ConfigFromEnv).
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	c, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(c, now), nil
}

func person(tags map[string]string, keys ...string) (*connectors.IdentityRef, string) {
	for _, k := range keys {
		v := strings.TrimSpace(tags[k])
		if v == "" {
			continue
		}
		if emailRE.MatchString(v) {
			return &connectors.IdentityRef{Email: strings.ToLower(v)}, v
		}
		return nil, v
	}
	return nil, ""
}

// Discover reads every agent in the region and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	agents, err := c.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	res := &connectors.DiscoveryResult{AgentSnapshotOf: []string{System}}
	seenRes, seenPerm := map[string]bool{}, map[string]bool{}
	for _, a := range agents {
		xid := "bedrock:" + a.ID
		name := a.Name
		if name == "" {
			name = a.ID
		}
		status := "active"
		if a.Status == "FAILED" || a.Status == "DELETING" {
			status = "disabled"
		}
		sponsor, sponsorRef := person(a.Tags, "sponsor", "owner")
		creator, creatorRef := person(a.Tags, "creator")
		desc := "Amazon Bedrock agent"
		if a.Description != "" {
			desc += ": " + a.Description
		}
		res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "ai_agent", Status: status,
			Description: &desc, Owner: sponsor})
		var created *time.Time
		if !a.CreatedAt.IsZero() {
			t := a.CreatedAt
			created = &t
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: a.ID, Username: name,
			Identity: &connectors.IdentityRef{ExternalID: xid}, Kind: "agent", Status: status, CreatedAt: created,
			Attributes: map[string]string{"agent_status": a.Status, "foundation_model": a.Model, "role_arn": a.RoleARN, "agent_arn": a.ARN}})
		res.Agents = append(res.Agents, connectors.AgentRecord{System: System, ExternalID: a.ID, Identity: connectors.IdentityRef{ExternalID: xid},
			Kind: AgentKind, Creator: creator, CreatorRef: creatorRef, Sponsor: sponsor, SponsorRef: sponsorRef})

		acct := connectors.Ref{Kind: "account", System: System, ExternalID: a.ID}
		var base []string
		if strings.EqualFold(a.Tags["pii"], "true") {
			base = []string{"pii"}
		}
		access := func(resID, name, kind, action string, privileged bool, tags ...string) {
			if !seenRes[resID] {
				seenRes[resID] = true
				res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: resID, Name: name, Kind: kind,
					Tags: append(append([]string(nil), base...), tags...)})
			}
			perm := resID + "#" + action
			if !seenPerm[perm] {
				seenPerm[perm] = true
				res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: perm, Action: action,
					ResourceExternalID: resID, Privileged: privileged})
			}
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acct, Dst: connectors.Ref{Kind: "perm", System: System, ExternalID: perm}, Relation: "direct_grant"})
		}
		if a.RoleARN != "" {
			access(a.RoleARN, a.RoleARN, "aws_resource", "assume_role", false)
		}
		if a.Model != "" {
			access("bedrock-model:"+a.Model, a.Model, "bedrock_model", "bedrock:InvokeModel", false)
		}
		for _, g := range a.ActionGroups {
			gname := g.Name
			if gname == "" {
				gname = g.ID
			}
			code := g.Signature == "AMAZON.CodeInterpreter"
			var tags []string
			if code {
				tags = append(tags, "code_execution")
			}
			if g.Lambda != "" {
				access(g.Lambda, gname, "aws_lambda_function", "lambda:InvokeFunction", code, tags...)
			} else {
				access("bedrock-action-group:"+a.ID+"/"+g.ID, gname, "bedrock_action_group", "return_control", code, tags...)
			}
		}
		for _, kb := range a.KnowledgeBases {
			access("bedrock-knowledge-base:"+kb, kb, "bedrock_knowledge_base", "bedrock:Retrieve", false)
		}
	}
	return res, nil
}
