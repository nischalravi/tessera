// Package agentcore discovers AI agents running on Amazon Bedrock AgentCore
// (issue #116).
//
// FIXTURE-ONLY. There is no live client in this package. The AWS SDK is not a
// dependency of this module, and a production client would need AgentCore's
// control-plane API (the bedrock-agentcore-control service: agent runtimes,
// workload identities and credential providers) plus the IAM policies of each
// runtime's execution role to work out what it can reach. None of that is
// built. What is built is the part that does not depend on it:
//
//   - API, the narrow read-only interface a live client implements;
//   - the mapping from what AgentCore reports to Tessera's model, tested
//     against recorded fixtures;
//   - FileAPI, which reads a recorded snapshot from a JSON file, so a demo or
//     a customer-supplied export can be ingested before the live client exists.
//
// Mapping, per agent runtime:
//
//	identity  agentcore:<runtime id>, type ai_agent, owned by its sponsor tag
//	account   <runtime id>, kind agent
//	secrets   its credential providers (OAuth client secrets, API keys), by id,
//	          kind, name and creation date; never a value
//	access    what the execution role reaches: a resource and permission each,
//	          direct_grant from the agent. The snapshot says what is privileged
//	          and what holds PII (a "pii" tag), so the existing ai-agents-no-pii
//	          policy applies unchanged.
//
// A runtime's creator is the principal that created it (an IAM ARN) or the
// "creator" tag; its sponsor is the "sponsor" tag (an e-mail address). A
// runtime without a sponsor tag has no sponsor, which the nhi-ownership policy
// reports.
package agentcore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the graph system name.
const System = "aws-agentcore"

// AgentKind is the AgentRecord kind of an AgentCore runtime.
const AgentKind = "bedrock_agentcore_runtime"

// Runtime is one AgentCore agent runtime and what is known about it.
type Runtime struct {
	ARN       string    `json:"arn"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"` // READY, CREATING, UPDATING, FAILED, DELETING
	CreatedAt time.Time `json:"created_at"`
	// CreatedBy is the principal that created the runtime (an IAM ARN).
	CreatedBy        string            `json:"created_by"`
	ExecutionRoleARN string            `json:"execution_role_arn"`
	Tags             map[string]string `json:"tags"`
	Credentials      []Credential      `json:"credentials"`
	Access           []Access          `json:"access"`
}

// Credential is a credential provider or workload identity secret. It carries
// no value: only what is needed to age and rotate it.
type Credential struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // oauth_client_secret | api_key
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Access is one thing the runtime's execution role can do to a resource.
type Access struct {
	Action      string   `json:"action"`
	Resource    string   `json:"resource"` // ARN
	Privileged  bool     `json:"privileged"`
	Tags        []string `json:"tags"`
	Environment string   `json:"environment"`
}

// API is the read-only view of AgentCore a live client implements.
type API interface {
	// Runtimes lists every agent runtime of the account, with its credential
	// providers and the access of its execution role.
	Runtimes(ctx context.Context) ([]Runtime, error)
}

// FileAPI serves a recorded snapshot from a JSON file: {"runtimes": [...]}.
type FileAPI struct{ Path string }

// maxSnapshotBytes bounds a snapshot file.
const maxSnapshotBytes = 8 << 20

// Runtimes implements API.
func (f FileAPI) Runtimes(ctx context.Context) ([]Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f.Path) // #nosec G304 -- the path is operator configuration, never request input
	if err != nil {
		return nil, fmt.Errorf("agentcore: read snapshot: %w", err)
	}
	if len(b) > maxSnapshotBytes {
		return nil, errors.New("agentcore: snapshot too large")
	}
	var doc struct {
		Runtimes []Runtime `json:"runtimes"`
	}
	if err := connsync.DecodeJSON(b, &doc); err != nil {
		return nil, fmt.Errorf("agentcore: snapshot: %w", err)
	}
	return doc.Runtimes, nil
}

// Connector implements connectors.Connector over an API.
type Connector struct {
	api API
	now func() time.Time
}

// New builds a connector over api.
func New(api API, now func() time.Time) (*Connector, error) {
	if api == nil {
		return nil, errors.New("agentcore: an API is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Connector{api: api, now: now}, nil
}

// FromEnv builds the connector from the environment:
//
//	TESSERA_AGENTCORE_SNAPSHOT   absolute path of a recorded snapshot (JSON)
//
// It refuses to run in production: with no live client, a snapshot file is a
// demo and test source and must not stand in for the account.
func FromEnv(getenv func(string) string, now time.Time) (connectors.Connector, error) {
	if getenv("TESSERA_ENV") == config.Prod {
		return nil, errors.New("agentcore: only a recorded snapshot is available (no live AgentCore client is built); refused in prod")
	}
	path := getenv("TESSERA_AGENTCORE_SNAPSHOT")
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, errors.New("agentcore: TESSERA_AGENTCORE_SNAPSHOT (an absolute path to a recorded snapshot) is required; there is no live client")
	}
	return New(FileAPI{Path: path}, func() time.Time { return time.Now().UTC() })
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "AWS Bedrock AgentCore" }
func (*Connector) TypeName() string    { return "AgentCoreConnector" }

// StreamEvents has no events: AgentCore usage is not read.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ref(v string) *connectors.IdentityRef {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 256 {
		return nil
	}
	if strings.Contains(v, "@") && !strings.HasPrefix(v, "arn:") {
		return &connectors.IdentityRef{Email: v}
	}
	return nil
}

// validID restricts runtime ids: they become external ids.
func validID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '-' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	runtimes, err := c.api.Runtimes(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(runtimes, func(i, j int) bool { return runtimes[i].ID < runtimes[j].ID })
	res := &connectors.DiscoveryResult{AgentSnapshotOf: []string{System}}
	seenRes, seenPerm := map[string]bool{}, map[string]bool{}
	for _, rt := range runtimes {
		if !validID(rt.ID) {
			return nil, fmt.Errorf("agentcore: runtime id %q is not valid", rt.ID)
		}
		xid := "agentcore:" + rt.ID
		name := rt.Name
		if name == "" {
			name = rt.ID
		}
		status := "active"
		if rt.Status == "FAILED" || rt.Status == "DELETING" {
			status = "disabled"
		}
		sponsor, creator := ref(rt.Tags["sponsor"]), ref(rt.Tags["creator"])
		creatorRef := rt.Tags["creator"]
		if creatorRef == "" {
			creatorRef = rt.CreatedBy
		}
		res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "ai_agent",
			Status: status, Description: strp("Bedrock AgentCore runtime"), Owner: sponsor})
		var created *time.Time
		if !rt.CreatedAt.IsZero() {
			t := rt.CreatedAt.UTC()
			created = &t
		}
		acct := connectors.Ref{Kind: "account", System: System, ExternalID: rt.ID}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: rt.ID, Username: name,
			Identity: &connectors.IdentityRef{ExternalID: xid}, Kind: "agent", Status: status, CreatedAt: created})
		res.Agents = append(res.Agents, connectors.AgentRecord{System: System, ExternalID: rt.ID,
			Identity: connectors.IdentityRef{ExternalID: xid}, Kind: AgentKind, Creator: creator, CreatorRef: creatorRef,
			Sponsor: sponsor, SponsorRef: strings.TrimSpace(rt.Tags["sponsor"])})
		for _, cr := range rt.Credentials {
			if !validID(cr.ID) {
				continue
			}
			at := cr.CreatedAt
			if at.IsZero() {
				at = c.now()
			}
			res.Secrets = append(res.Secrets, connectors.SecretRecord{System: System, ExternalID: rt.ID + ":" + cr.ID, Account: acct,
				Kind: cr.Kind, Name: cr.Name, CreatedAt: at.UTC()})
		}
		for _, ac := range rt.Access {
			if ac.Resource == "" || ac.Action == "" {
				continue
			}
			if !seenRes[ac.Resource] {
				seenRes[ac.Resource] = true
				res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: ac.Resource,
					Name: ac.Resource, Kind: "aws_resource", Environment: strp(ac.Environment), Tags: ac.Tags})
			}
			perm := ac.Resource + "#" + ac.Action
			if !seenPerm[perm] {
				seenPerm[perm] = true
				res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: perm,
					Action: ac.Action, ResourceExternalID: ac.Resource, Privileged: ac.Privileged})
			}
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acct,
				Dst: connectors.Ref{Kind: "perm", System: System, ExternalID: perm}, Relation: "direct_grant"})
		}
	}
	return res, nil
}
