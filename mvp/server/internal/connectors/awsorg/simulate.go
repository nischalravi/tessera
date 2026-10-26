package awsorg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The simulator oracle of the production shadow agreement (issue #641, EP-6):
// iam:SimulatePrincipalPolicy, called with the connector's reader role in the
// account that owns the principal. It is a read action (ReaderActions), so the
// connector stays unable to change anything.

// SimQuery is one question to the simulator: may the principal do the action
// on the resource? An empty Resource is "*".
type SimQuery struct {
	PrincipalARN string
	Action       string
	Resource     string
}

// SimAnswer is what the simulator said. Decision is its EvalDecision:
// "allowed", "explicitDeny" or "implicitDeny". Missing lists the context keys
// the simulator needed and was not given; the decision is then not a verdict on
// the request, so a caller must not compare it.
type SimAnswer struct {
	Decision string
	Missing  []string
}

type xmlSimResult struct {
	Results []struct {
		Action   string   `xml:"EvalActionName"`
		Resource string   `xml:"EvalResourceName"`
		Decision string   `xml:"EvalDecision"`
		Missing  []string `xml:"MissingContextValues>member"`
	} `xml:"SimulatePrincipalPolicyResult>EvaluationResults>member"`
}

// Simulator asks the simulator of the accounts of one connector. It keeps the
// assumed-role sessions between questions. It is not safe for concurrent use.
type Simulator struct {
	coll  *Collector
	cache map[string]*accountSession
}

// Simulator returns a simulator for the connector, reading it in a read
// transaction and holding none afterwards. A connector that cannot be built
// (no federation, static keys off, unreadable credentials) is an error.
func (s *Service) Simulator(ctx context.Context, db *store.DB, tenant tenancy.ID, connectorID string) (*Simulator, error) {
	if s.Client == nil || s.Client.HTTP == nil {
		return nil, errors.New("awsorg: no HTTP client")
	}
	var k *store.AWSConnector
	if err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) (err error) {
		k, err = c.AWSConnector(connectorID)
		return err
	}); err != nil {
		return nil, notFound(err)
	}
	cfg, err := ParseConfig(k.Config)
	if err != nil {
		return nil, err
	}
	coll, _, err := s.collectorFor(tenant, k, cfg)
	if err != nil {
		return nil, err
	}
	return &Simulator{coll: coll, cache: map[string]*accountSession{}}, nil
}

// Ask sends one question. The answer holds no policy text. An AWS refusal (no
// permission, no such principal) comes back as an error.
func (m *Simulator) Ask(ctx context.Context, q SimQuery) (*SimAnswer, error) {
	account := arnAccountID(q.PrincipalARN)
	if account == "" || !strings.HasPrefix(q.PrincipalARN, "arn:") {
		return nil, fmt.Errorf("awsorg: %q is not a principal ARN", q.PrincipalARN)
	}
	sess, err := m.coll.assume(ctx, m.cache, account)
	if err != nil {
		return nil, fmt.Errorf("assume the reader role in %s: %w", account, err)
	}
	resource := q.Resource
	if resource == "" {
		resource = "*"
	}
	p := url.Values{"PolicySourceArn": {q.PrincipalARN}, "ActionNames.member.1": {q.Action}, "ResourceArns.member.1": {resource},
		"MaxItems": {"100"}}
	var r xmlSimResult
	if err := sess.query(ctx, svcIAM, "us-east-1", "2010-05-08", "SimulatePrincipalPolicy", p, &r); err != nil {
		return nil, err
	}
	var mine *SimAnswer
	for _, e := range r.Results {
		if !strings.EqualFold(e.Action, q.Action) {
			continue
		}
		if mine != nil {
			return nil, fmt.Errorf("awsorg: SimulatePrincipalPolicy returned more than one result for %s", q.Action)
		}
		mine = &SimAnswer{Decision: e.Decision, Missing: e.Missing}
	}
	if mine == nil || mine.Decision == "" {
		return nil, fmt.Errorf("awsorg: SimulatePrincipalPolicy returned no result for %s", q.Action)
	}
	return mine, nil
}
