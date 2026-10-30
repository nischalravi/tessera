package blast

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
)

func people() map[int64]Person {
	return map[int64]Person{
		1: {1, "Alice", "human"}, 2: {2, "Bob", "human"}, 3: {3, "svc-etl", "service"},
		4: {4, "helper-bot", AgentType}, 5: {5, "deploy-bot", AgentType}, 6: {6, "Carol", "human"},
	}
}

const bucket = "arn:aws:s3:::prod-pii"

func gained(principals []string, resources ...string) query.Change {
	return query.Change{Principals: principals, Actions: []string{"s3:GetObject", "s3:PutObject"}, Resources: resources,
		ActionCount: 2, ResourceCount: len(resources), Kind: query.Gained}
}

// The acceptance shape: N identities gain a path to a bucket, and k of them are agents; the join reaches identities
// through the principals' accounts, and what it cannot reach is counted, not dropped.
func TestSummarize_IdentitiesGainPathToBucket(t *testing.T) {
	aws := &AWSDiff{
		Changes: []query.Change{
			gained([]string{"arn:u/alice", "arn:r/helper", "arn:r/deploy", "arn:u/nobody"}, bucket),
			{Principals: []string{"arn:u/bob"}, Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::other"}, ActionCount: 1, ResourceCount: 1, Kind: query.Lost},
			{Principals: []string{"arn:u/carol"}, Actions: []string{"s3:GetObject"}, Resources: []string{bucket}, ActionCount: 1, ResourceCount: 1, Kind: query.ConditionalChanged},
		},
		Principals: map[string]int64{"arn:u/alice": 1, "arn:u/bob": 2, "arn:r/helper": 4, "arn:r/deploy": 5, "arn:u/carol": 6},
	}
	r := Summarize(Inputs{People: people(), AWS: aws})
	s := r.Summary
	if s.IdentitiesGaining != 3 || s.AgentsGaining != 2 || s.IdentitiesLosing != 1 || s.AgentsLosing != 0 || s.IdentitiesAffected != 4 ||
		s.UnlinkedPrincipals != 1 || s.Approximate != 1 || s.AWSPathsGained != 6 || s.AWSPathsLost != 1 {
		t.Fatalf("summary = %+v", s)
	}
	want := []TypeDelta{{"ai_agent", 2, 0}, {"human", 1, 1}}
	if !reflect.DeepEqual(r.ByIdentityType, want) {
		t.Errorf("by type = %+v, want %+v", r.ByIdentityType, want)
	}
	if len(r.ByResource) != 2 || r.ByResource[0].Resource != bucket || r.ByResource[0].IdentitiesGaining != 3 || r.ByResource[0].AgentsGaining != 2 ||
		r.ByResource[0].Systems[0] != "aws" || r.ByResource[1].Resource != "arn:aws:s3:::other" || r.ByResource[1].IdentitiesLosing != 1 {
		t.Errorf("by resource = %+v", r.ByResource)
	}
	// a lost permission does not make an identity a gainer, and the bucket's gainers are alice and the two agents
	if len(r.Identities) != 4 || r.Identities[0].AWSPathsGained != 2 {
		t.Errorf("identities = %+v", r.Identities)
	}
}

// The graph half: effective permissions gained and lost per identity, resources, and the policy findings.
func TestSummarize_GraphAndViolations(t *testing.T) {
	two := int64(2)
	g := &simulate.Result{
		Identities: []simulate.IdentityChange{
			{IdentityID: 2, Name: "Bob", Type: "human", Added: []simulate.Added{{Action: "payments:approve", Resource: "payments", System: "workday"}}},
			{IdentityID: 4, Name: "helper-bot", Type: "ai_agent", Added: []simulate.Added{{Action: "s3:GetObject", Resource: "customer-pii", System: "aws"}},
				Removed: []simulate.Removed{{Action: "snowflake:SELECT", Resource: "CUSTOMERS", System: "snowflake"}}},
			{IdentityID: 99, Name: "Late", Type: "service", Removed: []simulate.Removed{{Action: "x", Resource: "payments", System: "workday"}}},
		},
		Violations: policy.Diff{
			Introduced: []policy.Violation{
				{PolicyID: "pay-create-approve", Key: "pay:2", Severity: "high", IdentityID: &two, IdentityName: "Bob", Message: "m"},
				{PolicyID: policy.PolicyAgentOutOfScope, Key: "hb:4", Severity: "high", Message: "n"},
			},
			Resolved: []policy.Violation{{PolicyID: policy.PolicyAgentExceedsOwner, Key: "own:4"}},
		},
		Summary: simulate.Summary{ViolationsBefore: 3, ViolationsAfter: 4},
	}
	r := Summarize(Inputs{People: people(), Graph: g})
	s := r.Summary
	if s.IdentitiesGaining != 2 || s.AgentsGaining != 1 || s.IdentitiesLosing != 2 || s.GraphPermissionsGained != 2 || s.GraphPermissionsLost != 2 || s.IdentitiesAffected != 3 {
		t.Fatalf("summary = %+v", s)
	}
	v := r.Violations
	if v.Before != 3 || v.After != 4 || v.IntroducedTotal != 2 || v.ResolvedTotal != 1 || v.AgentScopeIntroduced != 1 || v.AgentScopeResolved != 1 ||
		len(v.Introduced) != 2 || v.Introduced[0].Key != "pay:2" {
		t.Errorf("violations = %+v", v)
	}
	// an identity the caller did not list is still named, from the graph's own answer
	found := false
	for _, i := range r.Identities {
		found = found || (i.IdentityID == 99 && i.Name == "Late" && i.Type == "service")
	}
	if !found {
		t.Errorf("identities = %+v", r.Identities)
	}
}

// The same inputs give the same bytes, whatever the order of the maps behind them.
func TestSummarize_Deterministic(t *testing.T) {
	var ps []string
	owners := map[string]int64{}
	for i := 0; i < 40; i++ {
		a := fmt.Sprintf("arn:u/%d", i)
		ps = append(ps, a)
		owners[a] = int64(1 + i%6)
	}
	var res []string
	for i := 0; i < 30; i++ {
		res = append(res, fmt.Sprintf("arn:aws:s3:::b%02d", i))
	}
	in := Inputs{People: people(), AWS: &AWSDiff{Changes: []query.Change{gained(ps, res...), gained(ps[:5], "arn:aws:s3:::z")}, Principals: owners}}
	first, _ := json.Marshal(Summarize(in))
	for i := 0; i < 20; i++ {
		if again, _ := json.Marshal(Summarize(in)); string(again) != string(first) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, again)
		}
	}
}

// Lists are cut, the totals are not.
func TestSummarize_CapsListsNotCounts(t *testing.T) {
	const n = MaxIdentities + 37
	ppl := map[int64]Person{}
	owners := map[string]int64{}
	var ps, res []string
	for i := 1; i <= n; i++ {
		ppl[int64(i)] = Person{int64(i), fmt.Sprintf("p%04d", i), "human"}
		a := fmt.Sprintf("arn:u/%d", i)
		owners[a] = int64(i)
		ps = append(ps, a)
	}
	for i := 0; i < MaxResources+11; i++ {
		res = append(res, fmt.Sprintf("arn:r/%04d", i))
	}
	r := Summarize(Inputs{People: ppl, AWS: &AWSDiff{Changes: []query.Change{gained(ps, res...)}, Principals: owners}})
	if r.Summary.IdentitiesGaining != n || len(r.Identities) != MaxIdentities || r.IdentitiesOmitted != 37 ||
		len(r.ByResource) != MaxResources || r.ResourcesOmitted != 11 || r.Summary.ResourcesGained != MaxResources+11 {
		t.Errorf("summary %+v, %d identities (%d omitted), %d resources (%d omitted)", r.Summary, len(r.Identities), r.IdentitiesOmitted, len(r.ByResource), r.ResourcesOmitted)
	}
}

func TestSummarize_Empty(t *testing.T) {
	r := Summarize(Inputs{People: people()})
	raw, _ := json.Marshal(r)
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	// lists are [] not null, so a client never has to tell them apart
	for _, k := range []string{"by_identity_type", "by_resource", "identities"} {
		if l, ok := back[k].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %v", k, back[k])
		}
	}
	if r.Summary != (Summary{}) {
		t.Errorf("summary = %+v", r.Summary)
	}
}

func TestAddRoleEditsDedupes(t *testing.T) {
	acct, e1 := int64(7), int64(11)
	steps := []roles.Step{
		{Action: roles.AddGrant, AccountID: &acct, GroupID: 3},
		{Action: roles.AddGrant, AccountID: &acct, GroupID: 3}, // a second role wants the same group
		{Action: roles.AddGrant, GroupID: 4},                   // no account: nothing to add
		{Action: roles.RemoveGrant, EdgeID: &e1},
		{Action: roles.RemoveGrant, EdgeID: &e1},
		{Action: roles.KeepGrant, GroupID: 5},
		{Action: roles.AddMember}, {Action: roles.NoAccount},
	}
	var req simulate.Request
	addRoleEdits(&req, steps)
	if len(req.AddEdges) != 1 || req.AddEdges[0].Src != "account:7" || req.AddEdges[0].Dst != "group:3" || req.AddEdges[0].Relation != "member_of" ||
		!reflect.DeepEqual(req.RemoveEdgeIDs, []int64{11}) {
		t.Errorf("request = %+v", req)
	}
}

func TestCheckCeiling(t *testing.T) {
	for _, tc := range []struct {
		name        string
		max, b, ops int
		wantRefusal bool
	}{
		{"within", 10, 6, 4, false},
		{"over", 10, 6, 5, true},
		{"operations alone", 3, 0, 4, true},
		{"default limit", 0, 0, 20000, false},
		{"over the default", 0, 1, 20000, true},
	} {
		err := CheckCeiling(Options{MaxSteps: tc.max}, tc.b, tc.ops)
		var re *roles.Error
		if got := err != nil; got != tc.wantRefusal {
			t.Errorf("%s: err = %v", tc.name, err)
		} else if got && (!asRoles(err, &re) || re.Status != 413 || re.Code != "plan_too_large") {
			t.Errorf("%s: err = %v, want 413 plan_too_large", tc.name, err)
		}
	}
}

func asRoles(err error, out **roles.Error) bool {
	re, ok := err.(*roles.Error)
	*out = re
	return ok
}
