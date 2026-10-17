package awsorg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const estateRep = "arn:aws:s3:::prod-pii/x"

func evalConfig() *EvalConfig {
	return &EvalConfig{
		Index: func(*model.Snapshot) index.Config {
			return index.Config{Catalog: awstest.Catalog{}, Actions: awstest.Actions(), Resources: []string{estateRep}, Applies: awstest.SameServiceRule}
		},
		Privileged: func(a string) bool { return a == "kms:Decrypt" },
	}
}

func querierFor(t testing.TB, snap *model.Snapshot, cfg *EvalConfig) *query.Querier {
	t.Helper()
	ix, err := index.Build(snap, cfg.Index(snap))
	if err != nil {
		t.Fatal(err)
	}
	q, err := query.New(ix, nil, query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(awstest.EstateTime), Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func edgesFrom(r *connectors.DiscoveryResult, src connectors.Ref, rel string) []connectors.EdgeRecord {
	var out []connectors.EdgeRecord
	for _, e := range r.Edges {
		if e.Src == src && e.Relation == rel {
			out = append(out, e)
		}
	}
	return out
}

func TestMaterializeEmitsOnlyConfirmedPermissions(t *testing.T) {
	snap, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := evalConfig()
	m, err := Materialize(context.Background(), snap, nil, querierFor(t, snap, cfg), cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := m.Result

	// accounts: users are users, roles are service accounts; groups for IAM groups and for roles
	kinds := map[string]string{}
	for _, a := range r.Accounts {
		kinds[a.ExternalID] = a.Kind
		if a.System != "aws" || a.Status != "active" || a.Identity != nil {
			t.Errorf("account %+v", a)
		}
	}
	if kinds[awstest.EstateAlice] != "user" || kinds[awstest.EstateEngineer] != "service" || kinds[awstest.EstateDevUser] != "user" || len(kinds) != 4 {
		t.Errorf("accounts = %v", kinds)
	}
	groupKinds := map[string]string{}
	for _, g := range r.Groups {
		groupKinds[g.ExternalID] = g.Kind
	}
	if groupKinds[awstest.EstateGroup] != "group" || groupKinds[awstest.EstateEngineer] != "role" || len(groupKinds) != 2 {
		t.Errorf("groups = %v", groupKinds)
	}
	if es := edgesFrom(r, acctRef(awstest.EstateBob), "member_of"); len(es) != 1 || es[0].Dst != groupRef(awstest.EstateGroup) {
		t.Errorf("bob's membership = %v", es)
	}
	if es := edgesFrom(r, acctRef(awstest.EstateEngineer), "member_of"); len(es) != 1 || es[0].Dst != groupRef(awstest.EstateEngineer) {
		t.Errorf("the role account is not a member of the role group: %v", es)
	}

	// alice: s3:GetObject on the objects, exact, with a trace
	pk := "s3:GetObject|" + estateRep
	var get *connectors.EdgeRecord
	for _, e := range edgesFrom(r, acctRef(awstest.EstateAlice), "grants") {
		e := e
		if e.Dst == permRef(pk) {
			get = &e
		}
	}
	if get == nil || get.Evaluation == nil || get.Evaluation.Outcome != "allow" || get.Evaluation.Fidelity != "exact" {
		t.Fatalf("alice's s3:GetObject grant = %+v", get)
	}
	var trace *store.AWSExplanation
	for _, x := range m.Explanations {
		if x.ID == get.Evaluation.ExplanationID {
			trace = x
		}
	}
	if trace == nil {
		t.Fatalf("explanation %s was not produced", get.Evaluation.ExplanationID)
	}
	if sum := sha256.Sum256(trace.Trace); hex.EncodeToString(sum[:]) != trace.ID {
		t.Error("the explanation id is not the hash of its trace")
	}
	var d authz.Decision
	var raw struct {
		Outcome string `json:"outcome"`
		Steps   []any  `json:"steps"`
	}
	if err := json.Unmarshal(trace.Trace, &raw); err != nil || raw.Outcome != "allow" || len(raw.Steps) == 0 {
		t.Errorf("trace = %v, %v (%v)", raw, err, d)
	}

	// nothing is emitted for what the engine denies: bob has no object grant, dev holds nothing
	for _, who := range []string{awstest.EstateBob, awstest.EstateDevUser} {
		for _, e := range edgesFrom(r, acctRef(who), "grants") {
			if e.Dst == permRef(pk) {
				t.Errorf("%s was granted %s", who, pk)
			}
		}
	}
	if es := edgesFrom(r, acctRef(awstest.EstateDevUser), "grants"); len(es) != 0 {
		t.Errorf("dev holds %d grants", len(es))
	}
	// the role's grants hang on its role group; its decrypt is privileged because the catalog says so
	var decrypt *connectors.PermissionRecord
	for _, p := range r.Permissions {
		p := p
		if p.Action == "kms:Decrypt" {
			decrypt = &p
		}
	}
	if decrypt == nil || !decrypt.Privileged || decrypt.System != "aws" {
		t.Fatalf("kms:Decrypt = %+v", decrypt)
	}
	if es := edgesFrom(r, groupRef(awstest.EstateEngineer), "grants"); len(es) == 0 {
		t.Error("the role group grants nothing")
	}

	// every permission names a resource record, and no record is unused
	res := map[string]bool{}
	for _, x := range r.Resources {
		res[x.ExternalID] = true
	}
	for _, p := range r.Permissions {
		if !res[p.ResourceExternalID] {
			t.Errorf("permission %s names resource %s, which has no record", p.ExternalID, p.ResourceExternalID)
		}
	}

	// trust: alice may assume the role (her policy and its trust policy agree); bob and dev may not
	var assumes []string
	for _, e := range r.Edges {
		if e.Relation == "can_assume" {
			assumes = append(assumes, e.Src.ExternalID+" -> "+e.Dst.ExternalID)
			if e.Evaluation == nil || e.Evaluation.ExplanationID == "" {
				t.Errorf("can_assume edge without an evaluation: %+v", e)
			}
		}
	}
	if want := []string{awstest.EstateAlice + " -> " + awstest.EstateEngineer}; !slices.Equal(assumes, want) {
		t.Errorf("can_assume edges = %v, want %v", assumes, want)
	}
	if len(m.Trust) != 1 || m.Trust[0].FromARN != awstest.EstateAlice || m.Trust[0].ToRoleARN != awstest.EstateEngineer ||
		m.Trust[0].Mechanism != "assume_role" || m.Trust[0].Outcome != "allow" {
		t.Errorf("trust edges = %+v", m.Trust)
	}

	// deterministic
	m2, _ := Materialize(context.Background(), snap, nil, querierFor(t, snap, cfg), cfg)
	a, _ := json.Marshal(m.Result)
	b, _ := json.Marshal(m2.Result)
	if string(a) != string(b) {
		t.Error("materializing twice gives different records")
	}
}

// A finding of the collection that could change a cell makes its edge
// UNSUPPORTED, so least privilege never acts on it (design §3.3).
func TestMaterializeFindingsMakeEdgesUnsupported(t *testing.T) {
	snap, _ := awstest.Estate()
	cfg := evalConfig()
	findings := Findings{{Kind: store.AWSFindingPolicyUnparseable, SourceARN: awstest.EstateAlice + "#inline/x", PolicyKind: "identity",
		Code: "invalid_json", Detail: "bad", Scope: Scope{Type: ScopePrincipals, Targets: []string{awstest.EstateAlice}}}}
	m, err := Materialize(context.Background(), snap, findings, querierFor(t, snap, cfg), cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range m.Result.Edges {
		if e.Evaluation == nil || e.Relation != "grants" {
			continue
		}
		wantUnsupported := e.Src == acctRef(awstest.EstateAlice)
		if (e.Evaluation.Fidelity == "unsupported") != wantUnsupported {
			t.Errorf("%v -> %v is %s", e.Src.ExternalID, e.Dst.ExternalID, e.Evaluation.Fidelity)
		}
		if wantUnsupported {
			n++
		}
	}
	if n == 0 {
		t.Error("alice has no grants to mark")
	}
	for _, x := range m.Explanations {
		if strings.Contains(string(x.Trace), "POLICY_UNPARSEABLE") {
			return
		}
	}
	t.Error("no trace records POLICY_UNPARSEABLE")
}

func TestMaterializeBounds(t *testing.T) {
	snap, _ := awstest.Estate()
	cfg := evalConfig()
	cfg.MaxCellsPerPrincipal = 1
	cfg.MaxTrustEvaluations = 1
	m, err := Materialize(context.Background(), snap, nil, querierFor(t, snap, cfg), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Notes) == 0 {
		t.Error("a cut is not reported")
	}
	perPrincipal := map[connectors.Ref]int{}
	for _, e := range m.Result.Edges {
		if e.Relation == "grants" {
			perPrincipal[e.Src]++
		}
	}
	for src, n := range perPrincipal {
		if n > 1 {
			t.Errorf("%v has %d grants, the cap is 1", src, n)
		}
	}
	if _, err := Materialize(context.Background(), nil, nil, nil, nil); err == nil {
		t.Error("Materialize of nothing succeeded")
	}
}

// trustWorld is a snapshot of roles whose trust policies show the risks of
// design §11.4.
func trustWorld(t *testing.T) *model.Snapshot {
	t.Helper()
	b := snapshot.NewBuilder()
	b.SetTakenAt(awstest.EstateTime)
	const acct = "111111111111"
	const oidc = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
	b.SetOrg(&model.Organization{OrgID: "o-1", ManagementAccountID: "333333333333", SCPEnabled: false, Nodes: map[string]*model.OrgNode{
		"r-1":          {ID: "r-1", Kind: model.OrgRoot, Name: "Root"},
		acct:           {ID: acct, Kind: model.OrgAccount, ParentID: "r-1", Name: "main"},
		"444444444444": {ID: "444444444444", Kind: model.OrgAccount, ParentID: "r-1", Name: "sibling"}}})
	role := func(name, principal, action, cond string) string {
		arn := "arn:aws:iam::" + acct + ":role/" + name
		doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"` + action + `"` + cond + `}]}`
		id := b.AddPolicy(policy.Options{Kind: model.PolicyTrust, SourceARN: arn + "#trust"}, []byte(doc)).ID
		b.AddPrincipal(&model.Principal{ARN: arn, Kind: model.IAMRole, AccountID: acct, Path: "/"})
		b.AddResource(&model.Resource{ARN: arn, Type: "role", AccountID: acct})
		b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: arn, Kind: model.PolicyTrust, PolicyID: id, RequiresExplicitAllow: true})
		return arn
	}
	fed := `{"Federated":"` + oidc + `"}`
	web := "sts:AssumeRoleWithWebIdentity"
	role("ci-wild", fed, web, `,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:org/*"}}`)
	role("ci-pinned", fed, web, `,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:org/app:ref:refs/heads/main"}}`)
	role("ci-open", fed, web, ``)
	role("ext-noid", `{"AWS":"arn:aws:iam::999999999999:root"}`, "sts:AssumeRole", ``)
	role("ext-id", `{"AWS":"arn:aws:iam::999999999999:root"}`, "sts:AssumeRole", `,"Condition":{"StringEquals":{"sts:ExternalId":"abc"}}`)
	role("sibling", `{"AWS":"arn:aws:iam::444444444444:root"}`, "sts:AssumeRole", ``)
	role("anyone", `"*"`, "sts:AssumeRole", ``)
	role("anyone-org", `"*"`, "sts:AssumeRole", `,"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}`)
	snap, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestMaterializeTrustFlags(t *testing.T) {
	snap := trustWorld(t)
	cfg := &EvalConfig{Index: func(*model.Snapshot) index.Config {
		return index.Config{Catalog: awstest.Catalog{}, Actions: awstest.Actions(), Applies: awstest.SameServiceRule}
	}}
	m, err := Materialize(context.Background(), snap, nil, querierFor(t, snap, cfg), cfg)
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string][]string{}
	edges := map[string]int{}
	for _, e := range m.Trust {
		var tr trustResidual
		if err := json.Unmarshal(e.Residual, &tr); err != nil {
			t.Fatalf("residual %s: %v", e.Residual, err)
		}
		role := entityName(e.ToRoleARN)
		edges[role]++
		flags[role] = append(flags[role], tr.Flags...)
	}
	for role, want := range map[string][]string{
		"ci-wild":    {FlagWildcardOIDCTrust},
		"ci-pinned":  nil,
		"ci-open":    {FlagWildcardOIDCTrust},
		"ext-noid":   {FlagMissingExternalID},
		"ext-id":     nil,
		"sibling":    nil, // an account of the organization needs no external id
		"anyone":     {FlagPublicTrust},
		"anyone-org": nil,
	} {
		got := slices.Clone(flags[role])
		slices.Sort(got)
		got = slices.Compact(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: flags %v, want %v", role, got, want)
		}
	}
	// the OIDC roles have a real, evaluated trust edge from the provider; the flag rows of the
	// external ones are facts of the policy, with no explanation
	if edges["ci-wild"] != 1 || edges["ci-pinned"] != 1 || edges["ci-open"] != 1 {
		t.Errorf("edges = %v", edges)
	}
	for _, e := range m.Trust {
		fromPolicy := strings.HasPrefix(e.FromARN, trustOutsidePrefix)
		if fromPolicy != (e.ExplanationID == "") {
			t.Errorf("trust edge %+v: from policy %v, explanation %q", e, fromPolicy, e.ExplanationID)
		}
	}
}

func TestWildcardSubject(t *testing.T) {
	sub := func(op string, vs ...string) authz.Atom {
		return authz.Atom{Op: op, Key: "token.actions.githubusercontent.com:sub", Values: vs}
	}
	aud := authz.Atom{Op: "StringEquals", Key: "token.actions.githubusercontent.com:aud", Values: []string{"sts.amazonaws.com"}}
	for name, tc := range map[string]struct {
		r    authz.Residual
		want bool
	}{
		"unconditional":          {authz.Const(true), true},
		"no sub":                 {aud, true},
		"pinned":                 {sub("StringEquals", "repo:o/r:ref:refs/heads/main"), false},
		"wildcard":               {sub("StringLike", "repo:o/*"), true},
		"wildcard in a list":     {sub("StringLike", "repo:o/a", "repo:o/*"), true},
		"pinned and an audience": {authz.And{Terms: []authz.Residual{aud, sub("StringEquals", "repo:o/r")}}, false},
		"wildcard under And":     {authz.And{Terms: []authz.Residual{aud, sub("StringLike", "*")}}, true},
		"pinned under Or":        {authz.Or{Terms: []authz.Residual{sub("StringEquals", "a"), sub("StringEquals", "b")}}, false},
	} {
		if got := wildcardSubject(tc.r); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// Service.Materialize stores the evaluation and keeps the graph in step with
// it: edges the engine confirms are written with their evaluation, an edge it
// no longer confirms is removed, a manual edge is never touched, and an
// account keeps the person it was linked to.
func TestServiceMaterializeKeepsTheGraphInStep(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	cfg := evalConfig()
	svc := &Service{Eval: cfg, Clock: func() time.Time { return awstest.EstateTime }}

	persist := func(snap *model.Snapshot) string {
		col := &Collection{Snapshot: snap, AccountIDs: []string{awstest.EstateDev, awstest.EstateProd}}
		id, err := ContentID(col)
		if err != nil {
			t.Fatal(err)
		}
		snap.ID = id
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			_, err := Persist(c, col, PersistInput{Source: store.AWSSourceConnector, CatalogVersion: "awstest-1"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	snap1, _ := awstest.Estate()
	id1 := persist(snap1)

	// a person alice is linked to before the evaluation
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.UpsertIdentity(&store.Identity{ExternalID: "alice-person", Name: "Alice", Type: "human", Status: "active", CreatedAt: awstest.EstateTime}); err != nil {
			return err
		}
		idents, err := c.Identities()
		if err != nil {
			return err
		}
		var pid int64
		for _, i := range idents {
			if i.ExternalID == "alice-person" {
				pid = i.ID
			}
		}
		return c.UpsertAccount(&store.Account{System: "aws", ExternalID: awstest.EstateAlice, Username: "alice", IdentityID: &pid, Kind: "user", Status: "active", CreatedAt: nil})
	}); err != nil {
		t.Fatal(err)
	}

	stats, err := svc.Materialize(ctx, f.DB, f.A.ID, id1, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cells == 0 || stats.Trust != 1 || stats.Ingested.Edges == 0 {
		t.Fatalf("stats = %+v", stats)
	}
	count := func(tenant storetest.Tenant) (evaluator int, aliceGetObject bool) {
		_ = f.DB.ReadTenant(ctx, tenant.ID, func(c *store.TenantTx) error {
			edges, _ := c.Edges()
			accts, _ := c.Accounts()
			perms, _ := c.Permissions()
			key := func(kind string, id int64) string { return kind + ":" + strconv.FormatInt(id, 10) }
			var alice, get string
			for _, a := range accts {
				if a.System == "aws" && a.ExternalID == awstest.EstateAlice {
					alice = key("account", a.ID)
				}
			}
			for _, p := range perms {
				if p.System == "aws" && p.ExternalID == "s3:GetObject|"+estateRep {
					get = key("perm", p.ID)
				}
			}
			for _, e := range edges {
				if e.Source == store.EdgeSourceEvaluator {
					evaluator++
					if e.Src == alice && e.Dst == get && e.Outcome == "allow" && e.Fidelity == "exact" && e.ExplanationID != "" {
						aliceGetObject = true
					}
				}
			}
			return nil
		})
		return
	}
	n, ok := count(f.A)
	if n == 0 || !ok {
		t.Fatalf("evaluator edges = %d, alice's GetObject edge present = %v", n, ok)
	}
	if n, ok := count(f.B); n != 0 || ok {
		t.Errorf("tenant B has %d evaluator edges", n)
	}

	// the account kept its person, the trust edges and traces are stored, the run is audited
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		accts, _ := c.Accounts()
		for _, a := range accts {
			if a.System == "aws" && a.ExternalID == awstest.EstateAlice && a.IdentityID == nil {
				t.Error("evaluating unlinked alice's account from her person")
			}
		}
		tes, err := c.AWSTrustEdges(id1)
		if err != nil || len(tes) != 1 {
			t.Errorf("stored trust edges = %v, %v", tes, err)
		}
		if _, err := c.AWSExplanation(tes[0].ExplanationID); err != nil {
			t.Errorf("the trust edge's explanation is not stored: %v", err)
		}
		evs, _ := c.AuditLog(0)
		found := false
		for _, e := range evs {
			found = found || e.Action == "aws.snapshot.materialized"
		}
		if !found {
			t.Error("the evaluation is not audited")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// a manual edge between the same kind of nodes survives every evaluation
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		_, err := c.InsertEdge(&store.GrantEdge{Src: "account:999999", Dst: "perm:999999", Relation: "direct_grant", Source: "manual", CreatedAt: awstest.EstateTime})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// again, unchanged: nothing new, nothing lost
	if _, err := svc.Materialize(ctx, f.DB, f.A.ID, id1, "tester"); err != nil {
		t.Fatal(err)
	}
	if n2, _ := count(f.A); n2 != n {
		t.Errorf("evaluator edges after a second run = %d, want %d", n2, n)
	}

	// a pull request merged: alice's policy no longer grants GetObject; the edge goes
	snap2, err := snapshot.Apply(snap1, []snapshot.PolicyChange{{Op: snapshot.OpDetach, TargetARN: awstest.EstateAlice, PolicyARN: ptr(awstest.EstateS3Read)}},
		snapshot.ApplyOptions{FetchedAt: awstest.EstateTime})
	if err != nil {
		t.Fatal(err)
	}
	id2 := persist(snap2)
	stats, err = svc.Materialize(ctx, f.DB, f.A.ID, id2, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pruned == 0 {
		t.Errorf("stats = %+v, want the stale edge pruned", stats)
	}
	if _, ok := count(f.A); ok {
		t.Error("alice's GetObject edge is still there after the policy was detached")
	}
	f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		edges, _ := c.Edges()
		manual := false
		for _, e := range edges {
			manual = manual || (e.Source == "manual" && e.Src == "account:999999")
		}
		if !manual {
			t.Error("the manual edge was removed")
		}
		return nil
	})

	// no evaluator configured: Materialize refuses
	if _, err := (&Service{}).Materialize(ctx, f.DB, f.A.ID, id2, "t"); err == nil {
		t.Error("Materialize with no evaluator succeeded")
	}
}

func ptr(s string) *string { return &s }
