package leastpriv_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	awspolicy "github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	awsq "github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func awsQuerier(t *testing.T, snap *model.Snapshot) *awsq.Querier {
	t.Helper()
	ix, err := index.Build(snap, index.Config{Catalog: awstest.Catalog{}, Actions: awstest.Actions(),
		Resources: []string{"arn:aws:s3:::prod-pii/x"}, Applies: awstest.SameServiceRule})
	if err != nil {
		t.Fatal(err)
	}
	q, err := awsq.New(ix, nil, awsq.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(awstest.EstateTime), Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func sp(s string) *string { return &s }

// A least-privilege recommendation is verified by the evaluator: it must keep
// every call the principal used, and give it nothing (design §11.5).
func TestVerifyAWSPreservesTheUsedSet(t *testing.T) {
	base, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	bq := awsQuerier(t, base)
	apply := func(cs ...snapshot.PolicyChange) *awsq.Querier {
		head, err := snapshot.Apply(base, cs, snapshot.ApplyOptions{FetchedAt: awstest.EstateTime})
		if err != nil {
			t.Fatal(err)
		}
		return awsQuerier(t, head)
	}
	// alice was seen reading customer objects; she never assumed the role
	used := []leastpriv.UsedCall{{Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-pii/customers.csv"}}
	ch := func(op snapshot.PolicyChangeOp, target string, doc, pol *string) snapshot.PolicyChange {
		return snapshot.PolicyChange{Op: op, TargetARN: target, Document: doc, PolicyARN: pol}
	}
	widen := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::prod-pii/*"}]}`

	for _, tc := range []struct {
		name         string
		head         *awsq.Querier
		ok, auto     bool
		broken       int
		added        bool
		removedSome  bool
		reasonSubstr string
	}{
		{"remove the unused assume-role policy", apply(ch(snapshot.OpDeleteInline, awstest.EstateAlice, nil, sp("assume"))),
			true, true, 0, false, true, ""},
		{"no change", apply(), true, true, 0, false, false, ""},
		{"remove the policy she used", apply(ch(snapshot.OpDetach, awstest.EstateAlice, nil, sp(awstest.EstateS3Read))),
			false, false, 1, false, true, "no longer be allowed"},
		{"a candidate that gives more", apply(ch(snapshot.OpPutPolicyVersion, awstest.EstateS3Read, &widen, nil)),
			false, false, 0, true, false, "gives"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := leastpriv.VerifyAWS(context.Background(), bq, tc.head, awstest.EstateAlice, used)
			if err != nil {
				t.Fatal(err)
			}
			if v.OK != tc.ok || v.AutoApplicable != tc.auto || len(v.Broken) != tc.broken || (v.Added > 0) != tc.added || (v.Removed > 0) != tc.removedSome {
				t.Errorf("verification = %+v", v)
			}
			if tc.broken == 0 && len(v.Kept) != 1 {
				t.Errorf("kept = %v", v.Kept)
			}
			if tc.broken > 0 && (v.Broken[0].Action != "s3:GetObject" || v.Broken[0].Outcome != "deny") {
				t.Errorf("broken = %+v", v.Broken)
			}
			if tc.reasonSubstr != "" {
				found := false
				for _, r := range v.Reasons {
					found = found || strings.Contains(r, tc.reasonSubstr)
				}
				if !found {
					t.Errorf("reasons = %v, want one with %q", v.Reasons, tc.reasonSubstr)
				}
			}
		})
	}

	// an unknown principal is an error, not a pass
	if _, err := leastpriv.VerifyAWS(context.Background(), bq, bq, "arn:aws:iam::111111111111:user/nobody", used); err == nil {
		t.Error("VerifyAWS of an unknown principal succeeded")
	}
}

func policyOpts(src string) awspolicy.Options {
	return awspolicy.Options{Kind: model.PolicyIdentity, SourceARN: src}
}

// A narrowing that rests on an approximate evaluation is advice, not an action:
// it verifies, and is not auto-applicable.
func TestVerifyAWSNeverAutoAppliesOnAnApproximateBasis(t *testing.T) {
	base, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	// an unparseable policy document in the snapshot makes decisions UNSUPPORTED (§3.3)
	b := snapshot.NewBuilder()
	b.SetTakenAt(awstest.EstateTime)
	broken := b.AddPolicy(policyOpts("arn:aws:iam::111111111111:user/carol#inline/broken"), []byte(`{`))
	good := b.AddPolicy(policyOpts("arn:aws:iam::111111111111:user/carol#inline/good"),
		[]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-pii/*"}]}`))
	b.AddPrincipal(&model.Principal{ARN: "arn:aws:iam::111111111111:user/carol", Kind: model.IAMUser, AccountID: "111111111111", Path: "/",
		IdentityPolicyIDs: []string{broken.ID, good.ID}})
	b.AddResource(&model.Resource{ARN: "arn:aws:s3:::prod-pii", Type: "bucket", AccountID: "111111111111"})
	snap, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	_ = base
	bq := awsQuerier(t, snap)
	head, err := snapshot.Apply(snap, []snapshot.PolicyChange{{Op: snapshot.OpDeleteInline, TargetARN: "arn:aws:iam::111111111111:user/carol",
		PolicyARN: sp("good")}}, snapshot.ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := leastpriv.VerifyAWS(context.Background(), bq, awsQuerier(t, head), "arn:aws:iam::111111111111:user/carol", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Removed == 0 || v.AutoApplicable {
		t.Errorf("verification = %+v; want a narrowing that is not auto-applicable (the principal has an unreadable policy)", v)
	}
}

// Recommendations are generated only from rows that are not weak: a grant the
// evaluator found conditional, approximate or unsupported is never a basis for
// a removal (design §11.5, spec R2), and one it found exact still is.
func TestGrantRecommendationsSkipWeakEvaluatedGrants(t *testing.T) {
	for _, tc := range []struct {
		name, outcome, fidelity string
		want                    bool
	}{
		{"exact", "allow", "exact", true},
		{"approximate", "allow", "approximate", false},
		{"unsupported", "allow", "unsupported", false},
		{"conditional", "conditional", "exact", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, ids := testkit.Tiny(t)
			testkit.Write(t, st, func(c *store.TenantTx) error {
				edges, err := c.Edges()
				if err != nil {
					return err
				}
				for _, e := range edges {
					if e.Src == graph.Key("account", ids["acct:aws:svc-etl"]) {
						if err := c.DeleteEdge(e.ID); err != nil {
							return err
						}
						ok, err := c.UpsertEvaluatorEdge(e.Src, e.Dst, e.Relation, testkit.Now,
							store.EdgeEvaluation{ExplanationID: "x", Outcome: tc.outcome, Fidelity: tc.fidelity})
						if err != nil || !ok {
							t.Fatalf("UpsertEvaluatorEdge = %v, %v", ok, err)
						}
					}
				}
				return nil
			})
			g, u := load(t, st)
			recs := leastpriv.GrantRecommendations(g, u, 60, nil)
			got := false
			for _, r := range recs {
				got = got || r.IdentityName == "svc-etl"
			}
			if got != tc.want {
				t.Errorf("a recommendation for svc-etl = %v, want %v (%s)", got, tc.want, tc.name)
			}
		})
	}
}
