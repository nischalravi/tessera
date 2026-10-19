package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

func evalCase(t *testing.T, w *goldenWorld, c goldenCase, r goldenReq) *authz.Decision {
	t.Helper()
	d, err := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, c.request(w, r), eval.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestTraceDeterminism: the trace is byte-identical across repeated runs and
// across shuffled snapshot insertion orders (§15 PR-5).
func TestTraceDeterminism(t *testing.T) {
	for _, c := range loadCases(t) {
		w := buildWorld(t, c, nil)
		for i, r := range c.allRequests() {
			first := mustMarshal(t, evalCase(t, w, c, r))
			if again := mustMarshal(t, evalCase(t, w, c, r)); !bytes.Equal(first, again) {
				t.Fatalf("%s request %d: two runs differ", c.ID, i)
			}
			for seed := int64(1); seed <= 4; seed++ {
				rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- test shuffling
				w2 := buildWorld(t, c, func(steps []func()) {
					rng.Shuffle(len(steps), func(a, b int) { steps[a], steps[b] = steps[b], steps[a] })
				})
				if w2.snap.ID != w.snap.ID {
					t.Fatalf("%s: snapshot id depends on insertion order", c.ID)
				}
				if got := mustMarshal(t, evalCase(t, w2, c, r)); !bytes.Equal(first, got) {
					t.Fatalf("%s request %d: shuffled insertion (seed %d) changes the trace", c.ID, i, seed)
				}
			}
		}
	}
}

func mustMarshal(t *testing.T, d *authz.Decision) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEvalDoesNotMutateSnapshot: evaluation leaves the snapshot byte-identical.
func TestEvalDoesNotMutateSnapshot(t *testing.T) {
	for _, c := range loadCases(t) {
		w := buildWorld(t, c, nil)
		before, err := snapshot.Hash(w.snap)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c.allRequests() {
			evalCase(t, w, c, r)
		}
		if after, _ := snapshot.Hash(w.snap); after != before {
			t.Fatalf("%s: Evaluate changed the snapshot", c.ID)
		}
	}
}

func TestExplanationID(t *testing.T) {
	cases := loadCases(t)
	c := cases[2] // GC-03
	w := buildWorld(t, c, nil)
	r := c.allRequests()[0]
	a, err := eval.ExplanationID(evalCase(t, w, c, r))
	if err != nil || len(a) != 64 {
		t.Fatalf("id %q, %v", a, err)
	}
	if b, _ := eval.ExplanationID(evalCase(t, w, c, r)); a != b {
		t.Fatal("explanation id is not stable")
	}
	d := evalCase(t, w, c, r)
	if s := eval.Summary(d); s == "" || eval.Narrative(d) == "" {
		t.Fatal("empty rendering")
	}
}

func goldenByID(t *testing.T, id string) goldenCase {
	for _, c := range loadCases(t) {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no case %s", id)
	return goldenCase{}
}

// A policy that fails to parse is never skipped: every decision it could
// affect is UNSUPPORTED with POLICY_UNPARSEABLE (§3.3).
func TestFailClosedOnUnparseablePolicy(t *testing.T) {
	b := snapshot.NewBuilder()
	bad := b.AddPolicy(policy.Options{Kind: model.PolicyIdentity, SourceARN: "arn:aws:iam::111111111111:policy/bad"}, []byte(`{"Statement": [`))
	if bad.Unparseable == "" {
		t.Fatal("a broken document must be flagged")
	}
	// A dropped anomaly (NotPrincipal with Allow) is flagged too.
	dropped := b.AddPolicy(policy.Options{Kind: model.PolicyResource, SourceARN: "arn:aws:s3:::tsr-bkt#policy"},
		[]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"111111111111"},"Action":"s3:*","Resource":"*"}]}`))
	if dropped.Unparseable == "" {
		t.Fatal("a dropped statement must be flagged")
	}
	b.AddPrincipal(&model.Principal{ARN: "arn:aws:iam::111111111111:user/alice", Kind: model.IAMUser, AccountID: acctA, IdentityPolicyIDs: []string{bad.ID}})
	snap, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	d, err := eval.Evaluate(context.Background(), snap, fakeCatalog{}, &eval.EvaluationRequest{
		PrincipalARN: "arn:aws:iam::111111111111:user/alice", Action: "s3:GetObject", ResourceARN: "arn:aws:s3:::tsr-bkt/a"}, eval.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Fidelity != authz.Unsupported {
		t.Fatalf("fidelity %s, want unsupported", d.Fidelity)
	}
	found := false
	for _, r := range d.FidelityReasons {
		found = found || (r.Code == authz.ReasonPolicyUnparseable && r.OutcomeSensitive)
	}
	if !found {
		t.Fatalf("no POLICY_UNPARSEABLE reason: %+v", d.FidelityReasons)
	}
}

func TestUnknownActionIsCatalogMiss(t *testing.T) {
	c := goldenByID(t, "GC-02")
	w := buildWorld(t, c, nil)
	d, err := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, &eval.EvaluationRequest{
		PrincipalARN: w.principal, Action: "nosuchservice:Do", ResourceARN: "*"}, eval.Options{})
	if err != nil || d.Fidelity != authz.Unsupported {
		t.Fatalf("%v, %v", d, err)
	}
}

func TestEvaluateErrors(t *testing.T) {
	c := goldenByID(t, "GC-02")
	w := buildWorld(t, c, nil)
	ok := &eval.EvaluationRequest{PrincipalARN: w.principal, Action: "s3:GetObject", ResourceARN: "*"}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, f := range map[string]func() error{
		"nil snapshot": func() error {
			_, e := eval.Evaluate(context.Background(), nil, fakeCatalog{}, ok, eval.Options{})
			return e
		},
		"nil catalog": func() error { _, e := eval.Evaluate(context.Background(), w.snap, nil, ok, eval.Options{}); return e },
		"no action": func() error {
			_, e := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, &eval.EvaluationRequest{PrincipalARN: w.principal}, eval.Options{})
			return e
		},
		"unknown principal": func() error {
			_, e := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, &eval.EvaluationRequest{PrincipalARN: "arn:aws:iam::111111111111:user/ghost", Action: "s3:GetObject"}, eval.Options{})
			return e
		},
		"cancelled": func() error { _, e := eval.Evaluate(cancelled, w.snap, fakeCatalog{}, ok, eval.Options{}); return e },
	} {
		if f() == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := eval.Evaluate(cancelled, w.snap, fakeCatalog{}, ok, eval.Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// A substituted variable value is literal: a tag value "*" must not widen a Resource.
func TestVariableValueIsNotAWildcard(t *testing.T) {
	c := goldenByID(t, "GC-26")
	c.PrincipalTags = map[string]string{"team": "*"}
	w := buildWorld(t, c, nil)
	for res, want := range map[string]authz.Outcome{
		"arn:aws:s3:::tsr-team-*/x":       authz.Allow,
		"arn:aws:s3:::tsr-team-company/x": authz.Deny,
	} {
		d := evalCase(t, w, c, goldenReq{Action: "s3:GetObject", Resource: res})
		if d.Outcome != want {
			t.Errorf("%s: %s, want %s", res, d.Outcome, want)
		}
	}
}

func TestFastSkipsAssessment(t *testing.T) {
	c := goldenByID(t, "GC-71")
	w := buildWorld(t, c, nil)
	d, err := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, c.request(w, c.allRequests()[0]), eval.Options{Fast: true})
	if err != nil || d.Outcome != authz.Allow || d.Fidelity != authz.Exact {
		t.Fatalf("%+v, %v", d, err)
	}
}
