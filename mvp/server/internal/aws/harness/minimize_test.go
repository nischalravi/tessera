package harness

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDDMin(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		need []int // the units whose presence the "bug" requires
	}{
		{"none needed", 8, nil},
		{"one", 16, []int{11}},
		{"two apart", 20, []int{3, 17}},
		{"three", 33, []int{0, 16, 32}},
		{"all", 5, []int{0, 1, 2, 3, 4}},
		{"single unit", 1, []int{0}},
		{"empty", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := DDMin(tc.n, func(keep []int) (bool, error) {
				calls++
				have := map[int]bool{}
				for _, k := range keep {
					have[k] = true
				}
				for _, n := range tc.need {
					if !have[n] {
						return false, nil
					}
				}
				return true, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			sort.Ints(got)
			if !(len(got) == 0 && len(tc.need) == 0) && !reflect.DeepEqual(got, tc.need) {
				t.Fatalf("kept %v, want exactly %v (%d calls)", got, tc.need, calls)
			}
			if tc.n > 1 && calls > 4*tc.n*tc.n {
				t.Fatalf("%d calls for n=%d", calls, tc.n)
			}
		})
	}
	// An error from the test aborts.
	boom := errors.New("boom")
	if _, err := DDMin(4, func([]int) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
}

const (
	polA = `{"Version":"2012-10-17","Statement":[
	  {"Sid":"a","Effect":"Allow","Action":["ec2:*","sqs:*"],"Resource":"*"},
	  {"Sid":"b","Effect":"Allow","Action":["iam:List*","s3:GetObject","kms:Decrypt"],"Resource":["arn:aws:s3:::other/*","arn:aws:s3:::tsr-bkt/*"],
	   "Condition":{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*","aws:username":"*"},"Bool":{"aws:SecureTransport":"true"}}},
	  {"Sid":"c","Effect":"Allow","Action":"sns:*","Resource":"*"}]}`
	polB = `{"Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":"*"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`
)

// allowsGet is the "divergence": the engine allows while the (imagined) oracle
// denies. It runs the real engine, so the reduction is checked against it.
func allowsGet(ctx context.Context, s *RequestSpec) (*Check, error) {
	d, _, err := Decide(ctx, OfflineCatalog{}, s)
	if err != nil {
		return nil, err
	}
	c := &Check{Verdict: Agree}
	if OursDecision(d) == "allowed" {
		c.Verdict = Disagree
	}
	return c, nil
}

func TestMinimizeConverges(t *testing.T) {
	s := baseSpec("min")
	s.Identity = []string{polB, polA, polB}
	s.Boundary = []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}
	s.SCPLevels = [][]string{{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}, {`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}}
	s.Context = map[string]ContextEntry{"aws:username": {Values: []string{"alice"}}, "aws:SecureTransport": {Values: []string{"true"}}, "x:y": {Values: []string{"z"}}}

	got, st, err := Minimize(context.Background(), s, DivergencePredicate(allowsGet), MinimizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The engine still allows, and nothing that can go is left: one boundary-free,
	// SCP-free policy with one statement, one action, one resource, no conditions.
	// (The SCP levels and boundary cannot be dropped to nothing only if the
	// predicate needed them; it does not.)
	if len(got.Identity) != 1 || len(got.Boundary) != 0 || len(got.SCPLevels) != 0 || len(got.Context) != 0 {
		t.Fatalf("not reduced: %+v", got)
	}
	var doc struct {
		Statement []struct {
			Action    any
			Resource  any
			Condition any
		}
	}
	if err := json.Unmarshal([]byte(got.Identity[0]), &doc); err != nil {
		t.Fatalf("minimized policy is not JSON: %v\n%s", err, got.Identity[0])
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Condition != nil {
		t.Fatalf("statements/conditions left: %s", got.Identity[0])
	}
	if !strings.Contains(got.Identity[0], "s3:GetObject") || strings.Contains(got.Identity[0], "kms:Decrypt") || strings.Contains(got.Identity[0], "other/*") {
		t.Fatalf("values left: %s", got.Identity[0])
	}
	if st.After.Statements != 1 || st.After.Values > 3 || st.Before.Statements <= st.After.Statements || st.Calls == 0 {
		t.Fatalf("stats %+v", st)
	}
	// 1-minimality: the predicate still holds, and fails when anything more goes.
	if ok, _ := DivergencePredicate(allowsGet)(context.Background(), got); !ok {
		t.Fatal("the minimized spec no longer diverges")
	}
	if again, _, err := Minimize(context.Background(), got, DivergencePredicate(allowsGet), MinimizeOptions{}); err != nil || again.Hash() != got.Hash() {
		t.Fatalf("not a fixed point: %v", err)
	}
	// The original is untouched.
	if len(s.Identity) != 3 || len(s.Context) != 3 {
		t.Fatal("Minimize mutated its input")
	}
}

func TestMinimizeKeepsWhatTheDivergenceNeeds(t *testing.T) {
	s := baseSpec("needs")
	s.Identity = []string{polA}
	s.Context = map[string]ContextEntry{"k1": {Values: []string{"v"}}, "k2": {Values: []string{"v"}}}
	// Reproduces only while the condition block on aws:SecureTransport and context key k2 survive.
	pred := func(_ context.Context, c *RequestSpec) (bool, error) {
		_, hasK2 := c.Context["k2"]
		return hasK2 && strings.Contains(strings.Join(c.Identity, ""), "aws:SecureTransport"), nil
	}
	got, _, err := Minimize(context.Background(), s, pred, MinimizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Context["k1"]; ok || len(got.Context) != 1 {
		t.Fatalf("context %v", got.Context)
	}
	if strings.Contains(got.Identity[0], "aws:username") || !strings.Contains(got.Identity[0], `"Bool":{"aws:SecureTransport":"true"}`) || strings.Contains(got.Identity[0], "StringLike") {
		t.Fatalf("condition reduction: %s", got.Identity[0])
	}
}

func TestMinimizeErrors(t *testing.T) {
	s := baseSpec("err")
	never := func(context.Context, *RequestSpec) (bool, error) { return false, nil }
	if _, _, err := Minimize(context.Background(), s, never, MinimizeOptions{}); !errors.Is(err, ErrNotReproducible) {
		t.Fatalf("err %v", err)
	}
	// A reduction the parser refuses is "does not reproduce", not an error.
	refusing := func(_ context.Context, c *RequestSpec) (bool, error) {
		if err := c.CheckIngest(); err != nil {
			return false, err
		}
		return true, nil
	}
	s.Identity = []string{polA}
	if _, _, err := Minimize(context.Background(), s, refusing, MinimizeOptions{}); err != nil {
		t.Fatalf("a refusal aborted the minimizer: %v", err)
	}
	// Other errors abort; the budget returns the best spec so far.
	boom := errors.New("boom")
	if _, _, err := Minimize(context.Background(), s, func(context.Context, *RequestSpec) (bool, error) { return false, boom }, MinimizeOptions{}); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	needsDecrypt := func(_ context.Context, c *RequestSpec) (bool, error) {
		return strings.Contains(strings.Join(c.Identity, ""), "kms:Decrypt"), nil
	}
	best, st, err := Minimize(context.Background(), s, needsDecrypt, MinimizeOptions{MaxCalls: 5})
	if !errors.Is(err, ErrBudget) || best == nil || st.Calls != 5 {
		t.Fatalf("budget: %v %v %+v", err, best, st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Minimize(ctx, s, never, MinimizeOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
