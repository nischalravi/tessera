package leastpriv_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	awsq "github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
)

func TestRightSizeDocument(t *testing.T) {
	const deny = `{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}`
	cur := func(stmts string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[` + stmts + `]}`)
	}
	keep := []leastpriv.UsedCall{
		{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/x"},
		{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/y"},
		{Action: "s3:PutObject", Resource: "arn:aws:s3:::b/y"},
	}
	for _, tc := range []struct {
		name    string
		current []byte
		keep    []leastpriv.UsedCall
		want    string // exact document, "" when refused
		refuse  string
	}{
		{"allow replaced by the used calls, deny kept verbatim",
			cur(`{"Effect":"Allow","Action":"s3:*","Resource":"*"},` + deny), keep,
			`{"Statement":[` + deny + `,{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/x"]},` +
				`{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::b/y"]}],"Version":"2012-10-17"}`, ""},
		{"a single statement object", []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`), keep[:1],
			`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/x"]}],"Version":"2012-10-17"}`, ""},
		{"nothing used", cur(`{"Effect":"Allow","Action":"*","Resource":"*"}`), nil, "", "detach"},
		{"old language version", []byte(`{"Version":"2008-10-17","Statement":[]}`), keep, "", "2012-10-17"},
		{"not JSON", []byte(`{`), keep, "", "does not parse"},
		{"no statements", []byte(`{"Version":"2012-10-17"}`), keep, "", "readable statements"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := leastpriv.RightSizeDocument(tc.current, tc.keep)
			if tc.refuse != "" {
				if !errors.Is(err, leastpriv.ErrRightSize) || !strings.Contains(err.Error(), tc.refuse) {
					t.Fatalf("err = %v, want a refusal mentioning %q", err, tc.refuse)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid([]byte(got)) || got != tc.want {
				t.Errorf("document = %s\nwant       %s", got, tc.want)
			}
		})
	}

	// over IAM's size limit: refused, not truncated
	var many []leastpriv.UsedCall
	for i := 0; i < 400; i++ {
		many = append(many, leastpriv.UsedCall{Action: "s3:GetObject", Resource: "arn:aws:s3:::bucket/prefix/" + strings.Repeat("k", 10) + string(rune('a'+i%26)) + strings.Repeat("z", i)})
	}
	if _, err := leastpriv.RightSizeDocument(cur(`{"Effect":"Allow","Action":"*","Resource":"*"}`), many); !errors.Is(err, leastpriv.ErrRightSize) ||
		!strings.Contains(err.Error(), "limit") {
		t.Errorf("oversized: %v", err)
	}
}

// Only EXACT results verify (design §4 rule 4): a used call that is allowed but
// not EXACT after the change, a broken call, an addition and a no-op are refused;
// a removal that rests on an inexact basis is advice.
func TestJudge(t *testing.T) {
	call := leastpriv.UsedCall{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/x"}
	for _, tc := range []struct {
		name string
		v    leastpriv.Verification
		want string
	}{
		{"exact and narrower", leastpriv.Verification{OK: true, AutoApplicable: true, Removed: 3}, leastpriv.VerdictVerified},
		{"a used call is approximate after the change", leastpriv.Verification{OK: true, Removed: 3, Inexact: []leastpriv.UsedCall{call}}, leastpriv.VerdictRefused},
		{"a used call breaks", leastpriv.Verification{Removed: 3, Broken: []leastpriv.BrokenCall{{UsedCall: call, Outcome: "deny"}}, Reasons: []string{"1 used call(s) would no longer be allowed"}}, leastpriv.VerdictRefused},
		{"it adds", leastpriv.Verification{Removed: 3, Added: 1, Reasons: []string{"the change gives 1 permission(s)"}}, leastpriv.VerdictRefused},
		{"it removes nothing", leastpriv.Verification{OK: true, AutoApplicable: true}, leastpriv.VerdictRefused},
		{"a removal is inexact", leastpriv.Verification{OK: true, Removed: 3}, leastpriv.VerdictReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reasons := leastpriv.Judge(&tc.v)
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
			if got == leastpriv.VerdictRefused && len(reasons) == 0 {
				t.Error("a refusal carries no reason")
			}
		})
	}
}

// End to end against the evaluator: the right-sized S3Read keeps what alice
// used and drops the rest; one that is widened is refused by VerifyAWS.
func TestRightSizeAgainstTheEvaluator(t *testing.T) {
	base, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	// two objects in the universe, so that keeping one of them removes the other
	mk := func(snap *model.Snapshot) *awsq.Querier {
		ix, err := index.Build(snap, index.Config{Catalog: awstest.Catalog{}, Actions: awstest.Actions(),
			Resources: []string{"arn:aws:s3:::prod-pii/x", "arn:aws:s3:::prod-pii/y"}, Applies: awstest.SameServiceRule})
		if err != nil {
			t.Fatal(err)
		}
		q, err := awsq.New(ix, nil, awsq.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(awstest.EstateTime), Workers: 2})
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	bq := mk(base)
	var cur *model.PolicyDoc
	for _, d := range base.Policies {
		if d.SourceARN == awstest.EstateS3Read {
			cur = d
		}
	}
	used := []leastpriv.UsedCall{{Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-pii/x"}}
	doc, err := leastpriv.RightSizeDocument(cur.RawJSON, used)
	if err != nil {
		t.Fatal(err)
	}
	head, err := snapshot.Apply(base, []snapshot.PolicyChange{{Op: snapshot.OpPutPolicyVersion, TargetARN: awstest.EstateS3Read, Document: &doc}},
		snapshot.ApplyOptions{FetchedAt: awstest.EstateTime})
	if err != nil {
		t.Fatal(err)
	}
	v, err := leastpriv.VerifyAWS(context.Background(), bq, mk(head), awstest.EstateAlice, used)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, why := leastpriv.Judge(v); verdict != leastpriv.VerdictVerified || len(v.Kept) != 1 || len(v.Inexact) != 0 || v.Removed == 0 {
		t.Errorf("verdict %s (%v), verification %+v", verdict, why, v)
	}
}

func TestLowestConfidence(t *testing.T) {
	got := leastpriv.LowestConfidence([]leastpriv.Confidence{
		{Level: leastpriv.ConfHigh, Reasons: []string{"a"}},
		{Level: leastpriv.ConfMedium, Reasons: []string{"m", "m"}},
		{Level: leastpriv.ConfLow, Reasons: []string{"l"}},
	})
	if got.Level != leastpriv.ConfLow || len(got.Reasons) != 1 || got.Reasons[0] != "l" {
		t.Errorf("lowest = %+v", got)
	}
	if got := leastpriv.LowestConfidence(nil); got.Level != leastpriv.ConfUnknown {
		t.Errorf("empty = %+v", got)
	}
}
