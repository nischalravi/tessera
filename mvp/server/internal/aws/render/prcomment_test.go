package render_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/render"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

const (
	object = "arn:aws:s3:::prod-pii/customers.csv"
	v2012  = `"Version":"2012-10-17"`
)

func sp(s string) *string { return &s }

type side struct {
	snap *model.Snapshot
	q    *query.Querier
}

func querier(t *testing.T, snap *model.Snapshot, memo *index.Memo) side {
	t.Helper()
	ix, err := index.Build(snap, index.Config{Catalog: awstest.Catalog{}, Actions: awstest.Actions(),
		Resources: []string{object}, Applies: awstest.SameServiceRule})
	if err != nil {
		t.Fatal(err)
	}
	q, err := query.New(ix, memo, query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(awstest.EstateTime), Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	return side{snap, q}
}

// cellKey is one (principal, action, resource) triple.
type cellKey struct{ p, a, r string }

// diffCells expands a diff to its triples, by kind.
func diffCells(res *query.DiffResult) map[cellKey]query.ChangeKind {
	out := map[cellKey]query.ChangeKind{}
	for _, c := range res.Changes {
		for _, p := range c.Principals {
			for _, a := range c.Actions {
				for _, r := range c.Resources {
					out[cellKey{p, a, r}] = c.Kind
				}
			}
		}
	}
	return out
}

// bruteForce asks the engine every triple of the universe on both sides, with
// no index and no pruning: the answer the diff must equal (exit criterion 2).
func bruteForce(t *testing.T, base, head side) map[cellKey]query.ChangeKind {
	t.Helper()
	ctx := context.Background()
	principals := map[string]bool{}
	for a := range base.snap.Principals {
		principals[a] = true
	}
	for a := range head.snap.Principals {
		principals[a] = true
	}
	resources := map[string]bool{object: true}
	for _, s := range []*model.Snapshot{base.snap, head.snap} {
		for a := range s.Resources {
			resources[a] = true
		}
	}
	out := map[cellKey]query.ChangeKind{}
	for p := range principals {
		for _, a := range awstest.Actions() {
			for r := range resources {
				if parts := strings.SplitN(r, ":", 4); len(parts) == 4 {
					prefix, _, _ := strings.Cut(strings.ToLower(a), ":")
					if !awstest.SameServiceRule(prefix, parts[2]) {
						continue
					}
				}
				bd, err := base.q.Can(ctx, p, a, r)
				if err != nil {
					continue // a principal that is on one side only
				}
				hd, err := head.q.Can(ctx, p, a, r)
				if err != nil {
					continue
				}
				if kind, ok := query.Classify(index.NewCell(bd), index.NewCell(hd)); ok {
					out[cellKey{p, a, r}] = kind
				}
			}
		}
	}
	return out
}

func prChange(t *testing.T, base *model.Snapshot, cs ...snapshot.PolicyChange) side {
	t.Helper()
	head, err := snapshot.Apply(base, cs, snapshot.ApplyOptions{FetchedAt: awstest.EstateTime})
	if err != nil {
		t.Fatal(err)
	}
	return querier(t, head, nil)
}

// Exit criterion 2 (design §2): a policy pull request shows exactly who gains or
// loses which permission, with the traces that say why. "Exactly" is checked
// against the engine asked about every principal, action and resource.
func TestPolicyPRShowsExactlyWhoGainsAndLoses(t *testing.T) {
	baseSnap, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	memo := index.NewMemo(1 << 16)
	base := querier(t, baseSnap, memo)

	widen := `{` + v2012 + `,"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::prod-pii/*"}]}`
	bucketPolicy := `{` + v2012 + `,"Statement":[{"Effect":"Allow","Principal":{"AWS":"` + awstest.EstateBob + `"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-pii/*"}]}`
	denyS3 := `{` + v2012 + `,"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`
	ch := func(op snapshot.PolicyChangeOp, target string, doc *string) snapshot.PolicyChange {
		return snapshot.PolicyChange{Op: op, TargetARN: target, Document: doc}
	}

	for _, tc := range []struct {
		name    string
		changes []snapshot.PolicyChange
		gained  []cellKey // cells that must be gained
		lost    []cellKey
		silent  []string // principals the PR must not touch
	}{
		{
			name:    "widening a managed policy",
			changes: []snapshot.PolicyChange{ch(snapshot.OpPutPolicyVersion, awstest.EstateS3Read, &widen)},
			gained:  []cellKey{{awstest.EstateAlice, "s3:PutObject", object}, {awstest.EstateAlice, "s3:DeleteObject", object}},
			silent:  []string{awstest.EstateBob, awstest.EstateDevUser, awstest.EstateEngineer},
		},
		{
			name:    "a bucket policy for bob",
			changes: []snapshot.PolicyChange{ch(snapshot.OpPutResourcePolicy, awstest.EstateBucket, &bucketPolicy)},
			gained:  []cellKey{{awstest.EstateBob, "s3:GetObject", object}},
			silent:  []string{awstest.EstateAlice, awstest.EstateDevUser, awstest.EstateEngineer},
		},
		{
			name:    "an SCP that denies s3:GetObject",
			changes: []snapshot.PolicyChange{ch(snapshot.OpPutSCP, awstest.EstateFullSCP, &denyS3)},
			lost:    []cellKey{{awstest.EstateAlice, "s3:GetObject", object}},
			silent:  []string{awstest.EstateBob, awstest.EstateDevUser},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			head := prChange(t, baseSnap, tc.changes...)
			res, err := query.Diff(context.Background(), base.q, head.q, query.DiffOptions{MaxExpand: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			got, want := diffCells(res), bruteForce(t, base, head)
			if len(want) == 0 {
				t.Fatal("the pull request changes nothing; the test proves nothing")
			}
			for k, kind := range want {
				if got[k] != kind {
					t.Errorf("%v: diff says %v, the engine says %v", k, got[k], kind)
				}
			}
			for k, kind := range got {
				if _, ok := want[k]; !ok {
					t.Errorf("%v: the diff reports %v, the engine reports no change", k, kind)
				}
			}
			for _, k := range tc.gained {
				if got[k] != query.Gained {
					t.Errorf("%v is %v, want gained", k, got[k])
				}
			}
			for _, k := range tc.lost {
				if got[k] != query.Lost {
					t.Errorf("%v is %v, want lost", k, got[k])
				}
			}
			for k := range got {
				for _, s := range tc.silent {
					if k.p == s {
						t.Errorf("%s is touched by the pull request: %v", s, k)
					}
				}
			}

			// every change has a trace on the right side, and the decisive statement is the one the PR edited
			ctx := context.Background()
			for _, c := range res.Changes {
				if c.Kind != query.Gained && c.Kind != query.Lost {
					continue
				}
				q := head.q
				if c.Kind == query.Lost {
					q = base.q
				}
				d, err := q.Can(ctx, c.Principals[0], c.Actions[0], c.Resources[0])
				if err != nil {
					t.Fatal(err)
				}
				if d.Outcome != authz.Allow || d.Fidelity != authz.Exact || len(d.Decisive) == 0 || len(d.Steps) == 0 {
					t.Errorf("trace of %v = %s fidelity %s, %d decisive, %d steps", c, d.Outcome, d.Fidelity, len(d.Decisive), len(d.Steps))
				}
				if d.SnapshotID != q.Idx.Snap.ID {
					t.Errorf("the trace names snapshot %s, not %s", d.SnapshotID, q.Idx.Snap.ID)
				}
			}

			// the comment says the same, deterministically
			meta := render.Meta{BaseSnapshot: baseSnap.ID, Head: "PR head", CatalogVersion: awstest.Catalog{}.Version(), EngineVersion: eval.EngineVersion}
			opt := render.Options{Why: render.Explainer(ctx, base.q, head.q), MaxPrincipals: 3,
				UsedDays: func(p, a string) *int { d := 3; return &d }}
			text := render.Text(res, meta, opt)
			if again := render.Text(res, meta, opt); again != text {
				t.Error("the comment is not deterministic")
			}
			for _, k := range tc.gained {
				if !strings.Contains(text, "GAIN") || !strings.Contains(text, strings.TrimPrefix(k.p, "arn:aws:iam::111111111111:")) {
					t.Errorf("the comment does not name %v:\n%s", k, text)
				}
			}
			if len(tc.lost) > 0 && (!strings.Contains(text, "LOSE") || !strings.Contains(text, "used 3 days ago")) {
				t.Errorf("the comment does not show the loss and its use:\n%s", text)
			}
			if !strings.Contains(text, "[EXACT]") || !strings.Contains(text, "after: ") && !strings.Contains(text, "before: ") {
				t.Errorf("the comment has no fidelity or trace line:\n%s", text)
			}
		})
	}
}

func TestPolicyPRThatChangesNothingSaysSo(t *testing.T) {
	baseSnap, _ := awstest.Estate()
	base := querier(t, baseSnap, nil)
	head := prChange(t, baseSnap)
	res, err := query.Diff(context.Background(), base.q, head.q, query.DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	text := render.Text(res, render.Meta{BaseSnapshot: baseSnap.ID, Head: "PR head"}, render.Options{})
	if !strings.Contains(text, "no change in who can do what") || len(res.Changes) != 0 {
		t.Errorf("text = %q, %d changes", text, len(res.Changes))
	}
}

func TestMarkdownIsSafeAndBounded(t *testing.T) {
	hostile := "arn:aws:s3:::bucket`\n@everyone ```\n[x](http://evil)/*"
	res := &query.DiffResult{}
	for i := 0; i < 400; i++ {
		res.Changes = append(res.Changes, query.Change{Principals: []string{"arn:aws:iam::111111111111:role/r" + strings.Repeat("x", i%50)},
			Actions: []string{"s3:GetObject"}, Resources: []string{hostile}, ActionCount: 1, ResourceCount: 1,
			After: &index.Cell{Outcome: authz.Allow, Fidelity: authz.Exact}, Kind: query.Gained})
	}
	md := render.Markdown(res, render.Meta{BaseSnapshot: "abcdef0123456789"}, render.Options{MaxBytes: 5000})
	if !strings.HasPrefix(md, render.Marker+"\n```text\n") || !strings.HasSuffix(md, "```\n") {
		t.Fatalf("not a fenced block: %q ... %q", md[:40], md[len(md)-10:])
	}
	// the only fences are the opening and the closing one: nothing a name holds ends the block
	if n := strings.Count(md, "```"); n != 2 {
		t.Errorf("%d code fences, want 2", n)
	}
	if strings.Contains(md, "`\n@") || len(md) > 5000 {
		t.Errorf("hostile name not neutralised or comment not bounded (%d bytes)", len(md))
	}
	if !strings.Contains(md, "more change(s) not shown") {
		t.Error("a truncated comment does not say so")
	}
}

func TestFidelityAndConditionalLines(t *testing.T) {
	res := &query.DiffResult{Changes: []query.Change{
		{Principals: []string{"arn:aws:iam::1:role/a", "arn:aws:iam::1:role/b"}, Actions: []string{"sqs:SendMessage"}, Resources: []string{"arn:aws:sqs:us-east-1:1:q"},
			ActionCount: 1, ResourceCount: 1, Kind: query.ConditionalChanged,
			Before: nil, After: &index.Cell{Outcome: authz.Conditional, Fidelity: authz.Exact, ResidualText: `aws:SourceVpce = "vpce-0abc"`}},
		{Principals: []string{"arn:aws:iam::1:user/u"}, Actions: []string{"iam:PassRole"}, Resources: []string{"*"}, ActionCount: 1, ResourceCount: 1,
			Kind: query.FidelityChanged, After: &index.Cell{Outcome: authz.Allow, Fidelity: authz.Approximate, Reasons: "AMBIGUITY:A3!"}},
	}}
	text := render.Text(res, render.Meta{BaseSnapshot: "7f3a", Head: "PR head", CatalogVersion: "2026-10-08", EngineVersion: "1.0.0"}, render.Options{})
	for _, want := range []string{
		"Tessera access diff — snapshot 7f3a → PR head (catalog 2026-10-08, engine 1.0.0)",
		`~ 2 principals become CONDITIONAL (aws:SourceVpce = "vpce-0abc") on sqs:SendMessage on arn:aws:sqs:us-east-1:1:q`,
		"role/a (1)",
		"! 1 principal: result is APPROXIMATE (AMBIGUITY:A3) on iam:PassRole on *",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}
