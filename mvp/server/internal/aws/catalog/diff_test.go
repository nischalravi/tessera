package catalog

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden diff reports in testdata/")

// diffFixtures compiles the two offline upstream fixtures: v1 (2026-10-01,
// with iam-dataset) and v2 (2026-10-08) under the same overlays.
func diffFixtures(t *testing.T) (v1, v2 *Result) {
	t.Helper()
	return compileFixture(t, "upstream-v1", "2026-10-01", true), compileFixture(t, "upstream-v2", "2026-10-08", true)
}

func TestDiffFixtures(t *testing.T) {
	v1, v2 := diffFixtures(t)
	r := Diff(v1.Compiled, v2)
	check := func(name string, got, want []string) {
		t.Helper()
		if !equalStrings(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("ServicesAdded", r.ServicesAdded, []string{"sns"})
	check("ServicesRemoved", r.ServicesRemoved, []string{})
	check("ActionsAdded", r.ActionsAdded, []string{"s3:DeleteObject", "s3:GetObjectAttributes", "sns:Publish"})
	check("ActionsRemoved", r.ActionsRemoved, []string{"kms:Encrypt", "s3:ListAllMyBuckets", "s3:PutObjectTagging"})
	check("KeysAdded", r.KeysAdded, []string{"kms:ViaService"})
	check("KeysRemoved", r.KeysRemoved, []string{})
	if len(r.LevelChanges) != 1 || r.LevelChanges[0] != (LevelChange{"kms:CreateGrant", AccessPermissionsManagement, AccessWrite}) {
		t.Errorf("LevelChanges = %+v", r.LevelChanges)
	}
	// the live page (v2) lists sns; the overlay (kms, s3, sqs) does not
	check("RCPDrift.PageOnly", r.RCPDrift.PageOnly, []string{"sns"})
	check("RCPDrift.OverlayOnly", r.RCPDrift.OverlayOnly, []string{})
	check("RCPAdded", r.RCPAdded, []string{}) // the overlay itself did not change
	if r.From != v1.Compiled.Version || r.To != v2.Compiled.Version || !r.Changed() {
		t.Errorf("From/To: %+v", r)
	}
	if got, want := r.Title(), "catalog: 2026-10-08 (+3 actions, -3 actions, +1 RCP service)"; got != want {
		t.Errorf("Title = %q, want %q", got, want)
	}
}

func TestDiffOverlayChangeAndNoChange(t *testing.T) {
	v1, v2 := diffFixtures(t)
	// once a reviewer adds sns to the overlay, the drift is gone and the
	// overlay change shows up instead
	snap, _ := readFixture(t, "upstream-v2", "2026-10-08", true)
	res, err := Compile(snap, testOverlays(t, "kms", "s3", "sqs", "sns"))
	if err != nil {
		t.Fatal(err)
	}
	r := Diff(v1.Compiled, res)
	if len(r.RCPDrift.PageOnly) != 0 || !equalStrings(r.RCPAdded, []string{"sns"}) {
		t.Errorf("drift %+v added %v", r.RCPDrift, r.RCPAdded)
	}
	if !strings.HasSuffix(r.Title(), "+1 RCP service)") {
		t.Errorf("Title = %q", r.Title())
	}

	// identical inputs: no changes
	same := Diff(v1.Compiled, v1)
	if same.Changed() || same.Title() != "catalog: 2026-10-01 (no changes)" {
		t.Errorf("same catalog: %q %+v", same.Title(), same)
	}
	if !strings.Contains(same.Markdown(), "No changes.") {
		t.Error("Markdown of an empty diff")
	}

	// no earlier catalog: everything is added
	first := Diff(nil, v2)
	if first.From != "" || len(first.ActionsAdded) != v2.Compiled.numActions() || len(first.ServicesAdded) != 4 {
		t.Errorf("first catalog: %+v", first)
	}

	// an RCP service the page dropped
	snap2, _ := readFixture(t, "upstream-v1", "2026-10-01", true)
	res2, err := Compile(snap2, testOverlays(t, "kms", "s3", "sqs", "dsql"))
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(v1.Compiled, res2); !equalStrings(d.RCPDrift.OverlayOnly, []string{"dsql"}) || !strings.Contains(d.Title(), "-1 RCP service)") {
		t.Errorf("overlay-only drift: %q %+v", d.Title(), d.RCPDrift)
	}
}

func (c *Compiled) numActions() int {
	n := 0
	for _, s := range c.Services {
		n += len(s.Actions)
	}
	return n
}

func TestDiffTitlePlurals(t *testing.T) {
	r := &DiffReport{Snapshot: "2026-10-09", ActionsAdded: []string{"a:B"}, RCPDrift: RCPDrift{PageOnly: []string{"x", "y"}}}
	if got, want := r.Title(), "catalog: 2026-10-09 (+1 action, +2 RCP services)"; got != want {
		t.Errorf("Title = %q, want %q", got, want)
	}
	r = &DiffReport{Snapshot: "2026-10-09", KeysAdded: []string{"k"}}
	if got, want := r.Title(), "catalog: 2026-10-09 (other changes)"; got != want {
		t.Errorf("Title = %q, want %q", got, want)
	}
}

func TestDiffMarkdownGolden(t *testing.T) {
	v1, v2 := diffFixtures(t)
	// versions hash the real overlays, which change on their own schedule
	norm := strings.NewReplacer(v1.Compiled.Version, "<v1>", v2.Compiled.Version, "<v2>").Replace
	cases := map[string]string{
		"testdata/diff-v1-v2.golden.md":   norm(Diff(v1.Compiled, v2).Markdown()),
		"testdata/diff-initial.golden.md": norm(Diff(nil, v1).Markdown()),
	}
	for path, got := range cases {
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path) // #nosec G304 -- test fixture
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs (run `go test ./internal/aws/catalog -run TestDiffMarkdownGolden -update`):\n%s", path, got)
		}
	}
}

func TestDiffMarkdownSanitizesAndCaps(t *testing.T) {
	r := &DiffReport{Snapshot: "2026-10-09", To: "v", ActionsAdded: []string{"evil:`x`\n# Heading"}}
	for i := 0; i < maxListed+5; i++ {
		r.ServicesAdded = append(r.ServicesAdded, "svc")
	}
	md := r.Markdown()
	if strings.Contains(md, "\n# Heading") || strings.Contains(md, "`x`") {
		t.Errorf("upstream text escaped its code span:\n%s", md)
	}
	if !strings.Contains(md, "... and 5 more") {
		t.Error("long lists must be capped")
	}
}
