package ghapp_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/blast"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
)

func fixtureRightSize() ghapp.RightSize {
	r := &blast.Report{Summary: blast.Summary{IdentitiesLosing: 1, GraphPermissionsLost: 2}}
	return ghapp.RightSize{RecID: "grant-17", Kind: "remove", IdentityName: "Esme Thornbury", IdentityType: "human",
		Grant: "workday:emp-1057 → workday:Payroll Administrator", Group: "workday:Payroll Administrator", RoleKey: "payroll-ops",
		RoleFile: "roles/payroll-ops.yaml", RoleMembers: 1, Permissions: []string{"payroll:approve_run", "payroll:view_salaries"},
		PermissionsLost: 2, UnusedLost: 2, UsedLost: 0, UnusedDays: 60, Fidelity: "exact", ExplanationID: "ex-9",
		Preview: ghapp.Preview{Report: r, BundleSHA256: strings.Repeat("ab", 32), DiffSHA256: strings.Repeat("cd", 32)}}
}

// The pull request body of a fixture recommendation is pinned byte for byte (UPDATE_GOLDEN=1 rewrites it).
func TestRightSizeBodyGolden(t *testing.T) {
	got := ghapp.RightSizeBody(fixtureRightSize())
	const golden = "testdata/rightsize_pr_body.golden.md"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("body differs from %s:\n%s", golden, got)
	}
	if again := ghapp.RightSizeBody(fixtureRightSize()); again != got {
		t.Error("the body is not deterministic")
	}
	if !strings.HasPrefix(got, ghapp.LPMarker+"grant-17 -->\n") {
		t.Errorf("body does not open with the marker: %.80s", got)
	}
}

// Names from the estate are data: they cannot add markup, a line, a mention or a link to the body, the title or the commit.
func TestRightSizeEscapesUntrustedText(t *testing.T) {
	evil := "x`**bold**`\n# injected heading @octocat <img src=x onerror=alert(1)> [click](http://evil.example) | col |"
	rs := fixtureRightSize()
	rs.IdentityName, rs.Grant, rs.Group, rs.RoleKey, rs.RoleFile = evil, evil, evil, evil, evil
	rs.Permissions = []string{evil, "ok:action"}
	rs.LastUsed, rs.ExplanationID = evil, evil
	clean := ghapp.RightSizeBody(fixtureRightSize())

	body := ghapp.RightSizeBody(rs)
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "# injected") || strings.Contains(line, "\n") {
			t.Errorf("an injected line: %q", line)
		}
	}
	// every occurrence of the hostile text is inside a code span: strip the spans and nothing active is left
	var outside strings.Builder
	in := false
	for _, r := range body {
		if r == '`' {
			in = !in
			continue
		}
		if !in {
			outside.WriteRune(r)
		}
	}
	for _, bad := range []string{"@octocat", "<img", "[click]", "injected", "evil.example", "**bold**"} {
		if strings.Contains(outside.String(), bad) {
			t.Errorf("%q is outside a code span:\n%s", bad, body)
		}
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "|") && strings.Count(line, "|") != 3 {
			t.Errorf("a table row has more cells than the table: %q", line)
		}
	}
	if strings.Count(body, "\n") != strings.Count(clean, "\n") {
		t.Errorf("the body has %d lines, the clean one %d: a line was injected", strings.Count(body, "\n"), strings.Count(clean, "\n"))
	}
	for name, s := range map[string]string{"title": ghapp.RightSizeTitle(rs), "commit": ghapp.RightSizeCommitMessage(rs)} {
		if strings.Contains(s, "@") {
			t.Errorf("%s keeps a mention: %q", name, s)
		}
	}
	if strings.Contains(ghapp.RightSizeTitle(rs), "\n") {
		t.Errorf("the title has a line break: %q", ghapp.RightSizeTitle(rs))
	}
}

func TestRightSizeBodyListsAreCapped(t *testing.T) {
	rs := fixtureRightSize()
	for i := 0; i < 40; i++ {
		rs.Permissions = append(rs.Permissions, "svc:action"+strings.Repeat("x", i))
	}
	body := ghapp.RightSizeBody(rs)
	if !strings.Contains(body, "... and 32 more") || len(body) > ghapp.MaxCommentBytes {
		t.Errorf("body not capped (%d bytes)", len(body))
	}
	rs.UsedLost = 1
	if !strings.Contains(ghapp.RightSizeBody(rs), "Some of what this removes was used") {
		t.Error("used permissions are not called out")
	}
}
