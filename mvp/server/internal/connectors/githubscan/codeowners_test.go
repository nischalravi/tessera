package githubscan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

func TestCodeownersMatching(t *testing.T) {
	co := ParseCodeowners(`
# comment
*                @acme/engineering
*.md             @docs
/.mcp.json       @acme/ai-platform ada@example.com
/.cursor/        @acme/ai-platform
apps/**/mcp.json @apps-team
/legacy/
docs/            @docs-team
`)
	cases := []struct {
		path string
		want []string
	}{
		{"main.go", []string{"@acme/engineering"}},
		{"README.md", []string{"@docs"}},
		{"deep/dir/NOTES.md", []string{"@docs"}},
		{".mcp.json", []string{"@acme/ai-platform", "ada@example.com"}},
		{"sub/.mcp.json", []string{"@acme/engineering"}}, // anchored: only the root file
		{".cursor/mcp.json", []string{"@acme/ai-platform"}},
		{"apps/web/mcp.json", []string{"@apps-team"}},
		{"apps/a/b/mcp.json", []string{"@apps-team"}},
		{"apps/mcp.json", []string{"@apps-team"}},
		{"legacy/old.go", nil},                          // a rule with no owner leaves the path unowned
		{"docs/guide/index.md", []string{"@docs-team"}}, // the later rule wins
	}
	for _, c := range cases {
		if got := co.OwnersOf(c.path); !slices.Equal(got, c.want) {
			t.Errorf("OwnersOf(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	var none *Codeowners
	if none.OwnersOf("x") != nil {
		t.Error("a missing CODEOWNERS owns something")
	}
}

func TestCodeownersFixtureFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "CODEOWNERS"))
	if err != nil {
		t.Fatal(err)
	}
	co := ParseCodeowners(string(b))
	if got := co.OwnersOf(".mcp.json"); len(got) != 2 || got[1] != "ada.fixture@example.com" {
		t.Errorf("owners of .mcp.json = %v (the trailing comment must be dropped)", got)
	}
}

func TestLinkOwner(t *testing.T) {
	type want struct {
		ref, how string
		id       *connectors.IdentityRef
	}
	cases := []struct {
		name   string
		owners []string
		commit *Commit
		want   want
	}{
		{"a person's e-mail beats a team", []string{"@acme/ai-platform", "ada@example.com"}, nil,
			want{"ada@example.com", "codeowners", &connectors.IdentityRef{Email: "ada@example.com"}}},
		{"a team is the owner of record but not a person", []string{"@acme/ai-platform"}, &Commit{Login: "devon"},
			want{"github-team:acme/ai-platform", "codeowners", nil}},
		{"a user", []string{"@ada"}, nil, want{"github:ada", "codeowners", &connectors.IdentityRef{ExternalID: "github:ada"}}},
		{"committer with a real e-mail", nil, &Commit{Login: "devon", Email: "devon@example.com"},
			want{"devon@example.com", "committer", &connectors.IdentityRef{ExternalID: "github:devon", Email: "devon@example.com"}}},
		{"committer behind a noreply address", nil, &Commit{Email: "12345+devon@users.noreply.github.com"},
			want{"github:devon", "committer", &connectors.IdentityRef{ExternalID: "github:devon"}}},
		{"no codeowners, no commit", nil, nil, want{"", "none", nil}},
	}
	for _, c := range cases {
		ref, how, id := linkOwner(c.owners, c.commit)
		if ref != c.want.ref || how != c.want.how || (id == nil) != (c.want.id == nil) || (id != nil && *id != *c.want.id) {
			t.Errorf("%s: got (%q, %q, %v), want %+v", c.name, ref, how, id, c.want)
		}
	}
}
