package ghapp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
)

func TestValidBranchAndPath(t *testing.T) {
	for s, want := range map[string]bool{
		"tessera/rightsize-grant-17": true, "main": true, "a.b/c-d_e": true,
		"": false, "/x": false, "x/": false, "a//b": false, "a/../b": false, "..": false, ".hidden": false, "a/.b": false, "x.lock": false,
		"a b": false, "a\nb": false, "a~b": false, "a^b": false, "a:b": false, "a?b": false, "-x": false, strings.Repeat("a", 201): false,
	} {
		if got := ghapp.ValidBranch(s); got != want {
			t.Errorf("ValidBranch(%q) = %v, want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{
		"roles/payroll-ops.yaml": true, "a.yaml": true, "": false, "/etc/passwd": false, "roles/../x": false, "roles//x": false,
		"./x": false, "roles/a b.yaml": false, "roles/a\x00.yaml": false, "a/b/c/d/e/f/g/h/i.yaml": false,
	} {
		if got := ghapp.ValidPath(s); got != want {
			t.Errorf("ValidPath(%q) = %v, want %v", s, got, want)
		}
	}
}

// The repository calls of the right-sizing pull request, against canned answers: the token asks for contents:write only
// when the credentials say so, and every unexpected answer is an error or a named outcome, never silently a success.
func TestRepoCalls(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	cr.Contents = true
	ctx := context.Background()
	blob := strings.Repeat("a", 40)
	file := base64.StdEncoding.EncodeToString([]byte("key: v\n"))

	reply1 := func(status int, body string) []reply { return []reply{{status: status, body: body}} }
	f.failNext("GET /repos/o/policy", reply1(200, `{"default_branch":"main"}`)...)
	if b, err := c.DefaultBranch(ctx, cr); err != nil || b != "main" {
		t.Fatalf("DefaultBranch = %q, %v", b, err)
	}
	// the token request for these credentials carries contents:write, for the one repository; the others' stays at two
	if len(f.mintBodies) != 1 {
		t.Fatalf("mints = %d", len(f.mintBodies))
	}
	perms, _ := f.mintBodies[0]["permissions"].(map[string]any)
	repos, _ := f.mintBodies[0]["repositories"].([]any)
	if len(perms) != 3 || perms["contents"] != "write" || perms["checks"] != "write" || perms["pull_requests"] != "write" || len(repos) != 1 || repos[0] != "policy" {
		t.Errorf("mint body = %v", f.mintBodies[0])
	}
	plain := creds(t)
	if _, _, err := c.CreateComment(ctx, plain, 5, "x"); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.mintBodies[1]["permissions"].(map[string]any); len(f.mintBodies) != 2 || len(p) != 2 || p["contents"] != nil {
		t.Errorf("a check-only credential asked for %v; tokens must not be shared with contents ones", f.mintBodies)
	}

	f.failNext("GET /repos/o/policy/git/ref/heads/tessera/x", reply1(200, `{"object":{"sha":"`+blob+`"}}`)...)
	if sha, err := c.BranchHead(ctx, cr, "tessera/x"); err != nil || sha != blob {
		t.Errorf("BranchHead = %q, %v", sha, err)
	}
	if _, err := c.BranchHead(ctx, cr, "gone"); !errors.Is(err, ghapp.ErrBranchNotFound) {
		t.Errorf("BranchHead of a missing branch = %v", err)
	}

	f.failNext("POST /repos/o/policy/git/refs", reply1(201, `{}`)...)
	f.failNext("POST /repos/o/policy/git/refs", reply1(422, `{"message":"Reference already exists"}`)...)
	f.failNext("POST /repos/o/policy/git/refs", reply1(403, `{}`)...)
	if err := c.CreateBranchAt(ctx, cr, "tessera/x", blob); err != nil {
		t.Errorf("CreateBranchAt = %v", err)
	}
	if err := c.CreateBranchAt(ctx, cr, "tessera/x", blob); !errors.Is(err, ghapp.ErrBranchConflict) {
		t.Errorf("CreateBranchAt on an existing branch (422) = %v, want ErrBranchConflict", err)
	}
	if err := c.CreateBranchAt(ctx, cr, "tessera/x", blob); !ghapp.IsStatus(err, 403) {
		t.Errorf("CreateBranchAt refused = %v", err)
	}

	f.failNext("GET /repos/o/policy/contents/roles/a.yaml", reply1(200, `{"type":"file","encoding":"base64","size":7,"sha":"`+blob+`","content":"`+file+`"}`)...)
	if got, err := c.GetFile(ctx, cr, "roles/a.yaml", "main"); err != nil || string(got.Content) != "key: v\n" || got.SHA != blob {
		t.Errorf("GetFile = %+v, %v", got, err)
	}
	for name, body := range map[string]string{
		"a directory": `[{"type":"file"}]`, "a symlink": `{"type":"symlink"}`, "too large": `{"type":"file","encoding":"base64","size":999999,"sha":"` + blob + `","content":""}`,
		"not base64": `{"type":"file","encoding":"base64","size":3,"sha":"` + blob + `","content":"@@@"}`,
	} {
		f.failNext("GET /repos/o/policy/contents/roles/a.yaml", reply1(200, body)...)
		if _, err := c.GetFile(ctx, cr, "roles/a.yaml", "main"); !errors.Is(err, ghapp.ErrNotAFile) {
			t.Errorf("GetFile of %s = %v, want ErrNotAFile", name, err)
		}
	}
	if _, err := c.GetFile(ctx, cr, "roles/missing.yaml", "main"); !errors.Is(err, ghapp.ErrFileNotFound) {
		t.Errorf("GetFile of a missing file = %v", err)
	}

	// the commit is made on the verified parent with the Git Data API; its parents are checked
	tree, blob2, commit := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	commitSteps := func(parents string) {
		f.failNext("GET /repos/o/policy/git/commits/"+blob, reply1(200, `{"sha":"`+blob+`","tree":{"sha":"`+tree+`"}}`)...)
		f.failNext("POST /repos/o/policy/git/blobs", reply1(201, `{"sha":"`+blob2+`"}`)...)
		f.failNext("POST /repos/o/policy/git/trees", reply1(201, `{"sha":"`+tree+`"}`)...)
		f.failNext("POST /repos/o/policy/git/commits", reply1(201, `{"sha":"`+commit+`","parents":`+parents+`}`)...)
	}
	commitSteps(`[{"sha":"` + blob + `"}]`)
	if sha, err := c.CommitFile(ctx, cr, "roles/a.yaml", blob, "msg", []byte("k: v\n")); err != nil || sha != commit {
		t.Errorf("CommitFile = %q, %v", sha, err)
	}
	for name, parents := range map[string]string{"another parent": `[{"sha":"` + commit + `"}]`, "two parents": `[{"sha":"` + blob + `"},{"sha":"` + commit + `"}]`, "none": `[]`} {
		commitSteps(parents)
		if _, err := c.CommitFile(ctx, cr, "roles/a.yaml", blob, "msg", []byte("k: v\n")); !errors.Is(err, ghapp.ErrBranchConflict) {
			t.Errorf("a commit with %s = %v, want ErrBranchConflict", name, err)
		}
	}
	if _, err := c.CommitFile(ctx, cr, "roles/a.yaml", blob, "msg", make([]byte, ghapp.MaxFileBytes+1)); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("CommitFile over the size limit = %v", err)
	}
	// the ref moves without force; a refusal (not a fast-forward) is a branch conflict, and the answer must name the commit
	f.failNext("PATCH /repos/o/policy/git/refs/heads/tessera/x", reply1(200, `{"object":{"sha":"`+commit+`"}}`)...)
	f.failNext("PATCH /repos/o/policy/git/refs/heads/tessera/x", reply1(422, `{"message":"Update is not a fast forward"}`)...)
	f.failNext("PATCH /repos/o/policy/git/refs/heads/tessera/x", reply1(200, `{"object":{"sha":"`+blob+`"}}`)...)
	if err := c.MoveBranch(ctx, cr, "tessera/x", commit); err != nil {
		t.Errorf("MoveBranch = %v", err)
	}
	if err := c.MoveBranch(ctx, cr, "tessera/x", commit); !errors.Is(err, ghapp.ErrBranchConflict) {
		t.Errorf("MoveBranch refused = %v", err)
	}
	if err := c.MoveBranch(ctx, cr, "tessera/x", commit); !errors.Is(err, ghapp.ErrBranchConflict) {
		t.Errorf("MoveBranch answering another commit = %v", err)
	}
	if f.mintBodies != nil && len(f.log) > 0 {
		for _, l := range f.log {
			if strings.HasPrefix(l, "PUT ") && strings.Contains(l, "/contents/") {
				t.Errorf("the contents API was used: %s", l)
			}
		}
	}

	f.failNext("POST /repos/o/policy/pulls", reply1(201, `{"number":41,"state":"open","html_url":"https://github.com/o/policy/pull/41","head":{"sha":"`+blob+`"}}`)...)
	f.failNext("POST /repos/o/policy/pulls", reply1(422, `{"message":"A pull request already exists"}`)...)
	p, exists, err := c.CreatePull(ctx, cr, "t", "tessera/x", "main", "b")
	if err != nil || exists || p.Number != 41 || p.HeadSHA != blob || p.HTMLURL == "" {
		t.Errorf("CreatePull = %+v, %v, %v", p, exists, err)
	}
	if p, exists, err := c.CreatePull(ctx, cr, "t", "tessera/x", "main", "b"); err != nil || !exists || p != nil {
		t.Errorf("CreatePull with one open (422) = %+v, %v, %v", p, exists, err)
	}
	f.failNext("GET /repos/o/policy/pulls", reply1(200, `[]`)...)
	f.failNext("GET /repos/o/policy/pulls", reply1(200, `[{"number":40,"state":"open","head":{"sha":"`+blob+`"},"user":{"login":"x"}},{"number":41,"state":"open","head":{"sha":"`+blob+`"},"user":{"login":"app[bot]"}}]`)...)
	if ps, err := c.FindOpenPulls(ctx, cr, "tessera/x", "main"); err != nil || len(ps) != 0 {
		t.Errorf("FindOpenPulls of none = %+v, %v", ps, err)
	}
	if ps, err := c.FindOpenPulls(ctx, cr, "tessera/x", "main"); err != nil || len(ps) != 2 || ps[1].Author != "app[bot]" {
		t.Errorf("FindOpenPulls = %+v, %v", ps, err)
	}
	f.failNext("PATCH /repos/o/policy/pulls/41", reply1(200, `{"number":41,"state":"open","head":{"sha":"`+blob+`"}}`)...)
	if p, err := c.UpdatePull(ctx, cr, 41, "t2", "b2"); err != nil || p.Number != 41 {
		t.Errorf("UpdatePull = %+v, %v", p, err)
	}
	if _, err := c.GetPull(ctx, cr, 99); !errors.Is(err, ghapp.ErrPullNotFound) {
		t.Errorf("GetPull of none = %v", err)
	}
}

// A redirect (a renamed repository answers 301) is a failure, not a followed request: nothing is committed to a place the
// tenant did not configure.
func TestRepoCallsDoNotFollowRedirects(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	cr.Contents = true
	f.failNext("PATCH /repos/o/policy/git/refs/heads/tessera/x", reply{status: http.StatusMovedPermanently, header: map[string]string{"Location": "https://evil.example/x"}})
	err := c.MoveBranch(context.Background(), cr, "tessera/x", strings.Repeat("a", 40))
	if !ghapp.IsStatus(err, http.StatusMovedPermanently) {
		t.Errorf("a 301 = %v, want a status error", err)
	}
}

// A pull request link is kept only when it names github.com or the API base's host and is /<owner>/<repo>/pull/<n>.
func TestPullURLIsChecked(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	blob := strings.Repeat("a", 40)
	for url, want := range map[string]bool{
		"https://github.com/o/policy/pull/41":              true,
		"https://evil.example/o/policy/pull/41":            false,
		"https://github.com/o/other/pull/41":               false,
		"https://github.com/o/policy/pull/42":              false,
		"https://github.com/o/policy/pull/41?x=1":          false,
		"https://github.com.evil.example/o/policy/pull/41": false,
		"https://user@github.com/o/policy/pull/41":         false,
		"http://github.com/o/policy/pull/41":               false,
		"javascript:alert(1)":                              false,
	} {
		f.failNext("GET /repos/o/policy/pulls/41", reply{status: 200, body: `{"number":41,"state":"open","html_url":"` + url + `","head":{"sha":"` + blob + `"},"user":{"login":"app[bot]"}}`})
		p, err := c.GetPull(context.Background(), cr, 41)
		if err != nil {
			t.Fatal(err)
		}
		if (p.HTMLURL != "") != want || p.Author != "app[bot]" {
			t.Errorf("%q: kept = %q, want kept %v", url, p.HTMLURL, want)
		}
	}
}

func TestAppSlugAndCompare(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	ctx := context.Background()
	f.failNext("GET /app", reply{status: 200, body: `{"slug":"tessera-app"}`}, reply{status: 200, body: `{"slug":"bad slug\n"}`}, reply{status: 401, body: `{}`})
	if s, err := c.AppSlug(ctx, cr); err != nil || s != "tessera-app" {
		t.Errorf("AppSlug = %q, %v", s, err)
	}
	if _, err := c.AppSlug(ctx, cr); err == nil {
		t.Error("an unusable slug was accepted")
	}
	if _, err := c.AppSlug(ctx, cr); !errors.Is(err, ghapp.ErrAppAuth) {
		t.Errorf("AppSlug refused = %v", err)
	}
	f.failNext("GET /repos/o/policy/compare/main...tessera/x", reply{status: 200, body: `{"ahead_by":2,"status":"ahead","files":[{"filename":"roles/a.yaml"},{"filename":"b.yaml","previous_filename":"c.yaml"}]}`})
	cmp, err := c.CompareBranch(ctx, cr, "main", "tessera/x")
	if err != nil || cmp.AheadBy != 2 || strings.Join(cmp.Files, ",") != "roles/a.yaml,b.yaml,c.yaml" {
		t.Errorf("CompareBranch = %+v, %v", cmp, err)
	}
	for name, body := range map[string]string{
		"commits and no files": `{"ahead_by":1,"status":"ahead","files":[]}`,
		"files and no commits": `{"ahead_by":0,"status":"identical","files":[{"filename":"x"}]}`,
		"an unknown status":    `{"ahead_by":0,"status":"weird","files":[]}`,
		"no status":            `{"ahead_by":0,"files":[]}`,
	} {
		f.failNext("GET /repos/o/policy/compare/main...tessera/x", reply{status: 200, body: body})
		if _, err := c.CompareBranch(ctx, cr, "main", "tessera/x"); err == nil {
			t.Errorf("a comparison with %s was accepted", name)
		}
	}
	f.failNext("GET /repos/o/policy/compare/main...tessera/x", reply{status: 200, body: `{"ahead_by":0,"status":"identical","files":[]}`})
	if cmp, err := c.CompareBranch(ctx, cr, "main", "tessera/x"); err != nil || cmp.AheadBy != 0 {
		t.Errorf("an identical branch = %+v, %v", cmp, err)
	}
	var many strings.Builder
	many.WriteString(`{"ahead_by":1,"status":"ahead","files":[`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`{"filename":"a"}`)
	}
	many.WriteString(`]}`)
	f.failNext("GET /repos/o/policy/compare/main...tessera/x", reply{status: 200, body: many.String()})
	if _, err := c.CompareBranch(ctx, cr, "main", "tessera/x"); !errors.Is(err, ghapp.ErrNotAFile) {
		t.Errorf("a comparison that may hold more files than listed = %v, want refusal", err)
	}
}
