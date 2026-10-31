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
	if created, err := c.CreateBranch(ctx, cr, "tessera/x", blob); err != nil || !created {
		t.Errorf("CreateBranch = %v, %v", created, err)
	}
	if created, err := c.CreateBranch(ctx, cr, "tessera/x", blob); err != nil || created {
		t.Errorf("CreateBranch on an existing branch (422) = %v, %v; want reuse, no error", created, err)
	}
	if _, err := c.CreateBranch(ctx, cr, "tessera/x", blob); !ghapp.IsStatus(err, 403) {
		t.Errorf("CreateBranch refused = %v", err)
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

	f.failNext("PUT /repos/o/policy/contents/roles/a.yaml", reply1(200, `{"commit":{"sha":"`+blob+`"}}`)...)
	f.failNext("PUT /repos/o/policy/contents/roles/a.yaml", reply1(409, `{"message":"does not match"}`)...)
	f.failNext("PUT /repos/o/policy/contents/roles/a.yaml", reply1(200, `{"commit":{}}`)...)
	if sha, err := c.PutFile(ctx, cr, "roles/a.yaml", "tessera/x", "msg", []byte("k: v\n"), blob); err != nil || sha != blob {
		t.Errorf("PutFile = %q, %v", sha, err)
	}
	if _, err := c.PutFile(ctx, cr, "roles/a.yaml", "tessera/x", "msg", []byte("k: v\n"), blob); !errors.Is(err, ghapp.ErrStaleBase) {
		t.Errorf("PutFile on a moved file (409) = %v, want ErrStaleBase", err)
	}
	if _, err := c.PutFile(ctx, cr, "roles/a.yaml", "tessera/x", "msg", []byte("k: v\n"), blob); err == nil {
		t.Error("PutFile with no commit in the answer succeeded")
	}
	if _, err := c.PutFile(ctx, cr, "roles/a.yaml", "tessera/x", "msg", make([]byte, ghapp.MaxFileBytes+1), blob); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("PutFile over the size limit = %v", err)
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
	f.failNext("GET /repos/o/policy/pulls", reply1(200, `[{"number":41,"state":"open","head":{"sha":"`+blob+`"}}]`)...)
	if p, err := c.FindOpenPull(ctx, cr, "tessera/x"); err != nil || p != nil {
		t.Errorf("FindOpenPull of none = %+v, %v", p, err)
	}
	if p, err := c.FindOpenPull(ctx, cr, "tessera/x"); err != nil || p == nil || p.Number != 41 {
		t.Errorf("FindOpenPull = %+v, %v", p, err)
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
	f.failNext("PUT /repos/o/policy/contents/roles/a.yaml", reply{status: http.StatusMovedPermanently, header: map[string]string{"Location": "https://evil.example/x"}})
	_, err := c.PutFile(context.Background(), cr, "roles/a.yaml", "tessera/x", "m", []byte("x"), strings.Repeat("a", 40))
	if !ghapp.IsStatus(err, http.StatusMovedPermanently) {
		t.Errorf("a 301 = %v, want a status error", err)
	}
}
