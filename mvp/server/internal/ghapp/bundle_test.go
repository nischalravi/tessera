package ghapp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
)

// ReadBundle and the ancestry calls of the merge sync (issue #657, AC-11), against canned answers: the token asks for
// contents:read and nothing else, only the wanted files are fetched, and every odd answer is an error, never a short bundle.
func TestReadBundle(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	cr.ContentsRead = true
	ctx := context.Background()
	commit, tree, rolesTree := strings.Repeat("c", 40), strings.Repeat("d", 40), strings.Repeat("e", 40)
	blobA, blobB, blobBig := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	lim := ghapp.BundleLimits{MaxFiles: 3, MaxBytes: 100, MaxFileBytes: 50}
	tops := []string{"tessera.yaml", "roles"}
	keep := func(p string) bool { return p == "tessera.yaml" || strings.HasPrefix(p, "roles/") }
	one := func(status int, body string) []reply { return []reply{{status: status, body: body}} }
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	blob := func(s string) string {
		return fmt.Sprintf(`{"encoding":"base64","size":%d,"content":%q}`, len(s), enc(s))
	}
	commitAnswer := fmt.Sprintf(`{"sha":%q,"tree":{"sha":%q}}`, commit, tree)
	root := func(extra string) string {
		return fmt.Sprintf(`{"truncated":false,"tree":[{"path":"tessera.yaml","mode":"100644","type":"blob","sha":%q,"size":7},
			{"path":"roles","mode":"040000","type":"tree","sha":%q},{"path":"README.md","mode":"100644","type":"blob","sha":%q,"size":9}%s]}`, blobA, rolesTree, blobBig, extra)
	}
	sub := fmt.Sprintf(`{"truncated":false,"tree":[{"path":"a.yaml","mode":"100644","type":"blob","sha":%q,"size":4}]}`, blobB)
	serve := func(f *fakeGitHub, rootJSON, subJSON string) {
		f.failNext("GET /repos/o/policy/git/commits/"+commit, one(200, commitAnswer)...)
		f.failNext("GET /repos/o/policy/git/trees/"+tree, one(200, rootJSON)...)
		if subJSON != "" {
			f.failNext("GET /repos/o/policy/git/trees/"+rolesTree, one(200, subJSON)...)
		}
	}

	// the bundle: only the wanted files are fetched (README.md is not), with a contents:read token
	serve(f, root(""), sub)
	f.failNext("GET /repos/o/policy/git/blobs/"+blobA, one(200, blob("tenant:"))...)
	f.failNext("GET /repos/o/policy/git/blobs/"+blobB, one(200, blob("key:"))...)
	files, err := c.ReadBundle(ctx, cr, commit, tops, keep, lim)
	if err != nil || len(files) != 2 || string(files["tessera.yaml"]) != "tenant:" || string(files["roles/a.yaml"]) != "key:" {
		t.Fatalf("ReadBundle = %v, %v", files, err)
	}
	perms, _ := f.mintBodies[0]["permissions"].(map[string]any)
	if len(perms) != 1 || perms["contents"] != "read" {
		t.Errorf("token permissions = %v, want contents:read only", perms)
	}

	for name, tc := range map[string]struct {
		root, sub string
		want      error
	}{
		"a symlink":      {root(""), strings.Replace(sub, `"100644"`, `"120000"`, 1), ghapp.ErrNotAFile},
		"a submodule":    {strings.Replace(root(""), `"type":"tree"`, `"type":"commit"`, 1), "", ghapp.ErrNotAFile},
		"a cut tree":     {strings.Replace(root(""), `"truncated":false`, `"truncated":true`, 1), "", ghapp.ErrBundleTooLarge},
		"a cut subtree":  {root(""), strings.Replace(sub, `"truncated":false`, `"truncated":true`, 1), ghapp.ErrBundleTooLarge},
		"a big file":     {root(""), strings.Replace(sub, `"size":4`, `"size":51`, 1), ghapp.ErrBundleTooLarge},
		"too many files": {root(""), `{"truncated":false,"tree":[` + strings.TrimSuffix(strings.Repeat(`{"path":"a.yaml","mode":"100644","type":"blob","sha":"`+blobB+`","size":1},`, 3), ",") + `]}`, ghapp.ErrBundleTooLarge},
		"too many bytes": {root(""), `{"truncated":false,"tree":[{"path":"a.yaml","mode":"100644","type":"blob","sha":"` + blobB + `","size":50},{"path":"b.yaml","mode":"100644","type":"blob","sha":"` + blobB + `","size":50}]}`, ghapp.ErrBundleTooLarge},
		"a bad path":     {root(""), `{"truncated":false,"tree":[{"path":"a b.yaml","mode":"100644","type":"blob","sha":"` + blobB + `","size":1}]}`, ghapp.ErrNotAFile},
	} {
		cf := newFake(t) // each case has its own, so no canned answer is left over for the next
		cc, _ := cf.client(t)
		serve(cf, tc.root, tc.sub)
		if _, err := cc.ReadBundle(ctx, cr, commit, tops, keep, lim); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// a blob whose size or encoding is not what the tree said
	f = newFake(t)
	c, _ = f.client(t)
	serve(f, root(""), sub)
	f.failNext("GET /repos/o/policy/git/blobs/"+blobB, one(200, `{"encoding":"base64","size":99,"content":"`+enc("tenant:")+`"}`)...)
	if _, err := c.ReadBundle(ctx, cr, commit, tops, keep, lim); !errors.Is(err, ghapp.ErrNotAFile) {
		t.Errorf("a blob of the wrong size: %v", err)
	}
	if _, err := c.ReadBundle(ctx, cr, "main", tops, keep, lim); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("a branch name as the commit: %v", err)
	}
	// a commit GitHub does not have
	f.failNext("GET /repos/o/policy/git/commits/"+commit, one(404, `{}`)...)
	if _, err := c.ReadBundle(ctx, cr, commit, tops, keep, lim); err == nil || !ghapp.IsStatus(err, 404) {
		t.Errorf("an unknown commit: %v", err)
	}
}

func TestRelateAndOnBranch(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	cr.ContentsRead = true
	ctx := context.Background()
	sha := strings.Repeat("a", 40)
	route := "GET /repos/o/policy/compare/" + sha + "...main"
	one := func(status int, body string) []reply { return []reply{{status: status, body: body}} }
	for _, tc := range []struct {
		answer string
		on     bool
	}{
		{`{"status":"identical","ahead_by":0,"behind_by":0}`, true},
		{`{"status":"ahead","ahead_by":3,"behind_by":0}`, true},
		{`{"status":"behind","ahead_by":0,"behind_by":2}`, false},
		{`{"status":"diverged","ahead_by":1,"behind_by":1}`, false},
	} {
		f.failNext(route, one(200, tc.answer)...)
		if on, err := c.OnBranch(ctx, cr, sha, "main"); err != nil || on != tc.on {
			t.Errorf("OnBranch(%s) = %v, %v; want %v", tc.answer, on, err, tc.on)
		}
	}
	f.failNext(route, one(404, `{}`)...)
	if _, err := c.OnBranch(ctx, cr, sha, "main"); !errors.Is(err, ghapp.ErrCommitNotFound) {
		t.Errorf("an unknown commit: %v", err)
	}
	f.failNext(route, one(200, `{"status":"sideways"}`)...)
	if _, err := c.OnBranch(ctx, cr, sha, "main"); err == nil {
		t.Error("an unreadable comparison was accepted")
	}
	f.failNext(route, one(200, `not json`)...)
	if _, err := c.Relate(ctx, cr, sha, "main"); err == nil {
		t.Error("an unreadable answer was accepted")
	}
	if _, err := c.Relate(ctx, cr, "a b", "main"); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("a bad ref: %v", err)
	}
}
