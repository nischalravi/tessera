package api

import (
	"crypto/sha1" // #nosec G505 -- a fake git object id in a test double
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/syncverify"
)

// Merge sync, prediction check and rollback (issue #657, AC-11).

// syncExtra adds to the repository fake what the merge sync reads: trees (a folder is a tree of its own), blobs, and
// ancestry for the comparison of two commits. A commit made by push has its parent recorded.
func syncExtra(blobs map[string]string, subtrees map[string]map[string]string) func(g *gitRepo, r *http.Request, body map[string]any, send func(int, any)) bool {
	sum := func(s string) string {
		h := sha1.Sum([]byte(s)) // #nosec G401
		return hex.EncodeToString(h[:])
	}
	ancestors := func(g *gitRepo, c string) map[string]int {
		out := map[string]int{}
		for d := 0; c != ""; c, d = g.parents[c], d+1 {
			out[c] = d
		}
		return out
	}
	return func(g *gitRepo, r *http.Request, body map[string]any, send func(int, any)) bool {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(path, repoBase+"/git/trees/"):
			id := strings.TrimPrefix(path, repoBase+"/git/trees/")
			recursive := r.URL.Query().Get("recursive") == "1"
			files, ok := g.trees[id]
			if sub, isSub := subtrees[id]; isSub {
				files, ok = sub, true
			}
			if !ok {
				send(404, map[string]string{"message": "Not Found"})
				return true
			}
			var entries []map[string]any
			tops := map[string]map[string]string{}
			var paths []string
			for p := range files {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			for _, p := range paths {
				c := files[p]
				blobs[blobID(c)] = c
				top, rest, nested := strings.Cut(p, "/")
				if nested && !recursive {
					if tops[top] == nil {
						tops[top] = map[string]string{}
					}
					tops[top][rest] = c
					continue
				}
				entries = append(entries, map[string]any{"path": p, "mode": "100644", "type": "blob", "sha": blobID(c), "size": len(c)})
			}
			var names []string
			for top := range tops {
				names = append(names, top)
			}
			sort.Strings(names)
			for _, top := range names {
				tid := sum("subtree-" + id + "-" + top)
				subtrees[tid] = tops[top]
				entries = append(entries, map[string]any{"path": top, "mode": "040000", "type": "tree", "sha": tid})
			}
			send(200, map[string]any{"sha": id, "tree": entries, "truncated": false})
		case r.Method == http.MethodGet && strings.HasPrefix(path, repoBase+"/git/blobs/"):
			c, ok := blobs[strings.TrimPrefix(path, repoBase+"/git/blobs/")]
			if !ok {
				send(404, map[string]string{"message": "Not Found"})
				return true
			}
			send(200, map[string]any{"encoding": "base64", "size": len(c), "content": base64Of(c)})
		case r.Method == http.MethodGet && strings.HasPrefix(path, repoBase+"/compare/"):
			b, h, _ := strings.Cut(strings.TrimPrefix(path, repoBase+"/compare/"), "...")
			at := func(ref string) string {
				if sha, ok := g.branches[ref]; ok {
					return sha
				}
				if _, ok := g.commits[ref]; ok {
					return ref
				}
				return ""
			}
			base, head := at(b), at(h)
			if base == "" || head == "" {
				send(404, map[string]string{"message": "Not Found"})
				return true
			}
			status, ahead, behind := "diverged", 0, 0
			if d, ok := ancestors(g, head)[base]; ok {
				status, ahead = "ahead", d
				if d == 0 {
					status = "identical"
				}
			} else if d, ok := ancestors(g, base)[head]; ok {
				status, behind = "behind", d
			}
			send(200, map[string]any{"status": status, "ahead_by": ahead, "behind_by": behind, "files": []any{}})
		default:
			return false
		}
		return true
	}
}

func base64Of(s string) string { return strings.TrimRight(encodeB64([]byte(s)), "\n") }

// push commits files on top of the default branch and moves it.
func (g *gitRepo) push(files map[string]string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	sha := g.commit(files)
	g.parents[sha] = g.branches["main"]
	g.branches["main"] = sha
	return sha
}

// side commits files on a branch that is not the default branch.
func (g *gitRepo) side(branch string, files map[string]string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	sha := g.commit(files)
	g.parents[sha] = g.branches["main"]
	g.branches[branch] = sha
	return sha
}

type syncWorld struct {
	t      *testing.T
	e      *oauthEnv
	gh     *appGitHub
	repo   *gitRepo
	pa     authtest.Login
	ta1    authtest.Login
	ta2    authtest.Login
	files  map[string]string // the bundle of the first commit: Tessera's own export
	shaA   string
	groups map[string]string
}

func (w *syncWorld) do(l authtest.Login, method, path, body string) (int, map[string]any) {
	w.t.Helper()
	rec := reqDo(w.e.h, l, method, path, body)
	return rec.Code, body_(rec)
}

func (w *syncWorld) must(l authtest.Login, method, path, body string, want int) map[string]any {
	w.t.Helper()
	code, m := w.do(l, method, path, body)
	if code != want {
		w.t.Fatalf("%s %s = %d, want %d: %v", method, path, code, want, m)
	}
	return m
}

func syncSetup(t *testing.T) *syncWorld {
	t.Helper()
	gh, withGH := newAppGitHub(t, nil)
	e := newOAuthEnv(t, withGH)
	w := &syncWorld{t: t, e: e, gh: gh,
		pa:  reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, ""),
		ta1: ghAdmin(t, e.f, e.f.B, "ta1@b.example"), ta2: ghAdmin(t, e.f, e.f.B, "ta2@b.example")}
	_, pemKey := ghTestKey(t)
	putApp(t, e.h, w.ta1, pemKey, true)

	b := e.f.B.IDs
	body := fmt.Sprintf(`{"name":"Engineer","risk":"medium","requestable":true,"birthright":{"department":["Engineering"]},
		"entitlement_group_ids":[%d]}`, b["group:okta:eng"])
	w.must(w.pa, "POST", "/api/roles", body, 201)
	exp := w.must(w.pa, "GET", "/api/policy/roles/export", "", 200)
	w.files = map[string]string{}
	for k, v := range exp["files"].(map[string]any) {
		w.files[k] = v.(string)
	}
	w.repo = newGitRepo(w.files)
	w.repo.extra = syncExtra(map[string]string{}, map[string]map[string]string{})
	gh.mu.Lock()
	gh.repo = w.repo
	gh.mu.Unlock()
	w.shaA = w.repo.branches["main"]
	return w
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// engineerWith is the baseline bundle with one more entitlement on the Engineer role (the "merge").
func (w *syncWorld) merged() map[string]string {
	out := map[string]string{}
	for k, v := range w.files {
		out[k] = v
	}
	out["roles/engineer.yaml"] = strings.Replace(w.files["roles/engineer.yaml"], "    - okta:eng\n",
		"    - okta:eng\n    - okta:"+groupName(w.t, w.e.f, "group:okta:platform")+"\n", 1)
	if out["roles/engineer.yaml"] == w.files["roles/engineer.yaml"] {
		w.t.Fatalf("the merge changed nothing: %s", w.files["roles/engineer.yaml"])
	}
	return out
}

func (w *syncWorld) sync(l authtest.Login, sha string, want int) map[string]any {
	w.t.Helper()
	return w.must(l, "POST", "/api/policy/github/sync", fmt.Sprintf(`{"sha":%q}`, sha), want)
}

func (w *syncWorld) change(resp map[string]any) (id, hash string) {
	w.t.Helper()
	ch, _ := resp["change_request"].(map[string]any)
	id, _ = ch["id"].(string)
	if id == "" {
		id, _ = ch["change_id"].(string)
	}
	hash, _ = ch["payload_hash"].(string)
	if id == "" || hash == "" {
		w.t.Fatalf("no change request in %v", resp)
	}
	return id, hash
}

func (w *syncWorld) approve(l authtest.Login, resp map[string]any, want int) map[string]any {
	w.t.Helper()
	id, hash := w.change(resp)
	w.e.clock.Advance(time.Second) // the last synced commit is the newest applied: applies a clock tick apart
	return w.must(l, "POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash), want)
}

// syncAndApply files the commit as ta1 and has ta2 approve it.
func (w *syncWorld) syncAndApply(sha string) map[string]any {
	w.t.Helper()
	resp := w.sync(w.ta1, sha, 201)
	w.approve(w.ta2, resp, 200)
	return resp
}

func (w *syncWorld) status() map[string]any {
	w.t.Helper()
	return w.must(w.ta1, "GET", "/api/policy/github/sync", "", 200)
}

func (w *syncWorld) last() map[string]any {
	w.t.Helper()
	m, _ := w.status()["last_synced"].(map[string]any)
	return m
}

// state is what the store shows now: every identity's permissions and the violations.
func (w *syncWorld) state() *syncverify.State {
	w.t.Helper()
	var st *syncverify.State
	err := w.e.f.DB.ReadTenant(w.t.Context(), w.e.f.B.ID, func(tx *store.TenantTx) error {
		pols, err := w.e.srv.effectivePolicies(tx)
		if err != nil {
			return err
		}
		st, err = syncverify.Capture(tx, pols, w.e.clock.Now())
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return st
}

func (w *syncWorld) exportDigest() string {
	w.t.Helper()
	return w.must(w.pa, "GET", "/api/policy/roles/export", "", 200)["bundle_sha256"].(string)
}

func (w *syncWorld) audited(action string) bool {
	w.t.Helper()
	rec := reqDo(w.e.h, w.ta1, "GET", "/api/audit?limit=1000", "")
	return rec.Code == 200 && strings.Contains(rec.Body.String(), `"`+action+`"`)
}

func (w *syncWorld) predictionOf(resp map[string]any) *syncverify.Prediction {
	w.t.Helper()
	id, _ := w.change(resp)
	ch := w.must(w.ta1, "GET", "/api/admin/change-requests/"+id, "", 200)
	raw, _ := json.Marshal(ch["payload"].(map[string]any)["prediction"])
	var p syncverify.Prediction
	if err := json.Unmarshal(raw, &p); err != nil {
		w.t.Fatal(err)
	}
	return &p
}

// The whole loop: a baseline commit is synced, a merge is synced with its prediction, a second admin applies it, the check
// after the apply finds what was predicted, and syncing the revert commit puts the state back as it was before the merge.
func TestPolicySync_MergeCheckAndRevert(t *testing.T) {
	w := syncSetup(t)
	beforeAll := w.state()
	baseDigest := w.exportDigest()

	// the first sync records where the repository and Tessera agree: nothing to change, still two people
	resp := w.sync(w.ta1, w.shaA, 201)
	if resp["no_changes"] != true || resp["status"] != "filed" {
		t.Fatalf("baseline sync = %v", resp)
	}
	w.approve(w.ta1, resp, 403) // self-approval is refused
	if w.last() != nil {
		t.Fatalf("the sync applied before its approval: %v", w.last())
	}
	w.approve(w.ta2, resp, 200)
	if l := w.last(); l == nil || l["sha"] != w.shaA || l["check_status"] != "verified" || l["kind"] != "sync" {
		t.Fatalf("last synced after the baseline = %v", l)
	}

	// the merge
	shaB := w.repo.push(w.merged())
	resp = w.sync(w.ta1, shaB, 201)
	if resp["no_changes"] != false {
		t.Fatalf("merge sync = %v", resp)
	}
	sync := resp["sync"].(map[string]any)
	pred := w.predictionOf(resp)
	if pred.PermsTotal == 0 || pred.IdentitiesAffected == 0 || !strings.Contains(fmt.Sprint(sync["prediction"]), "permission_changes") {
		t.Fatalf("the prediction names no permission change: %+v", pred)
	}
	if got := w.exportDigest(); got != baseDigest {
		t.Fatal("filing the sync changed the state before approval")
	}
	if w.last()["sha"] != w.shaA {
		t.Fatalf("last synced moved before approval: %v", w.last())
	}
	w.approve(w.ta1, resp, 403)
	w.approve(w.ta2, resp, 200)
	l := w.last()
	if l == nil || l["sha"] != shaB || l["check_status"] != "verified" || l["findings"] != float64(0) || l["applied_at"] == nil {
		t.Fatalf("last synced after the merge = %v", l)
	}
	if w.exportDigest() == baseDigest {
		t.Fatal("the merge changed nothing")
	}
	afterB := w.state()
	if reflect.DeepEqual(afterB.Perms, beforeAll.Perms) {
		t.Fatal("the merge did not change any effective permission")
	}
	for _, a := range []string{"policy.roles.applied", "policy.sync.applied", "policy.sync.verified", "admin.change.approved"} {
		if !w.audited(a) {
			t.Errorf("no %s event", a)
		}
	}
	if w.audited("policy.sync.mismatch") {
		t.Error("a mismatch event for a sync that matched")
	}

	// the revert commit (the files of the first commit again) returns to the state before the merge
	shaC := w.repo.push(w.files)
	w.syncAndApply(shaC)
	if l := w.last(); l["sha"] != shaC || l["check_status"] != "verified" {
		t.Fatalf("last synced after the revert = %v", l)
	}
	if got := w.exportDigest(); got != baseDigest {
		t.Errorf("after the revert the roles bundle is %s, before the merge it was %s", got, baseDigest)
	}
	afterC := w.state()
	if !reflect.DeepEqual(afterC.Perms, beforeAll.Perms) || !reflect.DeepEqual(afterC.Violations, beforeAll.Violations) {
		t.Error("after the revert the effective permissions or violations are not those before the merge")
	}
	// the three syncs are listed, newest first, and the audit chain still verifies
	syncs := w.status()["syncs"].([]any)
	if len(syncs) != 3 || syncs[0].(map[string]any)["sha"] != shaC {
		t.Errorf("syncs = %v", syncs)
	}
	if code, m := w.do(w.ta1, "POST", "/api/audit/verify", ""); code != 200 || m["exit_code"] != float64(0) {
		t.Errorf("audit verify = %d %v", code, m)
	}
}

// A rollback to an earlier synced commit plans the bundle of that commit, so applying it returns to the state before.
func TestPolicySync_Rollback(t *testing.T) {
	w := syncSetup(t)
	beforeAll := w.state()
	baseDigest := w.exportDigest()
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	w.syncAndApply(shaB)
	if w.exportDigest() == baseDigest {
		t.Fatal("the merge changed nothing")
	}

	// refusals: a commit never synced, the commit already synced, a sha that is not one
	unknown := w.repo.push(w.files)
	if code, m := w.do(w.ta1, "POST", "/api/policy/github/rollback", fmt.Sprintf(`{"to_sha":%q}`, unknown)); code != 422 || m["error"] != "rollback_target_unknown" {
		t.Errorf("rollback to a commit never synced = %d %v", code, m)
	}
	if code, m := w.do(w.ta1, "POST", "/api/policy/github/rollback", fmt.Sprintf(`{"to_sha":%q}`, shaB)); code != 409 || m["error"] != "already_at_commit" {
		t.Errorf("rollback to the current commit = %d %v", code, m)
	}
	if code, m := w.do(w.ta1, "POST", "/api/policy/github/rollback", `{"to_sha":"main"}`); code != 422 || m["error"] != "invalid_to_sha" {
		t.Errorf("rollback to a branch name = %d %v", code, m)
	}

	resp := w.must(w.ta1, "POST", "/api/policy/github/rollback", fmt.Sprintf(`{"to_sha":%q}`, w.shaA), 201)
	sy := resp["sync"].(map[string]any)
	if sy["kind"] != "rollback" || sy["sha"] != w.shaA || sy["rollback_from"] != shaB || resp["no_changes"] != false {
		t.Fatalf("rollback filed = %v", resp)
	}
	pred := w.predictionOf(resp)
	if pred.PermsTotal == 0 {
		t.Errorf("a rollback that removes a grant predicts no permission change: %+v", pred)
	}
	w.approve(w.ta1, resp, 403)
	w.approve(w.ta2, resp, 200)
	if l := w.last(); l["sha"] != w.shaA || l["kind"] != "rollback" || l["check_status"] != "verified" {
		t.Fatalf("last synced after the rollback = %v", l)
	}
	if got := w.exportDigest(); got != baseDigest {
		t.Errorf("after the rollback the roles bundle is %s, before the merge it was %s", got, baseDigest)
	}
	after := w.state()
	if !reflect.DeepEqual(after.Perms, beforeAll.Perms) || !reflect.DeepEqual(after.Violations, beforeAll.Violations) {
		t.Error("after the rollback the effective permissions or violations are not those before the merge")
	}
	// the merge can be synced again (its earlier sync no longer holds it), and rolled back to again
	w.syncAndApply(shaB)
	if w.last()["sha"] != shaB || w.exportDigest() == baseDigest {
		t.Errorf("the merge was not applied again: %v", w.last())
	}
	w.must(w.ta1, "POST", "/api/policy/github/rollback", fmt.Sprintf(`{"to_sha":%q}`, w.shaA), 201)
}

// A target that drops a change is found: the check after the apply raises a finding with what was predicted and what was
// observed, the sync is marked mismatch, and the event is audited. The apply itself stands.
func TestPolicySync_MismatchRaisesFinding(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	resp := w.sync(w.ta1, shaB, 201)
	pred := w.predictionOf(resp)
	var dropped syncverify.PermChange
	for _, c := range pred.Perms {
		if c.Gain {
			dropped = c
			break
		}
	}
	if dropped.Perm == "" {
		t.Fatalf("no predicted gain to drop: %+v", pred.Perms)
	}
	// the fake target drops one of the changes
	w.e.srv.admin.SyncObserve = func(after *syncverify.State) { delete(after.Perms[dropped.IdentityID], dropped.Perm) }
	w.approve(w.ta2, resp, 200)

	l := w.last()
	if l["sha"] != shaB || l["check_status"] != "mismatch" || l["change_status"] != "applied" || l["findings"] != float64(1) {
		t.Fatalf("last synced after a dropped change = %v", l)
	}
	fl, _ := l["finding_list"].([]any)
	if len(fl) != 1 {
		t.Fatalf("finding list = %v", l["finding_list"])
	}
	f := fl[0].(map[string]any)
	if f["kind"] != syncverify.KindGainMissing || f["predicted"] != "gained" || f["observed"] != "not held" ||
		!strings.Contains(fmt.Sprint(f["subject"]), dropped.Perm) || !strings.Contains(fmt.Sprint(f["subject"]), dropped.Identity) {
		t.Errorf("finding = %v, want the dropped %+v", f, dropped)
	}
	for action, want := range map[string]bool{"policy.sync.mismatch": true, "policy.sync.applied": true} {
		if got := w.audited(action); got != want {
			t.Errorf("audited(%s) = %v, want %v", action, got, want)
		}
	}
	// the sync is listed with the finding in the status too
	syncs := w.status()["syncs"].([]any)
	if syncs[0].(map[string]any)["check_status"] != "mismatch" || len(syncs[0].(map[string]any)["finding_list"].([]any)) != 1 {
		t.Errorf("status = %v", syncs[0])
	}
}

// A commit that is not on the default branch, one GitHub does not know, a sync that is not a descendant of the last synced
// commit, a bundle for another tenant, an oversized file, and a bundle that does not load are refused with nothing filed.
func TestPolicySync_Refusals(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	w.syncAndApply(shaB)
	changes := func() int {
		return len(w.status()["syncs"].([]any))
	}
	n := changes()
	post := func(l authtest.Login, sha string) (int, map[string]any) {
		return w.do(l, "POST", "/api/policy/github/sync", fmt.Sprintf(`{"sha":%q}`, sha))
	}

	// not on the default branch: a commit of a side branch that was never merged
	side := w.repo.side("feature", w.merged())
	if code, m := post(w.ta1, side); code != 409 || m["error"] != "sha_not_on_default_branch" {
		t.Errorf("a commit off the default branch = %d %v", code, m)
	}
	// unknown to GitHub
	if code, m := post(w.ta1, strings.Repeat("ab", 20)); code != 422 || m["error"] != "commit_not_found" {
		t.Errorf("an unknown commit = %d %v", code, m)
	}
	for _, bad := range []string{"", "main", "HEAD~1", strings.Repeat("A", 40), strings.Repeat("a", 39), "../" + strings.Repeat("a", 40)} {
		if code, m := post(w.ta1, bad); code != 422 || m["error"] != "invalid_sha" {
			t.Errorf("sha %q = %d %v", bad, code, m)
		}
	}
	// the first commit is an ancestor of the last synced one, not a descendant: roll back to return to it
	if code, m := post(w.ta1, w.shaA); code != 409 || m["error"] != "not_a_descendant" {
		t.Errorf("an older commit = %d %v", code, m)
	}
	// a bundle that names another tenant is refused as invalid
	other := map[string]string{}
	for k, v := range w.merged() {
		other[k] = v
	}
	other["tessera.yaml"] = strings.Replace(w.files["tessera.yaml"], w.e.f.B.Slug, w.e.f.A.Slug, 1)
	shaX := w.repo.push(other)
	if code, m := post(w.ta1, shaX); code != 422 || m["error"] != "invalid_bundle" || !strings.Contains(fmt.Sprint(m), "tenant_mismatch") {
		t.Errorf("another tenant's bundle = %d %v", code, m)
	}
	// a file over the cap, and a bundle that does not load
	big := map[string]string{}
	for k, v := range w.merged() {
		big[k] = v
	}
	big["roles/huge.yaml"] = strings.Repeat("a", 300<<10)
	shaBig := w.repo.push(big)
	if code, m := post(w.ta1, shaBig); code != 413 || m["error"] != "bundle_too_large" {
		t.Errorf("an oversized file = %d %v", code, m)
	}
	broken := map[string]string{}
	for k, v := range w.merged() {
		broken[k] = v
	}
	broken["roles/engineer.yaml"] = strings.Replace(w.files["roles/engineer.yaml"], "okta:eng", "nowhere:eng", 1)
	shaBroken := w.repo.push(broken)
	if code, m := post(w.ta1, shaBroken); code != 422 || m["error"] != "invalid_bundle" || !strings.Contains(fmt.Sprint(m), "unknown_entitlement") {
		t.Errorf("a bundle that does not load = %d %v", code, m)
	}
	// a commit with no policy files at all
	shaEmpty := w.repo.push(map[string]string{"README.md": "hello"})
	if code, m := post(w.ta1, shaEmpty); code != 422 || m["error"] != "empty_bundle" {
		t.Errorf("a commit with no bundle = %d %v", code, m)
	}
	if got := changes(); got != n {
		t.Errorf("%d syncs were filed by refused requests", got-n)
	}
	if w.last()["sha"] != shaB {
		t.Errorf("last synced = %v", w.last())
	}
}

// Nothing is filed without the permission, a fresh step-up and an enabled App; every GitHub call asked for contents:read only.
func TestPolicySync_PermissionsStepUpAndApp(t *testing.T) {
	w := syncSetup(t)
	shaB := w.repo.push(w.merged())
	body := fmt.Sprintf(`{"sha":%q}`, shaB)
	viewer := reqLogin(t, w.e.f, "v@b.example", []auth.Role{auth.RoleViewer}, "alice")
	for name, l := range map[string]authtest.Login{"viewer": viewer, "policy admin": w.pa} {
		if code, m := w.do(l, "POST", "/api/policy/github/sync", body); code != 403 {
			t.Errorf("%s synced: %d %v", name, code, m)
		}
		if code, _ := w.do(l, "POST", "/api/policy/github/rollback", body); code != 403 {
			t.Errorf("%s rolled back: %d", name, code)
		}
	}
	if code, _ := w.do(viewer, "GET", "/api/policy/github/sync", ""); code != 200 && code != 403 {
		t.Errorf("viewer status = %d", code)
	}
	// a sign-in older than the step-up window can file nothing
	stale := signIn(t, w.e.f.DB, w.e.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: w.e.clock.Now().Add(-20 * time.Minute)}, w.e.clock.Now())
	w.gh.mu.Lock()
	calls := len(w.gh.got)
	w.gh.mu.Unlock()
	for _, path := range []string{"/api/policy/github/sync", "/api/policy/github/rollback"} {
		in := body
		if strings.HasSuffix(path, "rollback") {
			in = fmt.Sprintf(`{"to_sha":%q}`, shaB)
		}
		if code, m := w.do(stale, "POST", path, in); code != 401 || m["error"] != "step_up_required" {
			t.Errorf("%s with a stale sign-in = %d %v", path, code, m)
		}
	}
	// refused before GitHub is read (issue #792)
	w.gh.mu.Lock()
	if n := len(w.gh.got) - calls; n != 0 {
		t.Errorf("a stale sign-in made %d GitHub calls before it was refused: %v", n, w.gh.got[calls:])
	}
	w.gh.mu.Unlock()
	if n := len(w.status()["syncs"].([]any)); n != 0 {
		t.Errorf("%d syncs after refused requests", n)
	}
	// the other tenant has no App: nothing is read from the repository for it
	taA := ghAdmin(t, w.e.f, w.e.f.A, "ta@a.example")
	if code, m := w.do(taA, "POST", "/api/policy/github/sync", body); code != 409 || m["error"] != "github_app_disabled" {
		t.Errorf("a tenant without the App = %d %v", code, m)
	}
	// and the filed sync read the repository with contents:read and nothing else
	w.sync(w.ta1, shaB, 201)
	w.gh.mu.Lock()
	defer w.gh.mu.Unlock()
	if len(w.gh.mintBody) == 0 {
		t.Fatal("no token was minted")
	}
	for _, mb := range w.gh.mintBody {
		perms, _ := mb["permissions"].(map[string]any)
		if len(perms) != 1 || perms["contents"] != "read" {
			t.Errorf("token permissions = %v, want contents:read only", perms)
		}
		if repos, _ := mb["repositories"].([]any); len(repos) != 1 || repos[0] != "policy" {
			t.Errorf("token repositories = %v", mb["repositories"])
		}
	}
	for _, r := range w.gh.got {
		if !strings.HasPrefix(r, "GET ") && !strings.Contains(r, "access_tokens") {
			t.Errorf("a sync made a write call to GitHub: %s", r)
		}
	}
}

// The same commit is filed once: a repeat while the request is open answers the same one; a rejected request frees the commit;
// an applied one that is still the last sync is answered again.
func TestPolicySync_Idempotent(t *testing.T) {
	w := syncSetup(t)
	shaB := w.repo.push(w.merged())
	first := w.sync(w.ta1, shaB, 201)
	id, _ := w.change(first)
	again := w.sync(w.ta1, shaB, 200)
	if again["status"] != "existing" || again["sync"].(map[string]any)["change_id"] != id {
		t.Fatalf("repeat = %v", again)
	}
	if n := len(w.status()["syncs"].([]any)); n != 1 {
		t.Errorf("%d syncs after a repeat", n)
	}
	// rejected: the commit can be filed again, as a new request
	w.must(w.ta2, "POST", "/api/admin/change-requests/"+id+"/reject", "", 200)
	second := w.sync(w.ta1, shaB, 201)
	id2, _ := w.change(second)
	if id2 == id {
		t.Fatal("the rejected request was reused")
	}
	// applied and still the last sync: answered again, nothing new
	w.approve(w.ta2, second, 200)
	done := w.sync(w.ta1, shaB, 200)
	if done["status"] != "existing" || done["sync"].(map[string]any)["change_id"] != id2 || done["sync"].(map[string]any)["check_status"] != "verified" {
		t.Fatalf("repeat after apply = %v", done)
	}
	if n := len(w.status()["syncs"].([]any)); n != 2 {
		t.Errorf("%d syncs", n)
	}
	// a request that was cancelled frees the commit as well
	shaC := w.repo.push(w.files)
	third := w.sync(w.ta1, shaC, 201)
	idC, _ := w.change(third)
	w.must(w.ta1, "POST", "/api/admin/change-requests/"+idC+"/cancel", "", 200)
	w.sync(w.ta1, shaC, 201)
}

// CI holding tessera:policy-sync files a sync in the name of its owner and can never approve it; the scope gives it nothing
// else, and a client without the scope is refused.
func TestPolicySync_MachineClient(t *testing.T) {
	w := syncSetup(t)
	shaB := w.repo.push(w.merged())
	ci := w.e.addMachine("tenant-b", []string{"viewer"}, []string{"tessera:policy-sync"}, true)
	tok := w.e.machineToken(ci, "tenant-b", "tessera:policy-sync")
	body := fmt.Sprintf(`{"sha":%q}`, shaB)
	rec := w.e.call(tok, "POST", "/api/policy/github/sync", body)
	resp := body_(rec)
	if rec.Code != 201 || resp["status"] != "filed" {
		t.Fatalf("CI sync = %d %s", rec.Code, rec.Body)
	}
	id, hash := w.change(resp)
	if rec := w.e.call(tok, "POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); rec.Code != 403 {
		t.Errorf("CI approved its own sync: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/api/policy/github/app", "/api/policy/github/sync", "/api/summary", "/api/admin/change-requests/" + id} {
		if rec := w.e.call(tok, "GET", p, ""); rec.Code != 403 {
			t.Errorf("CI read %s: %d", p, rec.Code)
		}
	}
	// a repeat from CI is answered, not filed again
	if rec := w.e.call(tok, "POST", "/api/policy/github/sync", body); rec.Code != 200 || body_(rec)["status"] != "existing" {
		t.Errorf("CI repeat = %d %s", rec.Code, rec.Body)
	}
	// the change names the client, and a human admin approves it
	if w.audited("policy.sync.applied") {
		t.Fatal("applied before approval")
	}
	w.approve(w.ta2, resp, 200)
	if l := w.last(); l["sha"] != shaB || l["check_status"] != "verified" {
		t.Errorf("last synced = %v", l)
	}
	rec = reqDo(w.e.h, w.ta1, "GET", "/api/audit?limit=1000", "")
	if !strings.Contains(rec.Body.String(), ci.id) {
		t.Error("the audit trail does not name the client that proposed the sync")
	}
	// a machine client without the scope is refused, with any role
	other := w.e.addMachine("tenant-b", []string{"viewer", "operator"}, []string{"tessera:read", "tessera:write", "tessera:admin"}, true)
	otok := w.e.machineToken(other, "tenant-b", "tessera:read tessera:write tessera:admin")
	if rec := w.e.call(otok, "POST", "/api/policy/github/sync", body); rec.Code != 403 {
		t.Errorf("a client without the scope = %d %s", rec.Code, rec.Body)
	}
	// and a client that lost the scope after filing cannot have its request approved
	revert := w.repo.push(w.files)
	rec = w.e.call(tok, "POST", "/api/policy/github/sync", fmt.Sprintf(`{"sha":%q}`, revert))
	if rec.Code != 201 {
		t.Fatalf("CI second sync = %d %s", rec.Code, rec.Body)
	}
	err := w.e.f.DB.InTenant(t.Context(), w.e.f.B.ID, func(tx *store.TenantTx) error {
		return tx.SetAPIClientScopes(ci.id, []string{"tessera:read"})
	})
	if err != nil {
		t.Fatal(err)
	}
	w.approve(w.ta2, body_(rec), 409)
	if w.last()["sha"] != shaB {
		t.Errorf("a request of a client that lost its scope was applied: %v", w.last())
	}
}

// A tenant sees only its own syncs and last synced commit; a bundle is planned and applied in the session's tenant only.
func TestPolicySync_TenantIsolation(t *testing.T) {
	w := syncSetup(t)
	shaB := w.repo.push(w.merged())
	w.syncAndApply(shaB)
	taA := ghAdmin(t, w.e.f, w.e.f.A, "ta@a.example")
	_, pemKey := ghTestKey(t)
	putApp(t, w.e.h, taA, pemKey, true) // tenant A has the App on the same repository, and has synced nothing
	st := w.must(taA, "GET", "/api/policy/github/sync", "", 200)
	if st["last_synced"] != nil || len(st["syncs"].([]any)) != 0 {
		t.Errorf("tenant A sees tenant B's syncs: %v", st)
	}
	// tenant A syncing B's bundle (tessera.yaml names tenant B) is refused: the bundle is for another tenant
	code, m := w.do(taA, "POST", "/api/policy/github/sync", fmt.Sprintf(`{"sha":%q}`, shaB))
	if code != 422 || !strings.Contains(fmt.Sprint(m), "tenant_mismatch") {
		t.Errorf("tenant A synced tenant B's bundle: %d %v", code, m)
	}
	if st := w.must(taA, "GET", "/api/policy/github/sync", "", 200); len(st["syncs"].([]any)) != 0 {
		t.Errorf("a refused sync was recorded: %v", st)
	}
	if w.last()["sha"] != shaB {
		t.Errorf("tenant B's last synced = %v", w.last())
	}
}

// Every kind the commit holds is one request with one plan digest of all of them, applied in one transaction: roles and a
// SoD ruleset here, with the audit event of each kind and the commit on both.
func TestPolicySync_SeveralKindsInOneRequest(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	files := w.merged()
	files["tessera.yaml"] = fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n    sod: partial\n", w.e.f.B.Slug)
	files["sod/payments.yaml"] = `schema: tessera.sod/v1
ruleset:
  key: payments
  name: Payments controls
  enabled: true
functions:
  - key: create
    name: Create a payment
    selectors: [{name_pattern: "payments:create*"}]
  - key: approve
    name: Approve a payment
    selectors: [{name_pattern: "payments:approve*"}]
risks:
  - key: pay-create-approve
    name: Create and approve a payment
    priority: high
    functions: [create, approve]
`
	sha := w.repo.push(files)
	resp := w.sync(w.ta1, sha, 201)
	kinds := resp["plan"].(map[string]any)["kinds"].([]any)
	if len(kinds) != 2 || kinds[0].(map[string]any)["kind"] != "roles" || kinds[1].(map[string]any)["kind"] != "sod" {
		t.Fatalf("plan kinds = %v", kinds)
	}
	if rec := reqDo(w.e.h, w.pa, "GET", "/api/sod/rulesets", ""); strings.Contains(rec.Body.String(), "Payments controls") {
		t.Fatal("the ruleset exists before approval")
	}
	w.approve(w.ta2, resp, 200)
	if rec := reqDo(w.e.h, w.pa, "GET", "/api/sod/rulesets", ""); !strings.Contains(rec.Body.String(), "Payments controls") {
		t.Fatalf("the ruleset was not applied: %s", rec.Body)
	}
	if l := w.last(); l["sha"] != sha || l["check_status"] != "verified" {
		t.Errorf("last synced = %v", l)
	}
	for _, a := range []string{"policy.roles.applied", "policy.sod.applied"} {
		if !w.audited(a) {
			t.Errorf("no %s event", a)
		}
	}
}

// Approval plans again: a request filed against a state that has since changed is refused with nothing applied, and the
// commit can be synced again.
func TestPolicySync_StalePlanAtApproval(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	resp := w.sync(w.ta1, shaB, 201)
	// someone changes the Engineer role in the UI while the request waits
	var roleID string
	list := reqDo(w.e.h, w.pa, "GET", "/api/roles", "")
	var roles struct {
		Roles []map[string]any `json:"roles"`
	}
	_ = json.Unmarshal(list.Body.Bytes(), &roles)
	for _, r := range roles.Roles {
		if r["name"] == "Engineer" {
			roleID = fmt.Sprint(r["id"])
		}
	}
	if roleID == "" {
		t.Fatalf("no engineer role in %s", list.Body)
	}
	b := w.e.f.B.IDs
	w.must(w.pa, "PUT", "/api/roles/"+roleID, fmt.Sprintf(`{"version":1,"name":"Engineer","risk":"high","requestable":true,"birthright":{"department":["Engineering"]},
		"entitlement_group_ids":[%d,%d]}`, b["group:okta:eng"], b["group:okta:payments-clerks"]), 200)
	digest := w.exportDigest()
	id, hash := w.change(resp)
	code, m := w.do(w.ta2, "POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash))
	if code != 409 || !strings.Contains(fmt.Sprint(m), "stale_plan") {
		t.Fatalf("approval of a stale plan = %d %v", code, m)
	}
	if w.exportDigest() != digest || w.last()["sha"] != w.shaA {
		t.Error("a stale request changed the state")
	}
}

// A policy.sync.apply payload of the caller's own, through the generic change request route, is refused: only the sync routes
// file it, because they read the commit from GitHub and check it is on the default branch.
func TestPolicySync_GenericRouteIsRefused(t *testing.T) {
	w := syncSetup(t)
	forged := map[string]any{"repo": "o/policy", "sha": strings.Repeat("f", 40), "kind": "sync", "default_branch": "main", "files": w.files,
		"bundle_sha256": strings.Repeat("0", 64), "plan_sha256": strings.Repeat("1", 64), "kinds": []any{},
		"prediction": map[string]any{"perms": []any{}, "perms_total": 1}}
	raw, _ := json.Marshal(map[string]any{"type": "policy.sync.apply", "payload": forged})
	if code, m := w.do(w.ta1, "POST", "/api/admin/change-requests", string(raw)); code != 400 || m["error"] != "use_sync_route" {
		t.Errorf("a forged payload through the generic route = %d %v", code, m)
	}
	if n := len(w.status()["syncs"].([]any)); n != 0 || w.last() != nil {
		t.Errorf("a forged request left a sync: %d", n)
	}
}

// A sync filed against an older last synced commit is refused when another sync applied since: an older commit never
// replaces a newer one.
func TestPolicySync_StaleBase(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	older := w.sync(w.ta1, shaB, 201)
	shaC := w.repo.push(w.files)
	newer := w.sync(w.ta1, shaC, 201)
	w.approve(w.ta2, newer, 200)
	w.approve(w.ta2, older, 409)
	if l := w.last(); l["sha"] != shaC {
		t.Errorf("last synced = %v, want the newer commit", l)
	}
	// and the newer one still holds its commit
	if again := w.sync(w.ta1, shaC, 200); again["status"] != "existing" {
		t.Errorf("repeat of the newer = %v", again)
	}
}

// After stale_base the refused request ends failed and syncing the same commit again files a new request that applies: the
// route must not return the dead request as "existing" (issue #793).
func TestPolicySync_StaleBaseCommitCanBeSyncedAgain(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	shaC := w.repo.push(w.files) // a descendant of B
	stale := w.sync(w.ta1, shaC, 201)
	w.syncAndApply(shaB) // another sync is applied while C waits
	w.approve(w.ta2, stale, 409)
	sid, _ := w.change(stale)
	if _, m := w.do(w.ta1, "GET", "/api/admin/change-requests/"+sid, ""); fmt.Sprint(m["status"]) != "failed" {
		t.Errorf("the stale request is %v, want failed", m["status"])
	}
	fresh := w.sync(w.ta1, shaC, 201)
	if fresh["status"] != "filed" {
		t.Fatalf("sync of the commit after stale_base = %v, want a fresh filed request", fresh)
	}
	if nid, _ := w.change(fresh); nid == sid {
		t.Fatal("the stale request was returned again")
	}
	w.approve(w.ta2, fresh, 200)
	if l := w.last(); l["sha"] != shaC {
		t.Errorf("last synced = %v, want the commit synced again", l)
	}
}

// A comparison that could not be complete is partial, never verified.
func TestPolicySync_PartialIsNotVerified(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	resp := w.sync(w.ta1, shaB, 201)
	saved := w.e.srv.admin.EffectivePolicies
	w.e.srv.admin.EffectivePolicies = nil // violations cannot be read
	defer func() { w.e.srv.admin.EffectivePolicies = saved }()
	w.approve(w.ta2, resp, 200)
	if l := w.last(); l["sha"] != shaB || l["check_status"] != "partial" || !strings.Contains(fmt.Sprint(l["check"]), "violations_not_checked") {
		t.Fatalf("last synced = %v", l)
	}
	if !w.audited("policy.sync.partial") {
		t.Error("no policy.sync.partial event")
	}
}

// A rollback is refused when the bundle at the commit is no longer the one Tessera applied.
func TestPolicySync_RollbackBundleChanged(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	shaB := w.repo.push(w.merged())
	w.syncAndApply(shaB)
	w.repo.mu.Lock()
	w.repo.commits[w.shaA]["roles/engineer.yaml"] += "# changed after the sync\n"
	w.repo.mu.Unlock()
	if code, m := w.do(w.ta1, "POST", "/api/policy/github/rollback", fmt.Sprintf(`{"to_sha":%q}`, w.shaA)); code != 409 || m["error"] != "rollback_bundle_changed" {
		t.Errorf("rollback to a changed commit = %d %v", code, m)
	}
}

// A bundle whose other kinds name something only the same bundle's new role would create fails closed when filed, with
// the diagnostic, and nothing is applied.
func TestPolicySync_ReferenceToANewRoleFailsClosed(t *testing.T) {
	w := syncSetup(t)
	w.syncAndApply(w.shaA)
	digest := w.exportDigest()
	files := w.merged()
	files["tessera.yaml"] = fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n    jit: partial\n", w.e.f.B.Slug)
	files["roles/support.yaml"] = "schema: tessera.role/v1\nkey: support\nname: Support\nrisk: low\nentitlements: [okta:eng]\n"
	files["jit/support.yaml"] = "schema: tessera.jit/v1\nkey: support-jit\nprincipals: [okta:support]\nentitlements: [okta:eng]\nmax_hours: 4\n"
	sha := w.repo.push(files)
	code, m := w.do(w.ta1, "POST", "/api/policy/github/sync", fmt.Sprintf(`{"sha":%q}`, sha))
	if code != 422 || m["error"] != "invalid_bundle" {
		t.Fatalf("a reference to a role of the same bundle = %d %v", code, m)
	}
	if w.exportDigest() != digest || w.last()["sha"] != w.shaA || len(w.status()["syncs"].([]any)) != 1 {
		t.Error("a refused bundle left state behind")
	}
}
