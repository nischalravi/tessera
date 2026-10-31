package api

import (
	"context"
	"crypto/sha1" // #nosec G505 -- a fake git blob id in a test double
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Right-sizing recommendations as pull requests and Terraform suggestions (issue #665, LP-9).

// gitRepo is the repository half of the GitHub fake (policy_github_test.go hands it the routes the token and check run
// code does not know): branches with files, commits, and pull requests. A blob id is the SHA-1 of the content, and a commit
// of an existing file must name the blob it replaces, as GitHub requires.
type gitRepo struct {
	blobs map[string]string // blob -> content
	trees map[string]map[string]string
	// race, when set, runs once just before the commit is created (the Git Data API), as another writer's push would
	race func(g *gitRepo)
	// pullHead, when set, is the head sha every pull request answer reports
	pullHead string
	mu       sync.Mutex
	branches map[string]string            // branch -> commit
	commits  map[string]map[string]string // commit -> path -> content
	parents  map[string]string            // commit -> its parent
	pulls    map[int]*fakePull
	next     int
	nCommits int
}

type fakePull struct {
	Author      string
	Number      int
	Branch      string
	Title, Body string
	State       string
}

func newGitRepo(files map[string]string) *gitRepo {
	g := &gitRepo{branches: map[string]string{}, commits: map[string]map[string]string{}, parents: map[string]string{}, blobs: map[string]string{}, trees: map[string]map[string]string{}, pulls: map[int]*fakePull{}, next: 40}
	g.branches["main"] = g.commit(files)
	return g
}

func (g *gitRepo) commit(files map[string]string) string {
	g.nCommits++
	cp := make(map[string]string, len(files))
	for k, v := range files {
		cp[k] = v
	}
	sum := sha1.Sum([]byte("commit-" + strconv.Itoa(g.nCommits))) // #nosec G401
	sha := hex.EncodeToString(sum[:])
	g.commits[sha] = cp
	return sha
}

func treeID(commit string) string {
	sum := sha1.Sum([]byte("tree-of-" + commit)) // #nosec G401
	return hex.EncodeToString(sum[:])
}

func blobID(content string) string {
	sum := sha1.Sum([]byte("blob " + content)) // #nosec G401
	return hex.EncodeToString(sum[:])
}

func (g *gitRepo) resolve(ref string) (map[string]string, bool) {
	if sha, ok := g.branches[ref]; ok {
		return g.commits[sha], true
	}
	f, ok := g.commits[ref]
	return f, ok
}

func (g *gitRepo) file(branch, path string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	f, _ := g.resolve(branch)
	return f[path]
}

func (g *gitRepo) openPulls() []*fakePull {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*fakePull
	for _, p := range g.pulls {
		if p.State == "open" {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

func (g *gitRepo) pullJSON(p *fakePull) map[string]any {
	return map[string]any{"number": p.Number, "state": p.State, "html_url": "https://github.com/o/policy/pull/" + strconv.Itoa(p.Number),
		"head": map[string]string{"sha": g.headOf(p)}, "user": map[string]string{"login": p.Author}}
}

func (g *gitRepo) headOf(p *fakePull) string {
	if g.pullHead != "" {
		return g.pullHead
	}
	return g.branches[p.Branch]
}

const repoBase = "/repos/o/policy"

// serve answers a repository route and reports whether it was one.
func (g *gitRepo) serve(r *http.Request, body map[string]any, send func(int, any)) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	path := r.URL.Path
	str := func(k string) string { s, _ := body[k].(string); return s }
	switch {
	case r.Method == http.MethodGet && path == repoBase:
		send(200, map[string]any{"default_branch": "main"})
	case r.Method == http.MethodGet && strings.HasPrefix(path, repoBase+"/git/ref/heads/"):
		sha, ok := g.branches[strings.TrimPrefix(path, repoBase+"/git/ref/heads/")]
		if !ok {
			send(404, map[string]string{"message": "Not Found"})
			return true
		}
		send(200, map[string]any{"object": map[string]string{"sha": sha}})
	case r.Method == http.MethodPost && path == repoBase+"/git/refs":
		name := strings.TrimPrefix(str("ref"), "refs/heads/")
		if _, ok := g.branches[name]; ok {
			send(422, map[string]string{"message": "Reference already exists"})
			return true
		}
		files, ok := g.commits[str("sha")]
		if !ok {
			send(422, map[string]string{"message": "Object does not exist"})
			return true
		}
		_ = files
		g.branches[name] = str("sha")
		send(201, map[string]any{"ref": str("ref")})
	case r.Method == http.MethodGet && strings.HasPrefix(path, repoBase+"/git/commits/"):
		sha := strings.TrimPrefix(path, repoBase+"/git/commits/")
		files, ok := g.commits[sha]
		if !ok {
			send(404, map[string]string{"message": "Not Found"})
			return true
		}
		tree := treeID(sha)
		g.trees[tree] = files
		send(200, map[string]any{"sha": sha, "tree": map[string]string{"sha": tree}})
	case r.Method == http.MethodPost && path == repoBase+"/git/blobs":
		raw, _ := base64.StdEncoding.DecodeString(str("content"))
		id := blobID(string(raw))
		g.blobs[id] = string(raw)
		send(201, map[string]string{"sha": id})
	case r.Method == http.MethodPost && path == repoBase+"/git/trees":
		files := map[string]string{}
		for k, v := range g.trees[str("base_tree")] {
			files[k] = v
		}
		entries, _ := body["tree"].([]any)
		for _, e := range entries {
			m, _ := e.(map[string]any)
			files[fmt.Sprint(m["path"])] = g.blobs[fmt.Sprint(m["sha"])]
		}
		sum := sha1.Sum([]byte(fmt.Sprint("tree", len(g.trees), files))) // #nosec G401
		id := hex.EncodeToString(sum[:])
		g.trees[id] = files
		send(201, map[string]string{"sha": id})
	case r.Method == http.MethodPost && path == repoBase+"/git/commits":
		if g.race != nil {
			f := g.race
			g.race = nil
			f(g)
		}
		ps, _ := body["parents"].([]any)
		parent := ""
		if len(ps) > 0 {
			parent = fmt.Sprint(ps[0])
		}
		sha := g.commit(g.trees[str("tree")])
		g.parents[sha] = parent
		send(201, map[string]any{"sha": sha, "parents": []map[string]string{{"sha": parent}}})
	case r.Method == http.MethodPatch && strings.HasPrefix(path, repoBase+"/git/refs/heads/"):
		b := strings.TrimPrefix(path, repoBase+"/git/refs/heads/")
		cur, ok := g.branches[b]
		force, _ := body["force"].(bool)
		if !ok || (!force && g.parents[str("sha")] != cur) {
			send(422, map[string]string{"message": "Update is not a fast forward"})
			return true
		}
		g.branches[b] = str("sha")
		send(200, map[string]any{"object": map[string]string{"sha": str("sha")}})
	case strings.HasPrefix(path, repoBase+"/contents/"):
		p := strings.TrimPrefix(path, repoBase+"/contents/")
		if r.Method == http.MethodGet {
			files, ok := g.resolve(r.URL.Query().Get("ref"))
			c, has := files[p]
			if !ok || !has {
				send(404, map[string]string{"message": "Not Found"})
				return true
			}
			send(200, map[string]any{"type": "file", "encoding": "base64", "size": len(c), "sha": blobID(c),
				"content": base64.StdEncoding.EncodeToString([]byte(c))})
			return true
		}
		branch := str("branch")
		files, ok := g.resolve(branch)
		if !ok {
			send(404, map[string]string{"message": "Branch not found"})
			return true
		}
		if blobID(files[p]) != str("sha") {
			send(409, map[string]string{"message": p + " does not match"})
			return true
		}
		raw, _ := base64.StdEncoding.DecodeString(str("content"))
		next := map[string]string{}
		for k, v := range files {
			next[k] = v
		}
		next[p] = string(raw)
		sha := g.commit(next)
		g.parents[sha] = g.branches[branch]
		g.branches[branch] = sha
		send(200, map[string]any{"commit": map[string]string{"sha": sha}})
	case r.Method == http.MethodGet && strings.HasPrefix(path, repoBase+"/compare/"):
		spec := strings.TrimPrefix(path, repoBase+"/compare/")
		b, h, _ := strings.Cut(spec, "...")
		baseFiles, ok1 := g.resolve(b)
		headFiles, ok2 := g.resolve(h)
		if !ok1 || !ok2 {
			send(404, map[string]string{"message": "Not Found"})
			return true
		}
		var files []map[string]string
		for p, c := range headFiles {
			if baseFiles[p] != c {
				files = append(files, map[string]string{"filename": p})
			}
		}
		headSHA := h
		if sha, ok := g.branches[h]; ok {
			headSHA = sha
		}
		ahead := 0
		for c := headSHA; c != g.branches[b] && c != ""; c = g.parents[c] {
			ahead++
		}
		status := "identical"
		if ahead > 0 {
			status = "ahead"
		}
		send(200, map[string]any{"ahead_by": ahead, "status": status, "files": files})
	case r.Method == http.MethodGet && path == repoBase+"/pulls":
		q := r.URL.Query()
		var out []any
		for _, p := range g.pulls {
			if p.State == q.Get("state") && "o:"+p.Branch == q.Get("head") {
				out = append(out, g.pullJSON(p))
			}
		}
		if out == nil {
			out = []any{}
		}
		send(200, out)
	case r.Method == http.MethodPost && path == repoBase+"/pulls":
		for _, p := range g.pulls {
			if p.State == "open" && p.Branch == str("head") {
				send(422, map[string]string{"message": "A pull request already exists"})
				return true
			}
		}
		g.next++
		p := &fakePull{Author: "tessera-app[bot]", Number: g.next, Branch: str("head"), Title: str("title"), Body: str("body"), State: "open"}
		g.pulls[p.Number] = p
		send(201, g.pullJSON(p))
	case strings.HasPrefix(path, repoBase+"/pulls/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(path, repoBase+"/pulls/"))
		p := g.pulls[n]
		if p == nil {
			return false // the check route's own pull request (7)
		}
		if r.Method == http.MethodPatch {
			p.Title, p.Body = str("title"), str("body")
		}
		send(200, g.pullJSON(p))
	default:
		return false
	}
	return true
}

// ---------------------------------------------------------------- the pull request

type lpPRWorld struct {
	t    *testing.T
	c    rdClient
	gh   *appGitHub
	repo *gitRepo
	rec  string // the recommendation id (an edge id)
	role string // the role's file
	file map[string]string
}

// lpPRSetup is the demo tenant with the GitHub App on, a business role that grants Esme Thornbury the Payroll
// Administrator group (she has not used it), and a repository holding the roles as Tessera exports them.
func lpPRSetup(t *testing.T) *lpPRWorld {
	t.Helper()
	gh, withGH := newAppGitHub(t, nil)
	c := newRD(t, withGH)
	_, pemKey := ghTestKey(t)
	put, _ := json.Marshal(map[string]any{"enabled": true, "app_id": "4242", "installation_id": 77, "repo": "o/policy", "private_key": pemKey})
	c.json("PUT", "/api/policy/github/app", string(put), 200)

	var gid, gid2, iid int64
	c.read(func(tx *store.TenantTx) error {
		gs, err := tx.Groups()
		if err != nil {
			return err
		}
		for _, g := range gs {
			if g.System == "workday" && g.Name == "Payroll Administrator" {
				gid = g.ID
			}
			if g.System == "workday" && g.Name == "AP Approver" {
				gid2 = g.ID
			}
		}
		ids, err := tx.Identities()
		for _, i := range ids {
			if i.Name == "Esme Thornbury" {
				iid = i.ID
			}
		}
		return err
	})
	if gid == 0 || gid2 == 0 || iid == 0 {
		t.Fatalf("demo data: groups %d %d identity %d", gid, gid2, iid)
	}
	role := c.json("POST", "/api/roles", fmt.Sprintf(`{"name":"Payroll ops","risk":"high","entitlement_group_ids":[%d,%d]}`, gid, gid2), 201)
	c.json("POST", "/api/roles/"+asString(role["role"].(map[string]any)["id"])+"/members", fmt.Sprintf(`{"identity_id":%d}`, iid), 200)

	exp := c.json("GET", "/api/policy/roles/export", "", 200)
	files := map[string]string{}
	for k, v := range exp["files"].(map[string]any) {
		files[k] = v.(string)
	}
	w := &lpPRWorld{t: t, c: c, gh: gh, file: files, role: "roles/payroll-ops.yaml"}
	if files[w.role] == "" {
		t.Fatalf("export has no %s: %v", w.role, keysOf(files))
	}
	w.repo = newGitRepo(files)
	gh.mu.Lock()
	gh.repo = w.repo
	gh.mu.Unlock()

	for _, r := range c.recs() {
		if r["identity_name"] == "Esme Thornbury" && strings.Contains(asString(r["grant"]), "Payroll Administrator") {
			w.rec = fmt.Sprint(r["id"])
			if r["kind"] != "remove" || r["permissions_lost"].(float64) < 1 {
				t.Fatalf("recommendation = %v, want a remove that loses permissions", r)
			}
		}
	}
	if w.rec == "" {
		t.Fatal("no recommendation for the role's grant")
	}
	return w
}

// audited reports whether an event of the action is in the audit log.
func (c rdClient) audited(action string) bool {
	c.t.Helper()
	rec := c.do("GET", "/api/audit?limit=1000", "")
	return rec.Code == 200 && strings.Contains(rec.Body.String(), `"`+action+`"`)
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c rdClient) recs() []map[string]any {
	c.t.Helper()
	rec := c.do("GET", "/api/least-privilege/recommendations", "")
	var v []map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		c.t.Fatalf("recommendations = %d %.200s", rec.Code, rec.Body)
	}
	return v
}

func (w *lpPRWorld) open(want int) map[string]any {
	w.t.Helper()
	rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
	if rec.Code != want {
		w.t.Fatalf("pull-request = %d, want %d: %.600s", rec.Code, want, rec.Body)
	}
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	return v
}

func TestLPRecPR_OpenThenUpdateInPlace(t *testing.T) {
	w := lpPRSetup(t)
	branch := "tessera/rightsize-grant-" + w.rec

	v := w.open(200)
	if v["status"] != "opened" || v["committed"] != true || v["branch"] != branch || v["file"] != w.role || v["entitlement"] != "workday:Payroll Administrator" ||
		v["base_branch"] != "main" || v["conclusion"] != "success" {
		t.Fatalf("answer = %v", v)
	}
	pulls := w.repo.openPulls()
	if len(pulls) != 1 || pulls[0].Branch != branch || int(v["pull_number"].(float64)) != pulls[0].Number {
		t.Fatalf("open pulls = %+v", pulls)
	}

	// the body names the recommendation, the identity, the entitlement and the simulation, and is never auto-merged
	body := pulls[0].Body
	for _, want := range []string{"<!-- tessera:lp-rightsize:v1 grant-" + w.rec + " -->", "`Esme Thornbury`", "`workday:Payroll Administrator`",
		"`payroll-ops`", "Identities losing access | 1 |", "Role members who lose it | 1 |", "never merges it", "60 days"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(pulls[0].Title, "@") || !strings.HasPrefix(pulls[0].Title, "Tessera: remove workday:Payroll Administrator from role payroll-ops") {
		t.Errorf("title = %q", pulls[0].Title)
	}

	// the branch holds the edited file: the entitlement is gone, nothing else changed, and main is untouched
	edited := w.repo.file(branch, w.role)
	if strings.Contains(edited, "Payroll Administrator") || !strings.Contains(w.repo.file("main", w.role), "Payroll Administrator") {
		t.Errorf("edited = %q, main = %q", edited, w.repo.file("main", w.role))
	}
	for p, c := range w.file {
		if p != w.role && w.repo.file(branch, p) != c {
			t.Errorf("%s changed on the branch", p)
		}
	}

	// the edited file loads as code, and its policy diff is the recommendation's loss
	branchFiles := map[string]string{}
	for p := range w.file {
		branchFiles[p] = w.repo.file(branch, p)
	}
	rawFiles, _ := json.Marshal(map[string]any{"files": branchFiles})
	w.c.json("POST", "/api/policy/roles/validate", string(rawFiles), 200)
	diff := w.c.json("POST", "/api/policy/diff", string(rawFiles), 200)["summary"].(map[string]any)
	var lost float64
	for _, r := range w.c.recs() {
		if fmt.Sprint(r["id"]) == w.rec {
			lost = r["permissions_lost"].(float64)
		}
	}
	if diff["graph_permissions_lost"].(float64) != lost || diff["identities_losing"].(float64) != 1 || diff["graph_permissions_gained"].(float64) != 0 {
		t.Errorf("policy diff on the branch = %v, want exactly the recommended loss of %v permissions", diff, lost)
	}

	// the App's token asked for contents:write besides checks and pull requests, for the one repository
	w.gh.mu.Lock()
	mint := w.gh.mintBody[len(w.gh.mintBody)-1]
	w.gh.mu.Unlock()
	perms, _ := mint["permissions"].(map[string]any)
	repos, _ := mint["repositories"].([]any)
	if len(perms) != 3 || perms["contents"] != "write" || perms["checks"] != "write" || perms["pull_requests"] != "write" || len(repos) != 1 || repos[0] != "policy" {
		t.Errorf("token request = %v, want contents, checks and pull_requests write on [policy]", mint)
	}
	// the AC-10 check run is on the pull request's head
	if len(w.gh.checks) != 1 {
		t.Fatalf("check runs = %v", w.gh.checks)
	}
	for _, chk := range w.gh.checks {
		if chk["head_sha"] != w.repo.branches[branch] || chk["conclusion"] != "success" {
			t.Errorf("check run = %v, head %s", chk, w.repo.branches[branch])
		}
	}

	// a second request is the same pull request, updated in place: no second PR, no new commit, the branch reused (422),
	// the check run updated
	commits := w.repo.nCommits
	again := w.open(200)
	if again["status"] != "updated" || again["committed"] != false || again["pull_number"] != v["pull_number"] || again["head_sha"] != v["head_sha"] {
		t.Fatalf("second answer = %v", again)
	}
	if len(w.repo.openPulls()) != 1 || w.repo.nCommits != commits || len(w.gh.checks) != 1 || w.gh.calls("POST "+repoBase+"/pulls") != 1 {
		t.Errorf("after the repeat: %d open pulls, %d commits (was %d), %d check runs, %d creates", len(w.repo.openPulls()), w.repo.nCommits, commits, len(w.gh.checks), w.gh.calls("POST "+repoBase+"/pulls"))
	}
	if again["body_sha256"] != v["body_sha256"] {
		t.Error("the body changed between identical requests")
	}

	// the mapping is stored and the event audited with the pull request
	w.c.read(func(tx *store.TenantTx) error {
		p, err := tx.LPRecPR("grant-"+w.rec, "o/policy")
		if err != nil || p == nil || p.State != store.LPRecPROpen || p.Branch != branch || float64(p.PullNumber) != v["pull_number"] || p.RoleKey != "payroll-ops" {
			t.Errorf("mapping = %+v, %v", p, err)
		}
		return nil
	})
	if !w.c.audited("lp.recommendation.pull_request") {
		t.Error("the pull request was not audited")
	}

	// a pull request that was closed gets a new one on the same branch: still one open
	w.repo.mu.Lock()
	w.repo.pulls[pulls[0].Number].State = "closed"
	w.repo.mu.Unlock()
	third := w.open(200)
	if third["status"] != "opened" || third["pull_number"] == v["pull_number"] || len(w.repo.openPulls()) != 1 || third["committed"] != false {
		t.Errorf("after closing: %v (%d open)", third, len(w.repo.openPulls()))
	}
}

func TestLPRecPR_Refusals(t *testing.T) {
	w := lpPRSetup(t)
	post := func(id, body string, want int, code string) {
		t.Helper()
		rec := w.c.do("POST", "/api/lp/recommendations/"+id+"/pull-request", body)
		if rec.Code != want || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("POST %s %s = %d %.300s, want %d %s", id, body, rec.Code, rec.Body, want, code)
		}
	}
	post("999999", "", 404, "recommendation_not_found")
	post("abc", "", 422, "invalid_recommendation_id")
	post("007", "", 422, "invalid_recommendation_id")
	post(w.rec, `{"unused_days":0.5}`, 422, "")
	post(w.rec, `{"unused_days":365}`, 422, "invalid_unused_days")
	post(w.rec, `{"nope":1}`, 422, "")
	// a connector-made grant is not defined by a role file; a right-size is a suggestion
	var connector, rightSize string
	for _, r := range w.c.recs() {
		if connector == "" && r["kind"] == "remove" && strings.Contains(asString(r["grant"]), "AP Clerk") {
			connector = fmt.Sprint(r["id"])
		}
		if rightSize == "" && r["kind"] == "right_size" {
			rightSize = fmt.Sprint(r["id"])
		}
	}
	if connector == "" {
		t.Fatal("no connector-made remove recommendation in the demo data")
	}
	post(connector, "", 422, "not_policy_managed")
	if rightSize != "" {
		post(rightSize, "", 422, "not_removable")
	}
	if len(w.gh.got) != 0 {
		t.Errorf("a refused request reached GitHub: %v", w.gh.got)
	}
	if len(w.repo.openPulls()) != 0 {
		t.Error("a pull request was opened")
	}
}

func TestLPRecPR_GitHubFailures(t *testing.T) {
	fail := func(t *testing.T, route string, status int, wantStatus int, wantCode, wantReason string) {
		t.Helper()
		w := lpPRSetup(t)
		w.gh.mu.Lock()
		w.gh.fail[route] = ghFail{status: status}
		w.gh.mu.Unlock()
		rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
		if rec.Code != wantStatus || !strings.Contains(rec.Body.String(), wantCode) || (wantReason != "" && !strings.Contains(rec.Body.String(), wantReason)) {
			t.Errorf("%s answering %d: %d %.300s, want %d %s %s", route, status, rec.Code, rec.Body, wantStatus, wantCode, wantReason)
		}
		if !w.c.audited("lp.recommendation.pull_request.failed") {
			t.Errorf("the failure was not audited")
		}
		if len(w.repo.openPulls()) != 0 {
			t.Errorf("a pull request exists after a failure before it")
		}
	}
	// 404 installation: the App was uninstalled
	fail(t, "POST /app/installations/77/access_tokens", 404, 502, "github_failed", "installation_not_found")
	// the installation has not accepted contents:write yet
	fail(t, "POST /app/installations/77/access_tokens", 422, 502, "github_failed", "installation_scope_mismatch")
	// the commit cannot be created
	fail(t, "POST "+repoBase+"/git/commits", 500, 502, "github_failed", "github_500")
	// a rate limit
	fail(t, "GET "+repoBase, 429, 503, "github_rate_limited", "")
}

func TestLPRecPR_RoleFileNotInRepo(t *testing.T) {
	w := lpPRSetup(t)
	w.repo.mu.Lock()
	delete(w.repo.commits[w.repo.branches["main"]], w.role)
	w.repo.mu.Unlock()
	if rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", ""); rec.Code != 422 || !strings.Contains(rec.Body.String(), "role_file_not_in_repo") {
		t.Fatalf("no file in the repository: %d %s", rec.Code, rec.Body)
	}
	// already removed in the repository: nothing to change
	w = lpPRSetup(t)
	w.repo.mu.Lock()
	main := w.repo.commits[w.repo.branches["main"]]
	main[w.role] = strings.ReplaceAll(main[w.role], "workday:Payroll Administrator", "workday:Other")
	w.repo.mu.Unlock()
	if rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "entitlement_not_in_repo") {
		t.Fatalf("entitlement already gone: %d %s", rec.Code, rec.Body)
	}
}

func TestLPRecPR_AppDisabledAndPermissions(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "alice")
	if rec := reqDo(h, viewer, "POST", "/api/lp/recommendations/5/pull-request", ""); rec.Code != 403 {
		t.Errorf("a viewer opened a pull request: %d", rec.Code)
	}
	if rec := reqDo(h, viewer, "GET", "/api/lp/revocations/"+store.NewID()+"/terraform", ""); rec.Code != 404 {
		t.Errorf("an unknown candidate: %d", rec.Code)
	}
	admin := ghAdmin(t, f, f.B, "admin@b.example")
	if rec := reqDo(h, admin, "POST", "/api/lp/recommendations/5/pull-request", ""); rec.Code != 409 && rec.Code != 503 {
		t.Errorf("App not configured: %d %s", rec.Code, rec.Body)
	}
	// without a recent phishing-resistant sign-in the route asks for one
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin, auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := reqDo(h, stale, "POST", "/api/lp/recommendations/5/pull-request", ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("without step-up: %d %.200s", rec.Code, rec.Body)
	}
}

// ---------------------------------------------------------------- terraform

func lpInsertCandidate(t *testing.T, w *awsWB, id, state, kind, conf, doc string) {
	t.Helper()
	const arn = "arn:aws:iam::111111111111:policy/team/App-Read"
	p, _ := json.Marshal(target.AWSChange{PolicyARN: arn, Document: doc, Prior: `{"Version":"2012-10-17","Statement":[]}`})
	testkit.Write(t, w.st, func(tx *store.TenantTx) error {
		return tx.InsertLPRevocation(&store.LPRevocation{ID: id, State: state, Kind: kind, Eligibility: store.LPEligItem,
			ConnectorID: "c", SnapshotID: "s", AccountID: "111111111111", Principal: "arn:aws:iam::111111111111:role/a", PolicyARN: arn,
			UnusedDays: 120, Confidence: conf, Evidence: `{"diff_summary":{"permissions_removed":3}}`, CandidateSHA256: strings.Repeat("a", 64),
			RestorePayload: string(p), RestoreSHA256: lp.DigestPayload(string(p)), CreatedBy: "x", CreatedAt: testkit.Now})
	})
}

const tfDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::team-${aws:username}/*"}]}`

func TestLPTerraform_GoldenAndRefusals(t *testing.T) {
	w := lpOn(t)
	lpInsertCandidate(t, w, "11111111-1111-4111-8111-111111111111", store.LPCandidate, target.AWSSetPolicyVersion, "high", tfDoc)
	v := w.c.json("GET", "/api/lp/revocations/11111111-1111-4111-8111-111111111111/terraform", "", 200).(map[string]any)
	got := asString(v["snippet"])
	golden := "../../testdata/lp9/terraform_policy.tf.golden"
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
		t.Errorf("snippet differs from %s:\n%s", golden, got)
	}
	if v["format"] != "hcl" || v["confidence"] != "high" || len(asString(v["snippet_sha256"])) != 64 || v["policy_arn"] != "arn:aws:iam::111111111111:policy/team/App-Read" {
		t.Errorf("answer = %v", v)
	}
	// the same candidate, the same text
	if again := w.c.json("GET", "/api/lp/revocations/11111111-1111-4111-8111-111111111111/terraform", "", 200).(map[string]any); again["snippet_sha256"] != v["snippet_sha256"] {
		t.Error("the snippet is not deterministic")
	}

	for name, tc := range map[string]struct {
		id, state, kind, conf string
		want                  int
		code                  string
	}{
		"already final":    {"44444444-4444-4444-8444-444444444444", store.LPFinalized, target.AWSSetPolicyVersion, "high", 409, "candidate_not_open"},
		"not a right-size": {"55555555-5555-4555-8555-555555555555", store.LPCandidate, target.AWSDetachPolicy, "high", 422, "not_a_right_size"},
	} {
		lpInsertCandidate(t, w, tc.id, tc.state, tc.kind, tc.conf, tfDoc)
		if rec := w.c.do("GET", "/api/lp/revocations/"+tc.id+"/terraform", ""); rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %.200s, want %d %s", name, rec.Code, rec.Body, tc.want, tc.code)
		}
	}
	// an AWS managed policy cannot be suggested
	lpInsertCandidate(t, w, "66666666-6666-4666-8666-666666666666", store.LPCandidate, target.AWSSetPolicyVersion, "high", "not json")
	if rec := w.c.do("GET", "/api/lp/revocations/66666666-6666-4666-8666-666666666666/terraform", ""); rec.Code != 422 {
		t.Errorf("a document that is not JSON: %d", rec.Code)
	}
}

// the end to end candidate of the loop has a suggestion too
func TestLPTerraform_ForAProposedCandidate(t *testing.T) {
	w := lpOn(t)
	c := w.lpPropose()
	v := w.c.json("GET", "/api/lp/revocations/"+asString(c["id"])+"/terraform", "", 200).(map[string]any)
	if s := asString(v["snippet"]); !strings.Contains(s, `resource "aws_iam_policy"`) || !strings.Contains(s, "<<-POLICY") || strings.Contains(s, "s3:PutObject") {
		t.Errorf("snippet = %s", s)
	}
}

// A role whose only entitlement is the recommended group is not edited into an invalid file.
func TestLPRecPR_RoleWouldBeEmpty(t *testing.T) {
	w := lpPRSetup(t)
	var roleID string
	w.c.read(func(tx *store.TenantTx) error {
		rs, err := tx.BusinessRoles()
		for _, r := range rs {
			if r.Key == "payroll-ops" {
				roleID = r.ID
			}
		}
		return err
	})
	var gid int64
	w.c.read(func(tx *store.TenantTx) error {
		gs, err := tx.Groups()
		for _, g := range gs {
			if g.System == "workday" && g.Name == "Payroll Administrator" {
				gid = g.ID
			}
		}
		return err
	})
	w.c.json("PUT", "/api/roles/"+roleID, fmt.Sprintf(`{"name":"Payroll ops","risk":"high","entitlement_group_ids":[%d],"version":1}`, gid), 200)
	if rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", ""); rec.Code != 422 || !strings.Contains(rec.Body.String(), "role_would_be_empty") {
		t.Fatalf("a role left empty: %d %.300s", rec.Code, rec.Body)
	}
}

// Tenant B cannot open a pull request for a grant of tenant A: the recommendation is computed from B's own graph, so an
// edge id that exists only in A is not found, and nothing reaches GitHub.
func TestLPRecPR_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	gh, withGH := newAppGitHub(t, nil)
	h := newIsolationServerWith(f, withGH).Handler()
	_, pemKey := ghTestKey(t)
	admins := map[string]authtest.Login{"A": ghAdmin(t, f, f.A, "admin@a.example"), "B": ghAdmin(t, f, f.B, "admin@b.example")}
	for _, l := range admins {
		putApp(t, h, l, pemKey, true)
	}
	// ids of grant edges that tenant A has and tenant B does not
	var onlyA []int64
	for id := int64(1); id < 400; id++ {
		var inA, inB bool
		_ = f.DB.ReadTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error { e, err := tx.Edge(id); inA = err == nil && e != nil; return nil })
		_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error { e, err := tx.Edge(id); inB = err == nil && e != nil; return nil })
		if inA && !inB {
			onlyA = append(onlyA, id)
		}
	}
	if len(onlyA) == 0 {
		t.Skip("the fixtures give no edge that only tenant A has")
	}
	for _, id := range onlyA {
		if rec := reqDo(h, admins["B"], "POST", "/api/lp/recommendations/"+strconv.FormatInt(id, 10)+"/pull-request", ""); rec.Code != 404 {
			t.Errorf("B opened a pull request for A's edge %d: %d %.200s", id, rec.Code, rec.Body)
		}
	}
	if len(gh.got) != 0 {
		t.Errorf("a refused request reached GitHub: %v", gh.got)
	}
}

// ---------------------------------------------------------------- nothing on the repository is trusted

// A branch of the name that someone else made, with a commit of their own, is refused: no pull request is touched and no
// check run is posted on their commit.
func TestLPRecPR_PreExistingBranchIsNotAdopted(t *testing.T) {
	for name, files := range map[string]func(w *lpPRWorld) map[string]string{
		"a commit that adds a file":              func(w *lpPRWorld) map[string]string { return map[string]string{"roles/admins.yaml": "schema: x\n"} },
		"a commit that edits only the role file": func(w *lpPRWorld) map[string]string { return map[string]string{w.role: "schema: tessera.role/v1\n"} },
	} {
		w := lpPRSetup(t)
		branch := "tessera/rightsize-grant-" + w.rec
		w.repo.mu.Lock()
		main := w.repo.branches["main"]
		extra := map[string]string{}
		for k, v := range w.repo.commits[main] {
			extra[k] = v
		}
		for k, v := range files(w) {
			extra[k] = v
		}
		evil := w.repo.commit(extra)
		w.repo.parents[evil] = main
		w.repo.branches[branch] = evil
		w.repo.mu.Unlock()

		rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), "branch_conflict") {
			t.Errorf("%s: %d %.300s, want 409 branch_conflict", name, rec.Code, rec.Body)
		}
		if len(w.repo.openPulls()) != 0 || len(w.gh.checks) != 0 || w.gh.calls("POST "+repoBase+"/git/commits") != 0 || w.gh.calls("PATCH "+repoBase+"/git/refs") != 0 || w.gh.calls("POST "+repoBase+"/git/refs") != 0 || w.repo.branches[branch] != evil {
			t.Errorf("%s: a pull request, a check run or a commit was made on the foreign branch", name)
		}
		if !w.c.audited("lp.recommendation.pull_request.failed") {
			t.Errorf("%s: the refusal was not audited", name)
		}
	}
}

// A branch that holds nothing of its own (at the base head) is used; a pull request on it that the App did not open is not.
func TestLPRecPR_ForeignPullRequestIsNotAdopted(t *testing.T) {
	w := lpPRSetup(t)
	branch := "tessera/rightsize-grant-" + w.rec
	w.repo.mu.Lock()
	w.repo.branches[branch] = w.repo.branches["main"]
	w.repo.next++
	w.repo.pulls[w.repo.next] = &fakePull{Author: "attacker", Number: w.repo.next, Branch: branch, Title: "theirs", Body: "theirs", State: "open"}
	n := w.repo.next
	w.repo.mu.Unlock()
	rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "pull_request_conflict") {
		t.Fatalf("%d %.300s, want 409 pull_request_conflict", rec.Code, rec.Body)
	}
	if p := w.repo.pulls[n]; p.Title != "theirs" || p.Body != "theirs" || len(w.gh.checks) != 0 || w.gh.calls("POST "+repoBase+"/git/commits") != 0 || w.gh.calls("PATCH "+repoBase+"/git/refs") != 0 || w.gh.calls("POST "+repoBase+"/git/refs") != 0 {
		t.Errorf("their pull request was touched: %+v, %d check runs", p, len(w.gh.checks))
	}
	// an empty branch of ours (made by a failed earlier request) is reused
	w2 := lpPRSetup(t)
	w2.repo.mu.Lock()
	w2.repo.branches["tessera/rightsize-grant-"+w2.rec] = w2.repo.branches["main"]
	w2.repo.mu.Unlock()
	w2.open(200)
}

// When the repository's role file is not what Tessera exports, the body says so and the check is neutral.
func TestLPRecPR_RepoFileDiffersIsStated(t *testing.T) {
	w := lpPRSetup(t)
	w.repo.mu.Lock()
	main := w.repo.commits[w.repo.branches["main"]]
	main[w.role] = strings.Replace(main[w.role], "description: \"\"", "description: edited in the repository", 1)
	w.repo.mu.Unlock()
	v := w.open(200)
	if v["conclusion"] != "neutral" {
		t.Errorf("conclusion = %v, want neutral", v["conclusion"])
	}
	if b := w.repo.openPulls()[0].Body; !strings.Contains(b, "differs from the one Tessera exports") {
		t.Errorf("body does not say the file differs:\n%s", b)
	}
}

// ---------------------------------------------------------------- the cap

func (w *lpPRWorld) reserve(n int) {
	w.t.Helper()
	w.c.write(func(tx *store.TenantTx) error {
		for i := 0; i < n; i++ {
			if ok, err := tx.ReserveLPRecPRAttempt("grant-0", "o/policy", "x", testkit.Now, testkit.Now.Add(-time.Hour), 1000); err != nil || !ok {
				return fmt.Errorf("reserve: %v %v", ok, err)
			}
		}
		return nil
	})
}

func (c rdClient) write(fn func(tx *store.TenantTx) error) {
	c.t.Helper()
	testkit.Write(c.t, c.st, fn)
}

// Every request counts: repeats and closed-then-repeat requests use attempts, and the cap refuses before GitHub is called
// and before the preview is computed.
func TestLPRecPR_AttemptCap(t *testing.T) {
	w := lpPRSetup(t)
	w.reserve(lpRecPRHourlyCap - 3)
	w.open(200)
	// close it and repeat: a new pull request, a new attempt
	first := w.repo.openPulls()[0].Number
	w.repo.mu.Lock()
	w.repo.pulls[first].State = "closed"
	w.repo.mu.Unlock()
	w.open(200)
	w.open(200) // a repeat is an attempt too
	calls := len(w.gh.got)
	rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "pull_request_rate_limited") || len(w.gh.got) != calls {
		t.Errorf("past the cap: %d %.200s (%d new GitHub calls)", rec.Code, rec.Body, len(w.gh.got)-calls)
	}
	w.c.read(func(tx *store.TenantTx) error {
		if n, err := tx.LPRecPRAttemptsSince(testkit.Now.Add(-time.Hour)); err != nil || n != lpRecPRHourlyCap {
			t.Errorf("attempts = %d, %v; want %d", n, err, lpRecPRHourlyCap)
		}
		return nil
	})
}

// A failed request counts, and concurrent requests cannot take more attempts than the cap allows.
func TestLPRecPR_AttemptCapConcurrentAndFailures(t *testing.T) {
	w := lpPRSetup(t)
	w.reserve(lpRecPRHourlyCap - 6)
	w.gh.mu.Lock()
	w.gh.fail["GET "+repoBase] = ghFail{status: 500}
	w.gh.mu.Unlock()
	if rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", ""); rec.Code != 502 {
		t.Fatalf("failing request = %d %.200s", rec.Code, rec.Body)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	limited := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
			if rec.Code == 429 {
				mu.Lock()
				limited++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	w.c.read(func(tx *store.TenantTx) error {
		if n, err := tx.LPRecPRAttemptsSince(testkit.Now.Add(-time.Hour)); err != nil || n != lpRecPRHourlyCap {
			t.Errorf("attempts = %d, %v; want exactly %d", n, err, lpRecPRHourlyCap)
		}
		return nil
	})
	if limited != 5 {
		t.Errorf("%d of 10 concurrent requests were limited, want 5 (one attempt was used by the failure, 5 by the rest)", limited)
	}
	if len(w.repo.openPulls()) > 1 {
		t.Errorf("%d open pull requests", len(w.repo.openPulls()))
	}
}

// A push that lands between the verification of the branch and Tessera's commit is not built on: the ref update is not a
// fast-forward, so it is refused, the other writer's commit stays the head, and nothing is posted or recorded.
func TestLPRecPR_BranchMovesDuringCommit(t *testing.T) {
	w := lpPRSetup(t)
	branch := "tessera/rightsize-grant-" + w.rec
	w.repo.mu.Lock()
	main := w.repo.branches["main"]
	w.repo.branches[branch] = main // an empty branch: it verifies
	var foreign string
	w.repo.race = func(g *gitRepo) {
		files := map[string]string{}
		for k, v := range g.commits[main] {
			files[k] = v
		}
		files["roles/admins.yaml"] = "schema: x\n"
		foreign = g.commit(files)
		g.parents[foreign] = main
		g.branches[branch] = foreign
	}
	w.repo.mu.Unlock()
	rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "branch_conflict") {
		t.Fatalf("%d %.300s, want 409 branch_conflict", rec.Code, rec.Body)
	}
	if w.repo.branches[branch] != foreign || len(w.repo.openPulls()) != 0 || len(w.gh.checks) != 0 {
		t.Errorf("the foreign head was replaced or built on: tip %s, %d pulls, %d checks", w.repo.branches[branch], len(w.repo.openPulls()), len(w.gh.checks))
	}
	w.c.read(func(tx *store.TenantTx) error {
		if p, err := tx.LPRecPR("grant-"+w.rec, "o/policy"); err != nil || p != nil {
			t.Errorf("a mapping was recorded: %+v, %v", p, err)
		}
		return nil
	})
}

// A new branch is created at the commit, not at the base: another writer who made the branch first is refused.
func TestLPRecPR_NewBranchTakenDuringCommit(t *testing.T) {
	w := lpPRSetup(t)
	branch := "tessera/rightsize-grant-" + w.rec
	w.repo.mu.Lock()
	main := w.repo.branches["main"]
	w.repo.race = func(g *gitRepo) { g.branches[branch] = main }
	w.repo.mu.Unlock()
	rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "branch_conflict") || len(w.repo.openPulls()) != 0 || len(w.gh.checks) != 0 {
		t.Fatalf("%d %.300s", rec.Code, rec.Body)
	}
}

// A pull request whose head is not the commit Tessera made or verified gets no check run and no record.
func TestLPRecPR_PullHeadMustBeOurs(t *testing.T) {
	w := lpPRSetup(t)
	w.repo.mu.Lock()
	w.repo.pullHead = strings.Repeat("b", 40)
	w.repo.mu.Unlock()
	rec := w.c.do("POST", "/api/lp/recommendations/"+w.rec+"/pull-request", "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "pull_request_conflict") || len(w.gh.checks) != 0 {
		t.Fatalf("%d %.300s", rec.Code, rec.Body)
	}
	w.c.read(func(tx *store.TenantTx) error {
		if p, err := tx.LPRecPR("grant-"+w.rec, "o/policy"); err != nil || p != nil {
			t.Errorf("a mapping was recorded: %+v, %v", p, err)
		}
		return nil
	})
}

// With several pull requests open on the branch, the App's own is the one updated; someone else's is left alone.
func TestLPRecPR_PicksTheAppsOwnAmongSeveral(t *testing.T) {
	w := lpPRSetup(t)
	branch := "tessera/rightsize-grant-" + w.rec
	w.repo.mu.Lock()
	w.repo.branches[branch] = w.repo.branches["main"]
	w.repo.pulls[90] = &fakePull{Author: "attacker", Number: 90, Branch: branch, Title: "theirs", Body: "theirs", State: "open"}
	w.repo.pulls[91] = &fakePull{Author: "tessera-app[bot]", Number: 91, Branch: branch, Title: "ours", Body: "old", State: "open"}
	w.repo.mu.Unlock()
	v := w.open(200)
	if v["pull_number"] != float64(91) || v["status"] != "updated" || w.repo.pulls[90].Title != "theirs" || w.repo.pulls[91].Body == "old" {
		t.Errorf("answer %v; theirs %+v", v, w.repo.pulls[90])
	}
}
