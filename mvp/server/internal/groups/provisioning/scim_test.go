package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// scimServer is a small SCIM 2.0 server: /Groups with paging and filters, GET,
// POST, PATCH (add, remove, replace; the op name is recorded) and DELETE.
type scimServer struct {
	*httptest.Server
	mu       sync.Mutex
	token    string
	groups   map[string]*scimGroupRec
	seq      int
	ver      int
	requests []string
	opNames  map[string]bool
	paths    map[string]bool
	// listMembers: list responses carry members (a generic server). Otherwise only GET /Groups/{id} does.
	listMembers bool
	// requireExternal: POST needs externalId (GitHub)
	requireExternal bool
	// patchSizes records the number of operations of each PATCH
	patchSizes []int
	// lastQuery is the query of the last list request
	lastQuery string
	// dropMembers: PATCH adds are accepted and forgotten
	dropMembers bool
}

type scimGroupRec struct {
	ID, Name, External string
	Members            []string
	Version            int
}

func newSCIM(t *testing.T, token string) *scimServer {
	s := &scimServer{token: token, groups: map[string]*scimGroupRec{}, opNames: map[string]bool{}, paths: map[string]bool{}, listMembers: true}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *scimServer) view(g *scimGroupRec, members bool) map[string]any {
	out := map[string]any{"schemas": []string{scimGroupSchema}, "id": g.ID, "displayName": g.Name,
		"meta": map[string]any{"version": fmt.Sprintf("W/\"%d\"", g.Version), "resourceType": "Group"}}
	if g.External != "" {
		out["externalId"] = g.External
	}
	if members {
		ms := []map[string]string{}
		for _, m := range g.Members {
			ms = append(ms, map[string]string{"value": m})
		}
		out["members"] = ms
	}
	return out
}

var filterEq = regexp.MustCompile(`^displayName eq "((?:[^"\\]|\\.)*)"$`)

func (s *scimServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		http.Error(w, "unauthorized: token "+r.Header.Get("Authorization"), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	path := strings.TrimPrefix(r.URL.Path, "/scim/v2")
	switch {
	case path == "/Groups" && r.Method == http.MethodGet:
		s.lastQuery = r.URL.RawQuery
		q := r.URL.Query()
		var all []*scimGroupRec
		for _, g := range s.groups {
			all = append(all, g)
		}
		slices.SortFunc(all, func(a, b *scimGroupRec) int { return strings.Compare(a.ID, b.ID) })
		if f := q.Get("filter"); f != "" {
			m := filterEq.FindStringSubmatch(f)
			if m == nil {
				http.Error(w, "bad filter", http.StatusBadRequest)
				return
			}
			want := strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[1])
			all = slices.DeleteFunc(all, func(g *scimGroupRec) bool { return !strings.EqualFold(g.Name, want) })
		}
		start, _ := strconv.Atoi(q.Get("startIndex"))
		count, _ := strconv.Atoi(q.Get("count"))
		if start < 1 {
			start = 1
		}
		var page []map[string]any
		for i := start - 1; i < len(all) && len(page) < count; i++ {
			page = append(page, s.view(all[i], s.listMembers && q.Get("excludedAttributes") != "members"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{scimListSchema}, "totalResults": len(all), "startIndex": start,
			"itemsPerPage": len(page), "Resources": page})
	case path == "/Groups" && r.Method == http.MethodPost:
		var in struct {
			DisplayName string `json:"displayName"`
			ExternalID  string `json:"externalId"`
			Members     []struct {
				Value string `json:"value"`
			} `json:"members"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if s.requireExternal && in.ExternalID == "" {
			http.Error(w, "externalId required", http.StatusBadRequest)
			return
		}
		for _, g := range s.groups {
			if strings.EqualFold(g.Name, in.DisplayName) {
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
		}
		s.seq++
		g := &scimGroupRec{ID: fmt.Sprintf("g-%03d", s.seq), Name: in.DisplayName, External: in.ExternalID, Version: 1}
		for _, m := range in.Members {
			g.Members = append(g.Members, m.Value)
		}
		s.groups[g.ID] = g
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(s.view(g, true))
	case strings.HasPrefix(path, "/Groups/"):
		g := s.groups[strings.TrimPrefix(path, "/Groups/")]
		if g == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(s.view(g, true))
		case http.MethodDelete:
			delete(s.groups, g.ID)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPatch:
			var in struct {
				Operations []struct {
					Op    string          `json:"op"`
					Path  string          `json:"path"`
					Value json.RawMessage `json:"value"`
				} `json:"Operations"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			s.patchSizes = append(s.patchSizes, len(in.Operations))
			for _, op := range in.Operations {
				s.opNames[op.Op] = true
				s.paths[op.Path] = true
				switch strings.ToLower(op.Op) {
				case "add":
					var vs []struct {
						Value string `json:"value"`
					}
					_ = json.Unmarshal(op.Value, &vs)
					for _, v := range vs {
						if !s.dropMembers && !slices.Contains(g.Members, v.Value) {
							g.Members = append(g.Members, v.Value)
						}
					}
				case "remove":
					if m := regexp.MustCompile(`^members\[value eq "(.*)"\]$`).FindStringSubmatch(op.Path); m != nil {
						g.Members = slices.DeleteFunc(g.Members, func(x string) bool { return x == m[1] })
						continue
					}
					var vs []struct {
						Value string `json:"value"`
					}
					_ = json.Unmarshal(op.Value, &vs)
					for _, v := range vs {
						g.Members = slices.DeleteFunc(g.Members, func(x string) bool { return x == v.Value })
					}
				case "replace":
					if op.Path == "externalId" {
						_ = json.Unmarshal(op.Value, &g.External)
					}
				}
			}
			g.Version++
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		http.Error(w, "no such endpoint", http.StatusNotFound)
	}
}

func devHTTP(t *testing.T) *http.Client {
	t.Helper()
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// scimHarness is a harness whose provisioners use the real SCIM target against s.
func scimHarness(t *testing.T, n int, s *scimServer, target map[string]any, extra map[string]any) (*harness, *store.Provisioner) {
	t.Helper()
	x := newHarness(t, n)
	x.svc.Open = nil
	x.svc.Deps = Deps{HTTP: devHTTP(t)}
	tg := map[string]any{"base_url": s.URL + "/scim/v2"}
	for k, v := range target {
		tg[k] = v
	}
	cfg := map[string]any{"member_ref": "{{.ExternalID}}", "group_name": `{{.Name | replace ":" "-"}}`, "target": tg}
	for k, v := range extra {
		cfg[k] = v
	}
	var p *store.Provisioner
	x.must(func(e model.Env) error {
		var err error
		p, err = x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "scim", TargetType: TypeSCIM2, Config: scimConfig(cfg),
			Secret: map[string]string{"token": s.token}})
		return err
	})
	return x, p
}

func (s *scimServer) members(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.groups {
		if g.Name == name {
			out := slices.Clone(g.Members)
			slices.Sort(out)
			return out
		}
	}
	return nil
}

func TestSCIM_GenericSync(t *testing.T) {
	s := newSCIM(t, "tok-generic-123")
	x, p := scimHarness(t, 130, s, map[string]any{"page_size": 2}, nil)
	var gs []store.GroupID
	for i := 0; i < 5; i++ {
		g := x.group(x.root, fmt.Sprintf("g%d", i))
		gs = append(gs, g)
		x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	}
	for i := 0; i < 130; i++ {
		x.add(gs[0], x.idents[i])
	}
	x.add(gs[1], x.idents[0])
	// someone else's group of the same kind exists on the server and must not be touched
	s.groups["other"] = &scimGroupRec{ID: "other", Name: "unrelated", Members: []string{"x"}, Version: 1}
	x.setMode(p.ID, store.ProvModeActive)

	rep := x.full(p.ID)
	if rep.Run.Status != store.RunDone || rep.Summary.Verified != 5 || rep.Summary.Drift+rep.Summary.Failed != 0 {
		t.Fatalf("run %s, summary %+v, ops %v", rep.Run.Status, rep.Summary, names(x.ops(p.ID, rep.Run.ID)))
	}
	if got := s.members("g0"); len(got) != 130 {
		t.Errorf("g0 has %d members, want 130", len(got))
	}
	if got := s.members("g1"); !slices.Equal(got, []string{"acc-0"}) {
		t.Errorf("g1 = %v", got)
	}
	if got := s.members("unrelated"); !slices.Equal(got, []string{"x"}) {
		t.Errorf("an unrelated group was touched: %v", got)
	}
	// a create carries 100 members, the rest comes in PATCH requests of at most 100
	if !slices.Contains(s.patchSizes, 1) || slices.Max(s.patchSizes) > 100 {
		t.Errorf("patch sizes = %v", s.patchSizes)
	}
	if !s.opNames["add"] || s.opNames["Add"] {
		t.Errorf("op names = %v, want lower-case for the generic profile", s.opNames)
	}

	// the full read pages through 6 groups with 2 per page
	s.mu.Lock()
	s.requests = nil
	s.mu.Unlock()
	x.tick(1)
	rep = x.full(p.ID)
	if rep.Summary.CacheHits != 5 || rep.Summary.Verified != 0 {
		t.Errorf("second run %+v, want 5 cache hits (unchanged meta.version) and no ops", rep.Summary)
	}

	// members removed on the server are put back; members that should go are removed with a filter path
	s.mu.Lock()
	for _, g := range s.groups {
		if g.Name == "g0" {
			g.Members = append(g.Members[:10:10], "stranger")
			g.Version++
		}
	}
	s.mu.Unlock()
	rep = x.full(p.ID)
	if rep.Summary.Verified != 1 || len(s.members("g0")) != 130 || slices.Contains(s.members("g0"), "stranger") {
		t.Errorf("repair: %+v, %d members", rep.Summary, len(s.members("g0")))
	}
	if !s.paths[`members[value eq "stranger"]`] {
		t.Errorf("remove paths = %v, want a members[value eq ...] filter", s.paths)
	}
}

func TestSCIM_Profiles(t *testing.T) {
	t.Run("github_emu", func(t *testing.T) {
		s := newSCIM(t, "tok-github")
		s.requireExternal = true
		x, p := scimHarness(t, 3, s, map[string]any{"profile": "github_emu"}, map[string]any{"attrs": map[string]string{"externalId": "{{.ID}}"}})
		g := x.group(x.root, "eng")
		x.add(g, x.idents[0])
		x.add(g, x.idents[1])
		x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
		x.setMode(p.ID, store.ProvModeActive)
		rep := x.full(p.ID)
		if rep.Summary.Verified != 1 {
			t.Fatalf("summary %+v, ops %v", rep.Summary, x.ops(p.ID, rep.Run.ID))
		}
		var ext string
		for _, gr := range s.groups {
			ext = gr.External
		}
		if ext != string(g) {
			t.Errorf("externalId = %q, want the group id", ext)
		}
		x.remove(g, x.idents[1])
		x.add(g, x.idents[2])
		x.incremental(p.ID)
		if !s.opNames["Add"] || !s.opNames["Remove"] || s.opNames["add"] {
			t.Errorf("op names = %v, want capitalised for GitHub", s.opNames)
		}
		if got := s.members("eng"); !slices.Equal(got, []string{"acc-0", "acc-2"}) {
			t.Errorf("members = %v", got)
		}
		// members are excluded from list responses
		if !strings.Contains(s.lastQuery, "excludedAttributes=members") {
			t.Errorf("list query = %q", s.lastQuery)
		}
		// the profile needs externalId
		if err := x.svc.ValidateConfig(TypeSCIM2, scimConfig(map[string]any{"target": map[string]any{"base_url": "https://h/scim", "profile": "github_emu"}}),
			map[string]string{"token": "x"}); err == nil {
			t.Error("a github_emu config without attrs.externalId was accepted")
		}
	})

	t.Run("aws_identity_center", func(t *testing.T) {
		s := newSCIM(t, "tok-aws")
		s.listMembers = false // a list does not carry members; GET /Groups/{id} does
		x, p := scimHarness(t, 3, s, map[string]any{"profile": "aws_identity_center", "page_size": 100}, nil)
		g := x.group(x.root, "eng")
		x.add(g, x.idents[0])
		x.add(g, x.idents[1])
		x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
		x.setMode(p.ID, store.ProvModeActive)
		if rep := x.full(p.ID); rep.Summary.Verified != 1 {
			t.Fatalf("summary %+v", rep.Summary)
		}
		x.remove(g, x.idents[0])
		rep := x.incremental(p.ID)
		if rep.Summary.Verified != 1 || !slices.Equal(s.members("eng"), []string{"acc-1"}) {
			t.Fatalf("summary %+v, members %v", rep.Summary, s.members("eng"))
		}
		if !s.paths["members"] {
			t.Errorf("paths = %v, want remove by path members and a value list", s.paths)
		}
		if _, err := parseSCIMConfig(mustCompileTarget(t, map[string]any{"base_url": "https://h/scim", "profile": "aws_identity_center", "page_size": 500})); err == nil {
			t.Error("a page size above the profile's limit was accepted")
		}
	})
}

func mustCompileTarget(t *testing.T, target map[string]any) *Compiled {
	t.Helper()
	c, err := ParseCommon(mustJSON(t, map[string]any{"account_system": "dir", "target": target}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSCIM_ErrorsNeverLeakCredentials(t *testing.T) {
	s := newSCIM(t, "tok-right-token-456")
	x, p := scimHarness(t, 2, s, nil, nil)
	g := x.group(x.root, "eng")
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive)
	// a wrong token: the server's error body repeats the Authorization header; the run's error must not
	x.must(func(e model.Env) error {
		pp, _ := e.Tx.Provisioner(p.ID)
		_, err := x.svc.Update(e.Tx, x.now, "t", p.ID, UpdateInput{Version: pp.Version, Secret: map[string]string{"token": "tok-wrong-token-789"}})
		return err
	})
	_, err := x.svc.Run(context.Background(), tid, p.ID, RunOptions{Kind: store.RunFull})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("run with a wrong token: %v", err)
	}
	for _, secret := range []string{"tok-wrong-token-789", "tok-right-token-456", "Bearer"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error %q leaks %q", err, secret)
		}
	}
	x.read(func(tx *store.TenantTx) error {
		runs, _ := tx.SyncRuns(p.ID, 10, 0)
		if len(runs) != 2 || runs[0].Status != store.RunFailed || strings.Contains(runs[0].Error, "tok-") {
			t.Errorf("runs = %+v", runs)
		}
		return nil
	})
}

func TestSCIM_UsesTheAddressGuard(t *testing.T) {
	s := newSCIM(t, "tok-guard")
	// a production client refuses loopback: the SCIM server on 127.0.0.1 is unreachable
	prod, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	x, p := scimHarness(t, 2, s, nil, nil)
	g := x.group(x.root, "eng")
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive)
	s.requests = nil
	x.svc.Deps.HTTP = prod
	_, err = x.svc.Run(context.Background(), tid, p.ID, RunOptions{Kind: store.RunFull})
	if err == nil {
		t.Fatal("a run reached a loopback address through the production client")
	}
	if len(s.requests) != 0 {
		t.Errorf("the server saw %v", s.requests)
	}
	// no client at all is an error, not http.DefaultClient
	x.svc.Deps.HTTP = nil
	if _, err := x.svc.Run(context.Background(), tid, p.ID, RunOptions{Kind: store.RunFull}); err == nil || len(s.requests) != 0 {
		t.Errorf("without a client: %v, requests %v", err, s.requests)
	}
}

func TestSCIM_QuotedNamesAndLostMembers(t *testing.T) {
	s := newSCIM(t, "tok-quote")
	x, p := scimHarness(t, 2, s, nil, map[string]any{"group_name": `{{.Extension}}`})
	g := x.group(x.root, "a.b")
	x.add(g, x.idents[0])
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive)
	// a server that forgets adds is drift, whatever it answers
	s.dropMembers = true
	x.full(p.ID)
	x.add(g, x.idents[1])
	rep := x.incremental(p.ID)
	if rep.Summary.Verified != 0 || rep.Summary.Drift == 0 {
		t.Errorf("summary %+v, want drift", rep.Summary)
	}
	if got := scimFilterValue(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("filter value = %s", got)
	}
}
