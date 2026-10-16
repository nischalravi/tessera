package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func sqlHarness(t *testing.T, n int, file string) (*harness, *store.Provisioner, string) {
	t.Helper()
	x := newHarness(t, n)
	dir := t.TempDir()
	x.svc.Open = nil
	x.svc.Deps = Deps{SQLDir: dir}
	var p *store.Provisioner
	x.must(func(e model.Env) error {
		var err error
		p, err = x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "sql", TargetType: TypeSQL,
			Config: mustJSON(t, map[string]any{"account_system": "dir", "group_name": `{{.Name | replace ":" "-"}}`,
				"target": map[string]any{"file": file}})})
		return err
	})
	return x, p, dir
}

func TestSQLTarget(t *testing.T) {
	x, p, dir := sqlHarness(t, 4, "members.db")
	g1, g2 := x.group(x.root, "eng"), x.group(x.root, "ops")
	x.add(g1, x.idents[0])
	x.add(g1, x.idents[1])
	x.add(g2, x.idents[2])
	for _, g := range []store.GroupID{g1, g2} {
		x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	}
	x.setMode(p.ID, store.ProvModeActive)

	// rows other applications wrote are not Tessera's: a group Tessera does not own is never touched
	db, err := store.OpenExtSQLite(context.Background(), dir, tid, "members.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Apply(context.Background(), []store.ExtPair{{Group: "legacy", Member: "someone"}}, nil); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	rep := x.full(p.ID)
	if rep.Run.Status != store.RunDone || rep.Summary.Verified != 2 || rep.Summary.Drift+rep.Summary.Failed != 0 {
		t.Fatalf("run %s %+v", rep.Run.Status, rep.Summary)
	}
	read := func() map[string][]string {
		db, err := store.OpenExtSQLite(context.Background(), dir, tid, "members.db")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, err := db.Members(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if got := read(); !equalState(got, map[string][]string{"eng": {"u0", "u1"}, "ops": {"u2"}, "legacy": {"someone"}}) {
		t.Fatalf("rows = %v", got)
	}

	x.remove(g1, x.idents[0])
	x.add(g1, x.idents[3])
	x.incremental(p.ID)
	if got := read(); !equalState(got, map[string][]string{"eng": {"u1", "u3"}, "ops": {"u2"}, "legacy": {"someone"}}) {
		t.Fatalf("rows after the change = %v", got)
	}

	// a group that is no longer provisioned loses its rows (deleting a group needs approval)
	x.must(func(e model.Env) error { return x.svc.RemoveMark(e.Tx, x.now, "t", p.ID, "group", string(g2)) })
	if rep = x.full(p.ID); rep.Run.Status != store.RunHeld {
		t.Fatalf("run %s, want held: the group would be deleted", rep.Run.Status)
	}
	x.must(func(e model.Env) error { return x.svc.RequestFull(e.Tx, x.now, "admin", p.ID, true) })
	if rep = x.full(p.ID); rep.Run.Status != store.RunDone {
		t.Fatalf("run %s %+v", rep.Run.Status, rep.Summary)
	}
	if got := read(); !equalState(got, map[string][]string{"eng": {"u1", "u3"}, "legacy": {"someone"}}) {
		t.Fatalf("rows after the group was removed = %v", got)
	}
}

func TestSQLTarget_Containment(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for _, bad := range []string{"../x.db", "a/b.db", "x.txt", ".hidden.db", "", "x.db/../y.db", strings.Repeat("a", 70) + ".db", "x y.db"} {
		if db, err := store.OpenExtSQLite(ctx, dir, tid, bad); err == nil {
			_ = db.Close()
			t.Errorf("file name %q was accepted", bad)
		}
	}
	if _, err := store.OpenExtSQLite(ctx, "", tid, "x.db"); err == nil {
		t.Error("an unset directory was accepted")
	}
	// Tessera's own database is refused, even if it is put in the directory
	if err := os.MkdirAll(filepath.Join(dir, tid.String()), 0o750); err != nil {
		t.Fatal(err)
	}
	own, err := store.Open(ctx, filepath.Join(dir, tid.String(), "own.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = own.Close()
	if db, err := store.OpenExtSQLite(ctx, dir, tid, "own.db"); err == nil {
		_ = db.Close()
		t.Error("a database holding Tessera's tables was accepted as a target")
	}
	// a SQL target is not available unless the operator enabled it
	x := newHarness(t, 1)
	x.svc.Open = nil
	err = x.run(func(e model.Env) error {
		_, err := x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "sql", TargetType: TypeSQL,
			Config: mustJSON(t, map[string]any{"account_system": "dir", "target": map[string]any{"file": "m.db"}})})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "TESSERA_GROUPS_PROV_SQL_DIR") {
		t.Errorf("a SQL target without a directory: %v", err)
	}
	// statements are parameterised: hostile values are data
	if _, err := store.OpenExtSQLite(ctx, dir, tenancy.ID{}, "m.db"); err == nil {
		t.Error("a zero tenant was accepted")
	}
	db, err := store.OpenExtSQLite(ctx, dir, tid, "m.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evil := `x'); DROP TABLE tessera_group_members; --`
	if err := db.Apply(ctx, []store.ExtPair{{Group: evil, Member: evil}}, nil); err != nil {
		t.Fatal(err)
	}
	if rows, err := db.Members(ctx, []string{evil}); err != nil || len(rows[evil]) != 1 {
		t.Errorf("rows = %v, %v", rows, err)
	}
	if _, err := os.Stat(filepath.Join(dir, tid.String(), "m.db")); err != nil {
		t.Error(err)
	}
}

// Two tenants naming the same file get different files: neither reads the
// other's rows, and a sync in one never deletes the other's.
func TestSQLTarget_TenantScopedFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tidB := tenancy.MustParse("00000000-0000-4000-8000-0000000000d9")
	open := func(tn tenancy.ID) Provisioner {
		c := mustCompile(t, nil)
		c.Target = mustJSON(t, map[string]any{"file": "groups.db"})
		p, err := openSQL(ctx, TargetSpec{Tenant: tn, Type: TypeSQL, Common: c, Deps: Deps{SQLDir: dir}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	a, b := open(tid), open(tidB)
	if _, err := a.Apply(ctx, []Op{{ID: "1", Kind: OpMembers, Ref: TargetRef{Name: "eng"}, Add: []string{"alice", "bob"}}}); err != nil {
		t.Fatal(err)
	}
	if st, _ := b.ReadAll(ctx, Scope{}); len(st.Groups) != 0 {
		t.Fatalf("tenant B reads tenant A's rows: %v", st.Groups)
	}
	if st, _ := b.Read(ctx, []TargetRef{{Name: "eng"}}); len(st.Groups) != 0 {
		t.Fatalf("tenant B reads tenant A's group: %v", st.Groups)
	}
	// B's "sync": it adds its own member and removes whatever it thinks is stale
	if _, err := b.Apply(ctx, []Op{{ID: "2", Kind: OpMembers, Ref: TargetRef{Name: "eng"}, Add: []string{"carol"}, Remove: []string{"alice", "bob"}}}); err != nil {
		t.Fatal(err)
	}
	stA, _ := a.ReadAll(ctx, Scope{})
	if got := stA.Groups["eng"]; got == nil || len(got.Members) != 2 {
		t.Fatalf("tenant A's rows after B's sync = %+v", got)
	}
	stB, _ := b.ReadAll(ctx, Scope{})
	if got := stB.Groups["eng"]; got == nil || len(got.Members) != 1 || got.Members[0] != "carol" {
		t.Fatalf("tenant B's rows = %+v", got)
	}
	for _, tn := range []tenancy.ID{tid, tidB} {
		if st, err := os.Stat(filepath.Join(dir, tn.String())); err != nil || st.Mode().Perm()&0o007 != 0 {
			t.Errorf("tenant directory %s: %v", tn, err)
		}
	}
}

// Two provisioners of one tenant may not write the same file.
func TestSQLTarget_FileInUse(t *testing.T) {
	x, p, _ := sqlHarness(t, 1, "shared.db")
	create := func(name, file string) error {
		return x.run(func(e model.Env) error {
			_, err := x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: name, TargetType: TypeSQL,
				Config: mustJSON(t, map[string]any{"account_system": "dir", "target": map[string]any{"file": file}})})
			return err
		})
	}
	var inUse *FileInUseError
	if err := create("second", "shared.db"); !errors.As(err, &inUse) {
		t.Fatalf("a second provisioner on the same file = %v, want FileInUseError", err)
	}
	if err := create("third", "other.db"); err != nil {
		t.Fatal(err)
	}
	// changing a provisioner onto a taken file is refused too; keeping its own file is not
	err := x.run(func(e model.Env) error {
		cur, _ := e.Tx.Provisioner(p.ID)
		_, err := x.svc.Update(e.Tx, x.now, "t", p.ID, UpdateInput{Version: cur.Version,
			Config: mustJSON(t, map[string]any{"account_system": "dir", "target": map[string]any{"file": "other.db"}})})
		return err
	})
	if !errors.As(err, &inUse) {
		t.Errorf("moving onto a taken file = %v", err)
	}
	err = x.run(func(e model.Env) error {
		cur, _ := e.Tx.Provisioner(p.ID)
		_, err := x.svc.Update(e.Tx, x.now, "t", p.ID, UpdateInput{Version: cur.Version,
			Config: mustJSON(t, map[string]any{"account_system": "dir", "target": map[string]any{"file": "shared.db"}})})
		return err
	})
	if err != nil {
		t.Errorf("an unchanged file: %v", err)
	}
}

// ---------------------------------------------------------------- webhook

type hook struct {
	*httptest.Server
	mu       sync.Mutex
	secret   string
	got      []hookEvent
	state    map[string][]string
	status   int
	badSig   int
	readable bool
	reads    int
}

type hookEvent struct {
	Header http.Header
	Body   []byte
}

func newHook(t *testing.T, secret string) *hook {
	h := &hook{secret: secret, state: map[string][]string{}, status: 200}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		// verify the signature the way a receiver would
		sig := r.Header.Get(SignatureHeader)
		ts, v1, _ := strings.Cut(strings.TrimPrefix(sig, "t="), ",v1=")
		var tm int64
		for _, c := range ts {
			tm = tm*10 + int64(c-'0')
		}
		if want := Sign([]byte(h.secret), time.Unix(tm, 0), body); sig != want || v1 == "" {
			h.badSig++
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/read" {
			h.reads++
			var in struct {
				Groups []string `json:"groups"`
			}
			_ = json.Unmarshal(body, &in)
			var out []map[string]any
			for name, members := range h.state {
				if in.Groups == nil || slices.Contains(in.Groups, name) {
					out = append(out, map[string]any{"name": name, "members": members})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"groups": out})
			return
		}
		h.got = append(h.got, hookEvent{r.Header.Clone(), body})
		if h.status != 200 {
			w.WriteHeader(h.status)
			return
		}
		var ev webhookEvent
		_ = json.Unmarshal(body, &ev)
		if h.readable {
			ms := h.state[ev.Subject]
			for _, m := range ev.Data.Remove {
				ms = slices.DeleteFunc(ms, func(x string) bool { return x == m })
			}
			for _, m := range ev.Data.Add {
				if !slices.Contains(ms, m) {
					ms = append(ms, m)
				}
			}
			if ev.Data.Op == "delete" {
				delete(h.state, ev.Subject)
			} else {
				h.state[ev.Subject] = ms
			}
		}
	}))
	t.Cleanup(h.Close)
	return h
}

func hookHarness(t *testing.T, h *hook, readURL string) (*harness, *store.Provisioner, store.GroupID) {
	t.Helper()
	x := newHarness(t, 3)
	x.svc.Open = nil
	x.svc.Deps = Deps{HTTP: devHTTP(t)}
	target := map[string]any{"url": h.URL + "/hook/path-token-abc"}
	if readURL != "" {
		target["read_url"] = h.URL + readURL
	}
	var p *store.Provisioner
	x.must(func(e model.Env) error {
		var err error
		p, err = x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "hook", TargetType: TypeWebhook,
			Config: mustJSON(t, map[string]any{"account_system": "dir", "group_name": "{{.Extension}}", "target": target}),
			Secret: map[string]string{"signing_secret": h.secret}})
		return err
	})
	g := x.group(x.root, "eng")
	x.add(g, x.idents[0])
	x.add(g, x.idents[1])
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive)
	return x, p, g
}

func TestWebhook_SignedAndVerifiedByReadback(t *testing.T) {
	h := newHook(t, "a-long-signing-secret")
	h.readable = true
	x, p, g := hookHarness(t, h, "/read")
	rep := x.full(p.ID)
	if rep.Run.Status != store.RunDone || rep.Summary.Verified != 1 || rep.Summary.Unverifiable {
		t.Fatalf("run %s %+v", rep.Run.Status, rep.Summary)
	}
	if h.badSig != 0 || len(h.got) != 1 {
		t.Fatalf("%d deliveries, %d with a bad signature", len(h.got), h.badSig)
	}
	ev := h.got[0]
	if ct := ev.Header.Get("Content-Type"); ct != "application/cloudevents+json" {
		t.Errorf("content type %q", ct)
	}
	ops := x.ops(p.ID, rep.Run.ID)
	if ev.Header.Get(DeliveryHeader) != ops[0].ID {
		t.Errorf("delivery id %q, want the op id %q", ev.Header.Get(DeliveryHeader), ops[0].ID)
	}
	var ce webhookEvent
	if err := json.Unmarshal(ev.Body, &ce); err != nil || ce.SpecVersion != "1.0" || ce.Type != "io.tessera.groups.provision.create" ||
		ce.Subject != "eng" || ce.Data.Group != "eng" || !slices.Equal(ce.Data.Add, []string{"u0", "u1"}) || ce.ID != ops[0].ID {
		t.Errorf("event = %+v, %v", ce, err)
	}
	// the signature covers the body: a changed body does not verify
	sig := ev.Header.Get(SignatureHeader)
	if !strings.HasPrefix(sig, "t=") || !strings.Contains(sig, ",v1=") {
		t.Fatalf("signature %q", sig)
	}
	secs := strings.TrimPrefix(strings.SplitN(sig, ",", 2)[0], "t=")
	var unix int64
	for _, c := range secs {
		unix = unix*10 + int64(c-'0')
	}
	if Sign([]byte("a-long-signing-secret"), time.Unix(unix, 0), append(ev.Body, ' ')) == sig {
		t.Error("the signature does not cover the body")
	}
	if Sign([]byte("another-signing-secret"), time.Unix(unix, 0), ev.Body) == sig {
		t.Error("the signature does not depend on the secret")
	}
	x.remove(g, x.idents[0])
	if rep := x.incremental(p.ID); rep.Summary.Verified != 1 || !slices.Equal(h.state["eng"], []string{"u1"}) {
		t.Errorf("summary %+v, state %v", rep.Summary, h.state)
	}
}

func TestWebhook_WithoutReadEndpointOpsStayApplied(t *testing.T) {
	h := newHook(t, "a-long-signing-secret")
	x, p, g := hookHarness(t, h, "")
	rep := x.full(p.ID)
	if rep.Summary.Verified != 0 || rep.Summary.Applied != 1 || !rep.Summary.Unverifiable {
		t.Fatalf("summary %+v, want one applied and no verified op", rep.Summary)
	}
	if ops := x.ops(p.ID, rep.Run.ID); ops[0].Status != store.OpApplied || ops[0].VerifiedAt != nil {
		t.Errorf("op = %+v", ops[0])
	}
	// the next full sync diffs against what the receiver was told: nothing to send
	h.got = nil
	rep = x.full(p.ID)
	if len(h.got) != 0 || rep.Summary.Applied != 0 {
		t.Errorf("a repeat sync sent %d events, summary %+v", len(h.got), rep.Summary)
	}
	x.add(g, x.idents[2])
	rep = x.incremental(p.ID)
	if len(h.got) != 1 || rep.Summary.Applied != 1 {
		t.Errorf("%d events, summary %+v", len(h.got), rep.Summary)
	}
}

func TestWebhook_FailuresDoNotLeakTheURL(t *testing.T) {
	h := newHook(t, "a-long-signing-secret")
	h.status = 500
	x, p, _ := hookHarness(t, h, "")
	rep := x.full(p.ID)
	if rep.Summary.Failed != 1 {
		t.Fatalf("summary %+v", rep.Summary)
	}
	ops := x.ops(p.ID, rep.Run.ID)
	if ops[0].Status != store.OpFailed || !strings.Contains(ops[0].Error, "500") || strings.Contains(ops[0].Error, "path-token-abc") || strings.Contains(ops[0].Error, h.URL) {
		t.Errorf("op = %+v", ops[0])
	}
	// a closed port: the transport error has no URL either
	h.Close()
	x.tick(RetryAfter + time.Minute)
	rep, err := x.svc.Run(context.Background(), tid, p.ID, RunOptions{Kind: store.RunFull})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range x.ops(p.ID, rep.Run.ID) {
		if strings.Contains(op.Error, "path-token-abc") || strings.Contains(op.Error, h.URL) {
			t.Errorf("op error %q leaks the URL", op.Error)
		}
	}
}

func TestWebhook_Config(t *testing.T) {
	x := newHarness(t, 1)
	x.svc.Open = nil
	create := func(secret map[string]string, target map[string]any) error {
		return x.run(func(e model.Env) error {
			_, err := x.svc.Create(e.Tx, x.now, "t", CreateInput{Name: "h" + time.Now().Format("150405.000000"), TargetType: TypeWebhook,
				Config: mustJSON(t, map[string]any{"account_system": "dir", "target": target}), Secret: secret})
			return err
		})
	}
	ok := map[string]any{"url": "https://hooks.example.com/x"}
	good := map[string]string{"signing_secret": "0123456789abcdef"}
	if err := create(good, ok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		secret map[string]string
		target map[string]any
	}{
		"no secret":       {nil, ok},
		"short secret":    {map[string]string{"signing_secret": "short"}, ok},
		"a url with user": {good, map[string]any{"url": "https://u:p@hooks.example.com/x"}},
		"not a url":       {good, map[string]any{"url": "hooks.example.com"}},
		"ftp":             {good, map[string]any{"url": "ftp://hooks.example.com"}},
		"a query string":  {good, map[string]any{"url": "https://hooks.example.com/x?token=abc"}},
		"unknown field":   {good, map[string]any{"url": "https://h/x", "headers": "x"}},
		"foreign secret":  {map[string]string{"signing_secret": "0123456789abcdef", "token": "x"}, ok},
	} {
		t.Run(name, func(t *testing.T) {
			if err := create(c.secret, c.target); err == nil {
				t.Error("accepted")
			}
		})
	}
}
