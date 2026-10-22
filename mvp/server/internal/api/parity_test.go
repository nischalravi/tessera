package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// FrozenNow is the clock the parity fixtures were recorded with.
var FrozenNow = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const fixtureDir = "../../testdata/parity"

type fixture struct {
	Name    string `json:"name"`
	Request struct {
		Method  string          `json:"method"`
		Path    string          `json:"path"`
		Body    json.RawMessage `json:"body"`
		RawBody *string         `json:"raw_body"`
	} `json:"request"`
	Response struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	} `json:"response"`
}

// The fixtures were recorded unauthenticated. Since PR5 every route except
// the public allow-list needs a session, so the replay signs in as this
// principal of larkspur: a tenant admin and policy admin (every permission
// the fixtures use), with a phishing-resistant authentication at the frozen
// time (every step-up requirement met). Its ids are fixed so the audit rows
// of 155-audit-final are reproducible; its email is the approver the Python
// backend recorded by default, so decided_by values match where the fixtures
// did not name another one (testdata/parity/README.md).
var (
	parityUser = authtest.User{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000c1"),
		Email: "security-oncall@larkspur.example", Display: "Security on-call",
		Roles: []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}}
	parityCtx = authtest.Ctx{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000c2"), AAL: 2, Phr: true}
	// parityRequester makes the fixtures' JIT requests (POST /api/jit/requests):
	// a requester never approves their own request, so the approvals the
	// fixtures record are by a different person (parityUser).
	parityRequester = authtest.User{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000c3"),
		Email: "requester@larkspur.example", Display: "Requester", Roles: []auth.Role{auth.RoleOperator}}
	parityRequesterCtx = authtest.Ctx{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000c4"), AAL: 2, Phr: true}
)

// paritySrv sends JIT request creation as parityRequester and everything
// else as parityUser.
type paritySrv struct {
	testSrv
	requester authtest.Login
}

func (s paritySrv) Handler() http.Handler {
	h := s.testSrv.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/jit/requests" && r.Header.Get("Cookie") == "" {
			r = r.Clone(r.Context())
			s.requester.Apply(r)
		}
		h.ServeHTTP(w, r)
	})
}

// newSeededServer seeds a fresh database exactly as the recorder did (the
// larkspur tenant only: integer ids are global across tenants, so a second
// tenant's rows would shift the ids the fixtures recorded for rows the replay
// creates) and returns a server for larkspur on the frozen clock, signed in
// as parityUser (JIT requests as parityRequester). The seed is testkit.Demo's,
// the same seed.Larkspur run at the same instant, copied from the
// once-per-binary template instead of re-run: ids and ledger are identical.
func newSeededServer(tb testing.TB) paritySrv {
	tb.Helper()
	if testkit.Now != FrozenNow {
		tb.Fatal("testkit.Now and FrozenNow must agree: the parity replay uses the testkit demo database")
	}
	return newServer(tb, testkit.Demo(tb).DB)
}

func newSeededServerWith(tb testing.TB, tenants func([]connectors.Connector) []seed.Tenant) paritySrv {
	tb.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, store.TestTarget(tb))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	pols, err := policy.NewLoader(policies.FS).Load()
	if err != nil {
		tb.Fatal(err)
	}
	conns, err := connectors.Load("demo", FrozenNow)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := seed.Run(ctx, st, FrozenNow, pols, tenants(conns)); err != nil {
		tb.Fatal(err)
	}
	return newServer(tb, st)
}

func newServer(tb testing.TB, st *store.DB) paritySrv {
	tb.Helper()
	loader := policy.NewLoader(policies.FS)
	srv := New(Config{
		Store: st, Clock: timeutil.Frozen(FrozenNow), Policies: loader,
		Connectors: func(time.Time) ([]connectors.Connector, error) { return connectors.Load("demo", FrozenNow) },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{authtest.Origin},
	})
	// the on-call decides reviews, so it is linked to a person of the demo
	// directory (a decider with no linked identity is refused, issue #439); a
	// Security Engineer with no review items of their own in the fixtures
	pu := parityUser
	pu.IdentityID = ensureIdentity(tb, st, seed.LarkspurID, "emp-1030", "emp-1030", FrozenNow)
	return paritySrv{testSrv{srv, authtest.LoginAs(tb, st, seed.LarkspurID, pu, parityCtx, FrozenNow)},
		authtest.LoginAs(tb, st, seed.LarkspurID, parityRequester, parityRequesterCtx, FrozenNow)}
}

func loadFixtures(tb testing.TB) []fixture {
	tb.Helper()
	files, err := filepath.Glob(filepath.Join(fixtureDir, "[0-9][0-9][0-9]-*.json"))
	if err != nil || len(files) == 0 {
		tb.Fatalf("no fixtures found in %s: %v", fixtureDir, err)
	}
	sort.Strings(files)
	out := make([]fixture, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- test fixtures from a fixed directory
		if err != nil {
			tb.Fatal(err)
		}
		var fx fixture
		if err := json.Unmarshal(data, &fx); err != nil {
			tb.Fatalf("%s: %v", f, err)
		}
		fx.Name = strings.TrimSuffix(filepath.Base(f), ".json")
		out = append(out, fx)
	}
	return out
}

func buildRequest(tb testing.TB, fx fixture) *http.Request {
	tb.Helper()
	var body io.Reader
	jsonBody := false
	switch {
	case fx.Request.RawBody != nil:
		body, jsonBody = strings.NewReader(*fx.Request.RawBody), true
	case len(fx.Request.Body) > 0:
		v, err := ojson.Decode(fx.Request.Body) // keep member order, as the recorder sent it
		if err != nil {
			tb.Fatal(err)
		}
		b, err := ojson.Marshal(v)
		if err != nil {
			tb.Fatal(err)
		}
		body, jsonBody = bytes.NewReader(b), true
	}
	req := httptest.NewRequest(fx.Request.Method, fx.Request.Path, body)
	if jsonBody {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

var simEvtID = regexp.MustCompile(`^(sim-evt-\d+)-\d+$`)

var (
	auditHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidV4    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// normalizeAuditValue applies rule 3 (testdata/parity/README.md): audit event
// ids and request ids are random UUIDs, and the event hashes cover them.
func normalizeAuditValue(key string, v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	switch {
	case (key == "hash" || key == "prev_hash") && (auditHash.MatchString(s) || s == "<hash>"):
		return "<hash>"
	case (key == "event_id" || key == "request_id") && (uuidV4.MatchString(s) || s == "<uuid>"):
		return "<uuid>"
	}
	return v
}

// normalize applies the documented normalisation rules (see testdata/parity/README.md).
func normalize(v any) any {
	switch x := v.(type) {
	case string:
		return simEvtID.ReplaceAllString(x, "$1-<ts>")
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	case ojson.Object:
		for i := range x {
			x[i].Value = normalizeAuditValue(x[i].Key, normalize(x[i].Value))
			if x[i].Key == "violations" {
				if vo, ok := x[i].Value.(ojson.Object); ok {
					for j := range vo {
						if vo[j].Key == "resolved" || vo[j].Key == "introduced" {
							sortByKey(vo[j].Value)
						}
					}
				}
			}
		}
		return x
	}
	return v
}

func sortByKey(v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	key := func(e any) string {
		if o, ok := e.(ojson.Object); ok {
			if k, ok := o.Get("key"); ok {
				s, _ := k.(string)
				return s
			}
		}
		return ""
	}
	sort.SliceStable(arr, func(i, j int) bool { return key(arr[i]) < key(arr[j]) })
}

// diff returns a description of the first difference, "" when equal. Object
// member order and number spelling are compared exactly.
func diff(path string, want, got any) string {
	switch w := want.(type) {
	case ojson.Object:
		g, ok := got.(ojson.Object)
		if !ok {
			return fmt.Sprintf("%s: want object, got %T", path, got)
		}
		for i := 0; i < len(w) || i < len(g); i++ {
			if i >= len(w) {
				return fmt.Sprintf("%s: unexpected key %q", path, g[i].Key)
			}
			if i >= len(g) {
				return fmt.Sprintf("%s: missing key %q", path, w[i].Key)
			}
			if w[i].Key != g[i].Key {
				return fmt.Sprintf("%s: key #%d want %q got %q", path, i, w[i].Key, g[i].Key)
			}
			if d := diff(path+"."+w[i].Key, w[i].Value, g[i].Value); d != "" {
				return d
			}
		}
		return ""
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Sprintf("%s: want array, got %T", path, got)
		}
		for i := 0; i < len(w) && i < len(g); i++ {
			if d := diff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i]); d != "" {
				return d
			}
		}
		if len(w) != len(g) {
			return fmt.Sprintf("%s: want %d items, got %d", path, len(w), len(g))
		}
		return ""
	}
	if fmt.Sprintf("%T:%v", want, want) != fmt.Sprintf("%T:%v", got, got) {
		if pgIDsMayDiffer(path, want, got) {
			return ""
		}
		return fmt.Sprintf("%s: want %#v, got %#v", path, want, got)
	}
	return ""
}

// pgIDsMayDiffer: on Postgres (TESSERA_TEST_PG_URL) integer ids come from
// sequences, which are not gapless: an upsert that finds its row (every
// re-sync) still consumes a value, where SQLite's rowid reuses it. So the
// numeric value of an "id" or "edge_id" member may differ there; everything
// else, including the shape and the order of the response, must still match.
// The SQLite run compares them exactly.
func pgIDsMayDiffer(path string, want, got any) bool {
	if store.PostgresTestURL() == "" || !(strings.HasSuffix(path, ".id") || strings.HasSuffix(path, ".edge_id")) {
		return false
	}
	num := regexp.MustCompile(`^[0-9]+$`)
	return num.MatchString(fmt.Sprint(want)) && num.MatchString(fmt.Sprint(got))
}

// replay checks one fixture against h.
func replay(t *testing.T, h http.Handler, fx fixture) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, buildRequest(t, fx))
	if rec.Code != fx.Response.Status {
		t.Fatalf("status: want %d, got %d; body: %.400s", fx.Response.Status, rec.Code, rec.Body.String())
	}
	var wantStr string
	if json.Unmarshal(fx.Response.Body, &wantStr) == nil { // text body (docs pages)
		if got := rec.Body.String(); got != wantStr {
			t.Fatalf("text body differs:\nwant %.300q\ngot  %.300q", wantStr, got)
		}
		return
	}
	want, err := ojson.Decode(fx.Response.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ojson.Decode(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("response is not JSON: %v: %.300s", err, rec.Body.String())
	}
	if d := diff("$", normalize(want), normalize(got)); d != "" {
		t.Fatal(d)
	}
}

func TestParity(t *testing.T) {
	t.Parallel() // its own database; the replay inside stays in fixture order
	fixtures := loadFixtures(t)
	h := newSeededServer(t).Handler()
	passed := 0
	for _, fx := range fixtures {
		if t.Run(fx.Name, func(t *testing.T) { replay(t, h, fx) }) {
			passed++
		}
	}
	t.Logf("parity: %d/%d fixtures passed", passed, len(fixtures))
}

// TestParity_SecondTenantPresent seeds the default tenants (larkspur, then
// globex) and replays, as larkspur, every fixture up to the first request
// that changes data: with another tenant's data in the same tables, larkspur's
// responses must be byte-for-byte what a single-tenant database returns.
// (After the first write, newly allocated integer ids differ, because ids are
// global across tenants; the isolation tests cover that part.)
func TestParity_SecondTenantPresent(t *testing.T) {
	t.Parallel() // its own database
	fixtures := loadFixtures(t)
	h := newSeededServerWith(t, func(conns []connectors.Connector) []seed.Tenant {
		return seed.DefaultTenants(conns, FrozenNow)
	}).Handler()
	n := 0
	for _, fx := range fixtures {
		if fx.Request.Method != http.MethodGet && fx.Response.Status == http.StatusOK && !readOnlyPost(fx) {
			break
		}
		t.Run(fx.Name, func(t *testing.T) { replay(t, h, fx) })
		n++
	}
	if n < 60 {
		t.Fatalf("only %d fixtures replayed before the first write", n)
	}
	t.Logf("parity with a second tenant: %d fixtures replayed", n)
}

// readOnlyPost reports whether a POST only computes (a simulation or a
// dry-run revoke) and changes no data.
func readOnlyPost(fx fixture) bool {
	switch fx.Request.Path {
	case "/api/simulate":
		return true
	case "/api/least-privilege/revoke":
		var body struct {
			DryRun *bool `json:"dry_run"`
		}
		return json.Unmarshal(fx.Request.Body, &body) == nil && (body.DryRun == nil || *body.DryRun)
	}
	return false
}
