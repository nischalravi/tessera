package api

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/benchgen"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The REST half of the groups scale gate (issue #60, GR-17; design section 6.7):
// the same generated tenant as `tessera-bench groups`, read and written through
// the HTTP handler as an administrator, so that routing, authorization, the
// audit event of every request and the JSON are in the numbers (the network is
// not). TestGroupsScaleGate_RESTSmall runs the harness on a tiny tenant in every
// `go test` and asserts only that each route answers; the gate proper is
//
//	TESSERA_GROUPS_SCALE_GATE=1 [TESSERA_GROUPS_SCALE_PERCENT=10] go test -run TestGroupsScaleGate_REST$ -timeout 2h ./internal/api
func TestGroupsScaleGate_RESTSmall(t *testing.T) {
	rep := runRESTScale(t, 0.05, 15)
	if len(rep.Results) != 7 {
		t.Errorf("%d results, want 7: %+v", len(rep.Results), rep.Results)
	}
}

func TestGroupsScaleGate_REST(t *testing.T) {
	if os.Getenv("TESSERA_GROUPS_SCALE_GATE") != "1" {
		t.Skip("set TESSERA_GROUPS_SCALE_GATE=1 to run the scale gate")
	}
	percent := 10.0
	if v, err := strconv.ParseFloat(os.Getenv("TESSERA_GROUPS_SCALE_PERCENT"), 64); err == nil && v > 0 {
		percent = v
	}
	rep := runRESTScale(t, percent, 500)
	for _, r := range rep.Failed() {
		t.Errorf("%s missed its target: %.4g %s against %g %s", r.Design, r.Value, r.Unit, r.Limit, r.Unit)
	}
}

func runRESTScale(t *testing.T, percent float64, samples int) *benchgen.Report {
	t.Helper()
	ctx := context.Background()
	f := storetest.TwoTenants(t)
	tn, err := benchgen.Generate(ctx, f.DB, f.B.ID, benchgen.Spec{Percent: percent, Samples: samples,
		Now: func() time.Time { return storetest.Now }, Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	c := grpClient{client{t, asAdmin(t, newIsolationServer(f), f.DB, f.B.ID, storetest.Now).Handler()}}
	ids := func(i int) int64 { return tn.Idents[(i*7919)%len(tn.Idents)] }
	rep := &benchgen.Report{Percent: percent, Backend: "sqlite, REST", Stats: tn.Stats.String(), Started: time.Now().UTC()}
	add := func(r benchgen.Result) { rep.Results = append(rep.Results, r) }
	measure := func(n int, fn func(i int)) []time.Duration {
		ds := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			fn(i)
			ds = append(ds, time.Since(start))
		}
		return ds
	}
	ok := func(method, path, body string) {
		t.Helper()
		if rec := c.do(method, path, body); rec.Code >= 300 {
			t.Fatalf("%s %s = %d %.200s", method, path, rec.Code, rec.Body.String())
		}
	}
	heavy := max(5, samples/10)

	add(benchgen.Latency("rest_has_member", "GET /api/groups/{id}/members/{identity}: hasMember", "p99", 0.99, 5,
		measure(samples, func(i int) { ok("GET", fmt.Sprintf("/api/groups/%s/members/%d", tn.Leaf, ids(i)), "") }), ""))
	add(benchgen.Latency("rest_members_first_page", "GET /api/groups/{id}/members: first page of 100 by name", "p95", 0.95, 100,
		measure(heavy, func(int) {
			ok("GET", "/api/groups/"+string(tn.Top)+"/members?filter=effective&sort=name&limit=100", "")
		}),
		"a nested group; the reference group's page is in the engine numbers"))
	add(benchgen.Latency("rest_identity_groups", "GET /api/identities/{id}/groups", "p95", 0.95, 80,
		measure(samples, func(i int) { ok("GET", fmt.Sprintf("/api/identities/%d/groups?limit=500", ids(i)), "") }), ""))
	add(benchgen.Latency("rest_folder_browser", "GET /api/groups/native?folder=: a folder with 5,000 children the user can VIEW", "p95", 0.95, 300,
		measure(heavy, func(int) {
			ok("GET", "/api/groups/native?limit=100&folder="+url.QueryEscape(string(tn.BrowseFolder)), "")
		}),
		fmt.Sprintf("%d children, an administrator (the privilege filter runs)", tn.Stats.Counts.Browse)))
	var adds, removes []time.Duration
	for i := 0; i < samples; i++ {
		ident := ids(i)
		start := time.Now()
		ok("POST", "/api/groups/"+string(tn.Tail)+"/members", fmt.Sprintf(`{"identity":%d}`, ident))
		adds = append(adds, time.Since(start))
		start = time.Now()
		ok("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", tn.Tail, ident), "")
		removes = append(removes, time.Since(start))
	}
	add(benchgen.Latency("rest_single_add", "POST /api/groups/{id}/members: single add, effective state on the response", "p95", 0.95, 75, adds,
		"at the bottom of a chain of 12 groups"))
	add(benchgen.Latency("rest_single_remove", "DELETE /api/groups/{id}/members/{member}: single remove", "p95", 0.95, 75, removes,
		"at the bottom of a chain of 12 groups"))
	// members as of an instant, every page of the reference group
	start := time.Now()
	asOf := url.QueryEscape(storetest.Now.Format(time.RFC3339))
	pages := 0
	for off := 0; ; off += 500 {
		rec := c.do("GET", fmt.Sprintf("/api/groups/%s/members?as_of=%s&limit=500&offset=%d", tn.Ref, asOf, off), "")
		if rec.Code != 200 {
			t.Fatalf("as_of page %d = %d %.200s", off, rec.Code, rec.Body.String())
		}
		pages++
		if off+500 >= tn.Stats.Counts.Ref {
			break
		}
	}
	add(benchgen.Total("rest_pit_members_as_of", `GET /api/groups/{id}/members?as_of=: members as of T for the reference group`, 2*time.Second, time.Since(start),
		fmt.Sprintf("all %d members in %d pages of 500", tn.Stats.Counts.Ref, pages)))
	var md bytes.Buffer
	_ = rep.Markdown(&md)
	t.Log("\n" + md.String())
	if out := os.Getenv("TESSERA_GROUPS_SCALE_REST_MD"); out != "" {
		if err := os.WriteFile(out, md.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return rep
}
