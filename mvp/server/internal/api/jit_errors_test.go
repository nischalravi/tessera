package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Issue #142: an unknown id is a 404, a state conflict on an existing record a
// 409, an over-long justification a 422 with its own code, and a second
// pending request for the same identity and group a 409.

func TestJITAndHRISUnknownIDIs404(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	for _, tc := range []struct{ path, detail string }{
		{"/api/jit/requests/9999/approve", "request not found"},
		{"/api/jit/requests/9999/deny", "request not found"},
		{"/api/jit/requests/9999/revoke", "request not found"},
		{"/api/hris/events/9999/execute", "event not found"},
	} {
		rec := corrDo(h, l, "POST", tc.path, "{}")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), tc.detail) {
			t.Errorf("POST %s: %d %s, want 404 %q", tc.path, rec.Code, rec.Body, tc.detail)
		}
	}
}

func TestJITAndHRISStateConflictIs409(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	req := f.B.IDs["request:pending"]
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/jit/requests/%d/deny", req), "{}"); rec.Code != 200 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	for _, tc := range []struct{ action, detail string }{
		{"approve", "request is not pending"}, {"deny", "request is not pending"}, {"revoke", "request is not active"},
	} {
		rec := corrDo(h, l, "POST", fmt.Sprintf("/api/jit/requests/%d/%s", req, tc.action), "{}")
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), tc.detail) {
			t.Errorf("%s a denied request: %d %s, want 409 %q", tc.action, rec.Code, rec.Body, tc.detail)
		}
	}
	ev := fmt.Sprintf("/api/hris/events/%d/execute", f.B.IDs["hris:joiner"])
	if rec := corrDo(h, l, "POST", ev, "{}"); rec.Code != 200 {
		t.Fatalf("execute: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, l, "POST", ev, "{}"); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already executed") {
		t.Errorf("execute again: %d %s, want 409", rec.Code, rec.Body)
	}
}

func jitBody(f *storetest.Fixture, justification string) string {
	return fmt.Sprintf(`{"identity_id":%d,"group_id":%d,"duration_hours":1,"justification":%q}`,
		f.B.IDs["alice"], f.B.IDs["group:aws:ProdAdmin"], justification)
}

func TestJITJustificationCap(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	// the fixture's pending request would make every create a duplicate
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/jit/requests/%d/deny", f.B.IDs["request:pending"]), "{}"); rec.Code != 200 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	over := corrDo(h, l, "POST", "/api/jit/requests", jitBody(f, strings.Repeat("a", jit.MaxJustification+1)))
	if over.Code != http.StatusUnprocessableEntity || !strings.Contains(over.Body.String(), `"error":"justification_too_long"`) {
		t.Errorf("max+1: %d %.200s, want 422 justification_too_long", over.Code, over.Body)
	}
	huge := corrDo(h, l, "POST", "/api/jit/requests", jitBody(f, strings.Repeat("a", 20000)))
	if huge.Code != http.StatusUnprocessableEntity {
		t.Errorf("20000 chars: %d, want 422", huge.Code)
	}
	if rec := corrDo(h, l, "POST", "/api/jit/requests", jitBody(f, strings.Repeat("a", jit.MaxJustification))); rec.Code != 200 {
		t.Errorf("max: %d %.200s, want 200", rec.Code, rec.Body)
	}
}

func TestJITDuplicatePendingIs409(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	// the fixture already holds a pending request for alice and ProdAdmin
	rec := corrDo(h, l, "POST", "/api/jit/requests", jitBody(f, "again"))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"error":"duplicate_pending_request"`) {
		t.Errorf("duplicate: %d %s, want 409 duplicate_pending_request", rec.Code, rec.Body)
	}
	// decided, the request no longer blocks a new one
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/jit/requests/%d/deny", f.B.IDs["request:pending"]), "{}"); rec.Code != 200 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, l, "POST", "/api/jit/requests", jitBody(f, "after denial")); rec.Code != 200 {
		t.Errorf("after denial: %d %s", rec.Code, rec.Body)
	}
}

func TestJITConcurrentDoubleSubmit(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	l := policyAdmin(t, f, f.B.ID, "pa@b.example")
	if rec := corrDo(h, l, "POST", fmt.Sprintf("/api/jit/requests/%d/deny", f.B.IDs["request:pending"]), "{}"); rec.Code != 200 {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = corrDo(h, l, "POST", "/api/jit/requests", jitBody(f, "double submit")).Code
		}()
	}
	close(start)
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case http.StatusConflict:
			conflict++
		}
	}
	if ok != 1 || conflict != n-1 {
		t.Errorf("codes %v: want exactly one 200 and %d 409", codes, n-1)
	}
}
