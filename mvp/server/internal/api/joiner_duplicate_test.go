package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Issue #138: a joiner whose email or HR id belongs to an active identity is
// refused with 409 identity_exists, at creation and (authoritatively) at execution.

func seedIdentity(t *testing.T, st *testkit.DB, xid, email, status string) int64 {
	t.Helper()
	var id int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id, err = c.InsertIdentity(&store.Identity{ExternalID: xid, Name: "Existing " + xid, Email: &email, Type: "human",
			Status: status, CreatedAt: testkit.Now})
		return err
	})
	return id
}

func pendingJoiner(t *testing.T, st *testkit.DB, ext, email, hrID string) int64 {
	t.Helper()
	p := ojson.Object{{Key: "name", Value: "Noor Achterberg"}, {Key: "email", Value: email}}
	if hrID != "" {
		p = append(p, ojson.KV{Key: "employee_id", Value: hrID})
	}
	var id int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: ext, Type: "joiner", Payload: p, EffectiveAt: testkit.Now, Status: "pending"})
		return err
	})
	return id
}

func identityCount(t *testing.T, st *testkit.DB, name string) (all, active int) {
	t.Helper()
	for _, i := range testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Identity, error) { return c.Identities() }) {
		if i.Name == name {
			all++
			if i.Status == "active" {
				active++
			}
		}
	}
	return all, active
}

func refusals(t *testing.T, st *testkit.DB) (out []*store.AuditEvent) {
	t.Helper()
	for _, e := range ledger(t, st.DB, st.Tenant) {
		if e.Action == "jml.joiner.refused" {
			out = append(out, e)
		}
	}
	return out
}

func wantExists(t *testing.T, rec *httptest.ResponseRecorder, existing int64, on string) {
	t.Helper()
	body := strings.ReplaceAll(rec.Body.String(), " ", "")
	for _, s := range []string{`"error":"identity_exists"`, fmt.Sprintf(`"existing_identity_id":%d`, existing), `"matched_on":"` + on + `"`} {
		if !strings.Contains(body, s) {
			t.Errorf("body %.300s lacks %s", body, s)
		}
	}
	if rec.Code != http.StatusConflict {
		t.Errorf("status %d, want 409", rec.Code)
	}
}

func TestJoinerDuplicateRefusedAtCreation(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	existing := seedIdentity(t, st, "emp-70", "Noor.Achterberg@Larkspur.example", "active")
	tests := []struct{ name, body, on string }{
		{"email in another case", `{"type":"joiner","payload":{"name":"Noor Achterberg","email":" noor.achterberg@LARKSPUR.example "}}`, "email"},
		{"hr id", `{"type":"joiner","payload":{"name":"N A","email":"other@larkspur.example","employee_id":"emp-70"}}`, "hr_id"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := c.do("POST", "/api/hris/events", tt.body)
			wantExists(t, rec, existing, tt.on)
			if n := len(refusals(t, st)); n != i+1 {
				t.Errorf("refusal events = %d, want %d", n, i+1)
			}
		})
	}
	if evs := c.json("GET", "/api/hris/events", "", 200).([]any); len(evs) != 0 {
		t.Errorf("a refused event was persisted: %v", evs)
	}
}

func TestJoinerDuplicateRefusedAtExecution(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	existing := seedIdentity(t, st, "emp-70", "Noor.Achterberg@Larkspur.example", "active")
	byEmail := pendingJoiner(t, st, "e-1", "noor.achterberg@larkspur.example", "")
	byHR := pendingJoiner(t, st, "e-2", "other@larkspur.example", "emp-70")
	for i, ev := range []struct {
		id int64
		on string
	}{{byEmail, "email"}, {byHR, "hr_id"}} {
		rec := c.do("POST", fmt.Sprintf("/api/hris/events/%d/execute", ev.id), "")
		wantExists(t, rec, existing, ev.on)
		rs := refusals(t, st)
		if len(rs) != i+1 || !strings.Contains(string(rs[0].Detail), fmt.Sprintf(`"event_id":%d`, ev.id)) {
			t.Errorf("refusal events = %d (%v), want %d naming event %d", len(rs), rs, i+1, ev.id)
		}
		// the event stays pending, so the operator can resolve and retry
		evs := c.json("GET", "/api/hris/events", "", 200).([]any)
		for _, e := range evs {
			if at(e, "id") == float64(ev.id) && at(e, "status") != "pending" {
				t.Errorf("event %d is %v after a refusal", ev.id, at(e, "status"))
			}
		}
	}
	if all, _ := identityCount(t, st, "Noor Achterberg"); all != 0 {
		t.Errorf("a refused joiner created %d identities", all)
	}
}

func TestJoinerRehireAfterLeaverAPI(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	seedIdentity(t, st, "emp-80", "noor.achterberg@larkspur.example", "terminated")
	body := `{"type":"joiner","payload":{"name":"Noor Achterberg","email":"Noor.Achterberg@larkspur.example","employee_id":"emp-80"}}`
	ev := c.json("POST", "/api/hris/events", body, 200)
	c.json("POST", fmt.Sprintf("/api/hris/events/%v/execute", at(ev, "id")), "", 200)
	if _, active := identityCount(t, st, "Noor Achterberg"); active != 1 {
		t.Errorf("active rehired identities = %d, want 1", active)
	}
	// the repro from the issue: a second joiner for the same email is now refused
	c.json("POST", "/api/hris/events", body, http.StatusConflict)
}

func TestJoinerConcurrentDoubleExecute(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	ids := []int64{
		pendingJoiner(t, st, "e-1", "noor.achterberg@larkspur.example", ""),
		pendingJoiner(t, st, "e-2", "NOOR.ACHTERBERG@larkspur.example", ""),
		pendingJoiner(t, st, "e-3", "other@larkspur.example", "emp-95"),
		pendingJoiner(t, st, "e-4", "another@larkspur.example", "emp-95"),
	}
	codes := make([]int, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = c.do("POST", fmt.Sprintf("/api/hris/events/%d/execute", id), "").Code
		}()
	}
	wg.Wait()
	for pair := 0; pair < 4; pair += 2 {
		ok, conflict := 0, 0
		for _, code := range codes[pair : pair+2] {
			switch code {
			case 200:
				ok++
			case http.StatusConflict:
				conflict++
			}
		}
		if ok != 1 || conflict != 1 {
			t.Errorf("events %d/%d: statuses %v, want one 200 and one 409", ids[pair], ids[pair+1], codes[pair:pair+2])
		}
	}
	if all, active := identityCount(t, st, "Noor Achterberg"); all != 2 || active != 2 {
		t.Errorf("identities created = %d (%d active), want one per distinct person (2)", all, active)
	}
}
