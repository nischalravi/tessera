package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Access-review rules: a decided item is final (issue #137) and campaign
// input is bounded (issue #136).

func reviewEvents(c rdClient, action string) []*store.AuditEvent {
	var out []*store.AuditEvent
	for _, e := range ledger(c.t, c.st.DB, c.st.Tenant) {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// itemState is the item's stored decision and whether its grant edge is still live.
func itemState(c rdClient, id int64) (decision string, edgeLive bool) {
	c.read(func(tx *store.TenantTx) error {
		it, err := tx.Item(id)
		if err != nil {
			return err
		}
		if it.Decision != nil {
			decision = *it.Decision
		}
		_, err = tx.EdgeBetween(it.EdgeSrc, it.EdgeDst) // a revoked grant is deleted
		edgeLive = err == nil
		return nil
	})
	return decision, edgeLive
}

func TestReviewDecisionIsFinal(t *testing.T) {
	tests := []struct {
		name         string
		first        string
		second       string
		wantSecond   int
		wantDecision string
		wantEdgeLive bool
		refused      int // review.decide.refused events
	}{
		{"keep after revoke is refused", "revoke", "keep", 409, "revoke", false, 1},
		{"revoke after keep is refused", "keep", "revoke", 409, "keep", true, 1},
		{"same revoke is idempotent", "revoke", "revoke", 200, "revoke", false, 0},
		{"same keep is idempotent", "keep", "keep", 200, "keep", true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newRD(t)
			const path = "/api/reviews/items/1/decision"
			c.json("POST", path, fmt.Sprintf(`{"decision":%q}`, tc.first), 200)
			kept := len(reviewEvents(c, "review."+tc.first))
			rec := c.do("POST", path, fmt.Sprintf(`{"decision":%q,"comment":"changed my mind"}`, tc.second))
			if rec.Code != tc.wantSecond {
				t.Fatalf("second decision: status %d, want %d: %s", rec.Code, tc.wantSecond, rec.Body.String())
			}
			if tc.wantSecond == 409 {
				body := rec.Body.String()
				if !strings.Contains(body, `"error":"review_item_decided"`) || !strings.Contains(body, `"decision":"`+tc.first+`"`) {
					t.Errorf("409 body = %s", body)
				}
			}
			if d, live := itemState(c, 1); d != tc.wantDecision || live != tc.wantEdgeLive {
				t.Errorf("item = %q, edge live %v; want %q, %v", d, live, tc.wantDecision, tc.wantEdgeLive)
			}
			if n := len(reviewEvents(c, "review.decide.refused")); n != tc.refused {
				t.Errorf("review.decide.refused events = %d, want %d", n, tc.refused)
			}
			if n := len(reviewEvents(c, "review."+tc.first)); n != kept {
				t.Errorf("review.%s events went from %d to %d: a repeat must not write a second decision", tc.first, kept, n)
			}
			// the refused or repeated request leaves the recorded decision's comment alone
			var comment *string
			c.read(func(tx *store.TenantTx) error {
				it, err := tx.Item(1)
				comment = it.Comment
				return err
			})
			if comment != nil {
				t.Errorf("comment = %q, want unchanged (none)", *comment)
			}
		})
	}
}

func TestReviewDecisionRefusalAuditsActor(t *testing.T) {
	c := newRD(t)
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"revoke"}`, 200)
	c.json("POST", "/api/reviews/items/1/decision", `{"decision":"keep"}`, 409)
	ev := reviewEvents(c, "review.decide.refused")
	if len(ev) != 1 {
		t.Fatalf("refusal events = %d", len(ev))
	}
	d := string(ev[0].Detail)
	for _, want := range []string{`"item_id":1`, `"current":"revoke"`, `"requested":"keep"`, "review_item_decided"} {
		if !strings.Contains(d, want) {
			t.Errorf("refusal detail %s lacks %s", d, want)
		}
	}
}

// Two different decisions sent at once: exactly one is applied, the other is
// refused, and the stored decision and the grant agree.
func TestReviewDecisionConcurrent(t *testing.T) {
	for round := 0; round < 5; round++ {
		c := newRD(t)
		h := testServer(t, c.st)
		var wg sync.WaitGroup
		codes := make([]int, 8)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dec := "keep"
				if i%2 == 0 {
					dec = "revoke"
				}
				req := httptest.NewRequest("POST", "/api/reviews/items/1/decision", strings.NewReader(fmt.Sprintf(`{"decision":%q}`, dec)))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				codes[i] = rec.Code
			}()
		}
		wg.Wait()
		decision, live := itemState(c, 1)
		ok := map[string]int{}
		for i, code := range codes {
			dec := "keep"
			if i%2 == 0 {
				dec = "revoke"
			}
			switch code {
			case http.StatusOK:
				ok[dec]++
			case http.StatusConflict:
				if dec == decision {
					t.Errorf("request %d (%s) matches the stored decision but got 409", i, dec)
				}
			default:
				t.Fatalf("request %d: status %d", i, code)
			}
		}
		if len(ok) != 1 || ok[decision] == 0 {
			t.Fatalf("round %d: accepted decisions %v, stored %q", round, ok, decision)
		}
		if live != (decision == "keep") {
			t.Errorf("round %d: stored %q but edge live = %v", round, decision, live)
		}
		if n := len(reviewEvents(c, "review."+decision)); n != 1 {
			t.Errorf("round %d: review.%s events = %d, want exactly 1", round, decision, n)
		}
	}
}

func TestCampaignValidation(t *testing.T) {
	long := strings.Repeat("x", maxCampaignName+1)
	tests := []struct {
		name     string
		body     string
		want     int
		wantType string // pydantic-style error type at the field
		wantLoc  string
	}{
		{"defaults", `{}`, 200, "", ""},
		{"lowest days", `{"name":"a","unused_days":1}`, 200, "", ""},
		{"highest days", `{"name":"a","unused_days":3650}`, 200, "", ""},
		{"name at cap", `{"name":"` + strings.Repeat("x", maxCampaignName) + `"}`, 200, "", ""},
		{"empty name", `{"name":""}`, 422, "string_too_short", "name"},
		{"blank name", `{"name":"   \t "}`, 422, "string_too_short", "name"},
		{"name too long", `{"name":"` + long + `"}`, 422, "string_too_long", "name"},
		{"zero days", `{"unused_days":0}`, 422, "greater_than_equal", "unused_days"},
		{"negative days", `{"unused_days":-5}`, 422, "greater_than_equal", "unused_days"},
		{"huge days", `{"unused_days":3651}`, 422, "less_than_equal", "unused_days"},
		{"very huge days", `{"unused_days":9000000000000}`, 422, "less_than_equal", "unused_days"},
		{"days not a number", `{"unused_days":"soon"}`, 422, "int_parsing", "unused_days"},
		{"both bad", `{"name":" ","unused_days":0}`, 422, "string_too_short", "name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newRD(t)
			before := len(c.client.json("GET", "/api/reviews/campaigns", "", 200).([]any))
			rec := c.do("POST", "/api/reviews/campaigns", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %.300s", rec.Code, tc.want, rec.Body.String())
			}
			after := len(c.client.json("GET", "/api/reviews/campaigns", "", 200).([]any))
			if tc.want == 200 {
				if after != before+1 {
					t.Errorf("campaigns %d -> %d, want one more", before, after)
				}
				return
			}
			if after != before {
				t.Errorf("a refused request created a campaign (%d -> %d)", before, after)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `"type":"`+tc.wantType+`"`) || !strings.Contains(body, `"`+tc.wantLoc+`"`) {
				t.Errorf("body %s lacks %s at %s", body, tc.wantType, tc.wantLoc)
			}
			if tc.name == "both bad" && !strings.Contains(body, `"greater_than_equal"`) {
				t.Errorf("both errors should be reported: %s", body)
			}
		})
	}
}

// #142: an unknown item is a 404 (a bad decision value stays a 422).
func TestReviewDecisionUnknownItem(t *testing.T) {
	c := newRD(t)
	rec := c.do("POST", "/api/reviews/items/999999/decision", `{"decision":"keep"}`)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "unknown review item") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	c.json("POST", "/api/reviews/items/999999/decision", `{"decision":"maybe"}`, 422)
}

func TestCampaignNameIsTrimmed(t *testing.T) {
	c := newRD(t)
	v := c.json("POST", "/api/reviews/campaigns", `{"name":"  Q4 sweep  ","unused_days":30}`, 200)
	if n := at(v, "name"); n != "Q4 sweep" {
		t.Errorf("name = %q", n)
	}
}
