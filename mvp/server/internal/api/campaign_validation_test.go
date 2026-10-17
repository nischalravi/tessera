package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Issue #136: campaign creation bounds name and unused_days.
func TestCreateCampaignValidation(t *testing.T) {
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	long := strings.Repeat("x", 201)
	reject := []struct{ name, body, errType string }{
		{"empty name", `{"name":""}`, "string_too_short"},
		{"blank name", `{"name":"   \t"}`, "string_too_short"},
		{"name too long", fmt.Sprintf(`{"name":%q}`, long), "string_too_long"},
		{"zero days", `{"name":"a","unused_days":0}`, "greater_than_equal"},
		{"negative days", `{"name":"a","unused_days":-5}`, "greater_than_equal"},
		{"huge days", `{"name":"a","unused_days":3651}`, "less_than_equal"},
		{"overflow days", `{"name":"a","unused_days":9223372036854775807}`, "less_than_equal"},
	}
	for _, tc := range reject {
		rec := c.do("POST", "/api/reviews/campaigns", tc.body)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), tc.errType) {
			t.Errorf("%s: status %d body %.200s, want 422 %s", tc.name, rec.Code, rec.Body.String(), tc.errType)
		}
	}
	if got := c.json("GET", "/api/reviews/campaigns", "", 200).([]any); len(got) != 0 {
		t.Errorf("rejected requests created %d campaigns", len(got))
	}

	accept := []struct {
		name, body, wantName string
		days                 float64
	}{
		{"min days", `{"name":"a","unused_days":1}`, "a", 1},
		{"max days", `{"name":"a","unused_days":3650}`, "a", 3650},
		{"max name", fmt.Sprintf(`{"name":%q}`, strings.Repeat("x", 200)), strings.Repeat("x", 200), 60},
		{"trimmed name", `{"name":"  padded  "}`, "padded", 60},
		{"defaults", `{}`, "Exception-only review", 60},
	}
	for _, tc := range accept {
		got := c.json("POST", "/api/reviews/campaigns", tc.body, 200)
		if at(got, "name") != tc.wantName || at(got, "unused_days") != tc.days {
			t.Errorf("%s: got name %q days %v, want %q %v", tc.name, at(got, "name"), at(got, "unused_days"), tc.wantName, tc.days)
		}
	}
}
