package reviews

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The security lead is the active "Head of Security": a disabled one is skipped
// (issue #443), and none is better than an inactive one.
func TestFindSecurityLead(t *testing.T) {
	title := "Head of Security"
	other := "Engineer"
	mk := func(id int64, title *string, status string) *store.Identity {
		return &store.Identity{ID: id, Title: title, Status: status}
	}
	tests := []struct {
		name string
		all  []*store.Identity
		want int64
	}{
		{"active lead", []*store.Identity{mk(1, &other, "active"), mk(2, &title, "active")}, 2},
		{"inactive skipped for the next active one", []*store.Identity{mk(1, &title, "disabled"), mk(2, &title, "active")}, 2},
		{"only an inactive lead", []*store.Identity{mk(1, &title, "disabled"), mk(2, &other, "active")}, 0},
		{"no lead", []*store.Identity{mk(1, nil, "active")}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findSecurityLead(tc.all)
			switch {
			case tc.want == 0 && got != nil:
				t.Errorf("got %d, want none", got.ID)
			case tc.want != 0 && (got == nil || got.ID != tc.want):
				t.Errorf("got %v, want %d", got, tc.want)
			}
		})
	}
}
