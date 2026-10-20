package flatfile

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Change types of a delta.
const (
	Added   = "added"
	Removed = "removed"
	Changed = "changed"
)

// Change is one line of a delta. For a changed row, Detail names the fields
// that differ (never their values).
type Change struct {
	Kind   string `json:"kind"` // accounts | entitlements
	Type   string `json:"change"`
	Key    string `json:"-"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
}

// Delta is what an upload changes against the snapshot the last applied
// upload left.
type Delta struct {
	Added, Removed, Changed []Change
	Unchanged               int
}

// All lists the changes: added, then removed, then changed.
func (d Delta) All() []Change {
	out := append([]Change(nil), d.Added...)
	out = append(out, d.Removed...)
	return append(out, d.Changed...)
}

func labelOf(kind, key string) string {
	if kind == KindEntitlements {
		a, e := SplitEntitlementKey(key)
		return a + " / " + e
	}
	return key
}

// Diff compares an upload's records with the previous snapshot of the same
// kind. Each list is ordered by key, so a delta is the same every time.
func Diff(kind string, prev []*store.FlatRecord, next []Record) Delta {
	old := make(map[string]*store.FlatRecord, len(prev))
	for _, p := range prev {
		old[p.Key] = p
	}
	var d Delta
	seen := make(map[string]bool, len(next))
	for _, n := range next {
		seen[n.Key] = true
		p, ok := old[n.Key]
		switch {
		case !ok:
			d.Added = append(d.Added, Change{Kind: kind, Type: Added, Key: n.Key, Label: n.Label})
		case p.Hash == n.Hash:
			d.Unchanged++
		default:
			d.Changed = append(d.Changed, Change{Kind: kind, Type: Changed, Key: n.Key, Label: n.Label,
				Detail: changedFields(p.Data, n.Fields)})
		}
	}
	for _, p := range prev {
		if !seen[p.Key] {
			d.Removed = append(d.Removed, Change{Kind: kind, Type: Removed, Key: p.Key, Label: labelOf(kind, p.Key)})
		}
	}
	for _, l := range [][]Change{d.Added, d.Removed, d.Changed} {
		sort.Slice(l, func(i, j int) bool { return l[i].Key < l[j].Key })
	}
	return d
}

func changedFields(prevData string, next map[string]string) string {
	var prev map[string]string
	if err := json.Unmarshal([]byte(prevData), &prev); err != nil {
		return "" // an unreadable old row: the change is reported without detail
	}
	var names []string
	for k, v := range next {
		if prev[k] != v {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
