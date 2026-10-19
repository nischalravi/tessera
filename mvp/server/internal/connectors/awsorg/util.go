package awsorg

import (
	"encoding/json"
	"sort"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
)

func sha256Hex(b []byte) string { return seal.SHA256Hex(b) }

func jsonMarshal(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}

// sortedKeys returns the keys of m in order, so iteration is deterministic.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
