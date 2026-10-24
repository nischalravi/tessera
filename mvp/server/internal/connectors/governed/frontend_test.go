package governed

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The New connection form (frontend governed.ts) lists the setting keys of each
// type; they must be the keys the server accepts, so a setting added on one
// side cannot be missing on the other.
func TestFrontendSettingKeysMatch(t *testing.T) {
	raw, err := os.ReadFile("../../../../frontend/src/features/admin/connections/governed.ts")
	if err != nil {
		t.Skipf("frontend not checked out: %v", err)
	}
	src := string(raw)
	a := strings.Index(src, "export const SETTING_KEYS")
	if a < 0 {
		t.Fatal("no SETTING_KEYS in governed.ts")
	}
	block := src[a : a+strings.Index(src[a:], "};")]
	line := regexp.MustCompile(`(?m)^\s*(\w+): \[(.*)\],$`)
	got := map[string][]string{}
	for _, m := range line.FindAllStringSubmatch(block, -1) {
		var keys []string
		for _, k := range strings.Split(m[2], ",") {
			keys = append(keys, strings.Trim(strings.TrimSpace(k), `"`))
		}
		got[m[1]] = keys
	}
	if len(got) != len(Types) {
		t.Errorf("governed.ts lists %d types, the server has %d", len(got), len(Types))
	}
	for _, ty := range Types {
		var want []string
		for _, s := range SettingSpecs(ty.ID) {
			want = append(want, s.Key)
		}
		if !slices.Equal(got[ty.ID], want) {
			t.Errorf("%s: governed.ts has %v, the server takes %v", ty.ID, got[ty.ID], want)
		}
	}
}
