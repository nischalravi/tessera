package abac

import (
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func mustParse(t *testing.T, s string) *Node {
	t.Helper()
	n, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("Parse(%s): %v", s, err)
	}
	return n
}

func TestEval(t *testing.T) {
	fin := Attrs{"identity.department": "Finance", "identity.type": "human", "identity.tenure_days": 400.0,
		"context.aal": 2.0, "context.time": "2026-03-02T10:00:00Z", "identity.cleared": true, "identity.email": "a@x.example"}
	none := Attrs{"identity.type": "human"} // no department, no aal
	cases := []struct {
		name  string
		cond  string
		attrs Attrs
		want  Tri
	}{
		{"eq match", `{"attr":"identity.department","op":"eq","value":"Finance"}`, fin, True},
		{"eq differs", `{"attr":"identity.department","op":"eq","value":"HR"}`, fin, False},
		{"eq is case sensitive", `{"attr":"identity.department","op":"eq","value":"finance"}`, fin, False},
		{"ne", `{"attr":"identity.department","op":"ne","value":"HR"}`, fin, True},
		{"in", `{"attr":"identity.department","op":"in","value":["HR","Finance"]}`, fin, True},
		{"in miss", `{"attr":"identity.department","op":"in","value":["HR","Legal"]}`, fin, False},
		{"prefix", `{"attr":"identity.email","op":"prefix","value":"a@"}`, fin, True},
		{"prefix of a number is unknown", `{"attr":"identity.tenure_days","op":"prefix","value":"4"}`, fin, Unknown},
		{"bool eq", `{"attr":"identity.cleared","op":"eq","value":true}`, fin, True},
		{"type mismatch eq is false", `{"attr":"identity.tenure_days","op":"eq","value":"400"}`, fin, False},
		{"exists", `{"attr":"identity.department","op":"exists"}`, fin, True},
		{"exists, missing, is false not unknown", `{"attr":"identity.department","op":"exists"}`, none, False},
		{"gte number", `{"attr":"context.aal","op":"gte","value":2}`, fin, True},
		{"gt number", `{"attr":"context.aal","op":"gt","value":2}`, fin, False},
		{"lt number", `{"attr":"identity.tenure_days","op":"lt","value":90}`, fin, False},
		{"lte number", `{"attr":"identity.tenure_days","op":"lte","value":400}`, fin, True},
		{"time before", `{"attr":"context.time","op":"lt","value":"2026-03-02T12:00:00Z"}`, fin, True},
		{"time across zones", `{"attr":"context.time","op":"gte","value":"2026-03-02T05:00:00-05:00"}`, fin, True},
		{"number vs time is unknown", `{"attr":"context.aal","op":"lt","value":"2026-03-02T12:00:00Z"}`, fin, Unknown},
		{"all true", `{"all":[{"attr":"identity.department","op":"eq","value":"Finance"},{"attr":"identity.type","op":"eq","value":"human"}]}`, fin, True},
		{"all one false", `{"all":[{"attr":"identity.department","op":"eq","value":"HR"},{"attr":"identity.type","op":"eq","value":"human"}]}`, fin, False},
		{"any one true", `{"any":[{"attr":"identity.department","op":"eq","value":"HR"},{"attr":"identity.type","op":"eq","value":"human"}]}`, fin, True},
		{"any none", `{"any":[{"attr":"identity.department","op":"eq","value":"HR"},{"attr":"identity.type","op":"eq","value":"service"}]}`, fin, False},
		{"not", `{"not":{"attr":"identity.department","op":"eq","value":"HR"}}`, fin, True},

		// missing attributes deny
		{"missing eq", `{"attr":"identity.department","op":"eq","value":"Finance"}`, none, Unknown},
		{"missing ne is not a grant", `{"attr":"identity.department","op":"ne","value":"HR"}`, none, Unknown},
		{"missing in", `{"attr":"identity.department","op":"in","value":["Finance"]}`, none, Unknown},
		{"not of a missing attribute stays unknown", `{"not":{"attr":"identity.department","op":"eq","value":"HR"}}`, none, Unknown},
		{"all with a missing part is not true", `{"all":[{"attr":"identity.type","op":"eq","value":"human"},{"attr":"context.aal","op":"gte","value":2}]}`, none, Unknown},
		{"all: a false part wins over a missing one", `{"all":[{"attr":"identity.type","op":"eq","value":"service"},{"attr":"context.aal","op":"gte","value":2}]}`, none, False},
		{"any: a true part wins over a missing one", `{"any":[{"attr":"identity.type","op":"eq","value":"human"},{"attr":"context.aal","op":"gte","value":2}]}`, none, True},
		{"any with only missing parts", `{"any":[{"attr":"identity.department","op":"eq","value":"HR"},{"attr":"context.aal","op":"gte","value":2}]}`, none, Unknown},
		{"empty string counts as missing", `{"attr":"identity.department","op":"eq","value":"Finance"}`, Attrs{"identity.department": ""}, Unknown},
		{"nil attrs", `{"attr":"identity.department","op":"eq","value":"Finance"}`, nil, Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := mustParse(t, c.cond)
			if got := n.Tri(c.attrs); got != c.want {
				t.Errorf("Tri = %v, want %v", got, c.want)
			}
			if got, want := Eval(n, c.attrs), c.want == True; got != want {
				t.Errorf("Eval = %v, want %v (only true grants)", got, want)
			}
		})
	}
	if Eval(nil, fin) {
		t.Error("a nil condition granted")
	}
}

func TestParseRefuses(t *testing.T) {
	deep := strings.Repeat(`{"not":`, MaxDepth+1) + `{"attr":"identity.type","op":"exists"}` + strings.Repeat(`}`, MaxDepth+1)
	var wide strings.Builder
	wide.WriteString(`{"all":[`)
	for i := 0; i <= MaxNodes; i++ {
		if i > 0 {
			wide.WriteByte(',')
		}
		wide.WriteString(`{"attr":"identity.type","op":"exists"}`)
	}
	wide.WriteString(`]}`)
	long := `"` + strings.Repeat("x", MaxStringLen+1) + `"`
	bad := map[string]string{
		"empty":               ``,
		"not an object":       `[]`,
		"trailing":            `{"attr":"identity.type","op":"exists"} {}`,
		"unknown field":       `{"attr":"identity.type","op":"exists","code":"x"}`,
		"nothing set":         `{}`,
		"two forms":           `{"all":[{"attr":"identity.type","op":"exists"}],"not":{"attr":"identity.type","op":"exists"}}`,
		"empty all":           `{"all":[]}`,
		"empty any":           `{"any":[]}`,
		"all with op":         `{"all":[{"attr":"identity.type","op":"exists"}],"op":"eq"}`,
		"not with value":      `{"not":{"attr":"identity.type","op":"exists"},"value":1}`,
		"null part":           `{"all":[null]}`,
		"bad namespace":       `{"attr":"user.name","op":"exists"}`,
		"uppercase attribute": `{"attr":"identity.Department","op":"exists"}`,
		"trailing dot":        `{"attr":"identity.","op":"exists"}`,
		"no op":               `{"attr":"identity.type"}`,
		"unknown op":          `{"attr":"identity.type","op":"matches","value":"x"}`,
		"exists with value":   `{"attr":"identity.type","op":"exists","value":true}`,
		"eq without value":    `{"attr":"identity.type","op":"eq"}`,
		"eq with a list":      `{"attr":"identity.type","op":"eq","value":["a"]}`,
		"eq with an object":   `{"attr":"identity.type","op":"eq","value":{"a":1}}`,
		"in not a list":       `{"attr":"identity.type","op":"in","value":"a"}`,
		"in empty":            `{"attr":"identity.type","op":"in","value":[]}`,
		"in nested":           `{"attr":"identity.type","op":"in","value":[["a"]]}`,
		"prefix empty":        `{"attr":"identity.type","op":"prefix","value":""}`,
		"prefix number":       `{"attr":"identity.type","op":"prefix","value":3}`,
		"gt text":             `{"attr":"context.aal","op":"gt","value":"high"}`,
		"gt bool":             `{"attr":"context.aal","op":"gt","value":true}`,
		"too deep":            deep,
		"too many parts":      wide.String(),
		"long string":         `{"attr":"identity.type","op":"eq","value":` + long + `}`,
		"long list":           `{"attr":"identity.type","op":"in","value":[` + strings.Repeat(`"a",`, MaxListValues) + `"a"]}`,
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			if n, err := Parse([]byte(raw)); err == nil {
				t.Errorf("accepted: %+v", n)
			}
		})
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	in := `{ "any": [ {"op":"in","attr":"identity.department","value":["Finance","HR"]},
		{"not":{"attr":"context.aal","op":"lt","value":2}}, {"attr":"identity.cleared","op":"eq","value":false} ] }`
	n := mustParse(t, in)
	c1, err := n.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := mustParse(t, c1).Canonical()
	if err != nil || c1 != c2 {
		t.Errorf("canonical form is not stable: %s vs %s (%v)", c1, c2, err)
	}
	if !strings.Contains(c1, `"value":false`) {
		t.Errorf("a false value was dropped: %s", c1)
	}
	if want := `"attr":"identity.department","op":"in"`; !strings.Contains(c1, want) {
		t.Errorf("canonical form %s lacks %s", c1, want)
	}
}

func TestAttrBuilders(t *testing.T) {
	now := time.Date(2026, 3, 2, 22, 30, 0, 0, time.UTC) // a Monday
	dept, hired := "Finance", now.Add(-48*time.Hour)
	mgr := int64(7)
	i := &store.Identity{Name: "Ann", Type: "human", Status: "active", Department: &dept, ManagerID: &mgr, HiredAt: &hired}
	a := IdentityAttrs(i, now)
	if a["identity.department"] != "Finance" || a["identity.tenure_days"] != 2.0 || a["identity.manager_id"] != 7.0 ||
		a["identity.has_manager"] != true {
		t.Errorf("IdentityAttrs = %v", a)
	}
	for _, k := range []string{"identity.title", "identity.email", "identity.source"} {
		if _, ok := a[k]; ok {
			t.Errorf("%s is set for an identity without it", k)
		}
	}
	future := now.Add(time.Hour)
	i.HiredAt = &future
	if _, ok := IdentityAttrs(i, now)["identity.tenure_days"]; ok {
		t.Error("tenure for a hire date in the future")
	}
	c := ContextAttrs(now, 0)
	if c["context.hour"] != 22.0 || c["context.weekday"] != "mon" || c["context.time"] != "2026-03-02T22:30:00Z" {
		t.Errorf("ContextAttrs = %v", c)
	}
	if _, ok := c["context.aal"]; ok {
		t.Error("context.aal set with no signed-in user")
	}
	if ContextAttrs(now, 2)["context.aal"] != 2.0 {
		t.Error("context.aal missing")
	}
	// out-of-hours example: hour >= 18 or < 6 denies a daytime-only grant
	day := mustParse(t, `{"all":[{"attr":"context.hour","op":"gte","value":6},{"attr":"context.hour","op":"lt","value":18}]}`)
	if Eval(day, c) || !Eval(day, ContextAttrs(now.Add(-12*time.Hour), 0)) {
		t.Error("hour window")
	}
}
