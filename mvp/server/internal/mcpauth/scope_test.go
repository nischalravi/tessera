package mcpauth

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
)

func TestIntersect(t *testing.T) {
	cases := []struct {
		name string
		sets [][]string
		want []string
	}{
		{"no sets", nil, nil},
		{"one set is itself", [][]string{{"b", "a", "a"}}, []string{"a", "b"}},
		{"three-way overlap", [][]string{{"a", "b", "c"}, {"b", "c", "d"}, {"c", "b", "x"}}, []string{"b", "c"}},
		{"disjoint is empty", [][]string{{"a"}, {"b"}}, nil},
		{"an empty party empties it", [][]string{{"a", "b"}, {}, {"a"}}, nil},
		{"a nil party empties it", [][]string{{"a", "b"}, nil}, nil},
		{"duplicates in one set count once", [][]string{{"a", "a"}, {"b"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Intersect(c.sets...); !reflect.DeepEqual(got, c.want) {
				t.Errorf("Intersect = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSubset(t *testing.T) {
	if !Subset([]string{"a"}, []string{"a", "b"}) || !Subset(nil, nil) {
		t.Error("expected subsets")
	}
	if Subset([]string{"a", "c"}, []string{"a", "b"}) || Subset([]string{"a"}, nil) {
		t.Error("expected non-subsets")
	}
}

func TestParseScope(t *testing.T) {
	long := strings.Repeat("a", MaxScopeLength+1)
	many := make([]string, MaxScopes+1)
	for i := range many {
		many[i] = "s" + strings.Repeat("x", i)
	}
	cases := []struct {
		name, in string
		want     []string
		bad      bool
	}{
		{"sorted and unique", " b:x:y  a:x:y b:x:y ", []string{"a:x:y", "b:x:y"}, false},
		{"empty", "", nil, true},
		{"blank", "   ", nil, true},
		{"too long", long, nil, true},
		{"too many", strings.Join(many, " "), nil, true},
		{"quote", `a"b`, nil, true},
		{"backslash", `a\b`, nil, true},
		{"non ascii", "café:read:x", nil, true},
		{"control", "a\x01b", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseScope(c.in)
			if (err != nil) != c.bad || !reflect.DeepEqual(got, c.want) {
				t.Errorf("ParseScope(%q) = %v, %v", c.in, got, err)
			}
		})
	}
}

func TestScopeOf(t *testing.T) {
	cases := []struct {
		name string
		ep   *graph.EffectivePermission
		want string
		ok   bool
	}{
		{"plain", &graph.EffectivePermission{System: "s3", Action: "GetObject", ResourceName: "bucket"}, "s3:GetObject:bucket", true},
		{"system not repeated", &graph.EffectivePermission{System: "snowflake", Action: "snowflake:SELECT", ResourceName: "CUSTOMERS"},
			"snowflake:SELECT:CUSTOMERS", true},
		{"space in resource", &graph.EffectivePermission{System: "s3", Action: "Get", ResourceName: "my bucket"}, "", false},
		{"empty resource", &graph.EffectivePermission{System: "s3", Action: "Get"}, "", false},
		{"empty system", &graph.EffectivePermission{Action: "Get", ResourceName: "x"}, "", false},
		{"nil", nil, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ScopeOf(c.ep)
			if got != c.want || ok != c.ok {
				t.Errorf("ScopeOf = %q, %v", got, ok)
			}
		})
	}
}

func TestActorChain(t *testing.T) {
	var none *Actor
	if none.Depth() != 0 || none.Contains("a") {
		t.Error("a nil chain is empty")
	}
	c := &Actor{Sub: "identity:2", Act: &Actor{Sub: "identity:1"}}
	if c.Depth() != 2 || !c.Contains("identity:1") || c.Contains("identity:3") {
		t.Errorf("chain = %+v", c)
	}
}

func TestSubjectID(t *testing.T) {
	for in, want := range map[string]int64{"identity:7": 7, "identity:0": 0, "identity:-1": 0, "identity:07": 0, "identity:7x": 0,
		"user:7": 0, "": 0, "identity:": 0} {
		if got, ok := SubjectID(in); got != want || ok != (want != 0) {
			t.Errorf("SubjectID(%q) = %d, %v", in, got, ok)
		}
	}
	if SubjectOf(42) != "identity:42" {
		t.Error("SubjectOf")
	}
}

func TestChallengeS256(t *testing.T) {
	// RFC 7636 appendix B
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := ChallengeS256(verifier); got != want || !ValidChallenge(got) {
		t.Errorf("ChallengeS256 = %q", got)
	}
	for _, bad := range []string{"", "short", want + "=", strings.Repeat("!", 43)} {
		if ValidChallenge(bad) {
			t.Errorf("ValidChallenge(%q)", bad)
		}
	}
}
