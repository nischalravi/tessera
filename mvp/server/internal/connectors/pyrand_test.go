package connectors

import (
	"slices"
	"testing"
	"time"
)

// Reference values from CPython 3.13: r = random.Random(7) followed by the
// same sequence of calls.
func TestPyRandomMatchesCPython(t *testing.T) {
	r := NewPyRandom(7)
	for i, want := range []float64{0.32383276483316237, 0.15084917392450192, 0.6509344730398537} {
		if got := r.Random(); got != want {
			t.Errorf("random() #%d = %v, want %v", i, got, want)
		}
	}
	var ints []int
	for range 5 {
		ints = append(ints, r.RandInt(1, 100))
	}
	if want := []int{10, 69, 13, 47, 75}; !slices.Equal(ints, want) {
		t.Errorf("randint = %v, want %v", ints, want)
	}
	for i, want := range []float64{0.27609951614861805, 0.4783460799352391, 0.2668730462988932} {
		if got := r.Uniform(0.25, 0.7); got != want {
			t.Errorf("uniform #%d = %v, want %v", i, got, want)
		}
	}
	x := []string{"a", "b", "c", "d", "e", "f"}
	r.ShuffleStrings(x)
	if want := []string{"b", "c", "e", "a", "f", "d"}; !slices.Equal(x, want) {
		t.Errorf("shuffle = %v, want %v", x, want)
	}
	if got := r.ChoiceIndex(10); got != 8 {
		t.Errorf("choice = %d, want 8", got)
	}
}

func TestDemoCompanyIsDeterministic(t *testing.T) {
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	a, b := NewDemoCompany(DemoSeed, now), NewDemoCompany(DemoSeed, now)
	for _, sys := range []string{"workday", "okta", "aws", "github", "snowflake"} {
		if len(a.R[sys].Accounts) != len(b.R[sys].Accounts) || len(a.Usage[sys]) != len(b.Usage[sys]) {
			t.Errorf("%s differs between runs", sys)
		}
	}
	conns, err := Load("demo", now)
	if err != nil || len(conns) != 5 {
		t.Fatalf("Load(demo) = %d %v", len(conns), err)
	}
	if _, err := Load("demo-okta,nope", now); err == nil {
		t.Error("unknown connector should fail")
	}
}
