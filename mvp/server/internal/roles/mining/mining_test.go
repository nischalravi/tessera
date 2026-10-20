package mining

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
)

// people builds n people of a department who hold core, with extra.
func people(start int64, n int, dept, title string, core []int64, extra map[int]int64) []Person {
	var out []Person
	for i := 0; i < n; i++ {
		p := Person{ID: start + int64(i), Department: dept, Title: title, Type: "human", Entitlements: slices.Clone(core)}
		if e, ok := extra[i]; ok {
			p.Entitlements = append(p.Entitlements, e)
		}
		out = append(out, p)
	}
	return out
}

func fixture() Input {
	var in Input
	// engineering: five people with {1,2,3}; one also has a rare extra 90
	in.People = append(in.People, people(1, 5, "Engineering", "Engineer", []int64{1, 2, 3}, map[int]int64{0: 90})...)
	// finance: four people with {10,11}
	in.People = append(in.People, people(100, 4, "Finance", "Accountant", []int64{10, 11}, nil)...)
	// everyone holds 1 so it is not a signal alone; two loners hold odd sets
	in.People = append(in.People, Person{ID: 200, Department: "Sales", Title: "AE", Type: "human", Entitlements: []int64{50, 51}})
	in.People = append(in.People, Person{ID: 201, Department: "Sales", Title: "AE", Type: "human", Entitlements: []int64{60}})
	return in
}

func TestMine_FindsRolesWithRuleAndOutliers(t *testing.T) {
	out, err := Mine(context.Background(), Params{}, fixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Candidates) != 2 {
		t.Fatalf("candidates = %+v", out.Candidates)
	}
	eng := out.Candidates[0]
	if eng.Name == "" || !slices.Equal(eng.Entitlements, []int64{1, 2, 3}) || len(eng.Members) != 5 {
		t.Fatalf("engineering = %+v", eng)
	}
	if eng.Rule == nil || eng.Rule.Attribute != "department" || !slices.Equal(eng.Rule.Values, []string{"Engineering"}) ||
		eng.Rule.Precision != 100 || eng.Rule.Recall != 100 {
		t.Errorf("rule = %+v", eng.Rule)
	}
	// 90 is held by one of five (20%), under the 25% line: that person is an outlier
	if len(eng.Outliers) != 1 || eng.Outliers[0].IdentityID != 1 || !slices.Equal(eng.Outliers[0].Extra, []int64{90}) {
		t.Errorf("outliers = %+v", eng.Outliers)
	}
	fin := out.Candidates[1]
	if !slices.Equal(fin.Entitlements, []int64{10, 11}) || len(fin.Members) != 4 || len(fin.Outliers) != 0 {
		t.Errorf("finance = %+v", fin)
	}
	if eng.Confidence < fin.Confidence || eng.Confidence > 100 || fin.Confidence <= 0 {
		t.Errorf("confidence eng %d fin %d", eng.Confidence, fin.Confidence)
	}
	for i, c := range out.Candidates {
		if c.Rank != i+1 {
			t.Errorf("rank %d = %d", i, c.Rank)
		}
	}
}

// The same input in any order, run again, gives the same hash and candidates.
func TestMine_Deterministic(t *testing.T) {
	base, err := Mine(context.Background(), Params{}, fixture())
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20; i++ {
		in := fixture()
		rng.Shuffle(len(in.People), func(a, b int) { in.People[a], in.People[b] = in.People[b], in.People[a] })
		for j := range in.People {
			e := in.People[j].Entitlements
			rng.Shuffle(len(e), func(a, b int) { e[a], e[b] = e[b], e[a] })
		}
		got, err := Mine(context.Background(), Params{}, in)
		if err != nil {
			t.Fatal(err)
		}
		if got.SnapshotHash != base.SnapshotHash || !reflect.DeepEqual(got.Candidates, base.Candidates) {
			t.Fatalf("run %d differs:\n%+v\n%+v", i, got.Candidates, base.Candidates)
		}
	}
	// other parameters or other data change the hash
	other, _ := Mine(context.Background(), Params{MinMembers: 4}, fixture())
	if other.SnapshotHash == base.SnapshotHash {
		t.Error("parameters are not part of the hash")
	}
	in := fixture()
	in.People[0].Entitlements = append(in.People[0].Entitlements, 77)
	changed, _ := Mine(context.Background(), Params{}, in)
	if changed.SnapshotHash == base.SnapshotHash {
		t.Error("the data is not part of the hash")
	}
}

func TestMine_Filters(t *testing.T) {
	out, err := Mine(context.Background(), Params{Department: []string{"Finance"}}, fixture())
	if err != nil || out.People != 4 || len(out.Candidates) != 1 || !slices.Equal(out.Candidates[0].Entitlements, []int64{10, 11}) {
		t.Fatalf("department filter = %+v, %v", out, err)
	}
	out, err = Mine(context.Background(), Params{Title: []string{"Nobody"}}, fixture())
	if err != nil || out.People != 0 || len(out.Candidates) != 0 || out.Candidates == nil {
		t.Errorf("title filter = %+v, %v", out, err)
	}
	out, err = Mine(context.Background(), Params{Type: []string{"service"}}, fixture())
	if err != nil || out.People != 0 {
		t.Errorf("type filter = %+v, %v", out, err)
	}
}

// A set that matches an existing role is not suggested again; a near match is named.
func TestMine_ExistingRoles(t *testing.T) {
	in := fixture()
	in.Roles = []Role{{ID: "r-eng", Entitlements: []int64{3, 2, 1}}, {ID: "r-fin", Entitlements: []int64{10, 11, 12}}}
	out, err := Mine(context.Background(), Params{}, in)
	if err != nil {
		t.Fatal(err)
	}
	if out.SkippedExisting != 1 || len(out.Candidates) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if c := out.Candidates[0]; c.SimilarRole != "r-fin" || c.Similarity != 66 {
		t.Errorf("similar = %q %d", c.SimilarRole, c.Similarity)
	}
}

func TestMine_PredictorNeedsGoodFit(t *testing.T) {
	// the same two entitlements held across three departments: no department predicts them
	var in Input
	for i, d := range []string{"A", "B", "C", "A", "B", "C"} {
		in.People = append(in.People, Person{ID: int64(i + 1), Department: d, Title: "x", Type: "human", Entitlements: []int64{1, 2}})
	}
	for i := 0; i < 30; i++ {
		in.People = append(in.People, Person{ID: int64(100 + i), Department: []string{"A", "B", "C"}[i%3], Title: "x", Type: "human", Entitlements: []int64{9}})
	}
	out, err := Mine(context.Background(), Params{}, in)
	if err != nil || len(out.Candidates) != 1 {
		t.Fatalf("out = %+v, %v", out, err)
	}
	// one attribute value covering all three departments has recall 100 but precision 18: below the line
	if out.Candidates[0].Rule != nil {
		t.Errorf("rule = %+v", out.Candidates[0].Rule)
	}
}

func TestParams(t *testing.T) {
	p, err := Params{Department: []string{" b ", "a", "b", ""}}.Normalize()
	if err != nil || !slices.Equal(p.Department, []string{"a", "b"}) || p.MinMembers != DefaultMinMembers ||
		p.MinEntitlements != DefaultMinEntitlements || p.MinSimilarity != DefaultMinSimilarity || p.MaxCandidates != DefaultMaxCandidates {
		t.Errorf("normalized = %+v, %v", p, err)
	}
	long := make([]string, MaxFilterValues+1)
	for i := range long {
		long[i] = fmt.Sprint("v", i)
	}
	for name, bad := range map[string]Params{
		"min_members low":       {MinMembers: 1},
		"min_members high":      {MinMembers: 1001},
		"min_entitlements low":  {MinEntitlements: 1},
		"min_entitlements high": {MinEntitlements: 51},
		"similarity low":        {MinSimilarity: 10},
		"similarity high":       {MinSimilarity: 101},
		"max candidates high":   {MaxCandidates: MaxCandidates + 1},
		"negative":              {MaxCandidates: -1},
		"too many values":       {Title: long},
		"long value":            {Type: []string{string(make([]byte, MaxFilterLen+1))}},
	} {
		var pe *ParamError
		if _, err := bad.Normalize(); !errors.As(err, &pe) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMine_Bounds(t *testing.T) {
	// too many people for one run
	var in Input
	for i := 0; i <= MaxPeople; i++ {
		in.People = append(in.People, Person{ID: int64(i + 1), Entitlements: []int64{1, 2}})
	}
	var ie *InputError
	if _, err := Mine(context.Background(), Params{}, in); !errors.As(err, &ie) || ie.Code != "too_many_identities" {
		t.Errorf("too many people: %v", err)
	}
	// a filter brings it back under the bound
	for i := range in.People {
		if i%2 == 0 {
			in.People[i].Department = "x"
		}
	}
	if out, err := Mine(context.Background(), Params{Department: []string{"x"}}, in); err != nil || out.People != MaxPeople/2+1 {
		t.Errorf("filtered = %v, %v", out, err)
	}

	// people holding too many entitlements are skipped, not mined
	var admin Input
	var many []int64
	for i := 0; i <= MaxEntitlementsPerPerson; i++ {
		many = append(many, int64(i+1))
	}
	for i := 0; i < 5; i++ {
		admin.People = append(admin.People, Person{ID: int64(i + 1), Entitlements: many})
	}
	out, err := Mine(context.Background(), Params{}, admin)
	if err != nil || out.SkippedPeople != 5 || len(out.Candidates) != 0 {
		t.Errorf("admins = %+v, %v", out, err)
	}

	// the number of candidates is capped
	var wide Input
	id := int64(1)
	for g := int64(0); g < 40; g++ {
		for i := 0; i < 3; i++ {
			wide.People = append(wide.People, Person{ID: id, Entitlements: []int64{g*10 + 1, g*10 + 2}})
			id++
		}
	}
	out, err = Mine(context.Background(), Params{MaxCandidates: 7}, wide)
	if err != nil || len(out.Candidates) != 7 {
		t.Errorf("capped = %d, %v", len(out.Candidates), err)
	}
	if out, err = Mine(context.Background(), Params{MaxCandidates: 100}, wide); err != nil || len(out.Candidates) != 40 {
		t.Errorf("uncapped = %d, %v", len(out.Candidates), err)
	}

	// a cancelled context stops the run
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Mine(ctx, Params{}, wide); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled run = %v", err)
	}
}

// Many distinct profiles stay within the work bound and still finish.
func TestMine_RuntimeBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var in Input
	for i := 0; i < 4000; i++ {
		var e []int64
		for len(e) < 40 {
			e = append(e, int64(rng.Intn(400)+1))
		}
		in.People = append(in.People, Person{ID: int64(i + 1), Entitlements: e})
	}
	out, err := Mine(context.Background(), Params{MinMembers: 2}, in)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Mine(context.Background(), Params{MinMembers: 2}, in)
	if !reflect.DeepEqual(out.Candidates, again.Candidates) || out.SnapshotHash != again.SnapshotHash {
		t.Error("a large run is not repeatable")
	}
	if len(out.Candidates) > DefaultMaxCandidates {
		t.Errorf("%d candidates", len(out.Candidates))
	}
}
