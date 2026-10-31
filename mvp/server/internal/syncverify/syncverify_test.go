package syncverify

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
)

func st(perms map[int64][]string, viol ...string) *State {
	s := &State{Perms: map[int64]map[string]bool{}, Names: map[int64]string{1: "Ann", 2: "Bo"}, Violations: map[string]bool{}, Checked: true}
	for iid, ps := range perms {
		s.Perms[iid] = map[string]bool{}
		for _, p := range ps {
			s.Perms[iid][p] = true
		}
	}
	for _, v := range viol {
		s.Violations[v] = true
	}
	return s
}

func TestPredictSortsAndCaps(t *testing.T) {
	res := &simulate.Result{
		Identities: []simulate.IdentityChange{
			{IdentityID: 2, Name: "Bo", Added: []simulate.Added{{PermKey: "z"}, {PermKey: "a"}}},
			{IdentityID: 1, Name: "Ann", Removed: []simulate.Removed{{PermKey: "r"}}},
		},
		Summary:    simulate.Summary{IdentitiesAffected: 2, ViolationsBefore: 3, ViolationsAfter: 4},
		Violations: policy.Diff{Introduced: []policy.Violation{{Key: "v2"}, {Key: "v1"}}, Resolved: []policy.Violation{{Key: "w"}}},
	}
	p := Predict(res, "d")
	if p.PermsTotal != 3 || p.Perms[0].IdentityID != 1 || p.Perms[0].Gain || p.Perms[1].Perm != "a" || p.Perms[2].Perm != "z" {
		t.Errorf("perms = %+v", p.Perms)
	}
	if p.IntroducedTotal != 2 || p.Introduced[0] != "v1" || p.ResolvedTotal != 1 || p.ViolationsAfter != 4 || p.Truncated() {
		t.Errorf("prediction = %+v", p)
	}
	if e := Predict(nil, "x"); e.PermsTotal != 0 || len(e.Perms) != 0 || e.DiffSHA256 != "x" {
		t.Errorf("empty prediction = %+v", e)
	}
	// a list over its cap is cut and says so, with the exact total
	big := &simulate.Result{}
	ic := simulate.IdentityChange{IdentityID: 1}
	for i := 0; i < MaxPerms+5; i++ {
		ic.Added = append(ic.Added, simulate.Added{PermKey: "p" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)})
	}
	big.Identities = []simulate.IdentityChange{ic}
	bp := Predict(big, "d")
	if len(bp.Perms) != MaxPerms || bp.PermsTotal != MaxPerms+5 || !bp.Truncated() {
		t.Errorf("cut prediction: %d of %d, truncated %v", len(bp.Perms), bp.PermsTotal, bp.Truncated())
	}
}

func TestCompare(t *testing.T) {
	pred := &Prediction{
		Perms:      []PermChange{{IdentityID: 1, Identity: "Ann", Perm: "p-new", Gain: true}, {IdentityID: 2, Identity: "Bo", Perm: "p-old"}},
		PermsTotal: 2, Introduced: []string{"v-new"}, Resolved: []string{"v-old"}, IntroducedTotal: 1, ResolvedTotal: 1,
	}
	before := st(map[int64][]string{1: {"a"}, 2: {"p-old", "b"}}, "v-old", "v-keep")
	cases := []struct {
		name  string
		after *State
		want  []string // kind of each mismatch, in order
	}{
		{"as predicted", st(map[int64][]string{1: {"a", "p-new"}, 2: {"b"}}, "v-new", "v-keep"), nil},
		{"gain dropped by the target", st(map[int64][]string{1: {"a"}, 2: {"b"}}, "v-new", "v-keep"), []string{KindGainMissing}},
		{"loss not carried out", st(map[int64][]string{1: {"a", "p-new"}, 2: {"p-old", "b"}}, "v-new", "v-keep"), []string{KindLossMissing}},
		{"an unpredicted gain", st(map[int64][]string{1: {"a", "p-new", "extra"}, 2: {"b"}}, "v-new", "v-keep"), []string{KindUnexpectedGain}},
		{"an unpredicted loss", st(map[int64][]string{1: {"p-new"}, 2: {"b"}}, "v-new", "v-keep"), []string{KindUnexpectedLoss}},
		{"introduced violation absent", st(map[int64][]string{1: {"a", "p-new"}, 2: {"b"}}, "v-keep"), []string{KindViolationMissing}},
		{"resolved violation stays", st(map[int64][]string{1: {"a", "p-new"}, 2: {"b"}}, "v-new", "v-old", "v-keep"), []string{KindViolationStays}},
		{"a surprise violation", st(map[int64][]string{1: {"a", "p-new"}, 2: {"b"}}, "v-new", "v-keep", "v-surprise"), []string{KindViolationExtra}},
		{"a violation that vanished", st(map[int64][]string{1: {"a", "p-new"}, 2: {"b"}}, "v-new"), []string{KindViolationGone}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, total := Compare(pred, before, tc.after)
			var got []string
			for _, m := range ms {
				got = append(got, m.Kind)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") || total != len(tc.want) {
				t.Errorf("mismatches = %v (total %d), want %v", got, total, tc.want)
			}
			for _, m := range ms {
				if m.Subject == "" || m.Predicted == "" || m.Observed == "" || m.Describe() == "" {
					t.Errorf("mismatch without detail: %+v", m)
				}
			}
		})
	}

	// violations are not compared when no policies were read
	b2, a2 := st(map[int64][]string{1: {"a"}}), st(map[int64][]string{1: {"a"}})
	b2.Checked = false
	if _, total := Compare(&Prediction{Introduced: []string{"v"}, IntroducedTotal: 1}, b2, a2); total != 0 {
		t.Errorf("unchecked violations compared: %d", total)
	}
	// a cut prediction checks only what it names
	cut := &Prediction{PermsTotal: 5, Perms: []PermChange{{IdentityID: 1, Perm: "p", Gain: true}}}
	if _, total := Compare(cut, st(map[int64][]string{1: {"a"}}), st(map[int64][]string{1: {"a", "p", "other"}})); total != 0 {
		t.Errorf("a cut prediction flagged an unnamed change: %d", total)
	}
}

func TestCompareCapsFindings(t *testing.T) {
	pred := &Prediction{}
	b, a := st(map[int64][]string{1: {}}), st(map[int64][]string{1: {}})
	for i := 0; i < MaxFindings+20; i++ {
		a.Perms[1][strings.Repeat("k", i+1)] = true
	}
	ms, total := Compare(pred, b, a)
	if len(ms) != MaxFindings || total != MaxFindings+20 {
		t.Errorf("findings = %d, total %d", len(ms), total)
	}
	long := &State{Perms: map[int64]map[string]bool{1: {strings.Repeat("z", 2000): true}}, Names: map[int64]string{}, Violations: map[string]bool{}}
	ms, _ = Compare(pred, b, long)
	if len(ms) != 1 || len(ms[0].Subject) > 400 {
		t.Errorf("a long subject was not cut: %d", len(ms[0].Subject))
	}
}

func TestPredictionValid(t *testing.T) {
	for name, tc := range map[string]struct {
		p  Prediction
		ok bool
	}{
		"empty":                     {Prediction{}, true},
		"listed in full":            {Prediction{Perms: make([]PermChange, 3), PermsTotal: 3}, true},
		"cut at the cap":            {Prediction{Perms: make([]PermChange, MaxPerms), PermsTotal: MaxPerms + 9}, true},
		"a forged total":            {Prediction{PermsTotal: 1}, false},
		"a total below the list":    {Prediction{Perms: make([]PermChange, 2), PermsTotal: 1}, false},
		"a list over its cap":       {Prediction{Perms: make([]PermChange, MaxPerms+1), PermsTotal: MaxPerms + 1}, false},
		"forged introduced":         {Prediction{IntroducedTotal: 4}, false},
		"forged resolved":           {Prediction{Resolved: []string{"a"}, ResolvedTotal: 2}, false},
		"violations cut at the cap": {Prediction{Introduced: make([]string, MaxViolations), IntroducedTotal: MaxViolations + 1}, true},
	} {
		if err := tc.p.Valid(); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
