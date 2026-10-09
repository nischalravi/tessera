package readiness

import (
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// mkEval builds an evaluation from (level, status) pairs.
func mkEval(items ...[2]string) *Evaluation {
	e := &Evaluation{byID: map[string]*ItemEval{}}
	for i, x := range items {
		ie := &ItemEval{Item: template.Item{ID: fmt.Sprintf("x.%d", i), Title: "Item", Level: template.Level(x[0])},
			Applicable: x[1] != StatusNotApplicable, Status: x[1]}
		if x[1] == StatusSkipped {
			ie.Skip = &store.Skip{Reason: "Scheduled for the Q1 upgrade window"}
		}
		e.Items = append(e.Items, ie)
		e.byID[ie.ID] = ie
	}
	return e
}

func repeat(n int, level, status string) [][2]string {
	out := make([][2]string, n)
	for i := range out {
		out[i] = [2]string{level, status}
	}
	return out
}

func items(groups ...[][2]string) [][2]string {
	var out [][2]string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func TestScore_Formula(t *testing.T) {
	R, Rec, O := "required", "recommended", "optional"
	cases := []struct {
		name     string
		items    [][2]string
		findings []FindingInfo
		score    int
		band     string
		capped   bool
		penalty  int
	}{
		{"everything passes", items(repeat(4, R, "pass"), repeat(5, Rec, "pass"), repeat(2, O, "fail")), nil, 100, BandHealthy, false, 0},
		// The design's example: 132 of 150 points, penalty 8 + 3 + 3 = 14 → 74.
		{"design example", items(repeat(26, R, "pass"), repeat(1, Rec, "pass"), repeat(9, Rec, "fail")),
			[]FindingInfo{{Code: "RF-01", Severity: "high", Status: "open"}, {Code: "RF-07", Severity: "medium", Status: "open"},
				{Code: "RF-04", Severity: "medium", Status: "open"}}, 74, BandNeedsAttention, false, 14},
		{"a failing Required item caps the score at 49", items(repeat(30, R, "pass"), repeat(1, R, "fail")), nil, 49, BandNotReady, true, 0},
		{"a stale Required item caps too", items(repeat(30, R, "pass"), repeat(1, R, "stale")), nil, 49, BandNotReady, true, 0},
		{"the penalty is capped at 40", items(repeat(10, R, "pass")),
			[]FindingInfo{{Severity: "critical", Status: "open"}, {Severity: "critical", Status: "open"}, {Severity: "critical", Status: "open"}},
			60, BandAtRisk, false, 40},
		{"accepted findings count half, rounded down", items(repeat(10, R, "pass")),
			[]FindingInfo{{Severity: "critical", Status: "accepted"}, {Severity: "high", Status: "accepted"}, {Severity: "low", Status: "accepted"}},
			89, BandNeedsAttention, false, 11},
		{"resolved findings count zero", items(repeat(10, R, "pass")),
			[]FindingInfo{{Severity: "critical", Status: "resolved"}}, 100, BandHealthy, false, 0},
		{"skips earn no credit", items(repeat(10, R, "pass"), repeat(5, Rec, "skipped")), nil, 83, BandNeedsAttention, false, 0},
		{"too much skipped weight cannot be healthy", items(repeat(40, R, "pass"), repeat(9, Rec, "pass"), repeat(2, Rec, "skipped")),
			nil, 98, BandNeedsAttention, false, 0},
		{"not applicable items are excluded", items(repeat(10, R, "pass"), repeat(3, R, StatusNotApplicable)), nil, 100, BandHealthy, false, 0},
		{"never below zero", items(repeat(1, Rec, "pass"), repeat(9, Rec, "fail")),
			[]FindingInfo{{Severity: "critical", Status: "open"}, {Severity: "critical", Status: "open"}, {Severity: "critical", Status: "open"}},
			0, BandNotReady, false, 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := ComputeScore(mkEval(tc.items...), tc.findings)
			if b.Score != tc.score || b.Band != tc.band || b.Capped != tc.capped || b.Penalty.Total != tc.penalty {
				t.Fatalf("score %d band %s capped %v penalty %d; want %d %s %v %d (breakdown %+v)",
					b.Score, b.Band, b.Capped, b.Penalty.Total, tc.score, tc.band, tc.capped, tc.penalty, b)
			}
		})
	}
}

func TestScore_BreakdownSumsToScore(t *testing.T) {
	R, Rec, O := "required", "recommended", "optional"
	for _, tc := range [][][2]string{
		items(repeat(26, R, "pass"), repeat(1, Rec, "pass"), repeat(9, Rec, "fail"), repeat(3, O, "fail")),
		items(repeat(7, R, "pass"), repeat(2, R, "fail"), repeat(6, Rec, "skipped"), repeat(4, Rec, "pass")),
		items(repeat(3, R, "pass"), repeat(1, Rec, "pending")),
	} {
		fs := []FindingInfo{{Code: "RF-01", Severity: "high", Status: "open"}, {Code: "RF-09", Severity: "medium", Status: "accepted"}}
		b := ComputeScore(mkEval(tc...), fs)
		// The listed deductions explain every missing checklist point...
		lost := 0.0
		for _, m := range b.Checklist.Missing {
			lost += m.ScorePoints
		}
		if diff := 100 - b.Checklist.Exact - lost; diff > 0.5 || diff < -0.5 {
			t.Errorf("missing items explain %.1f points, the checklist lost %.1f", lost, 100-b.Checklist.Exact)
		}
		earned, possible := 0, 0
		for _, it := range mkEval(tc...).Items {
			if it.Applicable {
				possible += levelWeight[it.Level]
				if it.Status == StatusPass {
					earned += levelWeight[it.Level]
				}
			}
		}
		lostPts := 0
		for _, m := range b.Checklist.Missing {
			lostPts += m.Points
		}
		if b.Checklist.Earned != earned || b.Checklist.Possible != possible || earned+lostPts != possible {
			t.Errorf("checklist points: %+v", b.Checklist)
		}
		// ...the penalty is the sum of the listed findings...
		sum := 0
		for _, f := range b.Penalty.Findings {
			sum += f.Points
		}
		if sum != b.Penalty.Raw || b.Penalty.Total != min(40, sum) {
			t.Errorf("penalty %+v", b.Penalty)
		}
		// ...and checklist − penalty is the score before the Required cap.
		if b.Uncapped != max(0, b.Checklist.Score-b.Penalty.Total) || (!b.Capped && b.Score != b.Uncapped) || (b.Capped && b.Score != 49) {
			t.Errorf("score %d uncapped %d checklist %d penalty %d", b.Score, b.Uncapped, b.Checklist.Score, b.Penalty.Total)
		}
	}
}

func TestTenantScore_Weighted(t *testing.T) {
	score, capped, ok := TenantScore([]TenantInput{{Score: 90, Accounts: 300}, {Score: 40, Accounts: 100}}, true)
	if !ok || capped || score != 78 { // (90×300 + 40×100) / 400 = 77.5 → 78
		t.Errorf("score %d capped %v ok %v", score, capped, ok)
	}
	// A connection with no staged accounts weighs 1.
	score, _, _ = TenantScore([]TenantInput{{Score: 100, Accounts: 0}, {Score: 0, Accounts: 0}}, true)
	if score != 50 {
		t.Errorf("minimum weight: %d", score)
	}
	if _, _, ok := TenantScore(nil, true); ok {
		t.Error("an empty tenant has no score")
	}
}

func TestTenantScore_NoHRSourceCap(t *testing.T) {
	score, capped, _ := TenantScore([]TenantInput{{Score: 95, Accounts: 10}}, false)
	if score != 69 || !capped {
		t.Errorf("without an HR source: %d %v", score, capped)
	}
	score, capped, _ = TenantScore([]TenantInput{{Score: 60, Accounts: 10}}, false)
	if score != 60 || capped {
		t.Errorf("below the cap: %d %v", score, capped)
	}
}

func TestAttention_Ranking(t *testing.T) {
	// The formula itself.
	if r := Rank("critical", 1, true, true); r != 31.22 { // 8 × (1 + log10 2) × 2 × 1.5
		t.Errorf("rank %v", r)
	}
	if r := Rank("low", 0, false, false); r != 1 {
		t.Errorf("rank %v", r)
	}
	if Rank("high", 3412, false, false) <= Rank("high", 1, false, false) {
		t.Error("more affected objects must rank higher")
	}
	old := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	es := []AttentionEntry{
		{ID: "low", Rank: Rank("low", 1, false, false), since: old},
		{ID: "high-new", Rank: Rank("high", 1, false, false), since: old.Add(48 * time.Hour)},
		{ID: "crit-priv", Rank: Rank("critical", 1, true, false), since: old},
		{ID: "high-old", Rank: Rank("high", 1, false, false), since: old},
		{ID: "high-many", Rank: Rank("high", 3412, false, true), since: old},
	}
	SortAttention(es)
	got := ""
	for _, e := range es {
		got += e.ID + " "
	}
	// 3,412 affected objects outweigh one privileged critical item (27.2 > 20.8).
	if got != "high-many crit-priv high-old high-new low " {
		t.Errorf("order: %s (ties go to the oldest)", got)
	}
}
