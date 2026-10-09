package readiness

import (
	"math"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// Score weights and penalties (design §7.1). The formula is published so
// every point can be explained.
var (
	levelWeight     = map[template.Level]int{template.Required: 5, template.Recommended: 2, template.Optional: 0}
	severityPenalty = map[string]int{"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
)

// Score bands.
const (
	BandHealthy        = "healthy"
	BandNeedsAttention = "needs_attention"
	BandAtRisk         = "at_risk"
	BandNotReady       = "not_ready"
)

// PenaltyCap bounds the finding penalty; RequiredCap bounds the score while
// any applicable Required item is not passing.
const (
	PenaltyCap  = 40
	RequiredCap = 49
)

// ScoreItem is a checklist item that earned no credit.
type ScoreItem struct {
	Item        string  `json:"item"`
	Title       string  `json:"title"`
	Level       string  `json:"level"`
	Status      string  `json:"status"`
	Points      int     `json:"points"`       // its weight: the points it could have earned
	ScorePoints float64 `json:"score_points"` // what it costs on the 0–100 scale
	Reason      string  `json:"reason,omitempty"`
}

// ScoreFinding is a finding's penalty.
type ScoreFinding struct {
	Code     string `json:"code"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Points   int    `json:"points"`
}

// ChecklistScore is C = 100 × Σ wᵢcᵢ / Σ wᵢ.
type ChecklistScore struct {
	Score    int         `json:"score"`
	Exact    float64     `json:"exact"`
	Earned   int         `json:"earned"`
	Possible int         `json:"possible"`
	Missing  []ScoreItem `json:"missing"`
}

// Penalty is P = min(40, Σ points).
type Penalty struct {
	Total    int            `json:"total"`
	Raw      int            `json:"raw"`
	Capped   bool           `json:"capped"`
	Findings []ScoreFinding `json:"findings"`
}

// ScoreBreakdown explains a connection score: Checklist.Score − Penalty.Total
// is the score before the Required cap.
type ScoreBreakdown struct {
	Score                 int            `json:"score"`
	Band                  string         `json:"band"`
	Uncapped              int            `json:"uncapped"`
	Capped                bool           `json:"capped"`
	CapReason             string         `json:"cap_reason,omitempty"`
	BandLimited           bool           `json:"band_limited"`
	RecommendedSkippedPct int            `json:"recommended_skipped_pct"`
	Checklist             ChecklistScore `json:"checklist"`
	Penalty               Penalty        `json:"penalty"`
}

// BandOf maps a score to its band.
func BandOf(score int) string {
	switch {
	case score >= 90:
		return BandHealthy
	case score >= 70:
		return BandNeedsAttention
	case score >= 50:
		return BandAtRisk
	}
	return BandNotReady
}

// ComputeScore applies §7.1 to an evaluated checklist and its findings.
//
//  1. C = 100 × Σ wᵢcᵢ / Σ wᵢ over applicable items; weights Required 5,
//     Recommended 2, Optional 0; credit 1 for pass, 0 otherwise (a skip is
//     an accepted gap and earns nothing).
//  2. P = min(40, Σ points) with critical 15, high 8, medium 3, low 1;
//     accepted findings count half (rounded down); resolved count zero.
//  3. S = max(0, round(C) − P), capped at 49 while any applicable Required
//     item is not passing.
//  4. Bands 90+ healthy, 70+ needs attention, 50+ at risk, else not ready;
//     more than 10% of the Recommended weight skipped cannot be healthy.
func ComputeScore(e *Evaluation, findings []FindingInfo) ScoreBreakdown {
	var b ScoreBreakdown
	b.Checklist.Missing = []ScoreItem{}
	b.Penalty.Findings = []ScoreFinding{}
	requiredFailing := 0
	recWeight, recSkipped := 0, 0
	for _, it := range e.Items {
		if !it.Applicable {
			continue
		}
		w := levelWeight[it.Level]
		b.Checklist.Possible += w
		if it.Level == template.Recommended {
			recWeight += w
			if it.Status == StatusSkipped {
				recSkipped += w
			}
		}
		if it.Status == StatusPass {
			b.Checklist.Earned += w
			continue
		}
		if it.Level == template.Required {
			requiredFailing++
		}
		if w > 0 {
			si := ScoreItem{Item: it.ID, Title: it.Title, Level: string(it.Level), Status: it.Status, Points: w}
			if it.Status == StatusSkipped && it.Skip != nil {
				si.Reason = it.Skip.Reason
			}
			b.Checklist.Missing = append(b.Checklist.Missing, si)
		}
	}
	if b.Checklist.Possible > 0 {
		b.Checklist.Exact = 100 * float64(b.Checklist.Earned) / float64(b.Checklist.Possible)
		for i := range b.Checklist.Missing {
			b.Checklist.Missing[i].ScorePoints = math.Round(1000*float64(b.Checklist.Missing[i].Points)/float64(b.Checklist.Possible)) / 10
		}
	}
	b.Checklist.Score = int(math.Round(b.Checklist.Exact))
	for _, f := range findings {
		pts := severityPenalty[f.Severity]
		switch f.Status {
		case "accepted":
			pts /= 2
		case "resolved":
			pts = 0
		}
		b.Penalty.Raw += pts
		b.Penalty.Findings = append(b.Penalty.Findings, ScoreFinding{Code: f.Code + f.Variant, Title: f.Title,
			Severity: f.Severity, Status: f.Status, Points: pts})
	}
	b.Penalty.Total = min(PenaltyCap, b.Penalty.Raw)
	b.Penalty.Capped = b.Penalty.Raw > PenaltyCap
	b.Uncapped = max(0, b.Checklist.Score-b.Penalty.Total)
	b.Score = b.Uncapped
	if requiredFailing > 0 && b.Score > RequiredCap {
		b.Score, b.Capped = RequiredCap, true
		b.CapReason = "capped at 49 while a Required item is not passing"
	}
	if recWeight > 0 {
		b.RecommendedSkippedPct = 100 * recSkipped / recWeight
	}
	b.Band = BandOf(b.Score)
	if b.Band == BandHealthy && recWeight > 0 && float64(recSkipped)/float64(recWeight) > 0.10 {
		b.Band, b.BandLimited = BandNeedsAttention, true
	}
	return b
}

// TenantInput is one connection's contribution to the tenant score.
type TenantInput struct {
	Score    int
	Accounts int // in-scope accounts in the latest snapshot (minimum 1)
}

// TenantScore is T = Σ Sc × nc / Σ nc over connections that are validated or
// later, capped at 69 when the tenant has no active authoritative HR source
// (people with no account cannot be computed then). ok is false when no
// connection counts yet.
func TenantScore(in []TenantInput, hasHR bool) (score int, capped bool, ok bool) {
	num, den := 0.0, 0.0
	for _, c := range in {
		n := float64(max(1, c.Accounts))
		num += float64(c.Score) * n
		den += n
	}
	if den == 0 {
		return 0, false, false
	}
	score = int(math.Round(num / den))
	if !hasHR && score > 69 {
		return 69, true, true
	}
	return score, false, true
}
