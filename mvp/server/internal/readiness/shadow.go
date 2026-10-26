package readiness

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ShadowWindowDays is the period the production shadow agreement is measured over.
const ShadowWindowDays = 30

// ShadowAgreement is a tenant's production shadow agreement for AWS decisions
// (issue #641, EP-6): the share of sampled evaluator decisions that
// iam:SimulatePrincipalPolicy confirmed in the customer account. Rate is nil
// until at least one decision has been compared. Inconclusive checks (the
// simulator lacked context keys) and errors (the call failed) are counted
// apart and are not in the rate.
type ShadowAgreement struct {
	Enabled           bool     `json:"enabled"`
	DailyK            int      `json:"daily_k"`
	WindowDays        int      `json:"window_days"`
	Compared          int      `json:"compared"`
	Agree             int      `json:"agree"`
	Disagree          int      `json:"disagree"`
	Inconclusive      int      `json:"inconclusive"`
	Errors            int      `json:"errors"`
	Rate              *float64 `json:"rate"`
	OpenDisagreements int      `json:"open_disagreements"`
	LastCheckedAt     *string  `json:"last_checked_at"`
}

// ShadowAgreementOf measures the tenant's agreement over the last ShadowWindowDays.
// It returns nil for a tenant that has not opted in and has no checks, so the
// deployment health of a tenant that never used the feature is unchanged.
func ShadowAgreementOf(c *store.TenantTx, now time.Time) (*ShadowAgreement, error) {
	set, err := c.AWSShadowSettings()
	if err != nil {
		return nil, err
	}
	n, err := c.AWSShadowCounts(now.AddDate(0, 0, -ShadowWindowDays))
	if err != nil {
		return nil, err
	}
	out := &ShadowAgreement{Enabled: set.Enabled, DailyK: set.DailyK, WindowDays: ShadowWindowDays, Compared: n.Agree + n.Disagree,
		Agree: n.Agree, Disagree: n.Disagree, Inconclusive: n.Inconclusive, Errors: n.Error, OpenDisagreements: n.OpenDisagreements}
	if out.Compared > 0 {
		r := float64(n.Agree) / float64(out.Compared)
		out.Rate = &r
	}
	if n.LastCheckedAt != nil {
		t := store.RT(*n.LastCheckedAt)
		out.LastCheckedAt = &t
	}
	if !set.Enabled && n.LastCheckedAt == nil {
		return nil, nil
	}
	return out, nil
}
