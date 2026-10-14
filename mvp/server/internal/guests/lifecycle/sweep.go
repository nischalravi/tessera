package guestlife

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SweepResult counts what one pass did, by job.
type SweepResult struct {
	Reminders        RemindResult      `json:"reminders"`
	TransferTasks    int               `json:"transfer_tasks_opened"`
	TasksExpired     int               `json:"sponsorships_ended_by_deadline"`
	StepUpsApplied   int               `json:"stepup_renewals_applied"`
	Conversions      ConvertResult     `json:"conversions"`
	Deprovisioning   DeprovisionResult `json:"deprovisioning"`
	RenewalTokensOld int               `json:"renewal_links_expired"`
}

// Zero reports whether the pass did nothing.
func (r SweepResult) Zero() bool { return r == SweepResult{} }

// Sweep runs every lifecycle job for the tenant of tx, in the order that keeps
// each from undoing another: step-up renewals first (a guest who reached the
// assurance renews before anything ends them), then the deadlines of earlier
// tasks, new transfer tasks for departed sponsors, conversions, reminders, and
// last the grace and retention stages.
func (s *Service) Sweep(tx *store.TenantTx, now time.Time) (SweepResult, error) {
	var (
		res SweepResult
		err error
	)
	if res.StepUpsApplied, err = s.Sponsors.ApplyStepups(tx, 0, now); err != nil {
		return res, err
	}
	if res.TasksExpired, err = s.ExpireTasks(tx, now); err != nil {
		return res, err
	}
	if res.TransferTasks, err = s.ScanDepartures(tx, now); err != nil {
		return res, err
	}
	if res.Conversions, err = s.Convert(tx, now); err != nil {
		return res, err
	}
	if res.Reminders, err = s.Remind(tx, now); err != nil {
		return res, err
	}
	if res.RenewalTokensOld, err = tx.ExpireRenewalTokens(now); err != nil {
		return res, err
	}
	res.Deprovisioning, err = s.Deprovision(tx, now)
	return res, err
}
