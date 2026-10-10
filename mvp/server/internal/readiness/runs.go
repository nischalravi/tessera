package readiness

import (
	"encoding/json"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func runInfo(r *store.CheckRun) *RunInfo {
	return &RunInfo{ID: r.ID, Kind: r.Kind, Status: r.Status, ConfigHash: r.ConfigHash, Simulated: r.Simulated,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt}
}

func loadResults(c *store.TenantTx, run *store.CheckRun, into map[resultKey]*ResultInfo) error {
	rows, err := c.CheckResults(run.ID)
	if err != nil {
		return err
	}
	for _, r := range rows {
		ri := &ResultInfo{ItemID: r.ItemID, CheckID: r.CheckID, Status: r.Status, Message: r.Message,
			ItemHash: r.ItemHash, Simulated: r.Simulated, DurationMS: r.DurationMS}
		if err := json.Unmarshal([]byte(r.Observed), &ri.Observed); err != nil {
			return err
		}
		into[resultKey{r.ItemID, r.CheckID}] = ri
	}
	return nil
}

// loadRunEvidence loads the latest finished validation run (live results),
// the latest dry run (data results) and that dry run's findings.
func loadRunEvidence(c *store.TenantTx, rev *store.ConnectionRevision, ev *Evidence) error {
	live, err := c.LatestLiveRun(rev.ID)
	if err != nil {
		return err
	}
	if live != nil {
		ev.LiveRun = runInfo(live)
		if err := loadResults(c, live, ev.Live); err != nil {
			return err
		}
	}
	data, err := c.LatestDryRun(rev.ID)
	if err != nil {
		return err
	}
	if data != nil {
		ev.DataRun = runInfo(data)
		if err := loadResults(c, data, ev.Data); err != nil {
			return err
		}
		return loadFindings(c, data.ID, ev)
	}
	return nil
}
