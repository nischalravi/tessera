package readiness

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// FindingView is one finding as the API returns it.
type FindingView struct {
	ID          string             `json:"id"`
	RunID       string             `json:"run_id"`
	Code        string             `json:"code"`
	Variant     string             `json:"variant"`
	Title       string             `json:"title"`
	Severity    string             `json:"severity"`
	Status      string             `json:"status"`
	Count       int                `json:"count"`
	Denominator int                `json:"denominator"`
	Percent     int                `json:"percent"`
	Samples     []reconcile.Sample `json:"samples"`
	Impact      reconcile.Impact   `json:"impact"`
	Cause       *reconcile.Cause   `json:"cause"`
	ItemID      *string            `json:"item_id"`
	AcceptedBy  *string            `json:"accepted_by"`
	Reason      *string            `json:"reason"`
	ExpiresAt   *string            `json:"expires_at"`
	FirstSeenAt string             `json:"first_seen_at"`
	LastSeenAt  string             `json:"last_seen_at"`
}

// FindingOf renders a stored finding.
func FindingOf(f *store.Finding) (*FindingView, error) {
	v := &FindingView{ID: f.ID, RunID: f.RunID, Code: f.Code, Variant: f.Variant, Title: f.Title, Severity: f.Severity,
		Status: f.Status, Count: f.Count, Denominator: f.Denominator, ItemID: f.ItemID, AcceptedBy: f.AcceptedBy,
		Reason: f.Reason, FirstSeenAt: store.RT(f.FirstSeenAt), LastSeenAt: store.RT(f.LastSeenAt), Samples: []reconcile.Sample{}}
	if f.Denominator > 0 {
		v.Percent = (100*f.Count + f.Denominator/2) / f.Denominator
	}
	if f.ExpiresAt != nil {
		e := store.RT(*f.ExpiresAt)
		v.ExpiresAt = &e
	}
	if err := json.Unmarshal([]byte(f.Samples), &v.Samples); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(f.Impact), &v.Impact); err != nil {
		return nil, err
	}
	if f.Cause != nil {
		v.Cause = &reconcile.Cause{}
		if err := json.Unmarshal([]byte(*f.Cause), v.Cause); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// DryRunView is GET /api/connections/{id}/dry-runs/{run}.
type DryRunView struct {
	ID             string         `json:"id"`
	ConnectionID   string         `json:"connection_id"`
	RevisionID     string         `json:"revision_id"`
	Status         string         `json:"status"`
	Simulated      bool           `json:"simulated"`
	ConfigHash     string         `json:"config_hash"`
	Stale          bool           `json:"stale"`
	StaleReason    string         `json:"stale_reason,omitempty"`
	Actor          string         `json:"actor"`
	StartedAt      string         `json:"started_at"`
	FinishedAt     *string        `json:"finished_at"`
	Counts         DryRunCounts   `json:"counts"`
	KPIs           map[string]int `json:"kpis"`
	OpenBySeverity map[string]int `json:"open_by_severity"`
	ActivationNote string         `json:"activation_note"`
	Findings       []*FindingView `json:"findings"`
	Checks         []ResultView   `json:"checks"`
}

// DryRunView renders a dry run of a connection.
func (s *Service) DryRunView(c *store.Conn, connID, runID string, now time.Time) (*DryRunView, error) {
	rr, err := c.ReconRunByID(runID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && rr.ConnectionID != connID) {
		return nil, notFound("no dry run %s for this connection", runID)
	}
	if err != nil {
		return nil, err
	}
	rv, err := s.RunView(c, connID, runID, now)
	if err != nil {
		return nil, err
	}
	v := &DryRunView{ID: rr.ID, ConnectionID: connID, RevisionID: rr.RevisionID, Status: rr.Status, Simulated: rv.Simulated,
		ConfigHash: rv.ConfigHash, Stale: rv.Stale, StaleReason: rv.StaleReason, Actor: rv.Actor, StartedAt: rv.StartedAt,
		FinishedAt: rv.FinishedAt, KPIs: map[string]int{}, OpenBySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		Findings: []*FindingView{}, Checks: rv.Results}
	if rr.Counts != "" {
		if err := json.Unmarshal([]byte(rr.Counts), &v.Counts); err != nil {
			return nil, err
		}
	}
	fs, err := c.RunFindings(runID)
	if err != nil {
		return nil, err
	}
	orphans := 0
	for _, f := range fs {
		fv, err := FindingOf(f)
		if err != nil {
			return nil, err
		}
		v.Findings = append(v.Findings, fv)
		if f.Status == "open" {
			v.OpenBySeverity[f.Severity]++
		}
		switch f.Code {
		case "RF-01":
			orphans = f.Count
			v.KPIs["orphans"] = f.Count
		case "RF-02":
			v.KPIs["people_without_account"] = f.Count
		case "RF-08":
			v.KPIs["privileged_unexpected"] = f.Count
		}
	}
	for _, k := range []string{"orphans", "people_without_account", "privileged_unexpected"} {
		if _, ok := v.KPIs[k]; !ok {
			v.KPIs[k] = 0
		}
	}
	v.ActivationNote = fmt.Sprintf("Activating will add %d accounts to the graph.", v.Counts.Accounts)
	if orphans > 0 {
		b, err := s.reloadRev(c, rr.RevisionID, now)
		if err == nil && b.Config.HRIDAttribute != "" {
			v.ActivationNote = fmt.Sprintf("Activating will add %d accounts to the graph; %d will be orphans until %s is mapped.",
				v.Counts.Accounts, orphans, b.Config.HRIDAttribute)
		}
	}
	return v, nil
}

func (s *Service) reloadRev(c *store.Conn, revID string, now time.Time) (*Bundle, error) {
	return s.reload(c, revID, now)
}

// FindingFilter narrows GET /api/connections/{id}/findings.
type FindingFilter struct {
	RunID, Code, Severity, Status string
}

// Findings lists a connection's findings, by default those of the current
// revision's latest dry run.
func (s *Service) Findings(c *store.Conn, connID string, f FindingFilter, now time.Time) ([]*FindingView, error) {
	runID := f.RunID
	if runID == "" {
		b, err := s.Current(c, connID, now)
		if err != nil {
			return nil, err
		}
		if b.Evidence.DataRun == nil {
			return []*FindingView{}, nil
		}
		runID = b.Evidence.DataRun.ID
	} else if rr, err := c.ReconRunByID(runID); err != nil || rr.ConnectionID != connID {
		return nil, notFound("no dry run %s for this connection", runID)
	}
	fs, err := c.RunFindings(runID)
	if err != nil {
		return nil, err
	}
	out := []*FindingView{}
	for _, x := range fs {
		if (f.Code != "" && x.Code != f.Code) || (f.Severity != "" && x.Severity != f.Severity) || (f.Status != "" && x.Status != f.Status) {
			continue
		}
		v, err := FindingOf(x)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
