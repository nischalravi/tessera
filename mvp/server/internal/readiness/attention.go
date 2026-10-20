package readiness

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Needs attention (design §7.3): one ranked list per tenant.

var severityWeight = map[string]float64{"critical": 8, "high": 4, "medium": 2, "low": 1}

// Rank is severity_weight × (1 + log10(1 + affected)) × (privileged ? 2 : 1)
// × (blocks_activation ? 1.5 : 1).
func Rank(severity string, affected int, privileged, blocksActivation bool) float64 {
	r := severityWeight[severity] * (1 + math.Log10(1+float64(max(0, affected))))
	if privileged {
		r *= 2
	}
	if blocksActivation {
		r *= 1.5
	}
	return math.Round(r*100) / 100
}

// Fix is where an entry's single "Fix" link goes.
type Fix struct {
	Kind      string `json:"kind"` // item | finding
	ItemID    string `json:"item_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	Href      string `json:"href"`
}

// AttentionEntry is one needs-attention row.
type AttentionEntry struct {
	ID               string  `json:"id"`
	Kind             string  `json:"kind"` // item | finding | skip
	Severity         string  `json:"severity"`
	Sentence         string  `json:"sentence"`
	ConnectionID     string  `json:"connection_id"`
	ConnectionName   string  `json:"connection_name"`
	AgeDays          int     `json:"age_days"`
	Affected         int     `json:"affected"`
	Privileged       bool    `json:"privileged"`
	BlocksActivation bool    `json:"blocks_activation"`
	Rank             float64 `json:"rank"`
	Code             string  `json:"code,omitempty"`
	Fix              Fix     `json:"fix"`
	since            time.Time
}

func days(now, t time.Time) int { return max(0, int(now.Sub(t).Hours()/24)) }

// attention builds a connection's entries from its scored revision.
func attention(b *Bundle, findings []*store.Finding, now time.Time) []AttentionEntry {
	pending := IsPending(b.Rev.State)
	base := "/admin/connections/" + b.Conn.ID
	var out []AttentionEntry
	add := func(e AttentionEntry) {
		e.ConnectionID, e.ConnectionName = b.Conn.ID, b.Conn.Name
		e.Rank = Rank(e.Severity, e.Affected, e.Privileged, e.BlocksActivation)
		e.AgeDays = days(now, e.since)
		out = append(out, e)
	}
	for _, it := range b.Eval.Items {
		// base.dryrun.reviewed fails because of open findings, which are listed themselves.
		if !it.Applicable || it.ID == "base.dryrun.reviewed" {
			continue
		}
		item := Fix{Kind: "item", ItemID: it.ID, Href: base + "?item=" + it.ID}
		switch {
		case it.Level == template.Required && (it.Status == StatusFail || it.Status == StatusStale):
			add(AttentionEntry{ID: b.Conn.ID + "/" + it.ID, Kind: "item", Severity: "high", Affected: 1,
				BlocksActivation: true, Sentence: fmt.Sprintf("%s: %s", it.Title, strings.TrimSuffix(it.Reason, ".")) + ".",
				Fix: item, since: b.Rev.UpdatedAt})
		case it.Level == template.Recommended && (it.Status == StatusFail || it.Status == StatusStale ||
			(it.Status == StatusPending && it.Skip != nil)):
			sev := "medium"
			sentence := fmt.Sprintf("%s: %s", it.Title, strings.TrimSuffix(it.Reason, ".")) + "."
			add(AttentionEntry{ID: b.Conn.ID + "/" + it.ID, Kind: "item", Severity: sev, Affected: 1,
				BlocksActivation: pending, Sentence: sentence, Fix: item, since: b.Rev.UpdatedAt})
		case it.Status == StatusSkipped && it.Skip != nil:
			due := days(it.Skip.ReviewBy, now)
			if due <= 30 {
				add(AttentionEntry{ID: b.Conn.ID + "/" + it.ID + "/skip", Kind: "skip", Severity: "low", Affected: 1,
					Sentence: fmt.Sprintf("%s skipped by %s: %q (review due in %d days).", it.Title, it.Skip.ActorID, it.Skip.Reason, due),
					Fix:      item, since: it.Skip.SkippedAt})
			}
		}
	}
	for _, f := range findings {
		if f.Status != "open" {
			continue
		}
		var im reconcile.Impact
		_ = json.Unmarshal([]byte(f.Impact), &im) // written by this package
		sentence := im.Sentence
		if f.Cause != nil {
			var cause reconcile.Cause
			if json.Unmarshal([]byte(*f.Cause), &cause) == nil && cause.Sentence != "" {
				sentence = cause.Sentence
			}
		}
		if sentence == "" {
			sentence = f.Title + "."
		}
		add(AttentionEntry{ID: f.ID, Kind: "finding", Severity: f.Severity, Code: f.Code + f.Variant, Affected: f.Count,
			Privileged:       im.PrivilegedGrants > 0 || f.Code == "RF-08" || f.Code == "RF-11",
			BlocksActivation: pending && (f.Severity == "critical" || f.Severity == "high"),
			Sentence:         sentence, Fix: Fix{Kind: "finding", FindingID: f.ID, Href: base + "?finding=" + f.ID}, since: f.FirstSeenAt})
	}
	return out
}

// SortAttention orders entries by rank; ties go to the oldest.
func SortAttention(es []AttentionEntry) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].Rank != es[j].Rank {
			return es[i].Rank > es[j].Rank
		}
		if !es[i].since.Equal(es[j].since) {
			return es[i].since.Before(es[j].since)
		}
		return es[i].ID < es[j].ID
	})
}

// ---------------------------------------------------------------- dashboard

// ConnectionHealth is one row of the connections table.
type ConnectionHealth struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	ConnectorType string  `json:"connector_type"`
	State         string  `json:"state"`
	Health        string  `json:"health"`
	Simulated     bool    `json:"simulated"`
	Score         int     `json:"score"`
	Band          string  `json:"band"`
	Counted       bool    `json:"counted"` // included in the tenant score
	Accounts      int     `json:"accounts"`
	Blocking      int     `json:"blocking"`
	LastValidated *string `json:"last_validated"`
	LastDryRun    *string `json:"last_dry_run"`
	Drift         any     `json:"drift"`
}

// SkippedView is a skipped Recommended item.
type SkippedView struct {
	ConnectionID   string `json:"connection_id"`
	ConnectionName string `json:"connection_name"`
	ItemID         string `json:"item_id"`
	ItemTitle      string `json:"item_title"`
	Level          string `json:"level"`
	Actor          string `json:"actor"`
	Reason         string `json:"reason"`
	SkippedAt      string `json:"skipped_at"`
	ReviewBy       string `json:"review_by"`
	Expired        bool   `json:"expired"`
}

// TenantHealth is the tenant score and its basis.
type TenantHealth struct {
	Score     *int   `json:"score"`
	Band      string `json:"band"`
	Capped    bool   `json:"capped"`
	CapReason string `json:"cap_reason,omitempty"`
	HRSource  string `json:"hr_source"`
	Counted   int    `json:"connections_counted"`
	Formula   string `json:"formula"`
}

// Dashboard is GET /api/insights/deployment-health.
type Dashboard struct {
	GeneratedAt    string             `json:"generated_at"`
	Tenant         TenantHealth       `json:"tenant"`
	KPIs           map[string]int     `json:"kpis"`
	Connections    []ConnectionHealth `json:"connections"`
	NeedsAttention []AttentionEntry   `json:"needs_attention"`
	Skipped        []SkippedView      `json:"skipped"`
	Drift          []*DriftView       `json:"drift"`
	Tasks          []Task             `json:"tasks"` // Inbox tasks (source "connection"): degraded connections
	Schedule       map[string]string  `json:"schedule"`
	Scenario       string             `json:"scenario"`
}

// scored returns the revision a connection is scored on: the live one, or
// the in-progress one before the first activation.
func (s *Service) scored(c *store.TenantTx, conn *store.Connection, now time.Time) (*Bundle, error) {
	_, live, pending, err := Revisions(c, conn.ID)
	if err != nil {
		return nil, err
	}
	rev := live
	if rev == nil {
		rev = pending
	}
	if rev == nil {
		return nil, nil
	}
	return s.Load(c, rev, now)
}

func countedState(state string) bool {
	return state == store.StateValidated || state == store.StateDryRunReconciled || IsLive(state)
}

// ConnectionScore computes a connection's score breakdown.
func (s *Service) ConnectionScore(b *Bundle) ScoreBreakdown {
	return ComputeScore(b.Eval, b.Evidence.Findings)
}

func dryRunCounts(c *store.TenantTx, b *Bundle) (DryRunCounts, error) {
	var dc DryRunCounts
	if b.Evidence.DataRun == nil {
		return dc, nil
	}
	rr, err := c.ReconRunByID(b.Evidence.DataRun.ID)
	if err != nil || rr.Counts == "" {
		return dc, err
	}
	return dc, json.Unmarshal([]byte(rr.Counts), &dc)
}

// Dashboard builds the tenant's deployment health (§7.2–7.4). legacyHR
// names an env-configured HR connector still feeding the graph (the demo's
// Workday), which counts as the authoritative HR source until it is governed.
func (s *Service) Dashboard(c *store.TenantTx, now time.Time, legacyHR string) (*Dashboard, error) {
	d := &Dashboard{GeneratedAt: store.RT(now), KPIs: map[string]int{}, Connections: []ConnectionHealth{},
		NeedsAttention: []AttentionEntry{}, Skipped: []SkippedView{}, Drift: []*DriftView{}, Schedule: s.scheduleInfo(),
		Scenario: s.Runner.withDefaults().Scenario}
	conns, err := c.Connections()
	if err != nil {
		return nil, err
	}
	var inputs []TenantInput
	hrName := ""
	users, correlated, orphans, dormant, privileged, openCH, setup, degraded := 0, 0, 0, 0, 0, 0, 0, 0
	for _, conn := range conns {
		if conn.RetiredAt != nil {
			continue
		}
		b, err := s.scored(c, conn, now)
		if err != nil {
			return nil, err
		}
		if b == nil {
			continue
		}
		sc := s.ConnectionScore(b)
		dc, err := dryRunCounts(c, b)
		if err != nil {
			return nil, err
		}
		row := ConnectionHealth{ID: conn.ID, Name: conn.Name, ConnectorType: conn.ConnectorType, State: b.Rev.State,
			Health: conn.Health, Simulated: IsDemoType(conn.ConnectorType), Score: sc.Score, Band: sc.Band,
			Accounts: max(1, dc.Users), Counted: countedState(b.Rev.State)}
		if b.Evidence.LiveRun != nil && b.Evidence.LiveRun.FinishedAt != nil {
			t := store.RT(*b.Evidence.LiveRun.FinishedAt)
			row.LastValidated = &t
		}
		if b.Evidence.DataRun != nil && b.Evidence.DataRun.FinishedAt != nil {
			t := store.RT(*b.Evidence.DataRun.FinishedAt)
			row.LastDryRun = &t
		}
		if to, _ := nextStep(b.Rev.State); to != "" {
			row.Blocking = len(b.Gate(to, now).Blocking)
		}
		switch {
		case b.Rev.State == store.StateDegraded:
			degraded++
		case IsPending(b.Rev.State):
			setup++
		}
		if conn.Role == "authoritative" && IsLive(b.Rev.State) {
			hrName = conn.Name
		}
		if row.Counted {
			inputs = append(inputs, TenantInput{Score: sc.Score, Accounts: row.Accounts})
			users += dc.Users
			correlated += dc.Tier1 + dc.Tier2
		}
		dv, err := s.Drift(c, b, now)
		if err != nil {
			return nil, err
		}
		if dv != nil {
			row.Drift = dv.brief()
			d.Drift = append(d.Drift, dv)
		}
		d.Connections = append(d.Connections, row)
		var fs []*store.Finding
		if b.Evidence.DataRun != nil {
			if fs, err = c.RunFindings(b.Evidence.DataRun.ID); err != nil {
				return nil, err
			}
		}
		for _, f := range fs {
			if f.Status == "resolved" {
				continue
			}
			switch f.Code {
			case "RF-01":
				orphans += f.Count
			case "RF-07":
				dormant += f.Count
			}
			if f.Status == "open" && (f.Severity == "critical" || f.Severity == "high") {
				openCH++
			}
		}
		if b.Evidence.DataRun != nil {
			n, err := c.StagedPrivilegedAccounts(b.Evidence.DataRun.ID)
			if err != nil {
				return nil, err
			}
			privileged += n
		}
		d.NeedsAttention = append(d.NeedsAttention, attention(b, fs, now)...)
		for _, it := range b.Eval.Items {
			if it.Skip == nil {
				continue
			}
			d.Skipped = append(d.Skipped, SkippedView{ConnectionID: conn.ID, ConnectionName: conn.Name, ItemID: it.ID,
				ItemTitle: it.Title, Level: string(it.Level), Actor: it.Skip.ActorID, Reason: it.Skip.Reason,
				SkippedAt: store.RT(it.Skip.SkippedAt), ReviewBy: store.RT(it.Skip.ReviewBy), Expired: !it.Skip.ReviewBy.After(now)})
		}
	}
	if d.Tasks, err = s.Tasks(c, now); err != nil {
		return nil, err
	}
	if hrName == "" && legacyHR != "" {
		hrName = legacyHR + " (legacy connector)"
	}
	d.Tenant.HRSource = hrName
	d.Tenant.Formula = "Σ score × accounts / Σ accounts over connections validated or later; capped at 69 without an active authoritative HR source"
	if score, capped, ok := TenantScore(inputs, hrName != ""); ok {
		d.Tenant.Score, d.Tenant.Band, d.Tenant.Capped = &score, BandOf(score), capped
		if capped {
			d.Tenant.CapReason = "no active authoritative HR source: people with no account cannot be computed"
		}
	}
	d.Tenant.Counted = len(inputs)
	if users > 0 {
		d.KPIs["accounts_correlated_pct"] = (100*correlated + users/2) / users
	}
	d.KPIs["orphans"], d.KPIs["dormant"], d.KPIs["privileged_accounts"] = orphans, dormant, privileged
	d.KPIs["open_critical_high"], d.KPIs["connections_in_setup"], d.KPIs["degraded"] = openCH, setup, degraded
	SortAttention(d.NeedsAttention)
	return d, nil
}

// ConnectionHealthView is GET /api/connections/{id}/health.
type ConnectionHealthView struct {
	ConnectionID   string            `json:"connection_id"`
	RevisionID     string            `json:"revision_id"`
	State          string            `json:"state"`
	Breakdown      ScoreBreakdown    `json:"breakdown"`
	NeedsAttention []AttentionEntry  `json:"needs_attention"`
	Drift          *DriftView        `json:"drift"` // null until the revision is live and has a baseline
	Schedule       map[string]string `json:"schedule"`
}

// Health returns one connection's score breakdown and needs-attention list.
func (s *Service) Health(c *store.TenantTx, connID string, now time.Time) (*ConnectionHealthView, error) {
	conn, _, _, err := Revisions(c, connID)
	if err != nil {
		return nil, err
	}
	b, err := s.scored(c, conn, now)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, notFound("connection %s has no revision", connID)
	}
	var fs []*store.Finding
	if b.Evidence.DataRun != nil {
		if fs, err = c.RunFindings(b.Evidence.DataRun.ID); err != nil {
			return nil, err
		}
	}
	es := attention(b, fs, now)
	SortAttention(es)
	if es == nil {
		es = []AttentionEntry{}
	}
	dv, err := s.Drift(c, b, now)
	if err != nil {
		return nil, err
	}
	return &ConnectionHealthView{ConnectionID: conn.ID, RevisionID: b.Rev.ID, State: b.Rev.State, Breakdown: s.ConnectionScore(b),
		NeedsAttention: es, Drift: dv, Schedule: s.scheduleInfo()}, nil
}

// RecordScore appends a connection score to the readiness_scores series
// when it changed since the last recorded value.
func (s *Service) RecordScore(c *store.TenantTx, b *Bundle, now time.Time) error {
	sc := s.ConnectionScore(b)
	raw, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	return c.RecordScore(&store.ScoreRow{Scope: "connection", ConnectionID: &b.Conn.ID, RevisionID: &b.Rev.ID,
		ComputedAt: now, Score: sc.Score, Band: sc.Band, Breakdown: string(raw)})
}
