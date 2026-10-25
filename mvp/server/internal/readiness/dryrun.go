package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// StageFunc writes a discovery result into the staging tables (ingest.Stage;
// passed in because ingest depends on this package for ActiveConnection).
type StageFunc func(c *store.TenantTx, runID, system string, res *connectors.DiscoveryResult) error

// hrItems name the checklist item that maps the HR id, per template.
var hrItems = map[string]string{"ad": "ad.key.employeeid", "ldap": "ldap.key.hr_id", "entra": "entra.key.employeeid",
	"okta": "okta.key.employee_number", "google": "gws.key.employee", "scim_app": "scim.key.correlate", "salesforce": "salesforce.key.employee",
	// the governed types have no HR attribute of their own: the generic correlation item holds the mapping
	"pam": "base.correlation.rule", "erp": "base.correlation.rule", "agentcore": "base.correlation.rule", "servicenow": "base.correlation.rule", "atlassian": "base.correlation.rule", "mcp": "base.correlation.rule", "bedrock": "base.correlation.rule",
	"vertex": "base.correlation.rule", "foundry": "base.correlation.rule", "copilot": "base.correlation.rule", "agentforce": "base.correlation.rule"}

// meta describes a revision for reconciliation.
func meta(b *Bundle, now time.Time) reconcile.Meta {
	m := reconcile.Meta{ConnectionID: b.Conn.ID, System: b.Conn.System, SystemName: b.Template.DisplayName,
		TemplateID: b.Template.ID, Inventory: b.Template.Inventory, Role: b.Conn.Role, CorrelationKey: b.Config.CorrelationKey,
		HRAttribute: b.Config.HRIDAttribute, HRItem: hrItems[b.Template.ID],
		RequiredAttrs: b.Template.RequiredAttributes["user"], RecommendedAttrs: b.Template.RecommendedAttributes["user"],
		Thresholds: b.Template.Thresholds, Privileged: b.Config.PrivilegedExpected, StaleDays: b.Config.StaleDays, Now: now}
	if m.Role == "authoritative" {
		m.HRItem = ""
	}
	if ec := b.Config.ExpectedCounts; ec != nil {
		if ec.Users > 0 {
			m.ExpectedUsers = &ec.Users
		}
		if ec.Groups > 0 {
			m.ExpectedGroups = &ec.Groups
		}
	}
	return m
}

// connectorFor returns the connector a dry run discovers through: the demo
// connectors, and the governed types' own connectors built from the
// connection (PAM, ERP, code scan, AgentCore; see GovOptions). The live
// directory types arrive with DR-12 to DR-18.
func (s *Service) connectorFor(b *Bundle, now time.Time) (connectors.Connector, error) {
	if cn, ok := connectors.DemoConnectorFor(b.Conn.ConnectorType, now); ok {
		return cn, nil
	}
	if govLive(b) {
		return s.Runner.Gov.connector(b, now)
	}
	return nil, conflict("connector_unavailable", "no %s connector is available yet: live connectors arrive with DR-12 to DR-18",
		b.Conn.ConnectorType)
}

// OpenConnector returns the connector of a live connection for its first
// sync, or ok=false when the type has none to open (the live directory types
// before DR-12 to DR-18, and the governed types whose records are read by
// their own feature). A governed connection's connector is built from its
// live revision's settings and sealed credential, opened inside the transaction.
func (s *Service) OpenConnector(c *store.TenantTx, ac ActiveConnection, now time.Time) (cn connectors.Connector, ok bool, err error) {
	if cn, ok := connectors.DemoConnectorFor(ac.connectorType, now); ok {
		return cn, true, nil
	}
	t, isGov := governed.Lookup(ac.connectorType)
	if !isGov || t.Feature {
		return nil, false, nil
	}
	b, err := s.liveBundle(c, ac, now)
	if err != nil {
		return nil, false, err
	}
	cn, err = s.Runner.Gov.connector(b, now)
	return cn, err == nil, err
}

// GovernedConnectors opens the connectors of a tenant's live governed
// connections (PAM, ERP, code scan, AgentCore) for a sync, in its own read
// transaction. A connection whose connector cannot be opened (its credential no
// longer opens, the source refuses a setting) is returned in failed with the
// reason, so the others are still read and the failure is reported rather than
// hidden. Types that hand over to their own feature are not here: that feature
// syncs them.
func (s *Service) GovernedConnectors(ctx context.Context, db *store.DB, t tenancy.ID, now time.Time) (cns []connectors.Connector, failed map[string]error, err error) {
	err = db.ReadTenant(ctx, t, func(c *store.TenantTx) (err error) {
		cns, failed, err = s.GovernedConnectorsTx(c, now)
		return err
	})
	return cns, failed, err
}

// GovernedConnectorsTx is GovernedConnectors inside the caller's transaction.
func (s *Service) GovernedConnectorsTx(c *store.TenantTx, now time.Time) (cns []connectors.Connector, failed map[string]error, err error) {
	failed = map[string]error{}
	live, err := s.ActiveConnections(c)
	if err != nil {
		return nil, nil, err
	}
	for _, ac := range live {
		if gt, ok := governed.Lookup(ac.connectorType); !ok || gt.Feature {
			continue
		}
		cn, _, err := s.OpenConnector(c, ac, now)
		if err != nil {
			failed[ac.name] = err
			continue
		}
		cns = append(cns, cn)
	}
	return cns, failed, nil
}

// GovernedParams returns a live governed connection as the governed package
// opens it (settings and the opened credential), for the hand-over of the
// connector types whose records are read by their own feature.
func (s *Service) GovernedParams(c *store.TenantTx, ac ActiveConnection, now time.Time) (governed.Params, error) {
	if _, ok := governed.Lookup(ac.connectorType); !ok {
		return governed.Params{}, conflict("connector_unavailable", "%s is not a governed connector type", ac.connectorType)
	}
	b, err := s.liveBundle(c, ac, now)
	if err != nil {
		return governed.Params{}, err
	}
	return s.Runner.Gov.params(b), nil
}

func (s *Service) liveBundle(c *store.TenantTx, ac ActiveConnection, now time.Time) (*Bundle, error) {
	rev, err := c.Revision(ac.revisionID)
	if err != nil {
		return nil, err
	}
	b, err := s.Load(c, rev, now)
	if err != nil {
		return nil, err
	}
	return b, s.loadCredential(c, b)
}

// DryRun stages a snapshot of the connection's in-progress revision and
// reconciles it (§6). It writes staging tables and reconciliation results
// only; the live graph is untouched until activation.
func (s *Service) DryRun(ctx context.Context, st Scope, connID, actor string, clock func() time.Time, stage StageFunc) (*DryRunView, error) {
	return s.dryRun(ctx, st, connID, actor, clock, stage, false)
}

// dryRun is DryRun, or with live set the post-activation reconciliation of
// the live revision (§7.4): the same discovery, staging scratch tables and
// analysis, recorded as a 'live' reconciliation run.
func (s *Service) dryRun(ctx context.Context, st Scope, connID, actor string, clock func() time.Time, stage StageFunc, live bool) (*DryRunView, error) {
	start := clock()
	var b *Bundle
	var run *store.CheckRun
	var cn connectors.Connector
	mode, started := "staging", "readiness.dryrun.started"
	if live {
		mode, started = "live", "readiness.reconcile.started"
	}
	err := st.Write(ctx, func(c *store.TenantTx) error {
		conn, liveRev, pending, err := Revisions(c, connID)
		if err != nil {
			return err
		}
		if conn.RetiredAt != nil {
			return conflict("connection_retired", "connection %s is retired", conn.Name)
		}
		if live {
			pending = liveRev
			if pending == nil {
				return conflict("not_live", "the connection has no live revision")
			}
		}
		if pending == nil {
			return conflict("no_pending_revision", "the connection has no revision in setup")
		}
		if b, err = s.Load(c, pending, start); err != nil {
			return err
		}
		if !live && pending.State != store.StateValidated && pending.State != store.StateDryRunReconciled {
			return blocked("not_ready_for_dry_run", b.Gate(store.StateValidated, start))
		}
		if n, err := c.RunningDryRuns(); err != nil {
			return err
		} else if n > 0 {
			return conflict("dry_run_running", "a dry run is already in flight in this tenant")
		}
		if err = s.loadCredential(c, b); err != nil {
			return err
		}
		if cn, err = s.connectorFor(b, start); err != nil {
			return err
		}
		run = &store.CheckRun{ID: store.NewID(), RevisionID: pending.ID, Kind: "dry_run", Simulated: b.Simulated(),
			Status: "running", ActorID: actor, ConfigHash: b.ConfigHash, StartedAt: start}
		if err := c.InsertCheckRun(run); err != nil {
			return err
		}
		if err := c.InsertReconRun(&store.ReconRun{ID: run.ID, RevisionID: pending.ID, ConnectionID: conn.ID, Mode: mode,
			CheckRunID: run.ID, Status: "running", StartedAt: start}); err != nil {
			return err
		}
		return c.Audit(start, actor, started, ojson.Object{{Key: "connection_id", Value: conn.ID},
			{Key: "revision_id", Value: pending.ID}, {Key: "run_id", Value: run.ID}})
	})
	if err != nil {
		return nil, err
	}
	res, derr := cn.Discover(ctx)
	err = st.Write(context.WithoutCancel(ctx), func(c *store.TenantTx) error {
		now := clock()
		if derr != nil {
			if err := c.FinishCheckRun(run.ID, "aborted", now); err != nil {
				return err
			}
			return c.FinishReconRun(run.ID, "aborted", "{}", now)
		}
		return s.reconcileRun(c, b, run, res, actor, now, stage)
	})
	if err != nil {
		return nil, err
	}
	if derr != nil {
		return nil, fmt.Errorf("readiness: dry run discovery: %w", derr)
	}
	var v *DryRunView
	err = st.Read(ctx, func(c *store.TenantTx) error {
		var err error
		v, err = s.DryRunView(c, connID, run.ID, clock())
		return err
	})
	return v, err
}

// DryRunCounts are the staged object counts and correlation tiers.
type DryRunCounts struct {
	Accounts      int `json:"accounts"`
	Users         int `json:"users"`
	Service       int `json:"service"`
	Groups        int `json:"groups"`
	Privileged    int `json:"privileged_groups"`
	Memberships   int `json:"memberships"`
	Identities    int `json:"identities"`
	Tier1         int `json:"tier1"`
	Tier2         int `json:"tier2"`
	Proposed      int `json:"proposed"`
	Ambiguous     int `json:"ambiguous"`
	Uncorrelated  int `json:"uncorrelated"`
	CorrelatedPct int `json:"correlated_pct"`
}

func (s *Service) reconcileRun(c *store.TenantTx, b *Bundle, run *store.CheckRun, res *connectors.DiscoveryResult, actor string,
	now time.Time, stage StageFunc) error {
	m := meta(b, now)
	attrs := slices.Concat(m.RequiredAttrs, m.RecommendedAttrs, []string{m.CorrelationKey, m.HRAttribute})
	prepared := reconcile.PrepareDiscovery(b.Template.ID, res, attrs)
	if err := stage(c, run.ID, b.Conn.System, prepared); err != nil {
		return err
	}
	snap, err := reconcile.LoadSnapshot(c, run.ID, m)
	if err != nil {
		return err
	}
	in, links, err := liveContext(c, b.Conn.System)
	if err != nil {
		return err
	}
	var people []reconcile.Person
	for _, p := range in.People {
		people = append(people, p)
	}
	for _, r := range reconcile.Correlate(snap.Accounts, m.HRAttribute, m.Role, people, links) {
		if err := c.SetStagedCorrelation(run.ID, r.System, r.ExternalID, r.Outcome, r.Tier, r.IdentityID, r.ProposedID); err != nil {
			return err
		}
	}
	if snap, err = reconcile.LoadSnapshot(c, run.ID, m); err != nil {
		return err
	}
	if in.Impact, err = reconcile.BuildImpact(c); err != nil {
		return err
	}
	in.Snap = snap
	findings, err := reconcile.Analyze(in)
	if err != nil {
		return err
	}
	if err := s.storeFindings(c, b.Conn.ID, run.ID, findings, now); err != nil {
		return err
	}
	counts := countsOf(snap)
	raw, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	if snap, err = reconcile.LoadSnapshot(c, run.ID, m); err != nil {
		return err
	}
	if err := s.writeDataResults(c, b, run, snap, now); err != nil {
		return err
	}
	if err := c.FinishReconRun(run.ID, "completed", string(raw), now); err != nil {
		return err
	}
	if err := c.FinishCheckRun(run.ID, "completed", now); err != nil {
		return err
	}
	if err := c.BumpEvidence(b.Rev.ID, now); err != nil {
		return err
	}
	if err := c.PruneStaging(b.Rev.ID, 3); err != nil {
		return err
	}
	bySev := ojson.Object{}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := 0
		for _, f := range findings {
			if f.Severity == sev {
				n++
			}
		}
		bySev = append(bySev, ojson.KV{Key: sev, Value: n})
	}
	if err := c.Audit(now, actor, "readiness.dryrun.completed", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "run_id", Value: run.ID}, {Key: "accounts", Value: counts.Accounts},
		{Key: "findings", Value: bySev}}); err != nil {
		return err
	}
	nb, err := s.reload(c, b.Rev.ID, now)
	if err != nil {
		return err
	}
	return s.settle(c, nb, actor, now, "dry run")
}

// liveContext loads the authoritative people (the live HR identities), how
// many enabled accounts each has in other systems, the owned non-human
// identities, and tier-2 links from other live connections.
func liveContext(c *store.TenantTx, system string) (reconcile.Input, []reconcile.LiveLink, error) {
	in := reconcile.Input{People: map[int64]reconcile.Person{}, Elsewhere: map[int64]int{}}
	people, err := c.Identities()
	if err != nil {
		return in, nil, err
	}
	for _, p := range people {
		if p.Type != "human" {
			continue
		}
		in.People[p.ID] = reconcile.Person{ID: p.ID, ExternalID: p.ExternalID, Name: p.Name, Email: deref(p.Email),
			Status: p.Status, Department: deref(p.Department), Title: deref(p.Title), TerminatedAt: tsPtr(p.TerminatedAt)}
	}
	accts, err := c.Accounts()
	if err != nil {
		return in, nil, err
	}
	var links []reconcile.LiveLink
	for _, a := range accts {
		if a.System == system || a.IdentityID == nil {
			continue
		}
		links = append(links, reconcile.LiveLink{System: a.System, ExternalID: a.ExternalID, IdentityID: *a.IdentityID})
		if a.Status == "active" {
			in.Elsewhere[*a.IdentityID]++
		}
	}
	in.Owned, err = c.OwnedIdentityXIDs()
	return in, links, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func tsPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func countsOf(snap *reconcile.Snapshot) DryRunCounts {
	c := DryRunCounts{Accounts: len(snap.Accounts), Groups: len(snap.Groups), Memberships: len(snap.Memberships),
		Identities: len(snap.Identities)}
	for _, g := range snap.Groups {
		if g.Privileged {
			c.Privileged++
		}
	}
	for _, a := range snap.Accounts {
		switch a.Correlation {
		case reconcile.Service:
			c.Service++
			continue
		case reconcile.Correlated:
			if a.Tier == 2 {
				c.Tier2++
			} else {
				c.Tier1++
			}
		case reconcile.Proposed:
			c.Proposed++
		case reconcile.Ambiguous:
			c.Ambiguous++
		case reconcile.Uncorrelated:
			c.Uncorrelated++
		}
		if !reconcile.IsService(a) {
			c.Users++
		}
	}
	if c.Users > 0 {
		c.CorrelatedPct = (100*(c.Tier1+c.Tier2) + c.Users/2) / c.Users
	}
	return c
}

// storeFindings writes a run's findings. An accepted finding stays accepted
// in the next run when the same finding (code and variant) is found again
// and its acceptance has not expired; findings of the previous run that
// are no longer found are resolved (§6.6).
func (s *Service) storeFindings(c *store.TenantTx, connID, runID string, fs []reconcile.Finding, now time.Time) error {
	prev, err := c.PreviousFindings(connID, runID)
	if err != nil {
		return err
	}
	byKey := map[string]*store.Finding{}
	for _, p := range prev {
		byKey[p.Code+"|"+p.Variant] = p
	}
	found := map[string]bool{}
	for _, f := range fs {
		samples, err := json.Marshal(f.Samples)
		if err != nil {
			return err
		}
		impact, err := json.Marshal(f.Impact)
		if err != nil {
			return err
		}
		row := &store.Finding{ID: store.NewID(), RunID: runID, ConnectionID: connID, Code: f.Code, Variant: f.Variant,
			Title: f.Title, Severity: f.Severity, Count: f.Count, Denominator: f.Denominator, Samples: string(samples),
			Impact: string(impact), Status: "open", FirstSeenAt: now, LastSeenAt: now}
		if f.Cause != nil {
			raw, err := json.Marshal(f.Cause)
			if err != nil {
				return err
			}
			cs := string(raw)
			row.Cause = &cs
		}
		if f.ItemID != "" {
			item := f.ItemID
			row.ItemID = &item
		}
		if p := byKey[f.Key()]; p != nil {
			found[f.Key()] = true
			row.FirstSeenAt = p.FirstSeenAt
			if p.Status == "accepted" && (p.ExpiresAt == nil || p.ExpiresAt.After(now)) {
				row.Status, row.AcceptedBy, row.Reason, row.ExpiresAt = "accepted", p.AcceptedBy, p.Reason, p.ExpiresAt
			}
		}
		if err := c.InsertFinding(row); err != nil {
			return err
		}
	}
	for k, p := range byKey {
		if !found[k] && p.Status != "resolved" {
			if err := c.ResolveFinding(p.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeDataResults evaluates every applicable data check over the snapshot
// and replaces the run's results.
func (s *Service) writeDataResults(c *store.TenantTx, b *Bundle, run *store.CheckRun, snap *reconcile.Snapshot, now time.Time) error {
	if err := c.DeleteCheckResults(run.ID); err != nil {
		return err
	}
	env := checks.Env{Now: now, TemplateID: b.Template.ID, Snapshot: snap}
	for _, ie := range b.Eval.Items {
		if !ie.Applicable {
			continue
		}
		for _, v := range ie.Verify {
			if v.Kind != template.Data {
				continue
			}
			res := checks.Result{Status: checks.Error, Message: "no implementation for " + v.Check, Observed: map[string]any{}}
			start := time.Now()
			if ck, ok := checks.Get(v.Check); ok {
				res = checks.Run(context.Background(), ck, env, checks.Params(v.Params))
			}
			obs, err := json.Marshal(res.Observed)
			if err != nil {
				return err
			}
			if err := c.InsertCheckResult(&store.CheckResult{RunID: run.ID, ItemID: ie.ID, CheckID: v.Check, Status: res.Status,
				Observed: string(obs), Message: res.Message, DurationMS: int(time.Since(start).Milliseconds()),
				ItemHash: ie.ItemHash, Simulated: run.Simulated}); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadFindings loads a dry run's findings into the evidence.
func loadFindings(c *store.TenantTx, runID string, ev *Evidence) error {
	fs, err := c.RunFindings(runID)
	if err != nil {
		return err
	}
	for _, f := range fs {
		ev.Findings = append(ev.Findings, FindingInfo{ID: f.ID, Code: f.Code, Variant: f.Variant, Title: f.Title,
			Severity: f.Severity, Status: f.Status, Count: f.Count})
	}
	return nil
}

// MinAcceptReason is the minimum length of a finding acceptance reason (§4.3).
const MinAcceptReason = 20

// AcceptFinding accepts an open finding of the connection's latest dry run
// with a reason, then re-evaluates the data checks that read finding status.
// Accepting a critical finding additionally needs step-up, which the API
// handler checks (the authentication context is not known here).
func (s *Service) AcceptFinding(c *store.TenantTx, connID, findingID, reason string, expires *time.Time, actor string, now time.Time) (*store.Finding, error) {
	f, err := c.FindingByID(findingID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && f.ConnectionID != connID) {
		return nil, notFound("no finding %s for this connection", findingID)
	}
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) < MinAcceptReason || len(reason) > 2000 || !printableNote(reason) {
		return nil, unprocessable("reason_too_short", "accepting a finding needs a reason of at least %d characters", MinAcceptReason)
	}
	if expires != nil && !expires.After(now) {
		return nil, unprocessable("invalid_expires_at", "expires_at must be in the future")
	}
	if f.Status != "open" {
		return nil, conflict("finding_not_open", "the finding is %s", f.Status)
	}
	b, _, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	if b.Evidence.DataRun == nil || b.Evidence.DataRun.ID != f.RunID {
		return nil, conflict("stale_finding", "the finding belongs to an earlier dry run; accept findings of the latest one")
	}
	if err := c.AcceptFinding(f.ID, actor, reason, expires); err != nil {
		return nil, err
	}
	var exp any
	if expires != nil {
		exp = store.RT(*expires)
	}
	if err := c.Audit(now, actor, "readiness.finding.accepted", ojson.Object{{Key: "connection_id", Value: connID},
		{Key: "finding_id", Value: f.ID}, {Key: "code", Value: f.Code + f.Variant}, {Key: "severity", Value: f.Severity},
		{Key: "count", Value: f.Count}, {Key: "reason", Value: reason}, {Key: "expires_at", Value: exp}}); err != nil {
		return nil, err
	}
	run, err := c.CheckRun(f.RunID)
	if err != nil {
		return nil, err
	}
	snap, err := reconcile.LoadSnapshot(c, f.RunID, meta(b, now))
	if err != nil {
		return nil, err
	}
	if err := s.writeDataResults(c, b, run, snap, now); err != nil {
		return nil, err
	}
	if err := c.BumpEvidence(b.Rev.ID, now); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, b.Rev.ID, now)
	if err != nil {
		return nil, err
	}
	if err := s.settle(c, nb, actor, now, "finding accepted"); err != nil {
		return nil, err
	}
	return c.FindingByID(f.ID)
}
