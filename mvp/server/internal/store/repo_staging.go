package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Staging rows of a dry run (design §6.1). These functions write only the
// stg_* and recon_* tables.

// StagedIdentity is a person or worker from an authoritative source's dry run.
type StagedIdentity struct {
	RunID, ExternalID, Name         string
	Email, Type, Status, Department *string
	HiredAt, TerminatedAt           *time.Time
	Attributes                      map[string]string
}

// StagedAccount is an account staged by a dry run, with its correlation.
type StagedAccount struct {
	RunID, System, ExternalID string
	Username, Kind, Status    string
	CreatedAt, LastLoginAt    *time.Time
	Attributes                map[string]string
	Correlation               string // correlated | proposed | service | ambiguous | uncorrelated | authoritative
	Tier                      int
	IdentityID                *int64
	ProposedIdentityID        *int64
}

// StagedGroup is a group staged by a dry run.
type StagedGroup struct {
	RunID, System, ExternalID, Name, Kind string
	Privileged, InScope                   bool
}

// StagedMembership is a member_of relationship in a dry run.
type StagedMembership struct {
	MemberKind, MemberXID, GroupXID string
}

// AttrStat is the fill count of one attribute in one object class.
type AttrStat struct {
	Class, Attribute         string
	Total, Present, Distinct int
}

func jsonMap(m map[string]string) (any, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// InsertStagedIdentity stages an identity.
func (c *Conn) InsertStagedIdentity(x *StagedIdentity) error {
	attrs, err := jsonMap(x.Attributes)
	if err != nil {
		return err
	}
	_, err = c.Exec(`INSERT INTO stg_identities (tenant_id, run_id, external_id, name, email, type, status, department,
		hired_at, terminated_at, attributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		DefaultTenantID, x.RunID, x.ExternalID, x.Name, SP(x.Email), SP(x.Type), SP(x.Status), SP(x.Department),
		RTP(x.HiredAt), RTP(x.TerminatedAt), attrs)
	return err
}

// InsertStagedAccount stages an account (duplicates by key are ignored).
func (c *Conn) InsertStagedAccount(x *StagedAccount) error {
	attrs, err := jsonMap(x.Attributes)
	if err != nil {
		return err
	}
	_, err = c.Exec(`INSERT OR IGNORE INTO stg_accounts (tenant_id, run_id, system, external_id, username, kind, status,
		created_at, last_login_at, attributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		DefaultTenantID, x.RunID, x.System, x.ExternalID, x.Username, x.Kind, x.Status, RTP(x.CreatedAt), RTP(x.LastLoginAt), attrs)
	return err
}

// InsertStagedGroup stages a group.
func (c *Conn) InsertStagedGroup(x *StagedGroup) error {
	_, err := c.Exec(`INSERT OR IGNORE INTO stg_groups (tenant_id, run_id, system, external_id, name, kind, privileged, in_scope)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, DefaultTenantID, x.RunID, x.System, x.ExternalID, x.Name, x.Kind, B(x.Privileged), B(x.InScope))
	return err
}

// InsertStagedMembership stages a membership.
func (c *Conn) InsertStagedMembership(runID string, m StagedMembership) error {
	_, err := c.Exec(`INSERT OR IGNORE INTO stg_memberships (tenant_id, run_id, member_kind, member_xid, group_xid)
		VALUES (?, ?, ?, ?, ?)`, DefaultTenantID, runID, m.MemberKind, m.MemberXID, m.GroupXID)
	return err
}

// InsertAttrStat stages an attribute fill count.
func (c *Conn) InsertAttrStat(runID string, s AttrStat) error {
	_, err := c.Exec(`INSERT OR REPLACE INTO stg_attr_stats (tenant_id, run_id, object_class, attribute, total, present, distinct_values)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, DefaultTenantID, runID, s.Class, s.Attribute, s.Total, s.Present, s.Distinct)
	return err
}

// SetStagedCorrelation records an account's correlation result.
func (c *Conn) SetStagedCorrelation(runID, system, xid, correlation string, tier int, identityID, proposedID *int64) error {
	_, err := c.Exec(`UPDATE stg_accounts SET correlation = ?, tier = ?, identity_id = ?, proposed_identity_id = ?
		WHERE tenant_id = ? AND run_id = ? AND system = ? AND external_id = ?`,
		correlation, tier, IP(identityID), IP(proposedID), DefaultTenantID, runID, system, xid)
	return err
}

func parseAttrs(s sql.NullString) (map[string]string, error) {
	if !s.Valid || s.String == "" {
		return map[string]string{}, nil
	}
	var m map[string]string
	err := json.Unmarshal([]byte(s.String), &m)
	if m == nil {
		m = map[string]string{}
	}
	return m, err
}

// StagedAccounts returns a run's accounts.
func (c *Conn) StagedAccounts(runID string) ([]*StagedAccount, error) {
	return collect(c, func(s scanner) (*StagedAccount, error) {
		var a StagedAccount
		var created, last, attrs, corr sql.NullString
		var tier, ident, prop sql.NullInt64
		if err := s.Scan(&a.RunID, &a.System, &a.ExternalID, &a.Username, &a.Kind, &a.Status, &created, &last, &attrs,
			&corr, &tier, &ident, &prop); err != nil {
			return nil, err
		}
		var err error
		if a.CreatedAt, err = rtp(created); err != nil {
			return nil, err
		}
		if a.LastLoginAt, err = rtp(last); err != nil {
			return nil, err
		}
		if a.Attributes, err = parseAttrs(attrs); err != nil {
			return nil, err
		}
		a.Correlation, a.Tier, a.IdentityID, a.ProposedIdentityID = corr.String, int(tier.Int64), intp(ident), intp(prop)
		return &a, nil
	}, `SELECT run_id, system, external_id, COALESCE(username, ''), COALESCE(kind, ''), COALESCE(status, ''), created_at,
		last_login_at, attributes, correlation, tier, identity_id, proposed_identity_id FROM stg_accounts
		WHERE tenant_id = ? AND run_id = ? ORDER BY system, external_id`, DefaultTenantID, runID)
}

// StagedIdentities returns a run's identities.
func (c *Conn) StagedIdentities(runID string) ([]*StagedIdentity, error) {
	return collect(c, func(s scanner) (*StagedIdentity, error) {
		var x StagedIdentity
		var email, typ, status, dept, hired, term, attrs sql.NullString
		if err := s.Scan(&x.RunID, &x.ExternalID, &x.Name, &email, &typ, &status, &dept, &hired, &term, &attrs); err != nil {
			return nil, err
		}
		x.Email, x.Type, x.Status, x.Department = strp(email), strp(typ), strp(status), strp(dept)
		var err error
		if x.HiredAt, err = rtp(hired); err != nil {
			return nil, err
		}
		if x.TerminatedAt, err = rtp(term); err != nil {
			return nil, err
		}
		x.Attributes, err = parseAttrs(attrs)
		return &x, err
	}, `SELECT run_id, external_id, name, email, type, status, department, hired_at, terminated_at, attributes
		FROM stg_identities WHERE tenant_id = ? AND run_id = ? ORDER BY external_id`, DefaultTenantID, runID)
}

// StagedGroups returns a run's groups.
func (c *Conn) StagedGroups(runID string) ([]*StagedGroup, error) {
	return collect(c, func(s scanner) (*StagedGroup, error) {
		var g StagedGroup
		var kind sql.NullString
		var priv, scope int
		if err := s.Scan(&g.RunID, &g.System, &g.ExternalID, &g.Name, &kind, &priv, &scope); err != nil {
			return nil, err
		}
		g.Kind, g.Privileged, g.InScope = kind.String, priv != 0, scope != 0
		return &g, nil
	}, `SELECT run_id, system, external_id, name, kind, privileged, in_scope FROM stg_groups
		WHERE tenant_id = ? AND run_id = ? ORDER BY system, external_id`, DefaultTenantID, runID)
}

// StagedMemberships returns a run's memberships.
func (c *Conn) StagedMemberships(runID string) ([]StagedMembership, error) {
	list, err := collect(c, func(s scanner) (*StagedMembership, error) {
		var m StagedMembership
		return &m, s.Scan(&m.MemberKind, &m.MemberXID, &m.GroupXID)
	}, `SELECT member_kind, member_xid, group_xid FROM stg_memberships WHERE tenant_id = ? AND run_id = ?
		ORDER BY member_kind, member_xid, group_xid`, DefaultTenantID, runID)
	out := make([]StagedMembership, len(list))
	for i, m := range list {
		out[i] = *m
	}
	return out, err
}

// AttrStats returns a run's attribute fill counts.
func (c *Conn) AttrStats(runID string) ([]AttrStat, error) {
	list, err := collect(c, func(s scanner) (*AttrStat, error) {
		var a AttrStat
		return &a, s.Scan(&a.Class, &a.Attribute, &a.Total, &a.Present, &a.Distinct)
	}, `SELECT object_class, attribute, total, present, distinct_values FROM stg_attr_stats WHERE tenant_id = ? AND run_id = ?
		ORDER BY object_class, attribute`, DefaultTenantID, runID)
	out := make([]AttrStat, len(list))
	for i, a := range list {
		out[i] = *a
	}
	return out, err
}

// PruneStaging deletes the staging rows of a revision's older dry runs,
// keeping the newest keep runs (§6.1 retention).
func (c *Conn) PruneStaging(revisionID string, keep int) error {
	runs, err := collect(c, func(s scanner) (*string, error) {
		var id string
		return &id, s.Scan(&id)
	}, `SELECT id FROM recon_runs WHERE tenant_id = ? AND revision_id = ? ORDER BY started_at DESC, rowid DESC`, DefaultTenantID, revisionID)
	if err != nil {
		return err
	}
	for i, id := range runs {
		if i < keep {
			continue
		}
		for _, t := range []string{"stg_identities", "stg_accounts", "stg_groups", "stg_memberships", "stg_attr_stats"} {
			// t comes from the fixed list above.
			if _, err := c.Exec("DELETE FROM "+t+" WHERE tenant_id = ? AND run_id = ?", DefaultTenantID, *id); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- recon runs

// ReconRun is one dry-run reconciliation.
type ReconRun struct {
	ID, RevisionID, ConnectionID string
	Mode, CheckRunID             string
	Counts                       string // JSON
	Status                       string
	StartedAt                    time.Time
	FinishedAt                   *time.Time
}

// InsertReconRun records a reconciliation run.
func (c *Conn) InsertReconRun(r *ReconRun) error {
	_, err := c.Exec(`INSERT INTO recon_runs (id, tenant_id, revision_id, connection_id, mode, check_run_id, counts, status,
		started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.ID, DefaultTenantID, r.RevisionID, r.ConnectionID,
		r.Mode, r.CheckRunID, r.Counts, r.Status, RT(r.StartedAt), RTP(r.FinishedAt))
	return err
}

// ReconRunByID returns a reconciliation run or ErrNotFound.
func (c *Conn) ReconRunByID(id string) (*ReconRun, error) {
	return one(c, func(s scanner) (*ReconRun, error) {
		var r ReconRun
		var counts, finished sql.NullString
		var started string
		if err := s.Scan(&r.ID, &r.RevisionID, &r.ConnectionID, &r.Mode, &r.CheckRunID, &counts, &r.Status, &started, &finished); err != nil {
			return nil, err
		}
		r.Counts = counts.String
		var err error
		if r.StartedAt, err = ParseRT(started); err != nil {
			return nil, err
		}
		r.FinishedAt, err = rtp(finished)
		return &r, err
	}, `SELECT id, revision_id, connection_id, mode, check_run_id, counts, status, started_at, finished_at FROM recon_runs
		WHERE tenant_id = ? AND id = ?`, DefaultTenantID, id)
}

// RunningDryRuns counts dry runs in flight in the tenant (at most one, §5.2).
func (c *Conn) RunningDryRuns() (int, error) {
	return c.Count("SELECT count(*) FROM readiness_check_runs WHERE tenant_id = ? AND kind = 'dry_run' AND status = 'running'",
		DefaultTenantID)
}

// DeleteCheckResults removes a run's results (data checks are re-evaluated
// when a finding is accepted).
func (c *Conn) DeleteCheckResults(runID string) error {
	_, err := c.Exec("DELETE FROM readiness_check_results WHERE tenant_id = ? AND run_id = ?", DefaultTenantID, runID)
	return err
}

// ---------------------------------------------------------------- findings

// Finding is a reconciliation finding row. Samples, Impact and Cause are JSON.
type Finding struct {
	ID, RunID, ConnectionID string
	Code, Variant, Title    string
	Severity                string
	Count, Denominator      int
	Samples, Impact         string
	Cause, ItemID           *string
	Status                  string
	AcceptedBy, Reason      *string
	ExpiresAt               *time.Time
	FirstSeenAt, LastSeenAt time.Time
}

const findingCols = `id, run_id, connection_id, code, variant, title, severity, count, denominator, samples, impact, cause,
	item_id, status, accepted_by, reason, expires_at, first_seen_at, last_seen_at`

func scanFinding(s scanner) (*Finding, error) {
	var f Finding
	var cause, item, by, reason, exp sql.NullString
	var first, last string
	if err := s.Scan(&f.ID, &f.RunID, &f.ConnectionID, &f.Code, &f.Variant, &f.Title, &f.Severity, &f.Count, &f.Denominator,
		&f.Samples, &f.Impact, &cause, &item, &f.Status, &by, &reason, &exp, &first, &last); err != nil {
		return nil, err
	}
	f.Cause, f.ItemID, f.AcceptedBy, f.Reason = strp(cause), strp(item), strp(by), strp(reason)
	var err error
	if f.ExpiresAt, err = rtp(exp); err != nil {
		return nil, err
	}
	if f.FirstSeenAt, err = ParseRT(first); err != nil {
		return nil, err
	}
	f.LastSeenAt, err = ParseRT(last)
	return &f, err
}

// InsertFinding stores a finding.
func (c *Conn) InsertFinding(f *Finding) error {
	_, err := c.Exec(`INSERT INTO recon_findings (id, tenant_id, run_id, connection_id, code, variant, title, severity, count,
		denominator, samples, impact, cause, item_id, status, accepted_by, reason, expires_at, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, DefaultTenantID, f.RunID, f.ConnectionID, f.Code, f.Variant, f.Title, f.Severity, f.Count, f.Denominator,
		f.Samples, f.Impact, SP(f.Cause), SP(f.ItemID), f.Status, SP(f.AcceptedBy), SP(f.Reason), RTP(f.ExpiresAt),
		RT(f.FirstSeenAt), RT(f.LastSeenAt))
	return err
}

// FindingByID returns one finding or ErrNotFound.
func (c *Conn) FindingByID(id string) (*Finding, error) {
	return one(c, scanFinding, "SELECT "+findingCols+" FROM recon_findings WHERE tenant_id = ? AND id = ?", DefaultTenantID, id)
}

// RunFindings returns a reconciliation run's findings.
func (c *Conn) RunFindings(runID string) ([]*Finding, error) {
	return collect(c, scanFinding, "SELECT "+findingCols+` FROM recon_findings WHERE tenant_id = ? AND run_id = ?
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, code, variant`,
		DefaultTenantID, runID)
}

// AcceptFinding marks an open finding accepted with a reason.
func (c *Conn) AcceptFinding(id, actor, reason string, expires *time.Time) error {
	res, err := c.Exec(`UPDATE recon_findings SET status = 'accepted', accepted_by = ?, reason = ?, expires_at = ?
		WHERE tenant_id = ? AND id = ? AND status = 'open'`, actor, reason, RTP(expires), DefaultTenantID, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, ErrStateConflict)
	}
	return nil
}

// ResolveFinding marks a finding resolved: a later dry run no longer finds it.
func (c *Conn) ResolveFinding(id string) error {
	_, err := c.Exec("UPDATE recon_findings SET status = 'resolved' WHERE tenant_id = ? AND id = ?", DefaultTenantID, id)
	return err
}

// FinishReconRun records a reconciliation run's outcome and counts.
func (c *Conn) FinishReconRun(id, status, counts string, at time.Time) error {
	_, err := c.Exec("UPDATE recon_runs SET status = ?, counts = ?, finished_at = ? WHERE tenant_id = ? AND id = ?",
		status, counts, RT(at), DefaultTenantID, id)
	return err
}

// PreviousFindings returns the findings of a connection's newest
// completed reconciliation run before excludeRunID, or nil.
func (c *Conn) PreviousFindings(connectionID, excludeRunID string) ([]*Finding, error) {
	prev, err := one(c, func(s scanner) (*string, error) {
		var id string
		return &id, s.Scan(&id)
	}, `SELECT id FROM recon_runs WHERE tenant_id = ? AND connection_id = ? AND id <> ? AND status = 'completed'
		ORDER BY started_at DESC, rowid DESC LIMIT 1`, DefaultTenantID, connectionID, excludeRunID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c.RunFindings(*prev)
}

// OwnedIdentityXIDs returns the external ids of non-human identities with an owner.
func (c *Conn) OwnedIdentityXIDs() (map[string]bool, error) {
	list, err := collect(c, func(s scanner) (*string, error) {
		var x string
		return &x, s.Scan(&x)
	}, "SELECT external_id FROM identities WHERE type <> 'human' AND owner_id IS NOT NULL")
	out := map[string]bool{}
	for _, x := range list {
		out[*x] = true
	}
	return out, err
}
