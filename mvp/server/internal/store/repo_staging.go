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

var (
	stgIdentitiesInsert = tq("stg_identities.insert", `
		INSERT INTO stg_identities (tenant_id, run_id, external_id, name, email, type, status, department, hired_at,
			terminated_at, attributes)
		VALUES (@tenant, @run_id, @external_id, @name, @email, @type, @status, @department, @hired_at, @terminated_at,
			@attributes)`)
	stgAccountsInsert = tq("stg_accounts.insert", `
		INSERT OR IGNORE INTO stg_accounts (tenant_id, run_id, system, external_id, username, kind, status, created_at,
			last_login_at, attributes)
		VALUES (@tenant, @run_id, @system, @external_id, @username, @kind, @status, @created_at, @last_login_at,
			@attributes)`)
	stgGroupsInsert = tq("stg_groups.insert", `
		INSERT OR IGNORE INTO stg_groups (tenant_id, run_id, system, external_id, name, kind, privileged, in_scope)
		VALUES (@tenant, @run_id, @system, @external_id, @name, @kind, @privileged, @in_scope)`)
	stgMembershipsInsert = tq("stg_memberships.insert", `
		INSERT OR IGNORE INTO stg_memberships (tenant_id, run_id, member_kind, member_xid, group_xid)
		VALUES (@tenant, @run_id, @member_kind, @member_xid, @group_xid)`)
	stgAttrStatsUpsert = tq("stg_attr_stats.upsert", `
		INSERT INTO stg_attr_stats (tenant_id, run_id, object_class, attribute, total, present, distinct_values)
		VALUES (@tenant, @run_id, @object_class, @attribute, @total, @present, @distinct_values)
		ON CONFLICT (tenant_id, run_id, object_class, attribute) DO UPDATE SET total = excluded.total,
			present = excluded.present, distinct_values = excluded.distinct_values`)
	stgAccountsCorrelate = tq("stg_accounts.set_correlation", `
		UPDATE stg_accounts SET correlation = @correlation, tier = @tier, identity_id = @identity_id,
			proposed_identity_id = @proposed_identity_id
		WHERE tenant_id = @tenant AND run_id = @run_id AND system = @system AND external_id = @external_id`)
	stgAccountsOfRun = tq("stg_accounts.of_run", `
		SELECT a.run_id, a.system, a.external_id, COALESCE(a.username, ''), COALESCE(a.kind, ''), COALESCE(a.status, ''),
			a.created_at, a.last_login_at, a.attributes, a.correlation, a.tier, a.identity_id, a.proposed_identity_id
		FROM stg_accounts a WHERE a.tenant_id = @tenant AND a.run_id = @run_id ORDER BY a.system, a.external_id`)
	stgIdentitiesOfRun = tq("stg_identities.of_run", `
		SELECT i.run_id, i.external_id, i.name, i.email, i.type, i.status, i.department, i.hired_at, i.terminated_at,
			i.attributes
		FROM stg_identities i WHERE i.tenant_id = @tenant AND i.run_id = @run_id ORDER BY i.external_id`)
	stgGroupsOfRun = tq("stg_groups.of_run", `
		SELECT g.run_id, g.system, g.external_id, g.name, g.kind, g.privileged, g.in_scope
		FROM stg_groups g WHERE g.tenant_id = @tenant AND g.run_id = @run_id ORDER BY g.system, g.external_id`)
	stgMembershipsOfRun = tq("stg_memberships.of_run", `
		SELECT m.member_kind, m.member_xid, m.group_xid
		FROM stg_memberships m WHERE m.tenant_id = @tenant AND m.run_id = @run_id
		ORDER BY m.member_kind, m.member_xid, m.group_xid`)
	stgAttrStatsOfRun = tq("stg_attr_stats.of_run", `
		SELECT s.object_class, s.attribute, s.total, s.present, s.distinct_values
		FROM stg_attr_stats s WHERE s.tenant_id = @tenant AND s.run_id = @run_id ORDER BY s.object_class, s.attribute`)
	// stgPrivilegedAccounts counts the distinct accounts in privileged groups in a run.
	stgPrivilegedAccounts = tq("stg_memberships.count_privileged_accounts", `
		SELECT count(DISTINCT m.member_xid) FROM stg_memberships m
		JOIN stg_groups g ON g.tenant_id = @tenant AND g.run_id = m.run_id AND g.external_id = m.group_xid
		WHERE m.tenant_id = @tenant AND m.run_id = @run_id AND m.member_kind = 'account' AND g.privileged = 1`)
	reconRunsOfRevision = tq("recon_runs.ids_of_revision", `
		SELECT r.id FROM recon_runs r WHERE r.tenant_id = @tenant AND r.revision_id = @revision_id
		ORDER BY r.started_at DESC, r.rowid DESC`)
	// One delete per staging table: statements are constants (no table-name concatenation).
	stgIdentitiesDeleteRun  = tq("stg_identities.delete_run", `DELETE FROM stg_identities WHERE tenant_id = @tenant AND run_id = @run_id`)
	stgAccountsDeleteRun    = tq("stg_accounts.delete_run", `DELETE FROM stg_accounts WHERE tenant_id = @tenant AND run_id = @run_id`)
	stgGroupsDeleteRun      = tq("stg_groups.delete_run", `DELETE FROM stg_groups WHERE tenant_id = @tenant AND run_id = @run_id`)
	stgMembershipsDeleteRun = tq("stg_memberships.delete_run", `DELETE FROM stg_memberships WHERE tenant_id = @tenant AND run_id = @run_id`)
	stgAttrStatsDeleteRun   = tq("stg_attr_stats.delete_run", `DELETE FROM stg_attr_stats WHERE tenant_id = @tenant AND run_id = @run_id`)
	stgPrune                = []tstmt{stgIdentitiesDeleteRun, stgAccountsDeleteRun, stgGroupsDeleteRun, stgMembershipsDeleteRun,
		stgAttrStatsDeleteRun}
)

// InsertStagedIdentity stages an identity.
func (tx *TenantTx) InsertStagedIdentity(x *StagedIdentity) error {
	attrs, err := jsonMap(x.Attributes)
	if err != nil {
		return err
	}
	_, err = tx.exec(stgIdentitiesInsert, sql.Named("run_id", x.RunID), sql.Named("external_id", x.ExternalID),
		sql.Named("name", x.Name), sql.Named("email", SP(x.Email)), sql.Named("type", SP(x.Type)),
		sql.Named("status", SP(x.Status)), sql.Named("department", SP(x.Department)), sql.Named("hired_at", RTP(x.HiredAt)),
		sql.Named("terminated_at", RTP(x.TerminatedAt)), sql.Named("attributes", attrs))
	return err
}

// InsertStagedAccount stages an account (duplicates by key are ignored).
func (tx *TenantTx) InsertStagedAccount(x *StagedAccount) error {
	attrs, err := jsonMap(x.Attributes)
	if err != nil {
		return err
	}
	_, err = tx.exec(stgAccountsInsert, sql.Named("run_id", x.RunID), sql.Named("system", x.System),
		sql.Named("external_id", x.ExternalID), sql.Named("username", x.Username), sql.Named("kind", x.Kind),
		sql.Named("status", x.Status), sql.Named("created_at", RTP(x.CreatedAt)), sql.Named("last_login_at", RTP(x.LastLoginAt)),
		sql.Named("attributes", attrs))
	return err
}

// InsertStagedGroup stages a group.
func (tx *TenantTx) InsertStagedGroup(x *StagedGroup) error {
	_, err := tx.exec(stgGroupsInsert, sql.Named("run_id", x.RunID), sql.Named("system", x.System),
		sql.Named("external_id", x.ExternalID), sql.Named("name", x.Name), sql.Named("kind", x.Kind),
		sql.Named("privileged", B(x.Privileged)), sql.Named("in_scope", B(x.InScope)))
	return err
}

// InsertStagedMembership stages a membership.
func (tx *TenantTx) InsertStagedMembership(runID string, m StagedMembership) error {
	_, err := tx.exec(stgMembershipsInsert, sql.Named("run_id", runID), sql.Named("member_kind", m.MemberKind),
		sql.Named("member_xid", m.MemberXID), sql.Named("group_xid", m.GroupXID))
	return err
}

// InsertAttrStat stages an attribute fill count.
func (tx *TenantTx) InsertAttrStat(runID string, s AttrStat) error {
	_, err := tx.exec(stgAttrStatsUpsert, sql.Named("run_id", runID), sql.Named("object_class", s.Class),
		sql.Named("attribute", s.Attribute), sql.Named("total", s.Total), sql.Named("present", s.Present),
		sql.Named("distinct_values", s.Distinct))
	return err
}

// SetStagedCorrelation records an account's correlation result.
func (tx *TenantTx) SetStagedCorrelation(runID, system, xid, correlation string, tier int, identityID, proposedID *int64) error {
	_, err := tx.exec(stgAccountsCorrelate, sql.Named("correlation", correlation), sql.Named("tier", tier),
		sql.Named("identity_id", IP(identityID)), sql.Named("proposed_identity_id", IP(proposedID)),
		sql.Named("run_id", runID), sql.Named("system", system), sql.Named("external_id", xid))
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
func (tx *TenantTx) StagedAccounts(runID string) ([]*StagedAccount, error) {
	return collect(tx, func(s scanner) (*StagedAccount, error) {
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
	}, stgAccountsOfRun, sql.Named("run_id", runID))
}

// StagedIdentities returns a run's identities.
func (tx *TenantTx) StagedIdentities(runID string) ([]*StagedIdentity, error) {
	return collect(tx, func(s scanner) (*StagedIdentity, error) {
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
	}, stgIdentitiesOfRun, sql.Named("run_id", runID))
}

// StagedGroups returns a run's groups.
func (tx *TenantTx) StagedGroups(runID string) ([]*StagedGroup, error) {
	return collect(tx, func(s scanner) (*StagedGroup, error) {
		var g StagedGroup
		var kind sql.NullString
		var priv, scope int
		if err := s.Scan(&g.RunID, &g.System, &g.ExternalID, &g.Name, &kind, &priv, &scope); err != nil {
			return nil, err
		}
		g.Kind, g.Privileged, g.InScope = kind.String, priv != 0, scope != 0
		return &g, nil
	}, stgGroupsOfRun, sql.Named("run_id", runID))
}

// StagedMemberships returns a run's memberships.
func (tx *TenantTx) StagedMemberships(runID string) ([]StagedMembership, error) {
	list, err := collect(tx, func(s scanner) (*StagedMembership, error) {
		var m StagedMembership
		return &m, s.Scan(&m.MemberKind, &m.MemberXID, &m.GroupXID)
	}, stgMembershipsOfRun, sql.Named("run_id", runID))
	out := make([]StagedMembership, len(list))
	for i, m := range list {
		out[i] = *m
	}
	return out, err
}

// AttrStats returns a run's attribute fill counts.
func (tx *TenantTx) AttrStats(runID string) ([]AttrStat, error) {
	list, err := collect(tx, func(s scanner) (*AttrStat, error) {
		var a AttrStat
		return &a, s.Scan(&a.Class, &a.Attribute, &a.Total, &a.Present, &a.Distinct)
	}, stgAttrStatsOfRun, sql.Named("run_id", runID))
	out := make([]AttrStat, len(list))
	for i, a := range list {
		out[i] = *a
	}
	return out, err
}

// PruneStaging deletes the staging rows of a revision's older dry runs,
// keeping the newest keep runs (§6.1 retention).
func (tx *TenantTx) PruneStaging(revisionID string, keep int) error {
	runs, err := collect(tx, func(s scanner) (*string, error) {
		var id string
		return &id, s.Scan(&id)
	}, reconRunsOfRevision, sql.Named("revision_id", revisionID))
	if err != nil {
		return err
	}
	for i, id := range runs {
		if i < keep {
			continue
		}
		for _, st := range stgPrune {
			if _, err := tx.exec(st, sql.Named("run_id", *id)); err != nil {
				return err
			}
		}
	}
	return nil
}

// StagedPrivilegedAccounts counts the distinct accounts that are members of a
// privileged group in a dry run's snapshot.
func (tx *TenantTx) StagedPrivilegedAccounts(runID string) (int, error) {
	return tx.count(stgPrivilegedAccounts, sql.Named("run_id", runID))
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

var (
	reconRunsInsert = tq("recon_runs.insert", `
		INSERT INTO recon_runs (id, tenant_id, revision_id, connection_id, mode, check_run_id, counts, status, started_at,
			finished_at)
		VALUES (@id, @tenant, @revision_id, @connection_id, @mode, @check_run_id, @counts, @status, @started_at,
			@finished_at)`)
	reconRunsGet = tq("recon_runs.get", `
		SELECT r.id, r.revision_id, r.connection_id, r.mode, r.check_run_id, r.counts, r.status, r.started_at, r.finished_at
		FROM recon_runs r WHERE r.tenant_id = @tenant AND r.id = @id`)
	reconRunsFinish = tq("recon_runs.finish", `
		UPDATE recon_runs SET status = @status, counts = @counts, finished_at = @finished_at
		WHERE tenant_id = @tenant AND id = @id`)
	reconRunsPrevious = tq("recon_runs.previous_completed", `
		SELECT r.id FROM recon_runs r
		WHERE r.tenant_id = @tenant AND r.connection_id = @connection_id AND r.id <> @exclude AND r.status = 'completed'
		ORDER BY r.started_at DESC, r.rowid DESC LIMIT 1`)
	findingsInsert = tq("recon_findings.insert", `
		INSERT INTO recon_findings (id, tenant_id, run_id, connection_id, code, variant, title, severity, count,
			denominator, samples, impact, cause, item_id, status, accepted_by, reason, expires_at, first_seen_at,
			last_seen_at)
		VALUES (@id, @tenant, @run_id, @connection_id, @code, @variant, @title, @severity, @count, @denominator,
			@samples, @impact, @cause, @item_id, @status, @accepted_by, @reason, @expires_at, @first_seen_at,
			@last_seen_at)`)
	findingsGet = tq("recon_findings.get", `
		SELECT `+findingCols+` FROM recon_findings f WHERE f.tenant_id = @tenant AND f.id = @id`)
	findingsOfRun = tq("recon_findings.of_run", `
		SELECT `+findingCols+` FROM recon_findings f WHERE f.tenant_id = @tenant AND f.run_id = @run_id
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			f.code, f.variant`)
	findingsAccept = tq("recon_findings.accept", `
		UPDATE recon_findings SET status = 'accepted', accepted_by = @accepted_by, reason = @reason,
			expires_at = @expires_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'open'`)
	findingsResolve = tq("recon_findings.resolve", `
		UPDATE recon_findings SET status = 'resolved' WHERE tenant_id = @tenant AND id = @id`)
	identitiesOwnedNHIXIDs = tq("identities.owned_nhi_external_ids", `
		SELECT i.external_id FROM identities i
		WHERE i.tenant_id = @tenant AND i.type <> 'human' AND i.owner_id IS NOT NULL`)
)

// InsertReconRun records a reconciliation run.
func (tx *TenantTx) InsertReconRun(r *ReconRun) error {
	_, err := tx.exec(reconRunsInsert, sql.Named("id", r.ID), sql.Named("revision_id", r.RevisionID),
		sql.Named("connection_id", r.ConnectionID), sql.Named("mode", r.Mode), sql.Named("check_run_id", r.CheckRunID),
		sql.Named("counts", r.Counts), sql.Named("status", r.Status), sql.Named("started_at", RT(r.StartedAt)),
		sql.Named("finished_at", RTP(r.FinishedAt)))
	return err
}

// ReconRunByID returns a reconciliation run or ErrNotFound.
func (tx *TenantTx) ReconRunByID(id string) (*ReconRun, error) {
	return one(tx, func(s scanner) (*ReconRun, error) {
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
	}, reconRunsGet, sql.Named("id", id))
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

const findingCols = `f.id, f.run_id, f.connection_id, f.code, f.variant, f.title, f.severity, f.count, f.denominator,
	f.samples, f.impact, f.cause, f.item_id, f.status, f.accepted_by, f.reason, f.expires_at, f.first_seen_at,
	f.last_seen_at`

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
func (tx *TenantTx) InsertFinding(f *Finding) error {
	_, err := tx.exec(findingsInsert, sql.Named("id", f.ID), sql.Named("run_id", f.RunID),
		sql.Named("connection_id", f.ConnectionID), sql.Named("code", f.Code), sql.Named("variant", f.Variant),
		sql.Named("title", f.Title), sql.Named("severity", f.Severity), sql.Named("count", f.Count),
		sql.Named("denominator", f.Denominator), sql.Named("samples", f.Samples), sql.Named("impact", f.Impact),
		sql.Named("cause", SP(f.Cause)), sql.Named("item_id", SP(f.ItemID)), sql.Named("status", f.Status),
		sql.Named("accepted_by", SP(f.AcceptedBy)), sql.Named("reason", SP(f.Reason)),
		sql.Named("expires_at", RTP(f.ExpiresAt)), sql.Named("first_seen_at", RT(f.FirstSeenAt)),
		sql.Named("last_seen_at", RT(f.LastSeenAt)))
	return err
}

// FindingByID returns one finding or ErrNotFound.
func (tx *TenantTx) FindingByID(id string) (*Finding, error) {
	return one(tx, scanFinding, findingsGet, sql.Named("id", id))
}

// RunFindings returns a reconciliation run's findings.
func (tx *TenantTx) RunFindings(runID string) ([]*Finding, error) {
	return collect(tx, scanFinding, findingsOfRun, sql.Named("run_id", runID))
}

// AcceptFinding marks an open finding accepted with a reason.
func (tx *TenantTx) AcceptFinding(id, actor, reason string, expires *time.Time) error {
	res, err := tx.exec(findingsAccept, sql.Named("accepted_by", actor), sql.Named("reason", reason),
		sql.Named("expires_at", RTP(expires)), sql.Named("id", id))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, ErrStateConflict)
	}
	return nil
}

// ResolveFinding marks a finding resolved: a later dry run no longer finds it.
func (tx *TenantTx) ResolveFinding(id string) error {
	_, err := tx.exec(findingsResolve, sql.Named("id", id))
	return err
}

// FinishReconRun records a reconciliation run's outcome and counts.
func (tx *TenantTx) FinishReconRun(id, status, counts string, at time.Time) error {
	_, err := tx.exec(reconRunsFinish, sql.Named("status", status), sql.Named("counts", counts),
		sql.Named("finished_at", RT(at)), sql.Named("id", id))
	return err
}

// PreviousFindings returns the findings of a connection's newest
// completed reconciliation run before excludeRunID, or nil.
func (tx *TenantTx) PreviousFindings(connectionID, excludeRunID string) ([]*Finding, error) {
	prev, err := one(tx, func(s scanner) (*string, error) {
		var id string
		return &id, s.Scan(&id)
	}, reconRunsPrevious, sql.Named("connection_id", connectionID), sql.Named("exclude", excludeRunID))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tx.RunFindings(*prev)
}

// OwnedIdentityXIDs returns the external ids of non-human identities with an owner.
func (tx *TenantTx) OwnedIdentityXIDs() (map[string]bool, error) {
	list, err := collect(tx, func(s scanner) (*string, error) {
		var x string
		return &x, s.Scan(&x)
	}, identitiesOwnedNHIXIDs)
	out := map[string]bool{}
	for _, x := range list {
		out[*x] = true
	}
	return out, err
}
