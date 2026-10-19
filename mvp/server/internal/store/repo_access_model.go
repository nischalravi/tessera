package store

import (
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Intended and observed access (schema/0330_intended_observed.sql, issue #301).
//
// This file is the only place that writes intended_grants and
// observed_entitlements, and the two sets of writers are kept apart:
//
//   - intent is written by the edge writers of approval-side code (InsertEdge,
//     SetEdgeExpiry, the Delete*/Revoke edge methods, KeepIntent). A connector
//     edge (UpsertConnectorEdge, or an InsertEdge with source "connector")
//     never creates intent.
//   - observation is written by RecordObservedRun, which connector ingest
//     calls. Nothing in approval-side code does.
//
// internal/archtest and the store tests pin both rules.

// Provenance of an intended grant.
const (
	ProvRequest    = "request"
	ProvRole       = "role"
	ProvBirthright = "birthright"
	ProvJIT        = "jit"
	ProvReviewKeep = "review_keep"
	ProvManual     = "manual"
)

// Close reasons of an intended grant (free text for review and revoke
// reasons, which RevokeEdge passes through).
const (
	CloseRemoved      = "removed"
	CloseRequestEnded = "request_closed"
	CloseRoleRemoved  = "role_removed"
	CloseJITEnded     = "jit_ended"
	CloseExpired      = "expired"
)

// IntendedGrant is one identity's intended access to one target entitlement.
type IntendedGrant struct {
	ID              string
	TenantID        tenancy.ID
	IdentityID      int64
	AccountID       *int64
	TargetKind      string // group | perm
	TargetSystem    string
	TargetRef       string // the entitlement's external id
	Provenance      string
	ProvenanceRef   *string
	EdgeID          *int64
	ValidFrom       time.Time
	ValidUntil      *time.Time
	OwnerIdentityID *int64
	CreatedAt       time.Time
	ClosedAt        *time.Time
	CloseReason     *string
}

// Active reports whether the intent is open and inside its validity window at now.
func (g *IntendedGrant) Active(now time.Time) bool {
	if g.ClosedAt != nil || g.ValidFrom.After(now) {
		return false
	}
	return g.ValidUntil == nil || g.ValidUntil.After(now)
}

// ObservedRun is one connector run over one system.
type ObservedRun struct {
	ID           string
	TenantID     tenancy.ID
	System       string
	Source       string // connector | backfill
	ObservedAt   time.Time
	Entitlements int
}

// ObservedRow is one account's entitlement as a system reported it.
type ObservedRow struct {
	System            string // the account's system
	AccountRef        string // the account's external id
	EntitlementKind   string
	EntitlementSystem string
	EntitlementRef    string
}

// ObservedEntitlement is a stored observation. IdentityID is the account's
// current identity link when the account is known, else the one recorded.
type ObservedEntitlement struct {
	ID                int64
	TenantID          tenancy.ID
	System            string
	AccountRef        string
	AccountID         *int64
	IdentityID        *int64
	EntitlementKind   string
	EntitlementSystem string
	EntitlementRef    string
	RunID             string
	ObservedAt        time.Time
}

// Drift classes, statuses and remediation actions.
const (
	DriftMissing = "missing"
	DriftRogue   = "rogue"
	DriftOrphan  = "orphan"
	DriftStale   = "stale"

	DriftOpen        = "open"
	DriftRemediating = "remediating"
	DriftResolved    = "resolved"
	DriftAccepted    = "accepted"

	ActionNone          = "none"
	ActionAutoProvision = "auto_provision"
	ActionAutoRevoke    = "auto_revoke"
	ActionOwnerTask     = "owner_task"
	ActionReportOnly    = "report_only"
)

// DriftClasses and DriftStatuses list the values, in display order.
var (
	DriftClasses  = []string{DriftMissing, DriftRogue, DriftOrphan, DriftStale}
	DriftStatuses = []string{DriftOpen, DriftRemediating, DriftResolved, DriftAccepted}
	// PolicyActions are the actions a remediation policy can name.
	PolicyActions = []string{ActionAutoProvision, ActionAutoRevoke, ActionOwnerTask, ActionReportOnly}
)

// AccessDrift is one difference between intended and observed access.
type AccessDrift struct {
	ID              string
	TenantID        tenancy.ID
	Key             string
	Class           string
	System          string
	EntitlementKind string
	EntitlementRef  string
	AccountRef      string
	AccountID       *int64
	IdentityID      *int64
	IntendedID      *string
	ObservedID      *int64
	OwnerIdentityID *int64
	Status          string
	DetectedAt      time.Time
	UpdatedAt       time.Time
	ResolvedAt      *time.Time
	AcceptedBy      *string
	AcceptedReason  *string
	Action          string
	RemediationRef  *string
	RemediationNote *string
	RemediationAt   *time.Time
}

// DriftFilter narrows AccessDrifts. Empty fields match everything.
type DriftFilter struct {
	Class, Status, System string
	IdentityID            int64
	Limit                 int // 0: no limit
}

// DriftCount is a count of drift rows by class and status.
type DriftCount struct {
	Class, Status string
	N             int
}

// RemediationPolicy is the action for a class of drift on one system, or on
// one entitlement of it when EntitlementRef is set.
type RemediationPolicy struct {
	ID             string
	TenantID       tenancy.ID
	System         string
	EntitlementRef string // "": the whole system
	DriftClass     string
	Action         string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const intendedCols = `g.id, g.tenant_id, g.identity_id, g.account_id, g.target_kind, g.target_system, g.target_ref, g.provenance,
	g.provenance_ref, g.edge_id, g.valid_from, g.valid_until, g.owner_identity_id, g.created_at, g.closed_at, g.close_reason`

const observedCols = `o.id, o.tenant_id, o.system, o.account_ref, o.account_id,
	CASE WHEN a.id IS NULL THEN o.identity_id ELSE a.identity_id END,
	o.entitlement_kind, o.entitlement_system, o.entitlement_ref, o.run_id, o.observed_at`

const driftCols = `d.id, d.tenant_id, d.drift_key, d.class, d.system, d.entitlement_kind, d.entitlement_ref, d.account_ref,
	d.account_id, d.identity_id, d.intended_id, d.observed_id, d.owner_identity_id, d.status, d.detected_at, d.updated_at,
	d.resolved_at, d.accepted_by, d.accepted_reason, d.action, d.remediation_ref, d.remediation_note, d.remediation_at`

const remPolicyCols = `p.id, p.tenant_id, p.system, p.entitlement_ref, p.drift_class, p.action, p.created_by, p.created_at, p.updated_at`

var (
	intendedList = tq("intended_grants.list", `
		SELECT `+intendedCols+` FROM intended_grants g WHERE g.tenant_id = @tenant ORDER BY g.created_at, g.id`)
	intendedGet = tq("intended_grants.get", `
		SELECT `+intendedCols+` FROM intended_grants g WHERE g.tenant_id = @tenant AND g.id = @id`)
	intendedOpenFor = tq("intended_grants.count_open_for", `
		SELECT count(g.id) FROM intended_grants g WHERE g.tenant_id = @tenant AND g.identity_id = @identity_id
			AND g.target_kind = @target_kind AND g.target_system = @target_system AND g.target_ref = @target_ref
			AND g.closed_at IS NULL`)
	intendedInsert = tq("intended_grants.insert", `
		INSERT INTO intended_grants (id, tenant_id, identity_id, account_id, target_kind, target_system, target_ref, provenance,
			provenance_ref, edge_id, valid_from, valid_until, owner_identity_id, created_at)
		VALUES (@id, @tenant, @identity_id, @account_id, @target_kind, @target_system, @target_ref, @provenance,
			@provenance_ref, @edge_id, @valid_from, @valid_until, @owner_identity_id, @created_at)`)
	intendedCloseByEdge = tq("intended_grants.close_by_edge", `
		UPDATE intended_grants SET closed_at = @at, close_reason = @reason
		WHERE tenant_id = @tenant AND edge_id = @edge_id AND closed_at IS NULL`)
	intendedCloseExpiredJIT = tq("intended_grants.close_expired_jit", `
		UPDATE intended_grants SET closed_at = @at, close_reason = 'expired'
		WHERE intended_grants.tenant_id = @tenant AND closed_at IS NULL AND edge_id IN (
			SELECT e.id FROM grant_edges e WHERE e.tenant_id = @tenant AND e.source = 'jit' AND e.expires_at <= @now
				AND e.id NOT IN (SELECT r.edge_id FROM access_requests r
					WHERE r.tenant_id = @tenant AND r.status = 'approved' AND r.edge_id IS NOT NULL))`)
	intendedSetExpiry = tq("intended_grants.set_expiry", `
		UPDATE intended_grants SET valid_until = @valid_until WHERE tenant_id = @tenant AND edge_id = @edge_id AND closed_at IS NULL`)

	observedRunInsert = tq("observed_runs.insert", `
		INSERT INTO observed_runs (id, tenant_id, system, source, observed_at, entitlements)
		VALUES (@id, @tenant, @system, @source, @observed_at, 0)`)
	observedRunCount = tq("observed_runs.set_count", `
		UPDATE observed_runs SET entitlements = @n WHERE tenant_id = @tenant AND id = @id`)
	observedRunDropOld = tq("observed_runs.delete_older", `
		DELETE FROM observed_runs WHERE tenant_id = @tenant AND system = @system AND id <> @id`)
	observedRunsList = tq("observed_runs.list", `
		SELECT r.id, r.tenant_id, r.system, r.source, r.observed_at, r.entitlements FROM observed_runs r
		WHERE r.tenant_id = @tenant ORDER BY r.system, r.observed_at, r.id`)
	observedUpsert = tq("observed_entitlements.upsert", `
		INSERT INTO observed_entitlements (tenant_id, system, account_ref, account_id, identity_id, entitlement_kind,
			entitlement_system, entitlement_ref, run_id, observed_at)
		VALUES (@tenant, @system, @account_ref,
			(SELECT a.id FROM accounts a WHERE a.tenant_id = @tenant AND a.system = @system AND a.external_id = @account_ref),
			(SELECT a.identity_id FROM accounts a WHERE a.tenant_id = @tenant AND a.system = @system AND a.external_id = @account_ref),
			@entitlement_kind, @entitlement_system, @entitlement_ref, @run_id, @observed_at)
		ON CONFLICT (tenant_id, system, account_ref, entitlement_kind, entitlement_system, entitlement_ref) DO UPDATE SET
			account_id = excluded.account_id, identity_id = excluded.identity_id, run_id = excluded.run_id,
			observed_at = excluded.observed_at`)
	observedDropOld = tq("observed_entitlements.delete_not_in_run", `
		DELETE FROM observed_entitlements WHERE tenant_id = @tenant AND system = @system AND run_id <> @run_id`)
	observedList = tq("observed_entitlements.list", `
		SELECT `+observedCols+` FROM observed_entitlements o
		LEFT JOIN accounts a ON a.tenant_id = @tenant AND a.id = o.account_id
		WHERE o.tenant_id = @tenant ORDER BY o.id`)
	observedCount = tq("observed_entitlements.count", `
		SELECT count(o.id) FROM observed_entitlements o WHERE o.tenant_id = @tenant`)
	observedRunsCount = tq("observed_runs.count", `
		SELECT count(r.id) FROM observed_runs r WHERE r.tenant_id = @tenant`)
	intendedCount = tq("intended_grants.count", `
		SELECT count(g.id) FROM intended_grants g WHERE g.tenant_id = @tenant`)

	driftList = tq("access_drift.list", `
		SELECT `+driftCols+` FROM access_drift d WHERE d.tenant_id = @tenant
			AND (@class = '' OR d.class = @class) AND (@status = '' OR d.status = @status)
			AND (@system = '' OR d.system = @system) AND (CAST(@identity_id AS BIGINT) = 0 OR d.identity_id = @identity_id)
		ORDER BY d.detected_at DESC, d.id LIMIT @limit`)
	driftGet = tq("access_drift.get", `
		SELECT `+driftCols+` FROM access_drift d WHERE d.tenant_id = @tenant AND d.id = @id`)
	driftCounts = tq("access_drift.counts", `
		SELECT d.class, d.status, count(d.id) FROM access_drift d WHERE d.tenant_id = @tenant
		GROUP BY d.class, d.status ORDER BY d.class, d.status`)
	driftInsert = tq("access_drift.insert", `
		INSERT INTO access_drift (id, tenant_id, drift_key, class, system, entitlement_kind, entitlement_ref, account_ref,
			account_id, identity_id, intended_id, observed_id, owner_identity_id, status, detected_at, updated_at, action)
		VALUES (@id, @tenant, @drift_key, @class, @system, @entitlement_kind, @entitlement_ref, @account_ref,
			@account_id, @identity_id, @intended_id, @observed_id, @owner_identity_id, @status, @detected_at, @updated_at, 'none')`)
	driftUpdate = tq("access_drift.update", `
		UPDATE access_drift SET account_id = @account_id, identity_id = @identity_id, intended_id = @intended_id,
			observed_id = @observed_id, owner_identity_id = @owner_identity_id, status = @status, detected_at = @detected_at,
			updated_at = @updated_at, resolved_at = @resolved_at, accepted_by = @accepted_by, accepted_reason = @accepted_reason,
			action = @action, remediation_ref = @remediation_ref, remediation_note = @remediation_note,
			remediation_at = @remediation_at
		WHERE tenant_id = @tenant AND id = @id`)

	remPoliciesList = tq("remediation_policies.list", `
		SELECT `+remPolicyCols+` FROM remediation_policies p WHERE p.tenant_id = @tenant
		ORDER BY p.system, p.entitlement_ref, p.drift_class`)
	remPoliciesGet = tq("remediation_policies.get", `
		SELECT `+remPolicyCols+` FROM remediation_policies p WHERE p.tenant_id = @tenant AND p.id = @id`)
	remPoliciesUpsert = tq("remediation_policies.upsert", `
		INSERT INTO remediation_policies (id, tenant_id, system, entitlement_ref, drift_class, action, created_by, created_at,
			updated_at)
		VALUES (@id, @tenant, @system, @entitlement_ref, @drift_class, @action, @created_by, @at, @at)
		ON CONFLICT (tenant_id, system, entitlement_ref, drift_class) DO UPDATE SET action = excluded.action,
			updated_at = excluded.updated_at`)
	remPoliciesDelete = tq("remediation_policies.delete", `
		DELETE FROM remediation_policies WHERE tenant_id = @tenant AND id = @id`)
)

// ---------------------------------------------------------------- scanners

func scanIntended(s scanner) (*IntendedGrant, error) {
	var g IntendedGrant
	var tid string
	var acct, edge, owner sql.NullInt64
	var ref, reason sql.NullString
	var from, until, created, closed nullTime
	if err := s.Scan(&g.ID, &tid, &g.IdentityID, &acct, &g.TargetKind, &g.TargetSystem, &g.TargetRef, &g.Provenance, &ref,
		&edge, &from, &until, &owner, &created, &closed, &reason); err != nil {
		return nil, err
	}
	var err error
	if g.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	g.AccountID, g.EdgeID, g.OwnerIdentityID = intp(acct), intp(edge), intp(owner)
	if ref.Valid {
		g.ProvenanceRef = &ref.String
	}
	if reason.Valid {
		g.CloseReason = &reason.String
	}
	if g.ValidFrom, err = from.val(); err != nil {
		return nil, err
	}
	if g.ValidUntil, err = until.ptr(); err != nil {
		return nil, err
	}
	if g.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	g.ClosedAt, err = closed.ptr()
	return &g, err
}

func scanObservedRun(s scanner) (*ObservedRun, error) {
	var r ObservedRun
	var tid string
	var at nullTime
	if err := s.Scan(&r.ID, &tid, &r.System, &r.Source, &at, &r.Entitlements); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	r.ObservedAt, err = at.val()
	return &r, err
}

func scanObserved(s scanner) (*ObservedEntitlement, error) {
	var o ObservedEntitlement
	var tid string
	var acct, ident sql.NullInt64
	var at nullTime
	if err := s.Scan(&o.ID, &tid, &o.System, &o.AccountRef, &acct, &ident, &o.EntitlementKind, &o.EntitlementSystem,
		&o.EntitlementRef, &o.RunID, &at); err != nil {
		return nil, err
	}
	var err error
	if o.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	o.AccountID, o.IdentityID = intp(acct), intp(ident)
	o.ObservedAt, err = at.val()
	return &o, err
}

func scanDrift(s scanner) (*AccessDrift, error) {
	var d AccessDrift
	var tid string
	var acct, ident, obs, owner sql.NullInt64
	var intended, by, why, ref, note sql.NullString
	var detected, updated, resolved, rat nullTime
	if err := s.Scan(&d.ID, &tid, &d.Key, &d.Class, &d.System, &d.EntitlementKind, &d.EntitlementRef, &d.AccountRef, &acct,
		&ident, &intended, &obs, &owner, &d.Status, &detected, &updated, &resolved, &by, &why, &d.Action, &ref, &note,
		&rat); err != nil {
		return nil, err
	}
	var err error
	if d.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	d.AccountID, d.IdentityID, d.ObservedID, d.OwnerIdentityID = intp(acct), intp(ident), intp(obs), intp(owner)
	d.IntendedID, d.AcceptedBy, d.AcceptedReason = strp(intended), strp(by), strp(why)
	d.RemediationRef, d.RemediationNote = strp(ref), strp(note)
	if d.DetectedAt, err = detected.val(); err != nil {
		return nil, err
	}
	if d.UpdatedAt, err = updated.val(); err != nil {
		return nil, err
	}
	if d.ResolvedAt, err = resolved.ptr(); err != nil {
		return nil, err
	}
	d.RemediationAt, err = rat.ptr()
	return &d, err
}

func scanRemPolicy(s scanner) (*RemediationPolicy, error) {
	var p RemediationPolicy
	var tid string
	var created, updated nullTime
	if err := s.Scan(&p.ID, &tid, &p.System, &p.EntitlementRef, &p.DriftClass, &p.Action, &p.CreatedBy, &created,
		&updated); err != nil {
		return nil, err
	}
	var err error
	if p.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if p.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	p.UpdatedAt, err = updated.val()
	return &p, err
}

// ---------------------------------------------------------------- intended grants

// IntendedGrants returns every intended grant, open and closed, oldest first.
func (tx *TenantTx) IntendedGrants() ([]*IntendedGrant, error) {
	return collect(tx, scanIntended, intendedList)
}

// IntendedGrant returns one intended grant by id.
func (tx *TenantTx) IntendedGrant(id string) (*IntendedGrant, error) {
	return one(tx, scanIntended, intendedGet, sql.Named("id", id))
}

// CountIntendedGrants counts intended grants.
func (tx *TenantTx) CountIntendedGrants() (int, error) { return tx.count(intendedCount) }

// parseNode splits a graph node key such as "account:7".
func parseNode(key string) (kind string, id int64, ok bool) {
	k, rest, found := strings.Cut(key, ":")
	if !found {
		return "", 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return k, n, true
}

// provenanceOf maps a grant edge's source to the intent's provenance. A
// connector edge has none: connectors report access, they do not intend it.
func provenanceOf(source string) (string, bool) {
	switch source {
	case "request":
		return ProvRequest, true
	case "role":
		return ProvRole, true
	case "jit":
		return ProvJIT, true
	case "manual":
		return ProvManual, true
	}
	return "", false
}

// recordEdgeIntent writes the intended grant for a new account -> group edge
// that approval-side code created, in the caller's transaction. It writes
// nothing for a connector edge, for an edge that is not account -> group, for
// an account with no identity, or when the identity already has open intent
// for the entitlement.
func (tx *TenantTx) recordEdgeIntent(edgeID int64, e *GrantEdge) error {
	prov, ok := provenanceOf(e.Source)
	if !ok {
		return nil
	}
	if e.Provenance != "" {
		prov = e.Provenance
	}
	sk, aid, ok1 := parseNode(e.Src)
	dk, gid, ok2 := parseNode(e.Dst)
	if !ok1 || !ok2 || sk != "account" || dk != "group" {
		return nil
	}
	a, err := tx.Account(aid)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	g, err := tx.Group(gid)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if a.IdentityID == nil {
		return nil
	}
	return tx.insertIntent(*a.IdentityID, &a.ID, g, prov, e.Ref, &edgeID, e.CreatedAt, e.ExpiresAt)
}

// insertIntent adds an open intended grant unless the identity already has one for the entitlement.
func (tx *TenantTx) insertIntent(identity int64, account *int64, g *Group, prov, ref string, edge *int64, from time.Time,
	until *time.Time) error {
	if n, err := tx.count(intendedOpenFor, sql.Named("identity_id", identity), sql.Named("target_kind", "group"),
		sql.Named("target_system", g.System), sql.Named("target_ref", g.ExternalID)); err != nil || n > 0 {
		return err
	}
	var owner *int64
	if i, err := tx.Identity(identity); err == nil {
		if owner = i.OwnerID; owner == nil {
			owner = i.ManagerID
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	var refp *string
	if ref != "" {
		refp = &ref
	}
	_, err := tx.exec(intendedInsert, sql.Named("id", NewID()), sql.Named("identity_id", identity),
		sql.Named("account_id", IP(account)), sql.Named("target_kind", "group"), sql.Named("target_system", g.System),
		sql.Named("target_ref", g.ExternalID), sql.Named("provenance", prov), sql.Named("provenance_ref", SP(refp)),
		sql.Named("edge_id", IP(edge)), sql.Named("valid_from", T(from)), sql.Named("valid_until", TP(until)),
		sql.Named("owner_identity_id", IP(owner)), sql.Named("created_at", T(from)))
	return err
}

// closeEdgeIntent closes the open intent of a grant edge that is going away.
func (tx *TenantTx) closeEdgeIntent(edgeID int64, reason string, at time.Time) error {
	_, err := tx.exec(intendedCloseByEdge, sql.Named("edge_id", edgeID), sql.Named("reason", reason), sql.Named("at", T(at)))
	return err
}

// KeepIntent records a reviewer's decision to keep the grant src -> dst as
// intended access ("review_keep"), unless the identity already has open
// intent for it. ref names the review item. It is how access that only a
// connector reported becomes intended: through a person's decision.
func (tx *TenantTx) KeepIntent(src, dst, ref string, now time.Time) error {
	sk, aid, ok1 := parseNode(src)
	dk, gid, ok2 := parseNode(dst)
	if !ok1 || !ok2 || sk != "account" || dk != "group" {
		return nil
	}
	a, err := tx.Account(aid)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	g, err := tx.Group(gid)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if a.IdentityID == nil {
		return nil
	}
	var edge *int64
	var until *time.Time
	if e, err := tx.EdgeBetween(src, dst); err == nil {
		edge, until = &e.ID, e.ExpiresAt
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return tx.insertIntent(*a.IdentityID, &a.ID, g, ProvReviewKeep, ref, edge, now, until)
}

// ---------------------------------------------------------------- observed

// RecordObservedRun records one connector run over a system: a snapshot of
// what the system reported. The rows replace the system's earlier snapshot, so
// an entitlement the system no longer shows is gone from it. It returns the
// run id. Only connector ingest calls it.
func (tx *TenantTx) RecordObservedRun(system string, at time.Time, rows []ObservedRow) (string, error) {
	return tx.recordRun(system, ObsConnector, at, rows)
}

// Sources of an observed run.
const (
	ObsConnector = "connector"
	ObsBackfill  = "backfill"
)

func (tx *TenantTx) recordRun(system, source string, at time.Time, rows []ObservedRow) (string, error) {
	id := NewID()
	if _, err := tx.exec(observedRunInsert, sql.Named("id", id), sql.Named("system", system), sql.Named("source", source),
		sql.Named("observed_at", T(at))); err != nil {
		return "", err
	}
	for _, r := range rows {
		if _, err := tx.exec(observedUpsert, sql.Named("system", system), sql.Named("account_ref", r.AccountRef),
			sql.Named("entitlement_kind", r.EntitlementKind), sql.Named("entitlement_system", r.EntitlementSystem),
			sql.Named("entitlement_ref", r.EntitlementRef), sql.Named("run_id", id), sql.Named("observed_at", T(at))); err != nil {
			return "", err
		}
	}
	if _, err := tx.exec(observedDropOld, sql.Named("system", system), sql.Named("run_id", id)); err != nil {
		return "", err
	}
	if _, err := tx.exec(observedRunDropOld, sql.Named("system", system), sql.Named("id", id)); err != nil {
		return "", err
	}
	_, err := tx.exec(observedRunCount, sql.Named("n", len(rows)), sql.Named("id", id))
	return id, err
}

// ObservedRuns returns the latest run of each system (one per system).
func (tx *TenantTx) ObservedRuns() ([]*ObservedRun, error) {
	return collect(tx, scanObservedRun, observedRunsList)
}

// ObservedEntitlements returns every observed entitlement.
func (tx *TenantTx) ObservedEntitlements() ([]*ObservedEntitlement, error) {
	return collect(tx, scanObserved, observedList)
}

// CountObservedEntitlements counts observed entitlements.
func (tx *TenantTx) CountObservedEntitlements() (int, error) { return tx.count(observedCount) }

// BackfillAccessModel builds the intended and observed sets of a tenant that
// has neither yet, from grant_edges: an edge granted by a request, role, JIT
// approval or an admin becomes an intended grant, a connector edge an observed
// entitlement (a "backfill" run per system). It is how a deployment that
// predates the two tables picks them up; it does nothing once either exists.
// It reports whether it ran.
func (tx *TenantTx) BackfillAccessModel(now time.Time) (bool, error) {
	runs, err := tx.count(observedRunsCount)
	if err != nil {
		return false, err
	}
	intents, err := tx.count(intendedCount)
	if err != nil || runs > 0 || intents > 0 {
		return false, err
	}
	edges, err := tx.Edges()
	if err != nil {
		return false, err
	}
	bySystem := map[string][]ObservedRow{}
	for _, e := range edges {
		sk, aid, ok1 := parseNode(e.Src)
		dk, gid, ok2 := parseNode(e.Dst)
		if !ok1 || !ok2 || sk != "account" || dk != "group" {
			continue
		}
		if e.Source != "connector" {
			if err := tx.recordEdgeIntent(e.ID, e); err != nil {
				return false, err
			}
			continue
		}
		a, err := tx.Account(aid)
		if errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return false, err
		}
		g, err := tx.Group(gid)
		if errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return false, err
		}
		bySystem[a.System] = append(bySystem[a.System], ObservedRow{System: a.System, AccountRef: a.ExternalID,
			EntitlementKind: "group", EntitlementSystem: g.System, EntitlementRef: g.ExternalID})
	}
	for _, sys := range sortedSystems(bySystem) {
		if _, err := tx.recordRun(sys, ObsBackfill, now, bySystem[sys]); err != nil {
			return false, err
		}
	}
	return true, nil
}

func sortedSystems(m map[string][]ObservedRow) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- drift

// AccessDrifts returns drift rows, newest first.
func (tx *TenantTx) AccessDrifts(f DriftFilter) ([]*AccessDrift, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = -1
	}
	return collect(tx, scanDrift, driftList, sql.Named("class", f.Class), sql.Named("status", f.Status),
		sql.Named("system", f.System), sql.Named("identity_id", f.IdentityID), sql.Named("limit", limit))
}

// AccessDrift returns one drift row by id.
func (tx *TenantTx) AccessDrift(id string) (*AccessDrift, error) {
	return one(tx, scanDrift, driftGet, sql.Named("id", id))
}

// AccessDriftCounts counts drift rows by class and status.
func (tx *TenantTx) AccessDriftCounts() ([]DriftCount, error) {
	rows, err := collect(tx, func(s scanner) (*DriftCount, error) {
		var c DriftCount
		return &c, s.Scan(&c.Class, &c.Status, &c.N)
	}, driftCounts)
	if err != nil {
		return nil, err
	}
	out := make([]DriftCount, len(rows))
	for i, r := range rows {
		out[i] = *r
	}
	return out, nil
}

// InsertAccessDrift inserts an open drift row and returns its id (d.ID, or a new one).
func (tx *TenantTx) InsertAccessDrift(d *AccessDrift) (string, error) {
	if err := tx.own(d.TenantID); err != nil {
		return "", err
	}
	id := d.ID
	if id == "" {
		id = NewID()
	}
	_, err := tx.exec(driftInsert, sql.Named("id", id), sql.Named("drift_key", d.Key), sql.Named("class", d.Class),
		sql.Named("system", d.System), sql.Named("entitlement_kind", d.EntitlementKind),
		sql.Named("entitlement_ref", d.EntitlementRef), sql.Named("account_ref", d.AccountRef),
		sql.Named("account_id", IP(d.AccountID)), sql.Named("identity_id", IP(d.IdentityID)),
		sql.Named("intended_id", SP(d.IntendedID)), sql.Named("observed_id", IP(d.ObservedID)),
		sql.Named("owner_identity_id", IP(d.OwnerIdentityID)), sql.Named("status", d.Status),
		sql.Named("detected_at", T(d.DetectedAt)), sql.Named("updated_at", T(d.UpdatedAt)))
	return id, err
}

// UpdateAccessDrift saves a drift row's refs, status and remediation fields.
func (tx *TenantTx) UpdateAccessDrift(d *AccessDrift) error {
	return tx.execOne(driftUpdate, sql.Named("id", d.ID), sql.Named("account_id", IP(d.AccountID)),
		sql.Named("identity_id", IP(d.IdentityID)), sql.Named("intended_id", SP(d.IntendedID)),
		sql.Named("observed_id", IP(d.ObservedID)), sql.Named("owner_identity_id", IP(d.OwnerIdentityID)),
		sql.Named("status", d.Status), sql.Named("detected_at", T(d.DetectedAt)), sql.Named("updated_at", T(d.UpdatedAt)),
		sql.Named("resolved_at", TP(d.ResolvedAt)), sql.Named("accepted_by", SP(d.AcceptedBy)),
		sql.Named("accepted_reason", SP(d.AcceptedReason)), sql.Named("action", d.Action),
		sql.Named("remediation_ref", SP(d.RemediationRef)), sql.Named("remediation_note", SP(d.RemediationNote)),
		sql.Named("remediation_at", TP(d.RemediationAt)))
}

// ---------------------------------------------------------------- remediation policies

// RemediationPolicies returns every policy, by system, entitlement and class.
func (tx *TenantTx) RemediationPolicies() ([]*RemediationPolicy, error) {
	return collect(tx, scanRemPolicy, remPoliciesList)
}

// RemediationPolicy returns one policy by id.
func (tx *TenantTx) RemediationPolicy(id string) (*RemediationPolicy, error) {
	return one(tx, scanRemPolicy, remPoliciesGet, sql.Named("id", id))
}

// UpsertRemediationPolicy sets the action for a class of drift on a system or
// entitlement, replacing the action of the policy that is there.
func (tx *TenantTx) UpsertRemediationPolicy(p *RemediationPolicy) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	id := p.ID
	if id == "" {
		id = NewID()
	}
	_, err := tx.exec(remPoliciesUpsert, sql.Named("id", id), sql.Named("system", p.System),
		sql.Named("entitlement_ref", p.EntitlementRef), sql.Named("drift_class", p.DriftClass),
		sql.Named("action", p.Action), sql.Named("created_by", p.CreatedBy), sql.Named("at", T(p.UpdatedAt)))
	return err
}

// DeleteRemediationPolicy deletes a policy by id.
func (tx *TenantTx) DeleteRemediationPolicy(id string) error {
	res, err := tx.exec(remPoliciesDelete, sql.Named("id", id))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}
