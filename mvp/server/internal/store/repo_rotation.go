package store

import (
	"database/sql"
	"time"
)

// Secret rotation (schema/0225_rotation.sql). Every statement is
// tenant-scoped (tq) and linted like the rest of the store. Sealing and
// opening of adapter credentials is internal/rotation's job; the store keeps
// the sealed bytes.

// ---------------------------------------------------------------- adapters

const rotAdapterCols = `a.id, a.tenant_id, a.name, a.type, a.config, a.secret_enc, a.created_by, a.created_at, a.updated_at`

var (
	rotAdaptersList = tq("rotation_adapters.list", `
		SELECT `+rotAdapterCols+` FROM rotation_adapters a WHERE a.tenant_id = @tenant ORDER BY a.name`)
	rotAdaptersGet = tq("rotation_adapters.get", `
		SELECT `+rotAdapterCols+` FROM rotation_adapters a WHERE a.tenant_id = @tenant AND a.id = @id`)
	rotAdaptersByName = tq("rotation_adapters.by_name", `
		SELECT `+rotAdapterCols+` FROM rotation_adapters a WHERE a.tenant_id = @tenant AND a.name = @name`)
	rotAdaptersInsert = tq("rotation_adapters.insert", `
		INSERT INTO rotation_adapters (id, tenant_id, name, type, config, secret_enc, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @type, @config, @secret_enc, @created_by, @created_at, @updated_at)`)
	rotAdaptersUpdate = tq("rotation_adapters.update", `
		UPDATE rotation_adapters SET config = @config, secret_enc = @secret_enc, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)
	rotAdaptersDelete = tq("rotation_adapters.delete", `
		DELETE FROM rotation_adapters WHERE tenant_id = @tenant AND id = @id`)
	rotAdaptersUses = tq("rotation_adapters.uses", `
		SELECT (SELECT count(*) FROM rotation_policies p WHERE p.tenant_id = @tenant
				AND (p.adapter_id = @id OR p.dest_adapter_id = @id))
			+ (SELECT count(*) FROM rotation_jobs j WHERE j.tenant_id = @tenant
				AND (j.adapter_id = @id OR j.dest_adapter_id = @id)
				AND j.state NOT IN ('old_deleted','failed','cancelled'))`)
)

func scanRotAdapter(s scanner) (*RotationAdapter, error) {
	var a RotationAdapter
	var tid, created, updated string
	if err := s.Scan(&a.ID, &tid, &a.Name, &a.Type, &a.Config, &a.SecretEnc, &a.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if a.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	a.UpdatedAt, err = ParseRT(updated)
	return &a, err
}

// RotationAdapters lists the tenant's rotation adapters by name.
func (tx *TenantTx) RotationAdapters() ([]*RotationAdapter, error) {
	return collect(tx, scanRotAdapter, rotAdaptersList)
}

// RotationAdapter returns one adapter or ErrNotFound.
func (tx *TenantTx) RotationAdapter(id string) (*RotationAdapter, error) {
	return one(tx, scanRotAdapter, rotAdaptersGet, sql.Named("id", id))
}

// RotationAdapterByName returns the adapter with this name or ErrNotFound.
func (tx *TenantTx) RotationAdapterByName(name string) (*RotationAdapter, error) {
	return one(tx, scanRotAdapter, rotAdaptersByName, sql.Named("name", name))
}

// InsertRotationAdapter adds an adapter; ErrDuplicate when the name is taken.
func (tx *TenantTx) InsertRotationAdapter(a *RotationAdapter) error {
	if err := tx.own(a.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(rotAdaptersInsert, sql.Named("id", a.ID), sql.Named("name", a.Name), sql.Named("type", a.Type),
		sql.Named("config", a.Config), sql.Named("secret_enc", a.SecretEnc), sql.Named("created_by", a.CreatedBy),
		sql.Named("created_at", RT(a.CreatedAt)), sql.Named("updated_at", RT(a.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// UpdateRotationAdapter replaces an adapter's settings and sealed credential.
func (tx *TenantTx) UpdateRotationAdapter(id, config string, secretEnc []byte, now time.Time) error {
	_, err := tx.exec(rotAdaptersUpdate, sql.Named("config", config), sql.Named("secret_enc", secretEnc),
		sql.Named("updated_at", RT(now)), sql.Named("id", id))
	return err
}

// DeleteRotationAdapter removes an adapter; it reports whether one existed.
func (tx *TenantTx) DeleteRotationAdapter(id string) (bool, error) {
	res, err := tx.exec(rotAdaptersDelete, sql.Named("id", id))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RotationAdapterUses counts the policies and in-flight jobs naming an adapter.
func (tx *TenantTx) RotationAdapterUses(id string) (int, error) {
	return tx.count(rotAdaptersUses, sql.Named("id", id))
}

// ---------------------------------------------------------------- policies

const rotPolicyCols = `p.id, p.tenant_id, p.kind, p.system, p.max_age_days, p.grace_hours, p.adapter_id,
	p.dest_adapter_id, p.dest_path, p.auto_rotate, p.created_by, p.created_at, p.updated_at`

var (
	rotPoliciesList = tq("rotation_policies.list", `
		SELECT `+rotPolicyCols+` FROM rotation_policies p WHERE p.tenant_id = @tenant ORDER BY p.kind, p.system`)
	rotPoliciesGet = tq("rotation_policies.get", `
		SELECT `+rotPolicyCols+` FROM rotation_policies p WHERE p.tenant_id = @tenant AND p.id = @id`)
	rotPoliciesByKey = tq("rotation_policies.by_key", `
		SELECT `+rotPolicyCols+` FROM rotation_policies p
		WHERE p.tenant_id = @tenant AND p.kind = @kind AND p.system = @system`)
	rotPoliciesInsert = tq("rotation_policies.insert", `
		INSERT INTO rotation_policies (id, tenant_id, kind, system, max_age_days, grace_hours, adapter_id,
			dest_adapter_id, dest_path, auto_rotate, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @kind, @system, @max_age_days, @grace_hours, @adapter_id, @dest_adapter_id, @dest_path,
			@auto_rotate, @created_by, @created_at, @updated_at)`)
	rotPoliciesUpdate = tq("rotation_policies.update", `
		UPDATE rotation_policies SET max_age_days = @max_age_days, grace_hours = @grace_hours,
			adapter_id = @adapter_id, dest_adapter_id = @dest_adapter_id, dest_path = @dest_path,
			auto_rotate = @auto_rotate, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)
	rotPoliciesDelete = tq("rotation_policies.delete", `
		DELETE FROM rotation_policies WHERE tenant_id = @tenant AND id = @id`)
)

func scanRotPolicy(s scanner) (*RotationPolicy, error) {
	var p RotationPolicy
	var tid, created, updated string
	var adapter, dest sql.NullString
	var auto int
	if err := s.Scan(&p.ID, &tid, &p.Kind, &p.System, &p.MaxAgeDays, &p.GraceHours, &adapter, &dest, &p.DestPath, &auto,
		&p.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if p.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	p.AdapterID, p.DestAdapterID, p.AutoRotate = strp(adapter), strp(dest), auto == 1
	if p.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	p.UpdatedAt, err = ParseRT(updated)
	return &p, err
}

// RotationPolicies lists the tenant's policies by kind and system.
func (tx *TenantTx) RotationPolicies() ([]*RotationPolicy, error) {
	return collect(tx, scanRotPolicy, rotPoliciesList)
}

// RotationPolicy returns one policy or ErrNotFound.
func (tx *TenantTx) RotationPolicy(id string) (*RotationPolicy, error) {
	return one(tx, scanRotPolicy, rotPoliciesGet, sql.Named("id", id))
}

// RotationPolicyByKey returns the policy for a kind and system ("" = any), or ErrNotFound.
func (tx *TenantTx) RotationPolicyByKey(kind, system string) (*RotationPolicy, error) {
	return one(tx, scanRotPolicy, rotPoliciesByKey, sql.Named("kind", kind), sql.Named("system", system))
}

// InsertRotationPolicy adds a policy; ErrDuplicate when the kind and system have one.
func (tx *TenantTx) InsertRotationPolicy(p *RotationPolicy) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(rotPoliciesInsert, sql.Named("id", p.ID), sql.Named("kind", p.Kind), sql.Named("system", p.System),
		sql.Named("max_age_days", p.MaxAgeDays), sql.Named("grace_hours", p.GraceHours),
		sql.Named("adapter_id", SP(p.AdapterID)), sql.Named("dest_adapter_id", SP(p.DestAdapterID)),
		sql.Named("dest_path", p.DestPath), sql.Named("auto_rotate", B(p.AutoRotate)), sql.Named("created_by", p.CreatedBy),
		sql.Named("created_at", RT(p.CreatedAt)), sql.Named("updated_at", RT(p.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// UpdateRotationPolicy replaces a policy's settings.
func (tx *TenantTx) UpdateRotationPolicy(p *RotationPolicy) error {
	_, err := tx.exec(rotPoliciesUpdate, sql.Named("max_age_days", p.MaxAgeDays), sql.Named("grace_hours", p.GraceHours),
		sql.Named("adapter_id", SP(p.AdapterID)), sql.Named("dest_adapter_id", SP(p.DestAdapterID)),
		sql.Named("dest_path", p.DestPath), sql.Named("auto_rotate", B(p.AutoRotate)),
		sql.Named("updated_at", RT(p.UpdatedAt)), sql.Named("id", p.ID))
	return err
}

// DeleteRotationPolicy removes a policy; it reports whether one existed.
func (tx *TenantTx) DeleteRotationPolicy(id string) (bool, error) {
	res, err := tx.exec(rotPoliciesDelete, sql.Named("id", id))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---------------------------------------------------------------- bulks

const rotBulkCols = `b.id, b.tenant_id, b.system, b.reason, b.plan, b.plan_hash, b.requested_by, b.created_at`

var (
	rotBulksList = tq("rotation_bulks.list", `
		SELECT `+rotBulkCols+` FROM rotation_bulks b WHERE b.tenant_id = @tenant ORDER BY b.created_at DESC, b.rowid DESC`)
	rotBulksGet = tq("rotation_bulks.get", `
		SELECT `+rotBulkCols+` FROM rotation_bulks b WHERE b.tenant_id = @tenant AND b.id = @id`)
	rotBulksInsert = tq("rotation_bulks.insert", `
		INSERT INTO rotation_bulks (id, tenant_id, system, reason, plan, plan_hash, requested_by, created_at)
		VALUES (@id, @tenant, @system, @reason, @plan, @plan_hash, @requested_by, @created_at)`)
)

func scanRotBulk(s scanner) (*RotationBulk, error) {
	var b RotationBulk
	var tid, created string
	if err := s.Scan(&b.ID, &tid, &b.System, &b.Reason, &b.Plan, &b.PlanHash, &b.RequestedBy, &created); err != nil {
		return nil, err
	}
	var err error
	if b.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	b.CreatedAt, err = ParseRT(created)
	return &b, err
}

// RotationBulks lists the bulk runs, newest first.
func (tx *TenantTx) RotationBulks() ([]*RotationBulk, error) {
	return collect(tx, scanRotBulk, rotBulksList)
}

// RotationBulk returns one bulk run or ErrNotFound.
func (tx *TenantTx) RotationBulk(id string) (*RotationBulk, error) {
	return one(tx, scanRotBulk, rotBulksGet, sql.Named("id", id))
}

// InsertRotationBulk records a confirmed bulk run.
func (tx *TenantTx) InsertRotationBulk(b *RotationBulk) error {
	if err := tx.own(b.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(rotBulksInsert, sql.Named("id", b.ID), sql.Named("system", b.System), sql.Named("reason", b.Reason),
		sql.Named("plan", b.Plan), sql.Named("plan_hash", b.PlanHash), sql.Named("requested_by", b.RequestedBy),
		sql.Named("created_at", RT(b.CreatedAt)))
	return err
}

// ---------------------------------------------------------------- jobs

const rotJobCols = `j.id, j.tenant_id, j.secret_id, j.bulk_id, j.origin, j.adapter_id, j.adapter_type, j.dest_adapter_id,
	j.dest_path, j.state, j.failed_state, j.old_ref, j.new_ref, j.grace_hours, j.attempts, j.last_error, j.next_step_at,
	j.lease_until, j.handed_over_at, j.disabled_at, j.verified_at, j.completed_at, j.verification, j.requested_by,
	j.created_at, j.updated_at`

var (
	rotJobsGet = tq("rotation_jobs.get", `
		SELECT `+rotJobCols+` FROM rotation_jobs j WHERE j.tenant_id = @tenant AND j.id = @id`)
	rotJobsList = tq("rotation_jobs.list", `
		SELECT `+rotJobCols+` FROM rotation_jobs j
		WHERE j.tenant_id = @tenant AND (@state = '' OR j.state = @state) AND (@secret_id = 0 OR j.secret_id = @secret_id)
			AND (@bulk_id = '' OR j.bulk_id = @bulk_id)
		ORDER BY j.created_at DESC, j.rowid DESC LIMIT @limit`)
	rotJobsDue = tq("rotation_jobs.due", `
		SELECT `+rotJobCols+` FROM rotation_jobs j
		WHERE j.tenant_id = @tenant AND j.state IN ('pending','created','handed_over','old_disabled','verified')
			AND j.next_step_at <= @now AND (j.lease_until IS NULL OR j.lease_until < @now)
		ORDER BY j.next_step_at, j.rowid LIMIT @limit`)
	rotJobsInsert = tq("rotation_jobs.insert", `
		INSERT INTO rotation_jobs (id, tenant_id, secret_id, bulk_id, origin, adapter_id, adapter_type, dest_adapter_id,
			dest_path, state, old_ref, grace_hours, next_step_at, requested_by, created_at, updated_at)
		VALUES (@id, @tenant, @secret_id, @bulk_id, @origin, @adapter_id, @adapter_type, @dest_adapter_id, @dest_path,
			'pending', @old_ref, @grace_hours, @next_step_at, @requested_by, @created_at, @created_at)`)
	rotJobsClaim = tq("rotation_jobs.claim", `
		UPDATE rotation_jobs SET lease_until = @lease_until
		WHERE tenant_id = @tenant AND id = @id AND state = @state AND next_step_at <= @now
			AND (lease_until IS NULL OR lease_until < @now)`)
	// The CAS on state is the only way a job moves: a step that lost a race
	// changes nothing. lease_until is cleared by every write.
	rotJobsUpdate = tq("rotation_jobs.update", `
		UPDATE rotation_jobs SET state = @state, failed_state = @failed_state, new_ref = @new_ref, attempts = @attempts,
			last_error = @last_error, next_step_at = @next_step_at, lease_until = NULL,
			handed_over_at = @handed_over_at, disabled_at = @disabled_at, verified_at = @verified_at,
			completed_at = @completed_at, verification = @verification, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND state = @from`)
)

func scanRotJob(s scanner) (*RotationJob, error) {
	var j RotationJob
	var tid, next, created, updated string
	var bulk, destAd, failed, newRef, lastErr, verification sql.NullString
	var lease, handed, disabled, verified, completed nullTime
	if err := s.Scan(&j.ID, &tid, &j.SecretID, &bulk, &j.Origin, &j.AdapterID, &j.AdapterType, &destAd, &j.DestPath,
		&j.State, &failed, &j.OldRef, &newRef, &j.GraceHours, &j.Attempts, &lastErr, &next, &lease, &handed, &disabled,
		&verified, &completed, &verification, &j.RequestedBy, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if j.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	j.BulkID, j.DestAdapterID, j.FailedState, j.NewRef, j.LastError, j.Verification =
		strp(bulk), strp(destAd), strp(failed), strp(newRef), strp(lastErr), strp(verification)
	if j.NextStepAt, err = ParseRT(next); err != nil {
		return nil, err
	}
	if j.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if j.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		n nullTime
		p **time.Time
	}{{lease, &j.LeaseUntil}, {handed, &j.HandedOverAt}, {disabled, &j.DisabledAt}, {verified, &j.VerifiedAt},
		{completed, &j.CompletedAt}} {
		if *f.p, err = rtpOf(f.n); err != nil {
			return nil, err
		}
	}
	return &j, nil
}

// rtpOf parses an optional RT timestamp held in a nullTime scan target.
func rtpOf(n nullTime) (*time.Time, error) { return rtp(n.NullString) }

// RotationJob returns one job or ErrNotFound.
func (tx *TenantTx) RotationJob(id string) (*RotationJob, error) {
	return one(tx, scanRotJob, rotJobsGet, sql.Named("id", id))
}

// RotationJobs lists jobs, newest first (limit <= 0: 500).
func (tx *TenantTx) RotationJobs(f RotationJobFilter) ([]*RotationJob, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	return collect(tx, scanRotJob, rotJobsList, sql.Named("state", f.State), sql.Named("secret_id", f.SecretID),
		sql.Named("bulk_id", f.BulkID), sql.Named("limit", f.Limit))
}

// DueRotationJobs lists in-flight jobs whose next step is due and that no
// worker holds a lease on, oldest first.
func (tx *TenantTx) DueRotationJobs(now time.Time, limit int) ([]*RotationJob, error) {
	return collect(tx, scanRotJob, rotJobsDue, sql.Named("now", RT(now)), sql.Named("limit", limit))
}

// InsertRotationJob queues a job in state pending. ErrDuplicate when the
// secret already has a job in flight.
func (tx *TenantTx) InsertRotationJob(j *RotationJob) error {
	if err := tx.own(j.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(rotJobsInsert, sql.Named("id", j.ID), sql.Named("secret_id", j.SecretID),
		sql.Named("bulk_id", SP(j.BulkID)), sql.Named("origin", j.Origin), sql.Named("adapter_id", j.AdapterID),
		sql.Named("adapter_type", j.AdapterType), sql.Named("dest_adapter_id", SP(j.DestAdapterID)),
		sql.Named("dest_path", j.DestPath), sql.Named("old_ref", j.OldRef), sql.Named("grace_hours", j.GraceHours),
		sql.Named("next_step_at", RT(j.NextStepAt)), sql.Named("requested_by", j.RequestedBy),
		sql.Named("created_at", RT(j.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// ClaimRotationJob takes a lease on a due job in state; it reports whether
// this caller got it.
func (tx *TenantTx) ClaimRotationJob(id, state string, now, leaseUntil time.Time) (bool, error) {
	res, err := tx.exec(rotJobsClaim, sql.Named("lease_until", RT(leaseUntil)), sql.Named("state", state),
		sql.Named("now", RT(now)), sql.Named("id", id))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// UpdateRotationJob writes j's progress if the job is still in state from
// (ErrStateConflict otherwise) and releases its lease.
func (tx *TenantTx) UpdateRotationJob(j *RotationJob, from string, now time.Time) error {
	res, err := tx.exec(rotJobsUpdate, sql.Named("state", j.State), sql.Named("failed_state", SP(j.FailedState)),
		sql.Named("new_ref", SP(j.NewRef)), sql.Named("attempts", j.Attempts), sql.Named("last_error", SP(j.LastError)),
		sql.Named("next_step_at", RT(j.NextStepAt)), sql.Named("handed_over_at", RTP(j.HandedOverAt)),
		sql.Named("disabled_at", RTP(j.DisabledAt)), sql.Named("verified_at", RTP(j.VerifiedAt)),
		sql.Named("completed_at", RTP(j.CompletedAt)), sql.Named("verification", SP(j.Verification)),
		sql.Named("updated_at", RT(now)), sql.Named("id", j.ID), sql.Named("from", from))
	if isUnique(err) {
		return ErrStateConflict // another job for the secret is in flight
	}
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrStateConflict
	}
	return nil
}

// ---------------------------------------------------------------- secrets

var (
	secretsGet = tq("secrets.get", `
		SELECT `+secretCols+` FROM secrets s WHERE s.tenant_id = @tenant AND s.id = @id`)
	// After a rotation the inventory row follows the new credential: its
	// external id changes and the old key's last use no longer applies.
	secretsReplaceCredential = tq("secrets.replace_credential", `
		UPDATE secrets SET external_id = @external_id, last_rotated_at = @at, last_used_at = NULL
		WHERE tenant_id = @tenant AND id = @id`)
)

// SecretByID returns one secret or ErrNotFound.
func (tx *TenantTx) SecretByID(id int64) (*Secret, error) {
	return one(tx, scanSecret, secretsGet, sql.Named("id", id))
}

// ReplaceSecretCredential points a secret at the credential that replaced
// its old one and records the rotation time.
func (tx *TenantTx) ReplaceSecretCredential(id int64, externalID string, at time.Time) error {
	_, err := tx.exec(secretsReplaceCredential, sql.Named("external_id", externalID), sql.Named("at", T(at)),
		sql.Named("id", id))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}
