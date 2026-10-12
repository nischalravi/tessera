package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------- network_ranges

const netCols = `n.id, n.tenant_id, n.name, n.description, n.cidrs, n.created_by, n.created_at, n.updated_at`

var (
	netInsert = tq("network_ranges.insert", `
		INSERT INTO network_ranges (id, tenant_id, name, description, cidrs, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @description, @cidrs, @created_by, @created_at, @updated_at)`)
	netUpdate = tq("network_ranges.update", `
		UPDATE network_ranges SET name = @name, description = @description, cidrs = @cidrs, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)
	netDelete = tq("network_ranges.delete", `DELETE FROM network_ranges WHERE tenant_id = @tenant AND id = @id`)
	netGet    = tq("network_ranges.get", `
		SELECT `+netCols+` FROM network_ranges n WHERE n.tenant_id = @tenant AND n.id = @id`)
	netList = tq("network_ranges.list", `
		SELECT `+netCols+` FROM network_ranges n WHERE n.tenant_id = @tenant ORDER BY n.name, n.id`)
)

func scanNetwork(s scanner) (*NetworkRange, error) {
	var n NetworkRange
	var id, tid, cidrs, created, updated string
	var by sql.NullString
	if err := s.Scan(&id, &tid, &n.Name, &n.Description, &cidrs, &by, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if n.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if n.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(cidrs), &n.CIDRs); err != nil {
		return nil, fmt.Errorf("store: network_ranges.cidrs: %w", err)
	}
	if n.CreatedBy, err = uuidp(by); err != nil {
		return nil, err
	}
	if n.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	n.UpdatedAt, err = ParseRT(updated)
	return &n, err
}

// InsertNetworkRange adds a range (a zero ID gets a fresh one). ErrDuplicate
// when the tenant already has a range with that name.
func (tx *TenantTx) InsertNetworkRange(n *NetworkRange) error {
	if err := tx.own(n.TenantID); err != nil {
		return err
	}
	if n.ID == uuid.Nil {
		n.ID = uuid.New()
	}
	cidrs, err := jsonList(n.CIDRs)
	if err != nil {
		return err
	}
	_, err = tx.exec(netInsert, sql.Named("id", n.ID.String()), sql.Named("name", n.Name),
		sql.Named("description", n.Description), sql.Named("cidrs", cidrs), sql.Named("created_by", uuidOrNil(n.CreatedBy)),
		sql.Named("created_at", RT(n.CreatedAt)), sql.Named("updated_at", RT(n.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// UpdateNetworkRange replaces a range's name, description and CIDRs
// (ErrNotFound for another tenant's id, ErrDuplicate for a taken name).
func (tx *TenantTx) UpdateNetworkRange(n *NetworkRange) error {
	cidrs, err := jsonList(n.CIDRs)
	if err != nil {
		return err
	}
	err = tx.execOne(netUpdate, sql.Named("id", n.ID.String()), sql.Named("name", n.Name),
		sql.Named("description", n.Description), sql.Named("cidrs", cidrs), sql.Named("updated_at", RT(n.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// DeleteNetworkRange removes a range (ErrNotFound for another tenant's id).
func (tx *TenantTx) DeleteNetworkRange(id uuid.UUID) error {
	return tx.execOne(netDelete, sql.Named("id", id.String()))
}

// NetworkRange returns one of this tenant's ranges.
func (tx *TenantTx) NetworkRange(id uuid.UUID) (*NetworkRange, error) {
	return one(tx, scanNetwork, netGet, sql.Named("id", id.String()))
}

// NetworkRanges lists this tenant's ranges by name.
func (tx *TenantTx) NetworkRanges() ([]*NetworkRange, error) {
	return collect(tx, scanNetwork, netList)
}

// ---------------------------------------------------------------- access_policies

const polCols = `p.id, p.tenant_id, p.name, p.description, p.scope, p.mode, p.outcome, p.step_up_acr, p.step_up_max_age,
	p.network_op, p.network_range_ids, p.device, p.priority, p.created_by, p.created_at, p.updated_at`

var (
	polInsert = tq("access_policies.insert", `
		INSERT INTO access_policies (id, tenant_id, name, description, scope, mode, outcome, step_up_acr,
			step_up_max_age, network_op, network_range_ids, device, priority, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @description, @scope, @mode, @outcome, @step_up_acr, @step_up_max_age,
			@network_op, @network_range_ids, @device, @priority, @created_by, @created_at, @updated_at)`)
	polUpdate = tq("access_policies.update", `
		UPDATE access_policies SET name = @name, description = @description, scope = @scope, mode = @mode,
			outcome = @outcome, step_up_acr = @step_up_acr, step_up_max_age = @step_up_max_age,
			network_op = @network_op, network_range_ids = @network_range_ids, device = @device,
			priority = @priority, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)
	polDelete = tq("access_policies.delete", `DELETE FROM access_policies WHERE tenant_id = @tenant AND id = @id`)
	polGet    = tq("access_policies.get", `
		SELECT `+polCols+` FROM access_policies p WHERE p.tenant_id = @tenant AND p.id = @id`)
	// priority order, then age, then id: the evaluation order
	polList = tq("access_policies.list", `
		SELECT `+polCols+` FROM access_policies p WHERE p.tenant_id = @tenant
		ORDER BY p.scope, p.priority, p.created_at, p.id`)
	polCount = tq("access_policies.count", `SELECT count(*) FROM access_policies p WHERE p.tenant_id = @tenant`)
)

func scanPolicy(s scanner) (*AccessPolicy, error) {
	var p AccessPolicy
	var id, tid, ranges, created, updated string
	var acr, by sql.NullString
	if err := s.Scan(&id, &tid, &p.Name, &p.Description, &p.Scope, &p.Mode, &p.Outcome, &acr, &p.StepUpMaxAge,
		&p.NetworkOp, &ranges, &p.Device, &p.Priority, &by, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if p.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if p.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	p.StepUpACR = strp(acr)
	var ids []string
	if err := json.Unmarshal([]byte(ranges), &ids); err != nil {
		return nil, fmt.Errorf("store: access_policies.network_range_ids: %w", err)
	}
	for _, x := range ids {
		u, err := uuid.Parse(x)
		if err != nil {
			return nil, fmt.Errorf("store: access_policies.network_range_ids: %w", err)
		}
		p.NetworkRangeIDs = append(p.NetworkRangeIDs, u)
	}
	if p.CreatedBy, err = uuidp(by); err != nil {
		return nil, err
	}
	if p.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	p.UpdatedAt, err = ParseRT(updated)
	return &p, err
}

func policyArgs(p *AccessPolicy) ([]sql.NamedArg, error) {
	ids := make([]string, len(p.NetworkRangeIDs))
	for i, u := range p.NetworkRangeIDs {
		ids[i] = u.String()
	}
	ranges, err := jsonList(ids)
	if err != nil {
		return nil, err
	}
	return []sql.NamedArg{sql.Named("id", p.ID.String()), sql.Named("name", p.Name),
		sql.Named("description", p.Description), sql.Named("scope", p.Scope), sql.Named("mode", p.Mode),
		sql.Named("outcome", p.Outcome), sql.Named("step_up_acr", SP(p.StepUpACR)),
		sql.Named("step_up_max_age", p.StepUpMaxAge), sql.Named("network_op", p.NetworkOp),
		sql.Named("network_range_ids", ranges), sql.Named("device", p.Device), sql.Named("priority", p.Priority),
		sql.Named("updated_at", RT(p.UpdatedAt))}, nil
}

// InsertAccessPolicy adds a policy (a zero ID gets a fresh one). ErrDuplicate
// when the tenant already has a policy with that name.
func (tx *TenantTx) InsertAccessPolicy(p *AccessPolicy) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	args, err := policyArgs(p)
	if err != nil {
		return err
	}
	args = append(args, sql.Named("created_by", uuidOrNil(p.CreatedBy)), sql.Named("created_at", RT(p.CreatedAt)))
	_, err = tx.exec(polInsert, args...)
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// UpdateAccessPolicy replaces a policy's definition (ErrNotFound for another
// tenant's id, ErrDuplicate for a taken name).
func (tx *TenantTx) UpdateAccessPolicy(p *AccessPolicy) error {
	args, err := policyArgs(p)
	if err != nil {
		return err
	}
	err = tx.execOne(polUpdate, args...)
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// DeleteAccessPolicy removes a policy (ErrNotFound for another tenant's id).
func (tx *TenantTx) DeleteAccessPolicy(id uuid.UUID) error {
	return tx.execOne(polDelete, sql.Named("id", id.String()))
}

// AccessPolicy returns one of this tenant's policies.
func (tx *TenantTx) AccessPolicy(id uuid.UUID) (*AccessPolicy, error) {
	return one(tx, scanPolicy, polGet, sql.Named("id", id.String()))
}

// AccessPolicies lists this tenant's policies in evaluation order (scope,
// priority, age, id).
func (tx *TenantTx) AccessPolicies() ([]*AccessPolicy, error) {
	return collect(tx, scanPolicy, polList)
}

// CountAccessPolicies counts this tenant's policies.
func (tx *TenantTx) CountAccessPolicies() (int, error) { return tx.count(polCount) }

// ---------------------------------------------------------------- device_compliance_signals

const sigCols = `d.tenant_id, d.user_id, d.status, d.source, d.reason, d.set_by_user_id, d.set_at, d.expires_at`

var (
	sigUpsert = tq("device_compliance_signals.upsert", `
		INSERT INTO device_compliance_signals (tenant_id, user_id, status, source, reason, set_by_user_id, set_at, expires_at)
		VALUES (@tenant, @user_id, @status, @source, @reason, @set_by_user_id, @set_at, @expires_at)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET status = excluded.status, source = excluded.source,
			reason = excluded.reason, set_by_user_id = excluded.set_by_user_id, set_at = excluded.set_at,
			expires_at = excluded.expires_at`)
	sigDelete = tq("device_compliance_signals.delete", `
		DELETE FROM device_compliance_signals WHERE tenant_id = @tenant AND user_id = @user_id`)
	sigGet = tq("device_compliance_signals.get", `
		SELECT `+sigCols+` FROM device_compliance_signals d WHERE d.tenant_id = @tenant AND d.user_id = @user_id`)
	sigList = tq("device_compliance_signals.list", `
		SELECT `+sigCols+` FROM device_compliance_signals d WHERE d.tenant_id = @tenant ORDER BY d.set_at DESC, d.user_id`)
)

func scanSignal(s scanner) (*DeviceSignal, error) {
	var d DeviceSignal
	var tid, uid, setAt string
	var by, expires sql.NullString
	if err := s.Scan(&tid, &uid, &d.Status, &d.Source, &d.Reason, &by, &setAt, &expires); err != nil {
		return nil, err
	}
	var err error
	if d.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if d.UserID, err = uuid.Parse(uid); err != nil {
		return nil, err
	}
	if d.SetBy, err = uuidp(by); err != nil {
		return nil, err
	}
	if d.SetAt, err = ParseRT(setAt); err != nil {
		return nil, err
	}
	d.ExpiresAt, err = rtp(expires)
	return &d, err
}

// SetDeviceSignal records the user's latest device-compliance verdict,
// replacing the previous one. The user must belong to this tenant
// (ErrCrossTenant otherwise).
func (tx *TenantTx) SetDeviceSignal(d *DeviceSignal) error {
	if err := tx.own(d.TenantID); err != nil {
		return err
	}
	var exp any
	if d.ExpiresAt != nil {
		exp = RT(*d.ExpiresAt)
	}
	_, err := tx.exec(sigUpsert, sql.Named("user_id", d.UserID.String()), sql.Named("status", d.Status),
		sql.Named("source", d.Source), sql.Named("reason", d.Reason), sql.Named("set_by_user_id", uuidOrNil(d.SetBy)),
		sql.Named("set_at", RT(d.SetAt)), sql.Named("expires_at", exp))
	return err
}

// ClearDeviceSignal removes the user's signal (ErrNotFound when none).
func (tx *TenantTx) ClearDeviceSignal(userID uuid.UUID) error {
	return tx.execOne(sigDelete, sql.Named("user_id", userID.String()))
}

// DeviceSignal returns the user's signal, expired or not (ErrNotFound when none).
func (tx *TenantTx) DeviceSignal(userID uuid.UUID) (*DeviceSignal, error) {
	return one(tx, scanSignal, sigGet, sql.Named("user_id", userID.String()))
}

// DeviceSignals lists this tenant's signals, newest first.
func (tx *TenantTx) DeviceSignals() ([]*DeviceSignal, error) { return collect(tx, scanSignal, sigList) }
