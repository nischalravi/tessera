package store

import (
	"database/sql"
	"time"
)

// Identity disable / enable records (schema/0310_identity_disables.sql).

// IdentityDisable is one Disable of a person. EnabledAt is nil while the
// identity is disabled. AccountIDs are the accounts Disable set to disabled.
type IdentityDisable struct {
	ID                string
	IdentityID        int64
	Reason            string
	DisabledBy        string
	DisabledAt        time.Time
	ContainmentStatus string
	EnabledBy         *string
	EnabledAt         *time.Time
	EnableReason      *string
	AccountIDs        []int64
}

const disableCols = `d.id, d.identity_id, d.reason, d.disabled_by, d.disabled_at, d.containment_status,
	d.enabled_by, d.enabled_at, d.enable_reason`

var (
	disablesInsert = tq("identity_disables.insert", `
		INSERT INTO identity_disables (id, tenant_id, identity_id, reason, disabled_by, disabled_at, containment_status)
		VALUES (@id, @tenant, @identity_id, @reason, @disabled_by, @disabled_at, @containment_status)`)
	disablesAccountInsert = tq("identity_disable_accounts.insert", `
		INSERT INTO identity_disable_accounts (tenant_id, disable_id, account_id)
		VALUES (@tenant, @disable_id, @account_id)`)
	disablesOpen = tq("identity_disables.open", `
		SELECT `+disableCols+` FROM identity_disables d
		WHERE d.tenant_id = @tenant AND d.identity_id = @identity_id AND d.enabled_at IS NULL`)
	disablesByIdentity = tq("identity_disables.by_identity", `
		SELECT `+disableCols+` FROM identity_disables d
		WHERE d.tenant_id = @tenant AND d.identity_id = @identity_id ORDER BY d.disabled_at DESC, d.id`)
	disablesAccounts = tq("identity_disable_accounts.by_disable", `
		SELECT a.account_id FROM identity_disable_accounts a
		WHERE a.tenant_id = @tenant AND a.disable_id = @disable_id ORDER BY a.account_id`)
	disablesClose = tq("identity_disables.close", `
		UPDATE identity_disables SET enabled_by = @enabled_by, enabled_at = @enabled_at, enable_reason = @enable_reason
		WHERE tenant_id = @tenant AND id = @id AND enabled_at IS NULL`)
	identitiesSetStatusFrom = tq("identities.set_status_from", `
		UPDATE identities SET status = @to WHERE tenant_id = @tenant AND id = @id AND status = @from`)
)

func scanDisable(s scanner) (*IdentityDisable, error) {
	var d IdentityDisable
	var at string
	var by, reason sql.NullString
	var en nullTime
	if err := s.Scan(&d.ID, &d.IdentityID, &d.Reason, &d.DisabledBy, &at, &d.ContainmentStatus, &by, &en, &reason); err != nil {
		return nil, err
	}
	var err error
	if d.DisabledAt, err = ParseRT(at); err != nil {
		return nil, err
	}
	d.EnabledBy, d.EnableReason = strp(by), strp(reason)
	if en.Valid {
		t, err := ParseRT(en.String)
		if err != nil {
			return nil, err
		}
		d.EnabledAt = &t
	}
	return &d, nil
}

// InsertIdentityDisable records a Disable and the accounts it disabled
// (d.ID is set when empty). ErrDuplicate when the identity already has an
// open Disable.
func (tx *TenantTx) InsertIdentityDisable(d *IdentityDisable) error {
	if d.ID == "" {
		d.ID = NewID()
	}
	if d.ContainmentStatus == "" {
		d.ContainmentStatus = "none"
	}
	_, err := tx.exec(disablesInsert, sql.Named("id", d.ID), sql.Named("identity_id", d.IdentityID),
		sql.Named("reason", d.Reason), sql.Named("disabled_by", d.DisabledBy), sql.Named("disabled_at", RT(d.DisabledAt)),
		sql.Named("containment_status", d.ContainmentStatus))
	if isUnique(err) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	for _, a := range d.AccountIDs {
		if _, err := tx.exec(disablesAccountInsert, sql.Named("disable_id", d.ID), sql.Named("account_id", a)); err != nil {
			return err
		}
	}
	return nil
}

func (tx *TenantTx) loadDisableAccounts(d *IdentityDisable) error {
	rows, err := tx.query(disablesAccounts, sql.Named("disable_id", d.ID))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	d.AccountIDs = []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		d.AccountIDs = append(d.AccountIDs, id)
	}
	return rows.Err()
}

// OpenIdentityDisable returns the identity's current Disable (with its
// accounts) or ErrNotFound when it is not disabled by Tessera.
func (tx *TenantTx) OpenIdentityDisable(identityID int64) (*IdentityDisable, error) {
	d, err := one(tx, scanDisable, disablesOpen, sql.Named("identity_id", identityID))
	if err != nil {
		return nil, err
	}
	return d, tx.loadDisableAccounts(d)
}

// IdentityDisables lists an identity's Disable records, newest first, with their accounts.
func (tx *TenantTx) IdentityDisables(identityID int64) ([]*IdentityDisable, error) {
	out, err := collect(tx, scanDisable, disablesByIdentity, sql.Named("identity_id", identityID))
	if err != nil {
		return nil, err
	}
	for _, d := range out {
		if err := tx.loadDisableAccounts(d); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CloseIdentityDisable marks a Disable enabled (ErrNotFound when it is not open).
func (tx *TenantTx) CloseIdentityDisable(id, by, reason string, at time.Time) error {
	return tx.execOne(disablesClose, sql.Named("id", id), sql.Named("enabled_by", by),
		sql.Named("enabled_at", RT(at)), sql.Named("enable_reason", reason))
}

// SetIdentityStatusFrom changes an identity's status from one value to another
// (ErrNotFound when the identity is not in the from status).
func (tx *TenantTx) SetIdentityStatusFrom(id int64, from, to string) error {
	return tx.execOne(identitiesSetStatusFrom, sql.Named("id", id), sql.Named("from", from), sql.Named("to", to))
}
