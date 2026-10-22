package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Contractor (VMS) feed sources (schema/0600_vms_sources.sql, issue #304).
// Every statement binds @tenant.

// VMS vendors and source states.
const (
	VmsFieldglass = "fieldglass"
	VmsBeeline    = "beeline"
	VmsCSV        = "csv"

	VmsActive = "active"
	VmsPaused = "paused"

	// ChannelVMS is the intake channel of every contractor feed.
	ChannelVMS = "vms"
)

// ErrVmsNameTaken is a source name the tenant already uses.
var ErrVmsNameTaken = errors.New("store: a VMS source with this name exists")

// VmsSource is one contractor feed. CredentialEnc is sealed (internal/seal)
// and is never shown; Settings is a JSON object without secrets.
type VmsSource struct {
	ID            string
	Vendor        string
	Name          string
	BaseURL       string
	Settings      string
	CredentialEnc []byte
	CredentialVer *string
	Status        string
	Cursor        *time.Time
	LastSyncAt    *time.Time
	LastResult    *string // ok | failed
	LastError     *string
	LastCounts    string // JSON object of outcome counts
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const vmsCols = `v.id, v.vendor, v.name, v.base_url, v.settings, v.credential_enc, v.credential_version, v.status, v.cursor,
	v.last_sync_at, v.last_result, v.last_error, v.last_counts, v.created_by, v.created_at, v.updated_at`

var (
	vmsInsert = tq("vms_sources.insert", `
		INSERT INTO vms_sources (id, tenant_id, vendor, name, base_url, settings, credential_enc, credential_version,
			status, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @vendor, @name, @base_url, @settings, @credential_enc, @credential_version,
			@status, @created_by, @now, @now)`)
	vmsUpdate = tq("vms_sources.update", `
		UPDATE vms_sources SET name = @name, base_url = @base_url, settings = @settings,
			credential_enc = @credential_enc, credential_version = @credential_version, status = @status,
			updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	vmsGet = tq("vms_sources.get", `
		SELECT `+vmsCols+` FROM vms_sources v WHERE v.tenant_id = @tenant AND v.id = @id`)
	vmsList = tq("vms_sources.list", `
		SELECT `+vmsCols+` FROM vms_sources v WHERE v.tenant_id = @tenant ORDER BY v.name, v.id`)
	vmsDelete = tq("vms_sources.delete", `
		DELETE FROM vms_sources WHERE tenant_id = @tenant AND id = @id`)
	vmsSetResult = tq("vms_sources.set_result", `
		UPDATE vms_sources SET cursor = COALESCE(CAST(@cursor AS TEXT), cursor), last_sync_at = @at, last_result = @result,
			last_error = @error, last_counts = @counts, updated_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	vmsEventsByChannel = tq("intake_events.by_channel", `
		SELECT `+intakeEventCols+` FROM intake_events r WHERE r.tenant_id = @tenant AND r.channel = @channel
		ORDER BY r.created_at DESC, r.id DESC LIMIT @limit`)
)

func scanVmsSource(s scanner) (*VmsSource, error) {
	var v VmsSource
	var ver, result, lastErr sql.NullString
	var cursor, last, created, updated nullTime
	if err := s.Scan(&v.ID, &v.Vendor, &v.Name, &v.BaseURL, &v.Settings, &v.CredentialEnc, &ver, &v.Status, &cursor,
		&last, &result, &lastErr, &v.LastCounts, &v.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	v.CredentialVer, v.LastResult, v.LastError = strp(ver), strp(result), strp(lastErr)
	var err error
	if v.Cursor, err = cursor.ptr(); err != nil {
		return nil, err
	}
	if v.LastSyncAt, err = last.ptr(); err != nil {
		return nil, err
	}
	if v.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	v.UpdatedAt, err = updated.val()
	return &v, err
}

func credArg(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// InsertVmsSource creates a source; ErrVmsNameTaken if the name is in use.
func (tx *TenantTx) InsertVmsSource(v *VmsSource, now time.Time) error {
	_, err := tx.exec(vmsInsert, sql.Named("id", v.ID), sql.Named("vendor", v.Vendor), sql.Named("name", v.Name),
		sql.Named("base_url", v.BaseURL), sql.Named("settings", v.Settings), sql.Named("credential_enc", credArg(v.CredentialEnc)),
		sql.Named("credential_version", SP(v.CredentialVer)), sql.Named("status", v.Status),
		sql.Named("created_by", v.CreatedBy), sql.Named("now", T(now)))
	if isUnique(err) {
		return ErrVmsNameTaken
	}
	return err
}

// UpdateVmsSource replaces a source's editable fields (the vendor is fixed);
// ErrNotFound if unknown, ErrVmsNameTaken on a name clash.
func (tx *TenantTx) UpdateVmsSource(v *VmsSource, now time.Time) error {
	res, err := tx.exec(vmsUpdate, sql.Named("id", v.ID), sql.Named("name", v.Name), sql.Named("base_url", v.BaseURL),
		sql.Named("settings", v.Settings), sql.Named("credential_enc", credArg(v.CredentialEnc)),
		sql.Named("credential_version", SP(v.CredentialVer)), sql.Named("status", v.Status), sql.Named("now", T(now)))
	if isUnique(err) {
		return ErrVmsNameTaken
	}
	return affectedOne(res, err)
}

// VmsSource returns one source, or ErrNotFound.
func (tx *TenantTx) VmsSource(id string) (*VmsSource, error) {
	return one(tx, scanVmsSource, vmsGet, sql.Named("id", id))
}

// VmsSources lists the tenant's sources by name.
func (tx *TenantTx) VmsSources() ([]*VmsSource, error) {
	return collect(tx, scanVmsSource, vmsList)
}

// DeleteVmsSource removes a source; ErrNotFound if unknown. The contractors it
// brought in stay: their intake events and lifecycles are the record.
func (tx *TenantTx) DeleteVmsSource(id string) error {
	return tx.execOne(vmsDelete, sql.Named("id", id))
}

// SetVmsResult records the outcome of a sync. cursor (when non-nil) moves the
// watermark forward; a failed sync passes nil and keeps it.
func (tx *TenantTx) SetVmsResult(id string, cursor *time.Time, at time.Time, result string, errMsg *string, counts string) error {
	res, err := tx.exec(vmsSetResult, sql.Named("id", id), sql.Named("cursor", TP(cursor)), sql.Named("at", T(at)),
		sql.Named("result", result), sql.Named("error", SP(errMsg)), sql.Named("counts", counts))
	return affectedOne(res, err)
}

// IntakeEventsByChannel lists the newest intake events of a channel, newest first.
func (tx *TenantTx) IntakeEventsByChannel(channel string, limit int) ([]*IntakeEvent, error) {
	return collect(tx, scanIntakeEvent, vmsEventsByChannel, sql.Named("channel", channel), sql.Named("limit", limit))
}

var identitiesByEmail = tq("identities.by_email", `
	SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant AND lower(i.email) = @email AND i.type = 'human'
	ORDER BY i.id LIMIT 2`)

// IdentitiesByEmail returns the people with this address (compared lower-case),
// at most two: a caller that needs exactly one treats two as ambiguous.
func (tx *TenantTx) IdentitiesByEmail(email string) ([]*Identity, error) {
	return collect(tx, scanIdentity, identitiesByEmail, sql.Named("email", strings.ToLower(strings.TrimSpace(email))))
}
