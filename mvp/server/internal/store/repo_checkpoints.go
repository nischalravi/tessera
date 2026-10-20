package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// ConnectorCheckpoint is where an incremental sync of one system resumes.
type ConnectorCheckpoint struct {
	System, Name string
	Cursor       string
	State        []byte
	FullSyncAt   *time.Time
	UpdatedAt    time.Time
}

const checkpointCols = `k.system, k.name, k.cursor, k.state, k.full_sync_at, k.updated_at`

var (
	checkpointPut = tq("connector_checkpoints.put", `
		INSERT INTO connector_checkpoints (tenant_id, system, name, cursor, state, full_sync_at, updated_at)
		VALUES (@tenant, @system, @name, @cursor, @state, @full_sync_at, @updated_at)
		ON CONFLICT (tenant_id, system, name) DO UPDATE SET cursor = excluded.cursor, state = excluded.state,
			full_sync_at = excluded.full_sync_at, updated_at = excluded.updated_at`)
	checkpointGet = tq("connector_checkpoints.get", `
		SELECT `+checkpointCols+` FROM connector_checkpoints k
		WHERE k.tenant_id = @tenant AND k.system = @system AND k.name = @name`)
	checkpointList = tq("connector_checkpoints.list", `
		SELECT `+checkpointCols+` FROM connector_checkpoints k WHERE k.tenant_id = @tenant ORDER BY k.system, k.name`)
	checkpointDelete = tq("connector_checkpoints.delete", `
		DELETE FROM connector_checkpoints WHERE tenant_id = @tenant AND system = @system AND name = @name`)
)

func scanCheckpoint(s scanner) (*ConnectorCheckpoint, error) {
	var k ConnectorCheckpoint
	var full sql.NullString
	var at string
	if err := s.Scan(&k.System, &k.Name, &k.Cursor, &k.State, &full, &at); err != nil {
		return nil, err
	}
	var err error
	if k.FullSyncAt, err = (nullTime{full}).ptr(); err != nil {
		return nil, err
	}
	k.UpdatedAt, err = timeutil.ParseDB(at)
	return &k, err
}

// PutConnectorCheckpoint stores (or replaces) a system's checkpoint.
func (tx *TenantTx) PutConnectorCheckpoint(k *ConnectorCheckpoint) error {
	_, err := tx.exec(checkpointPut, sql.Named("system", k.System), sql.Named("name", k.Name),
		sql.Named("cursor", k.Cursor), sql.Named("state", k.State), sql.Named("full_sync_at", TP(k.FullSyncAt)),
		sql.Named("updated_at", T(k.UpdatedAt)))
	return err
}

// ConnectorCheckpoint returns a checkpoint or ErrNotFound.
func (tx *TenantTx) ConnectorCheckpoint(system, name string) (*ConnectorCheckpoint, error) {
	return one(tx, scanCheckpoint, checkpointGet, sql.Named("system", system), sql.Named("name", name))
}

// ConnectorCheckpoints lists the tenant's checkpoints.
func (tx *TenantTx) ConnectorCheckpoints() ([]*ConnectorCheckpoint, error) {
	return collect(tx, scanCheckpoint, checkpointList)
}

// DeleteConnectorCheckpoint removes a checkpoint, so the next sync is full.
func (tx *TenantTx) DeleteConnectorCheckpoint(system, name string) error {
	_, err := tx.exec(checkpointDelete, sql.Named("system", system), sql.Named("name", name))
	return err
}
