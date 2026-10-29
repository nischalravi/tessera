package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// The machine client behind a config proposal (schema/0952_config_proposals.sql, issue #721). Every statement is
// tenant-scoped (tq).

var (
	proposalInsert = tq("admin_change_proposals.insert", `
		INSERT INTO admin_change_proposals (tenant_id, change_id, client_id, proposed_at)
		VALUES (@tenant, @change_id, @client_id, @proposed_at)`)
	proposalClient = tq("admin_change_proposals.client", `
		SELECT client_id FROM admin_change_proposals WHERE tenant_id = @tenant AND change_id = @change_id`)
)

// InsertAdminChangeProposal records that the machine client clientID proposed the change request changeID.
// ErrDuplicate if the request already has a proposer, and a cross-tenant reference is refused.
func (tx *TenantTx) InsertAdminChangeProposal(changeID uuid.UUID, clientID string, at time.Time) error {
	_, err := tx.exec(proposalInsert, sql.Named("change_id", changeID.String()), sql.Named("client_id", clientID),
		sql.Named("proposed_at", RT(at)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// AdminChangeProposer returns the client id that proposed the change request, or "" when a person filed it.
func (tx *TenantTx) AdminChangeProposer(changeID uuid.UUID) (string, error) {
	var id string
	err := tx.queryRow(proposalClient, sql.Named("change_id", changeID.String())).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
