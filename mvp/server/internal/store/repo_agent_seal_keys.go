package store

import (
	"database/sql"
	"time"
)

// The public key a Directory Agent is sealed secrets to (schema/0621_agent_seal_keys.sql,
// issue #302). The agent registers it over its mutual-TLS channel; the caller
// passes the id of the authenticated agent, never one the agent sent.

// AgentSealKey is an agent's current sealing key.
type AgentSealKey struct {
	AgentID      string
	PublicKey    []byte // 32 bytes, X25519
	KeyID        string
	RegisteredAt time.Time
}

var (
	agentSealKeyGet = tq("agent_seal_keys.get", `
		SELECT k.agent_id, k.public_key, k.key_id, k.registered_at FROM agent_seal_keys k
		WHERE k.tenant_id = @tenant AND k.agent_id = @agent_id`)
	agentSealKeyPut = tq("agent_seal_keys.put", `
		INSERT INTO agent_seal_keys (id, tenant_id, agent_id, public_key, key_id, registered_at)
		VALUES (@id, @tenant, @agent_id, @public_key, @key_id, @now)
		ON CONFLICT (tenant_id, agent_id) DO UPDATE SET public_key = excluded.public_key, key_id = excluded.key_id,
			registered_at = @now`)
	agentSealKeyDelete = tq("agent_seal_keys.delete", `
		DELETE FROM agent_seal_keys WHERE tenant_id = @tenant AND agent_id = @agent_id`)
)

func scanAgentSealKey(s scanner) (*AgentSealKey, error) {
	var k AgentSealKey
	var at string
	if err := s.Scan(&k.AgentID, &k.PublicKey, &k.KeyID, &at); err != nil {
		return nil, err
	}
	var err error
	k.RegisteredAt, err = ParseRT(at)
	return &k, err
}

// AgentSealKey returns the agent's registered sealing key, or ErrNotFound.
func (tx *TenantTx) AgentSealKey(agentID string) (*AgentSealKey, error) {
	return one(tx, scanAgentSealKey, agentSealKeyGet, sql.Named("agent_id", agentID))
}

// PutAgentSealKey registers (or replaces) the agent's sealing key. The agent
// must be this tenant's (the schema refuses others).
func (tx *TenantTx) PutAgentSealKey(k *AgentSealKey, now time.Time) error {
	_, err := tx.exec(agentSealKeyPut, sql.Named("id", NewID()), sql.Named("agent_id", k.AgentID),
		sql.Named("public_key", k.PublicKey), sql.Named("key_id", k.KeyID), sql.Named("now", RT(now)))
	return err
}

// DeleteAgentSealKey removes the agent's key (it was revoked). ErrNotFound when it had none.
func (tx *TenantTx) DeleteAgentSealKey(agentID string) error {
	return tx.execOne(agentSealKeyDelete, sql.Named("agent_id", agentID))
}
