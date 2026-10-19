package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Directory agents (DR-11) and their single-use enrolment codes. Every
// statement is tenant-scoped (tq) except the two bearer-hash lookups of
// design §14.2 (lq), which return only the pair needed to open the tenant.

// Directory agent statuses.
const (
	AgentPending = "pending"
	AgentActive  = "active"
	AgentRevoked = "revoked"
)

// DirectoryAgent is one enrolled (or pending) Directory Agent.
type DirectoryAgent struct {
	ID            string
	TenantID      tenancy.ID // zero on insert means "this transaction's tenant"
	Name          string
	Status        string
	CertPin       string // SHA-256 (hex) of the agent certificate's public key; empty until enrolled
	Hostname      string
	OS            string
	Version       string
	AllowlistHash string
	LastSeenAt    *time.Time
	EnrolledAt    *time.Time
	CreatedBy     string
	CreatedAt     time.Time
	RevokedAt     *time.Time
	RevokedBy     string
}

// AgentEnrolment is a single-use enrolment code. TokenHash is the SHA-256
// (hex) of the code; the code itself is never stored.
type AgentEnrolment struct {
	ID         string
	TenantID   tenancy.ID // zero on insert means "this transaction's tenant"
	AgentID    string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedBy  string
	CreatedAt  time.Time
}

const agentCols = `a.id, a.tenant_id, a.name, a.status, a.cert_pin, a.hostname, a.os, a.version, a.allowlist_hash,
	a.last_seen_at, a.enrolled_at, a.created_by, a.created_at, a.revoked_at, a.revoked_by`

const enrolCols = `e.id, e.tenant_id, e.agent_id, e.token_hash, e.expires_at, e.consumed_at, e.created_by, e.created_at`

var (
	agentsInsert = tq("directory_agents.insert", `
		INSERT INTO directory_agents (id, tenant_id, name, status, created_by, created_at)
		VALUES (@id, @tenant, @name, 'pending', @created_by, @created_at)`)
	agentsGet = tq("directory_agents.get", `
		SELECT `+agentCols+` FROM directory_agents a WHERE a.tenant_id = @tenant AND a.id = @id`)
	agentsList = tq("directory_agents.list", `
		SELECT `+agentCols+` FROM directory_agents a WHERE a.tenant_id = @tenant ORDER BY a.created_at, a.rowid`)
	// pending -> active, once: the agent's key is pinned here.
	agentsActivate = tq("directory_agents.activate", `
		UPDATE directory_agents SET status = 'active', cert_pin = @cert_pin, hostname = @hostname, os = @os,
			version = @version, allowlist_hash = @allowlist_hash, enrolled_at = @now, last_seen_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
	agentsTouch = tq("directory_agents.touch", `
		UPDATE directory_agents SET hostname = @hostname, os = @os, version = @version,
			allowlist_hash = @allowlist_hash, last_seen_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	agentsRevoke = tq("directory_agents.revoke", `
		UPDATE directory_agents SET status = 'revoked', revoked_at = @now, revoked_by = @by
		WHERE tenant_id = @tenant AND id = @id AND status <> 'revoked'`)

	enrolInsert = tq("agent_enrolments.insert", `
		INSERT INTO agent_enrolments (id, tenant_id, agent_id, token_hash, expires_at, created_by, created_at)
		VALUES (@id, @tenant, @agent_id, @token_hash, @expires_at, @created_by, @created_at)`)
	enrolGet = tq("agent_enrolments.get", `
		SELECT `+enrolCols+` FROM agent_enrolments e WHERE e.tenant_id = @tenant AND e.id = @id`)
	// Single use: consumed only while unconsumed and unexpired. Exactly one
	// concurrent enrolment can win.
	enrolConsume = tq("agent_enrolments.consume", `
		UPDATE agent_enrolments SET consumed_at = @now
		WHERE tenant_id = @tenant AND id = @id AND consumed_at IS NULL AND expires_at > @now`)
	// Revoking an agent voids its unused codes.
	enrolVoid = tq("agent_enrolments.void_for_agent", `
		UPDATE agent_enrolments SET consumed_at = @now
		WHERE tenant_id = @tenant AND agent_id = @agent_id AND consumed_at IS NULL`)

	enrolLookup = lq("agent_enrolments.lookup_by_token_hash", `
		SELECT e.tenant_id, e.id FROM agent_enrolments e WHERE e.token_hash = @hash`)
	agentLookup = lq("directory_agents.lookup_by_cert_pin", `
		SELECT a.tenant_id, a.id FROM directory_agents a WHERE a.cert_pin = @hash`)
)

func scanAgent(s scanner) (*DirectoryAgent, error) {
	var a DirectoryAgent
	var tid, created string
	var pin, host, os, ver, allow, seen, enrolled, revoked, revBy sql.NullString
	if err := s.Scan(&a.ID, &tid, &a.Name, &a.Status, &pin, &host, &os, &ver, &allow, &seen, &enrolled, &a.CreatedBy,
		&created, &revoked, &revBy); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	a.CertPin, a.Hostname, a.OS, a.Version = pin.String, host.String, os.String, ver.String
	a.AllowlistHash, a.RevokedBy = allow.String, revBy.String
	if a.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		dst **time.Time
		src sql.NullString
	}{{&a.LastSeenAt, seen}, {&a.EnrolledAt, enrolled}, {&a.RevokedAt, revoked}} {
		if *p.dst, err = rtp(p.src); err != nil {
			return nil, err
		}
	}
	return &a, nil
}

func scanEnrolment(s scanner) (*AgentEnrolment, error) {
	var e AgentEnrolment
	var tid, expires, created string
	var consumed sql.NullString
	if err := s.Scan(&e.ID, &tid, &e.AgentID, &e.TokenHash, &expires, &consumed, &e.CreatedBy, &created); err != nil {
		return nil, err
	}
	var err error
	if e.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if e.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	if e.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	e.ConsumedAt, err = rtp(consumed)
	return &e, err
}

// InsertDirectoryAgent adds a pending agent; ErrDuplicate when the name is taken.
func (tx *TenantTx) InsertDirectoryAgent(a *DirectoryAgent) error {
	if err := tx.own(a.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(agentsInsert, sql.Named("id", a.ID), sql.Named("name", a.Name),
		sql.Named("created_by", a.CreatedBy), sql.Named("created_at", RT(a.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// DirectoryAgent returns one agent or ErrNotFound (also another tenant's).
func (tx *TenantTx) DirectoryAgent(id string) (*DirectoryAgent, error) {
	return one(tx, scanAgent, agentsGet, sql.Named("id", id))
}

// DirectoryAgents lists the tenant's agents, oldest first.
func (tx *TenantTx) DirectoryAgents() ([]*DirectoryAgent, error) {
	return collect(tx, scanAgent, agentsList)
}

// ActivateDirectoryAgent moves a pending agent to active and pins its key
// (ErrNotFound unless it is pending; ErrDuplicate if the key is already
// pinned to another agent).
func (tx *TenantTx) ActivateDirectoryAgent(id, certPin string, t AgentTelemetry, now time.Time) error {
	err := tx.execOne(agentsActivate, sql.Named("id", id), sql.Named("cert_pin", certPin), sql.Named("hostname", t.Hostname),
		sql.Named("os", t.OS), sql.Named("version", t.Version), sql.Named("allowlist_hash", t.AllowlistHash),
		sql.Named("now", RT(now)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// AgentTelemetry is what an agent reports about itself.
type AgentTelemetry struct{ Hostname, OS, Version, AllowlistHash string }

// TouchDirectoryAgent records a heartbeat of an active agent.
func (tx *TenantTx) TouchDirectoryAgent(id string, t AgentTelemetry, now time.Time) error {
	return tx.execOne(agentsTouch, sql.Named("id", id), sql.Named("hostname", t.Hostname), sql.Named("os", t.OS),
		sql.Named("version", t.Version), sql.Named("allowlist_hash", t.AllowlistHash), sql.Named("now", RT(now)))
}

// RevokeDirectoryAgent revokes an agent and voids its unused enrolment codes
// (ErrNotFound if it does not exist or is already revoked).
func (tx *TenantTx) RevokeDirectoryAgent(id, by string, now time.Time) error {
	if err := tx.execOne(agentsRevoke, sql.Named("id", id), sql.Named("by", by), sql.Named("now", RT(now))); err != nil {
		return err
	}
	_, err := tx.exec(enrolVoid, sql.Named("agent_id", id), sql.Named("now", RT(now)))
	return err
}

// InsertAgentEnrolment stores the hash of a new single-use code.
func (tx *TenantTx) InsertAgentEnrolment(e *AgentEnrolment) error {
	if err := tx.own(e.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(enrolInsert, sql.Named("id", e.ID), sql.Named("agent_id", e.AgentID),
		sql.Named("token_hash", e.TokenHash), sql.Named("expires_at", RT(e.ExpiresAt)),
		sql.Named("created_by", e.CreatedBy), sql.Named("created_at", RT(e.CreatedAt)))
	return err
}

// AgentEnrolment returns one code row or ErrNotFound.
func (tx *TenantTx) AgentEnrolment(id string) (*AgentEnrolment, error) {
	return one(tx, scanEnrolment, enrolGet, sql.Named("id", id))
}

// ConsumeAgentEnrolment marks a code used. It succeeds exactly once, and only
// before expiry; otherwise ErrNotFound.
func (tx *TenantTx) ConsumeAgentEnrolment(id string, now time.Time) error {
	return tx.execOne(enrolConsume, sql.Named("id", id), sql.Named("now", RT(now)))
}

// LookupAgentEnrolmentByTokenHash resolves an enrolment code's hash to its
// tenant and row id (ErrNotFound if none). One of the reads of a tenant table
// outside a TenantTx (design §14.2).
func (s *SystemTx) LookupAgentEnrolmentByTokenHash(hash string) (tenancy.ID, uuid.UUID, error) {
	return s.lookup(enrolLookup, "agent_enrolment_hash", hash)
}

// LookupDirectoryAgentByCertPin resolves an agent key pin to its tenant and
// agent id (ErrNotFound if none).
func (s *SystemTx) LookupDirectoryAgentByCertPin(pin string) (tenancy.ID, uuid.UUID, error) {
	return s.lookup(agentLookup, "agent_cert_pin", pin)
}
