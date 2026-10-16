package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// AI agent discovery (schema/0300_agent_discovery.sql, issue #116). Nothing
// here holds a secret value: findings keep a location, a truncated hash and a
// secret type.

// AgentProfile is where a discovered AI agent came from.
type AgentProfile struct {
	Source, ExternalID string
	IdentityID         int64
	Kind               string
	CreatorRef         string
	CreatorID          *int64
	SponsorRef         string
	SponsorID          *int64
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
}

// MCPFinding is one MCP server or agent credential found in source code.
type MCPFinding struct {
	ID                                  int64
	Source, Kind, Org, Repo, Path       string
	Location, Server, Transport, Target string
	SecretType, Fingerprint             string
	OwnerRef, OwnerSource               string
	OwnerID                             *int64
	CommitSHA                           string
	FirstSeenAt, LastSeenAt             time.Time
}

const agentProfileCols = `a.source, a.external_id, a.identity_id, a.kind, a.creator_ref, a.creator_identity_id,
	a.sponsor_ref, a.sponsor_identity_id, a.first_seen_at, a.last_seen_at`

const mcpFindingCols = `f.id, f.source, f.kind, f.org, f.repo, f.path, f.location, f.server, f.transport, f.target,
	f.secret_type, f.fingerprint, f.owner_ref, f.owner_source, f.owner_identity_id, f.commit_sha, f.first_seen_at, f.last_seen_at`

var (
	agentProfilesList = tq("agent_profiles.list", `
		SELECT `+agentProfileCols+` FROM agent_profiles a WHERE a.tenant_id = @tenant ORDER BY a.source, a.external_id`)
	agentProfilesUpsert = tq("agent_profiles.upsert", `
		INSERT INTO agent_profiles (tenant_id, source, external_id, identity_id, kind, creator_ref, creator_identity_id,
			sponsor_ref, sponsor_identity_id, first_seen_at, last_seen_at)
		VALUES (@tenant, @source, @external_id, @identity_id, @kind, @creator_ref, @creator_identity_id,
			@sponsor_ref, @sponsor_identity_id, @seen_at, @seen_at)
		ON CONFLICT (tenant_id, source, external_id) DO UPDATE SET identity_id = excluded.identity_id, kind = excluded.kind,
			creator_ref = excluded.creator_ref, creator_identity_id = excluded.creator_identity_id,
			sponsor_ref = excluded.sponsor_ref, sponsor_identity_id = excluded.sponsor_identity_id,
			last_seen_at = excluded.last_seen_at`)
	agentProfilesDelete = tq("agent_profiles.delete", `
		DELETE FROM agent_profiles WHERE tenant_id = @tenant AND source = @source AND external_id = @external_id`)

	mcpFindingsList = tq("mcp_findings.list", `
		SELECT `+mcpFindingCols+` FROM mcp_findings f WHERE f.tenant_id = @tenant
		ORDER BY f.org, f.repo, f.path, f.location, f.kind, f.fingerprint`)
	mcpFindingsUpsert = tq("mcp_findings.upsert", `
		INSERT INTO mcp_findings (tenant_id, source, kind, org, repo, path, location, server, transport, target,
			secret_type, fingerprint, owner_ref, owner_source, owner_identity_id, commit_sha, first_seen_at, last_seen_at)
		VALUES (@tenant, @source, @kind, @org, @repo, @path, @location, @server, @transport, @target,
			@secret_type, @fingerprint, @owner_ref, @owner_source, @owner_identity_id, @commit_sha, @seen_at, @seen_at)
		ON CONFLICT (tenant_id, source, kind, org, repo, path, location, fingerprint) DO UPDATE SET
			server = excluded.server, transport = excluded.transport, target = excluded.target,
			secret_type = excluded.secret_type, owner_ref = excluded.owner_ref, owner_source = excluded.owner_source,
			owner_identity_id = excluded.owner_identity_id, commit_sha = excluded.commit_sha,
			last_seen_at = excluded.last_seen_at`)
	mcpFindingsDelete = tq("mcp_findings.delete", `
		DELETE FROM mcp_findings WHERE tenant_id = @tenant AND id = @id`)
)

func scanAgentProfile(s scanner) (*AgentProfile, error) {
	var a AgentProfile
	var creator, sponsor sql.NullInt64
	var first, last string
	if err := s.Scan(&a.Source, &a.ExternalID, &a.IdentityID, &a.Kind, &a.CreatorRef, &creator, &a.SponsorRef, &sponsor,
		&first, &last); err != nil {
		return nil, err
	}
	a.CreatorID, a.SponsorID = intp(creator), intp(sponsor)
	var err error
	if a.FirstSeenAt, err = timeutil.ParseDB(first); err != nil {
		return nil, err
	}
	a.LastSeenAt, err = timeutil.ParseDB(last)
	return &a, err
}

func scanMCPFinding(s scanner) (*MCPFinding, error) {
	var f MCPFinding
	var owner sql.NullInt64
	var first, last string
	if err := s.Scan(&f.ID, &f.Source, &f.Kind, &f.Org, &f.Repo, &f.Path, &f.Location, &f.Server, &f.Transport, &f.Target,
		&f.SecretType, &f.Fingerprint, &f.OwnerRef, &f.OwnerSource, &owner, &f.CommitSHA, &first, &last); err != nil {
		return nil, err
	}
	f.OwnerID = intp(owner)
	var err error
	if f.FirstSeenAt, err = timeutil.ParseDB(first); err != nil {
		return nil, err
	}
	f.LastSeenAt, err = timeutil.ParseDB(last)
	return &f, err
}

// AgentProfiles lists the tenant's agent profiles.
func (tx *TenantTx) AgentProfiles() ([]*AgentProfile, error) {
	return collect(tx, scanAgentProfile, agentProfilesList)
}

// UpsertAgentProfile stores a profile; first_seen_at is kept on update.
func (tx *TenantTx) UpsertAgentProfile(a *AgentProfile, seenAt time.Time) error {
	_, err := tx.exec(agentProfilesUpsert, sql.Named("source", a.Source), sql.Named("external_id", a.ExternalID),
		sql.Named("identity_id", a.IdentityID), sql.Named("kind", a.Kind), sql.Named("creator_ref", a.CreatorRef),
		sql.Named("creator_identity_id", IP(a.CreatorID)), sql.Named("sponsor_ref", a.SponsorRef),
		sql.Named("sponsor_identity_id", IP(a.SponsorID)), sql.Named("seen_at", T(seenAt)))
	return err
}

// DeleteAgentProfile removes one profile.
func (tx *TenantTx) DeleteAgentProfile(source, externalID string) error {
	_, err := tx.exec(agentProfilesDelete, sql.Named("source", source), sql.Named("external_id", externalID))
	return err
}

// MCPFindings lists the tenant's findings.
func (tx *TenantTx) MCPFindings() ([]*MCPFinding, error) {
	return collect(tx, scanMCPFinding, mcpFindingsList)
}

// UpsertMCPFinding stores a finding; first_seen_at is kept on update.
func (tx *TenantTx) UpsertMCPFinding(f *MCPFinding, seenAt time.Time) error {
	_, err := tx.exec(mcpFindingsUpsert, sql.Named("source", f.Source), sql.Named("kind", f.Kind), sql.Named("org", f.Org),
		sql.Named("repo", f.Repo), sql.Named("path", f.Path), sql.Named("location", f.Location), sql.Named("server", f.Server),
		sql.Named("transport", f.Transport), sql.Named("target", f.Target), sql.Named("secret_type", f.SecretType),
		sql.Named("fingerprint", f.Fingerprint), sql.Named("owner_ref", f.OwnerRef), sql.Named("owner_source", f.OwnerSource),
		sql.Named("owner_identity_id", IP(f.OwnerID)), sql.Named("commit_sha", f.CommitSHA), sql.Named("seen_at", T(seenAt)))
	return err
}

// DeleteMCPFinding removes one finding.
func (tx *TenantTx) DeleteMCPFinding(id int64) error {
	_, err := tx.exec(mcpFindingsDelete, sql.Named("id", id))
	return err
}
