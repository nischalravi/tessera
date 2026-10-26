package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Per-tenant policy sources (schema/0917_policy_sources.sql, issue #649).
// Every statement binds the tenant.

// Policy source kinds and statuses.
const (
	PolicyKindInvariant = "invariant"

	PolicyActive   = "active"
	PolicyDisabled = "disabled"

	// MaxPolicySourceBytes is the size of one source (the cedarx file limit).
	MaxPolicySourceBytes = 256 << 10
)

// PolicySource is one policy file of a tenant: its Cedar, status and version.
// SHA256 is the hex digest of Cedar, set by PutPolicySource.
type PolicySource struct {
	Kind      string
	Key       string
	Cedar     string
	SHA256    string
	Status    string
	Version   int
	PolicyRef string
	UpdatedBy string
	UpdatedAt time.Time
}

// PolicyVersion is one change of a PolicySource.
type PolicyVersion struct {
	Kind      string
	Key       string
	Version   int
	Cedar     string
	SHA256    string
	Status    string
	PolicyRef string
	Actor     string
	At        time.Time
}

const tenantPolSrcCols = `s.kind, s.src_key, s.cedar, s.sha256, s.status, s.version, s.policy_ref, s.updated_by, s.updated_at`

var (
	tenantPolSrcGet = tq("policy_sources.get", `
		SELECT `+tenantPolSrcCols+` FROM policy_sources s WHERE s.tenant_id = @tenant AND s.kind = @kind AND s.src_key = @key`)
	tenantPolSrcList = tq("policy_sources.list", `
		SELECT `+tenantPolSrcCols+` FROM policy_sources s WHERE s.tenant_id = @tenant AND s.kind = @kind ORDER BY s.src_key`)
	tenantPolSrcPut = tq("policy_sources.put", `
		INSERT INTO policy_sources (tenant_id, kind, src_key, cedar, sha256, status, version, policy_ref, updated_by, updated_at)
		VALUES (@tenant, @kind, @key, @cedar, @sha256, @status, @version, @policy_ref, @actor, @at)
		ON CONFLICT (tenant_id, kind, src_key) DO UPDATE SET cedar = excluded.cedar, sha256 = excluded.sha256,
			status = excluded.status, version = excluded.version, policy_ref = excluded.policy_ref,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	policyVersionInsert = tq("policy_versions.insert", `
		INSERT INTO policy_versions (tenant_id, kind, src_key, version, cedar, sha256, status, policy_ref, actor, at)
		VALUES (@tenant, @kind, @key, @version, @cedar, @sha256, @status, @policy_ref, @actor, @at)`)
	policyVersionList = tq("policy_versions.list", `
		SELECT v.kind, v.src_key, v.version, v.cedar, v.sha256, v.status, v.policy_ref, v.actor, v.at
		FROM policy_versions v WHERE v.tenant_id = @tenant AND v.kind = @kind AND v.src_key = @key ORDER BY v.version`)
)

func scanTenantPolSrc(s scanner) (*PolicySource, error) {
	var p PolicySource
	var at string
	if err := s.Scan(&p.Kind, &p.Key, &p.Cedar, &p.SHA256, &p.Status, &p.Version, &p.PolicyRef, &p.UpdatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	p.UpdatedAt, err = ParseRT(at)
	return &p, err
}

// PolicySource returns one source, or ErrNotFound.
func (tx *TenantTx) PolicySource(kind, key string) (*PolicySource, error) {
	return one(tx, scanTenantPolSrc, tenantPolSrcGet, sql.Named("kind", kind), sql.Named("key", key))
}

// PolicySources lists the tenant's sources of a kind by key, active and disabled.
func (tx *TenantTx) PolicySources(kind string) ([]*PolicySource, error) {
	return collect(tx, scanTenantPolSrc, tenantPolSrcList, sql.Named("kind", kind))
}

// PutPolicySource creates or replaces the source (Kind, Key). The digest is
// computed here and the version is the next one. Writing what is already
// stored (same Cedar, Status and PolicyRef) changes nothing and returns false;
// otherwise the new version is also appended to the history. The size is held
// to MaxPolicySourceBytes; the Cedar is not parsed here (internal/policy
// validates it before it gets here).
func (tx *TenantTx) PutPolicySource(s *PolicySource, now time.Time) (bool, error) {
	if len(s.Cedar) == 0 || len(s.Cedar) > MaxPolicySourceBytes {
		return false, fmt.Errorf("store: policy source of %d bytes; 1 to %d", len(s.Cedar), MaxPolicySourceBytes)
	}
	sum := sha256.Sum256([]byte(s.Cedar))
	digest := hex.EncodeToString(sum[:])
	cur, err := tx.PolicySource(s.Kind, s.Key)
	version := 1
	switch {
	case err == nil:
		if cur.SHA256 == digest && cur.Status == s.Status && cur.PolicyRef == s.PolicyRef {
			return false, nil
		}
		version = cur.Version + 1
	case !errors.Is(err, ErrNotFound):
		return false, err
	}
	args := []sql.NamedArg{sql.Named("kind", s.Kind), sql.Named("key", s.Key), sql.Named("cedar", s.Cedar),
		sql.Named("sha256", digest), sql.Named("status", s.Status), sql.Named("version", version),
		sql.Named("policy_ref", s.PolicyRef), sql.Named("actor", s.UpdatedBy), sql.Named("at", RT(now))}
	if _, err := tx.exec(tenantPolSrcPut, args...); err != nil {
		return false, err
	}
	if _, err := tx.exec(policyVersionInsert, args...); err != nil {
		return false, err
	}
	s.SHA256, s.Version, s.UpdatedAt = digest, version, now
	return true, nil
}

// PolicyVersions is the history of a source, oldest first.
func (tx *TenantTx) PolicyVersions(kind, key string) ([]*PolicyVersion, error) {
	return collect(tx, func(s scanner) (*PolicyVersion, error) {
		var v PolicyVersion
		var at string
		if err := s.Scan(&v.Kind, &v.Key, &v.Version, &v.Cedar, &v.SHA256, &v.Status, &v.PolicyRef, &v.Actor, &at); err != nil {
			return nil, err
		}
		var err error
		v.At, err = ParseRT(at)
		return &v, err
	}, policyVersionList, sql.Named("kind", kind), sql.Named("key", key))
}
