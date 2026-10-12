package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ---------------------------------------------------------------- grant edges

// GrantEdge is a grant between two graph nodes, e.g. account:3 -> group:7.
type GrantEdge struct {
	ID        int64
	TenantID  tenancy.ID
	Src, Dst  string
	Relation  string
	Source    string // connector | jit | manual | request | role
	ExpiresAt *time.Time
	CreatedAt time.Time
}

const edgeCols = `e.id, e.tenant_id, e.src, e.dst, e.relation, e.source, e.expires_at, e.created_at`

var (
	edgesList = tq("grant_edges.list", `
		SELECT `+edgeCols+` FROM grant_edges e WHERE e.tenant_id = @tenant ORDER BY e.id`)
	edgesGet = tq("grant_edges.get", `
		SELECT `+edgeCols+` FROM grant_edges e WHERE e.tenant_id = @tenant AND e.id = @id`)
	edgesBetween = tq("grant_edges.between", `
		SELECT `+edgeCols+` FROM grant_edges e WHERE e.tenant_id = @tenant AND e.src = @src AND e.dst = @dst
		ORDER BY e.id LIMIT 1`)
	edgesFrom = tq("grant_edges.from", `
		SELECT `+edgeCols+` FROM grant_edges e WHERE e.tenant_id = @tenant AND e.src = @src ORDER BY e.id`)
	edgesCountStanding = tq("grant_edges.count_standing_between", `
		SELECT count(*) FROM grant_edges e WHERE e.tenant_id = @tenant AND e.src = @src AND e.dst = @dst
		AND e.source != 'jit'`)
	edgesCount = tq("grant_edges.count", `
		SELECT count(e.id) FROM grant_edges e WHERE e.tenant_id = @tenant`)
	edgesUpsertConnector = tq("grant_edges.upsert_connector", `
		INSERT INTO grant_edges (tenant_id, src, dst, relation, source, created_at)
		VALUES (@tenant, @src, @dst, @relation, 'connector', @created_at)
		ON CONFLICT (tenant_id, src, dst) DO UPDATE SET relation = excluded.relation`)
	edgesInsert = tq("grant_edges.insert", `
		INSERT INTO grant_edges (tenant_id, src, dst, relation, source, expires_at, created_at)
		VALUES (@tenant, @src, @dst, @relation, @source, @expires_at, @created_at)`)
	edgesSetExpiry = tq("grant_edges.set_expiry", `
		UPDATE grant_edges SET expires_at = @expires_at WHERE tenant_id = @tenant AND id = @id`)
	edgesDelete = tq("grant_edges.delete", `
		DELETE FROM grant_edges WHERE tenant_id = @tenant AND id = @id`)
	edgesDeleteJIT = tq("grant_edges.delete_jit", `
		DELETE FROM grant_edges WHERE tenant_id = @tenant AND id = @id AND source = 'jit'`)
	edgesDeleteExpiredJIT = tq("grant_edges.delete_expired_jit", `
		DELETE FROM grant_edges WHERE tenant_id = @tenant AND source = 'jit' AND expires_at <= @now`)
)

func scanEdge(s scanner) (*GrantEdge, error) {
	var e GrantEdge
	var tid string
	var exp, created nullTime
	if err := s.Scan(&e.ID, &tid, &e.Src, &e.Dst, &e.Relation, &e.Source, &exp, &created); err != nil {
		return nil, err
	}
	var err error
	if e.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if e.ExpiresAt, err = exp.ptr(); err != nil {
		return nil, err
	}
	e.CreatedAt, err = created.val()
	return &e, err
}

// Edges returns every grant edge, in id order.
func (tx *TenantTx) Edges() ([]*GrantEdge, error) { return collect(tx, scanEdge, edgesList) }

// Edge returns one grant edge by id.
func (tx *TenantTx) Edge(id int64) (*GrantEdge, error) {
	return one(tx, scanEdge, edgesGet, sql.Named("id", id))
}

// EdgeBetween returns the edge src -> dst, if any.
func (tx *TenantTx) EdgeBetween(src, dst string) (*GrantEdge, error) {
	return one(tx, scanEdge, edgesBetween, sql.Named("src", src), sql.Named("dst", dst))
}

// EdgesFrom returns the edges leaving src, in id order.
func (tx *TenantTx) EdgesFrom(src string) ([]*GrantEdge, error) {
	return collect(tx, scanEdge, edgesFrom, sql.Named("src", src))
}

// HasStandingEdge reports whether a non-JIT edge src -> dst exists.
func (tx *TenantTx) HasStandingEdge(src, dst string) (bool, error) {
	n, err := tx.count(edgesCountStanding, sql.Named("src", src), sql.Named("dst", dst))
	return n > 0, err
}

// CountEdges counts grant edges.
func (tx *TenantTx) CountEdges() (int, error) { return tx.count(edgesCount) }

// UpsertConnectorEdge inserts a connector edge or updates the relation of the existing src -> dst edge.
func (tx *TenantTx) UpsertConnectorEdge(src, dst, relation string, createdAt time.Time) error {
	_, err := tx.exec(edgesUpsertConnector, sql.Named("src", src), sql.Named("dst", dst), sql.Named("relation", relation),
		sql.Named("created_at", T(createdAt)))
	return err
}

// InsertEdge inserts a grant edge and returns its id.
func (tx *TenantTx) InsertEdge(e *GrantEdge) (int64, error) {
	if err := tx.own(e.TenantID); err != nil {
		return 0, err
	}
	return tx.insert(edgesInsert, sql.Named("src", e.Src), sql.Named("dst", e.Dst), sql.Named("relation", e.Relation),
		sql.Named("source", e.Source), sql.Named("expires_at", TP(e.ExpiresAt)), sql.Named("created_at", T(e.CreatedAt)))
}

// SetEdgeExpiry sets a grant edge's expiry.
func (tx *TenantTx) SetEdgeExpiry(id int64, expires time.Time) error {
	_, err := tx.exec(edgesSetExpiry, sql.Named("expires_at", T(expires)), sql.Named("id", id))
	return err
}

// DeleteEdge deletes a grant edge by id.
func (tx *TenantTx) DeleteEdge(id int64) error {
	_, err := tx.exec(edgesDelete, sql.Named("id", id))
	return err
}

// DeleteJITEdge deletes a grant edge by id if it is a JIT edge.
func (tx *TenantTx) DeleteJITEdge(id int64) error {
	_, err := tx.exec(edgesDeleteJIT, sql.Named("id", id))
	return err
}

// DeleteExpiredJITEdges deletes JIT edges that expired at or before now.
func (tx *TenantTx) DeleteExpiredJITEdges(now time.Time) (int64, error) {
	res, err := tx.exec(edgesDeleteExpiredJIT, sql.Named("now", T(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- secrets

// Secret is a credential bound to an account. Secret material is never stored.
type Secret struct {
	ID            int64
	TenantID      tenancy.ID
	System        string
	ExternalID    string
	AccountID     int64
	Kind          string
	Name          string
	CreatedAt     time.Time
	LastRotatedAt *time.Time
	LastUsedAt    *time.Time
	Status        string
}

// secretCols lists secret metadata columns; secret material is never stored.
//
// #nosec G101 -- column names, not a credential
const secretCols = `s.id, s.tenant_id, s.system, s.external_id, s.account_id, s.kind, s.name, s.created_at,
	s.last_rotated_at, s.last_used_at, s.status`

var (
	secretsList = tq("secrets.list", `
		SELECT `+secretCols+` FROM secrets s WHERE s.tenant_id = @tenant ORDER BY s.id`)
	secretsByAccount = tq("secrets.by_account", `
		SELECT `+secretCols+` FROM secrets s WHERE s.tenant_id = @tenant AND s.account_id = @account_id ORDER BY s.id`)
	secretsWithAccounts = tq("secrets.with_accounts", `
		SELECT `+secretCols+`, `+accountCols+`
		FROM secrets s JOIN accounts a ON a.tenant_id = s.tenant_id AND s.account_id = a.id
		WHERE s.tenant_id = @tenant AND a.tenant_id = @tenant ORDER BY s.id`)
	secretsUpsert = tq("secrets.upsert", `
		INSERT INTO secrets (tenant_id, system, external_id, account_id, kind, name, created_at, last_rotated_at,
			last_used_at, status)
		VALUES (@tenant, @system, @external_id, @account_id, @kind, @name, @created_at, @last_rotated_at,
			@last_used_at, 'active')
		ON CONFLICT (tenant_id, system, external_id) DO UPDATE SET account_id = excluded.account_id,
			kind = excluded.kind, name = excluded.name, created_at = excluded.created_at,
			last_rotated_at = excluded.last_rotated_at, last_used_at = excluded.last_used_at`)
	secretsSetRotated = tq("secrets.set_rotated", `
		UPDATE secrets SET last_rotated_at = @at WHERE tenant_id = @tenant AND id = @id`)
)

func scanSecret(s scanner) (*Secret, error) {
	var x Secret
	var tid string
	var created, rot, used nullTime
	if err := s.Scan(&x.ID, &tid, &x.System, &x.ExternalID, &x.AccountID, &x.Kind, &x.Name, &created, &rot, &used,
		&x.Status); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if x.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if x.LastRotatedAt, err = rot.ptr(); err != nil {
		return nil, err
	}
	x.LastUsedAt, err = used.ptr()
	return &x, err
}

// Secrets returns every secret, in id order.
func (tx *TenantTx) Secrets() ([]*Secret, error) { return collect(tx, scanSecret, secretsList) }

// AccountSecrets returns an account's secrets, in id order.
func (tx *TenantTx) AccountSecrets(accountID int64) ([]*Secret, error) {
	return collect(tx, scanSecret, secretsByAccount, sql.Named("account_id", accountID))
}

// SecretWithAccount pairs a secret with its account.
type SecretWithAccount struct {
	Secret  *Secret
	Account *Account
}

// SecretsWithAccounts joins secrets to their accounts, in secret id order.
func (tx *TenantTx) SecretsWithAccounts() ([]SecretWithAccount, error) {
	type pair = SecretWithAccount
	rows, err := collect(tx, func(s scanner) (*pair, error) {
		var x Secret
		var stid, atid string
		var created, rot, used nullTime
		var a Account
		var iid sql.NullInt64
		var acreated, last nullTime
		if err := s.Scan(&x.ID, &stid, &x.System, &x.ExternalID, &x.AccountID, &x.Kind, &x.Name, &created, &rot, &used,
			&x.Status, &a.ID, &atid, &a.System, &a.ExternalID, &iid, &a.Username, &a.Kind, &a.Status, &acreated,
			&last); err != nil {
			return nil, err
		}
		var err error
		if x.TenantID, err = tenantOf(stid); err != nil {
			return nil, err
		}
		if a.TenantID, err = tenantOf(atid); err != nil {
			return nil, err
		}
		if x.CreatedAt, err = created.val(); err != nil {
			return nil, err
		}
		if x.LastRotatedAt, err = rot.ptr(); err != nil {
			return nil, err
		}
		if x.LastUsedAt, err = used.ptr(); err != nil {
			return nil, err
		}
		a.IdentityID = intp(iid)
		if a.CreatedAt, err = acreated.ptr(); err != nil {
			return nil, err
		}
		if a.LastLoginAt, err = last.ptr(); err != nil {
			return nil, err
		}
		return &pair{&x, &a}, nil
	}, secretsWithAccounts)
	if err != nil {
		return nil, err
	}
	out := make([]SecretWithAccount, len(rows))
	for i, r := range rows {
		out[i] = *r
	}
	return out, nil
}

// UpsertSecret inserts a secret (status active) or updates the one with the
// same system and external id. A nil AccountID stores NULL (the schema then
// rejects it, as before).
func (tx *TenantTx) UpsertSecret(x *Secret, accountID *int64) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(secretsUpsert, sql.Named("system", x.System), sql.Named("external_id", x.ExternalID),
		sql.Named("account_id", IP(accountID)), sql.Named("kind", x.Kind), sql.Named("name", x.Name),
		sql.Named("created_at", T(x.CreatedAt)), sql.Named("last_rotated_at", TP(x.LastRotatedAt)),
		sql.Named("last_used_at", TP(x.LastUsedAt)))
	return err
}

// SetSecretRotated records a rotation at.
func (tx *TenantTx) SetSecretRotated(id int64, at time.Time) error {
	_, err := tx.exec(secretsSetRotated, sql.Named("at", T(at)), sql.Named("id", id))
	return err
}

// ---------------------------------------------------------------- delegations

// Delegation is an AI agent acting on behalf of a principal with bounded scopes.
type Delegation struct {
	ID          int64
	TenantID    tenancy.ID
	AgentID     int64
	PrincipalID int64
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
}

var (
	delegationsList = tq("agent_delegations.list", `
		SELECT d.id, d.tenant_id, d.agent_id, d.principal_id, d.scopes, d.created_at, d.expires_at
		FROM agent_delegations d WHERE d.tenant_id = @tenant ORDER BY d.id`)
	delegationsInsert = tq("agent_delegations.insert", `
		INSERT INTO agent_delegations (tenant_id, agent_id, principal_id, scopes, created_at, expires_at)
		VALUES (@tenant, @agent_id, @principal_id, @scopes, @created_at, @expires_at)`)
	// The Python MVP's "replace wholesale" was an unscoped DELETE that would
	// have removed every tenant's delegations. This one is scoped by construction.
	delegationsDeleteAll = tq("agent_delegations.delete_all", `
		DELETE FROM agent_delegations WHERE tenant_id = @tenant`)
	delegationsDelete = tq("agent_delegations.delete", `
		DELETE FROM agent_delegations WHERE tenant_id = @tenant AND id = @id`)
)

func scanDelegation(s scanner) (*Delegation, error) {
	var d Delegation
	var tid, scopes string
	var created, exp nullTime
	if err := s.Scan(&d.ID, &tid, &d.AgentID, &d.PrincipalID, &scopes, &created, &exp); err != nil {
		return nil, err
	}
	var err error
	if d.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopes), &d.Scopes); err != nil {
		return nil, err
	}
	if d.Scopes == nil {
		d.Scopes = []string{}
	}
	if d.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	d.ExpiresAt, err = exp.ptr()
	return &d, err
}

// Delegations returns every delegation, in id order.
func (tx *TenantTx) Delegations() ([]*Delegation, error) {
	return collect(tx, scanDelegation, delegationsList)
}

// DeleteAgentDelegations deletes this tenant's delegations (ingest replaces
// them wholesale) and returns how many were deleted.
func (tx *TenantTx) DeleteAgentDelegations() (int64, error) {
	res, err := tx.exec(delegationsDeleteAll)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertDelegations inserts delegations in order.
func (tx *TenantTx) InsertDelegations(rows []Delegation) error {
	for i := range rows {
		d := &rows[i]
		if err := tx.own(d.TenantID); err != nil {
			return err
		}
		scopes := d.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		s, err := JSON(scopes)
		if err != nil {
			return err
		}
		if _, err := tx.exec(delegationsInsert, sql.Named("agent_id", d.AgentID), sql.Named("principal_id", d.PrincipalID),
			sql.Named("scopes", s), sql.Named("created_at", T(d.CreatedAt)), sql.Named("expires_at", TP(d.ExpiresAt))); err != nil {
			return err
		}
	}
	return nil
}

// DeleteDelegation deletes one delegation.
func (tx *TenantTx) DeleteDelegation(id int64) error {
	_, err := tx.exec(delegationsDelete, sql.Named("id", id))
	return err
}
