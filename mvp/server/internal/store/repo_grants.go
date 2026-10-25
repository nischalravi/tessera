package store

import (
	"database/sql"
	"encoding/json"
	"errors"
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
	Source    string // connector | jit | manual | request | role | evaluator
	ExpiresAt *time.Time
	CreatedAt time.Time
	// ExplanationID, Outcome ("allow" | "conditional") and Fidelity ("exact" |
	// "approximate" | "unsupported") are set only on edges the AWS evaluator
	// confirmed (design §11.2); "" means unset, which is every other edge.
	ExplanationID, Outcome, Fidelity string
	// Ref and Provenance describe the intent behind a new edge (see
	// repo_access_model.go): Ref names what approved it (a request line, a
	// role id, a JIT request) and Provenance overrides the one the source
	// implies (a birthright role grant). They are not stored in grant_edges.
	Ref        string
	Provenance string
}

// EdgeSourceEvaluator is the source of an edge the AWS evaluator confirmed.
const EdgeSourceEvaluator = "evaluator"

// edgeCols are the columns of an edge, with the evaluator's fields from the
// side table (schema/0321_aws_integration.sql) that edgeFrom joins.
const edgeCols = `e.id, e.tenant_id, e.src, e.dst, e.relation, e.source, e.expires_at, e.created_at,
	COALESCE(v.explanation_id, ''), COALESCE(v.outcome, ''), COALESCE(v.fidelity, '')`

const edgeFrom = ` FROM grant_edges e LEFT JOIN aws_edge_evaluations v ON v.tenant_id = @tenant AND v.edge_id = e.id `

var (
	edgesList = tq("grant_edges.list", `
		SELECT `+edgeCols+edgeFrom+`WHERE e.tenant_id = @tenant ORDER BY e.id`)
	edgeExplanations = tq("aws_edge_evaluations.explanations", `
		SELECT v.edge_id, v.explanation_id FROM aws_edge_evaluations v
		WHERE v.tenant_id = @tenant AND v.explanation_id <> '' ORDER BY v.edge_id`)
	edgesGet = tq("grant_edges.get", `
		SELECT `+edgeCols+edgeFrom+`WHERE e.tenant_id = @tenant AND e.id = @id`)
	edgesBetween = tq("grant_edges.between", `
		SELECT `+edgeCols+edgeFrom+`WHERE e.tenant_id = @tenant AND e.src = @src AND e.dst = @dst
		ORDER BY e.id LIMIT 1`)
	edgesFrom = tq("grant_edges.from", `
		SELECT `+edgeCols+edgeFrom+`WHERE e.tenant_id = @tenant AND e.src = @src ORDER BY e.id`)
	edgesUpsertEvaluator = tq("grant_edges.upsert_evaluator", `
		INSERT INTO grant_edges (tenant_id, src, dst, relation, source, created_at)
		VALUES (@tenant, @src, @dst, @relation, 'evaluator', @created_at)
		ON CONFLICT (tenant_id, src, dst) DO UPDATE SET relation = excluded.relation WHERE grant_edges.source = 'evaluator'`)
	edgeEvalUpsert = tq("aws_edge_evaluations.upsert", `
		INSERT INTO aws_edge_evaluations (tenant_id, edge_id, explanation_id, outcome, fidelity)
		VALUES (@tenant, @edge_id, @explanation_id, @outcome, @fidelity)
		ON CONFLICT (tenant_id, edge_id) DO UPDATE SET explanation_id = excluded.explanation_id, outcome = excluded.outcome,
			fidelity = excluded.fidelity`)
	edgeEvalDelete = tq("aws_edge_evaluations.delete", `
		DELETE FROM aws_edge_evaluations WHERE tenant_id = @tenant AND edge_id = @id`)
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
	revokedRecord = tq("revoked_grants.record", `
		INSERT INTO revoked_grants (tenant_id, src, dst, reason, revoked_at)
		VALUES (@tenant, @src, @dst, @reason, @at)
		ON CONFLICT (tenant_id, src, dst) DO UPDATE SET reason = excluded.reason, revoked_at = excluded.revoked_at`)
	revokedCount = tq("revoked_grants.count_between", `
		SELECT count(*) FROM revoked_grants r WHERE r.tenant_id = @tenant AND r.src = @src AND r.dst = @dst`)
	revokedList = tq("revoked_grants.list", `
		SELECT r.tenant_id, r.src, r.dst, r.reason, r.revoked_at FROM revoked_grants r WHERE r.tenant_id = @tenant
		ORDER BY r.src, r.dst`)
	edgesDeleteJIT = tq("grant_edges.delete_jit", `
		DELETE FROM grant_edges WHERE tenant_id = @tenant AND id = @id AND source = 'jit'`)
	edgesDeleteExpiredJIT = tq("grant_edges.delete_expired_jit", `
		DELETE FROM grant_edges WHERE grant_edges.tenant_id = @tenant AND grant_edges.source = 'jit'
			AND grant_edges.expires_at <= @now
			AND grant_edges.id NOT IN (SELECT r.edge_id FROM access_requests r
				WHERE r.tenant_id = @tenant AND r.status = 'approved' AND r.edge_id IS NOT NULL)`)
)

func scanEdge(s scanner) (*GrantEdge, error) {
	var e GrantEdge
	var tid string
	var exp, created nullTime
	if err := s.Scan(&e.ID, &tid, &e.Src, &e.Dst, &e.Relation, &e.Source, &exp, &created,
		&e.ExplanationID, &e.Outcome, &e.Fidelity); err != nil {
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

// EdgeExplanations maps a grant edge id to the evaluator explanation id of its
// evaluation, for the edges that have one (EP-8: findings link to the trace).
func (tx *TenantTx) EdgeExplanations() (map[int64]string, error) {
	rows, err := tx.query(edgeExplanations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var x string
		if err := rows.Scan(&id, &x); err != nil {
			return nil, err
		}
		out[id] = x
	}
	return out, rows.Err()
}

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
// A grant revoked inside Tessera (see RevokeEdge) is not brought back.
//
// Every change of the edge set also opens or closes a span in edge_history in
// the same transaction (see EdgeSpan): a new edge opens one at createdAt, a
// changed relation closes the old one and opens another.
func (tx *TenantTx) UpsertConnectorEdge(src, dst, relation string, createdAt time.Time) error {
	if n, err := tx.count(revokedCount, sql.Named("src", src), sql.Named("dst", dst)); err != nil || n > 0 {
		return err
	}
	prev, err := getEdgeOrNil(tx.EdgeBetween(src, dst))
	if err != nil {
		return err
	}
	if _, err := tx.exec(edgesUpsertConnector, sql.Named("src", src), sql.Named("dst", dst), sql.Named("relation", relation),
		sql.Named("created_at", T(createdAt))); err != nil {
		return err
	}
	if prev != nil && prev.Relation == relation {
		return nil
	}
	cur, err := tx.EdgeBetween(src, dst)
	if err != nil {
		return err
	}
	if prev != nil {
		if err := tx.closeSpan(src, dst, createdAt); err != nil {
			return err
		}
	}
	return tx.openSpan(cur.ID, src, dst, relation, cur.Source, cur.ExpiresAt, createdAt)
}

// EdgeEvaluation is what the AWS evaluator confirmed about a grant edge.
type EdgeEvaluation struct {
	ExplanationID, Outcome, Fidelity string
}

// UpsertEvaluatorEdge inserts an edge the AWS evaluator confirmed, or updates
// the one it made before, with the evaluation's explanation, outcome and
// fidelity. An edge from another source (manual, JIT, a demo connector) keeps
// its source and gets no evaluation. A grant revoked inside Tessera is not
// brought back. It reports whether an edge now carries the evaluation. Like
// UpsertConnectorEdge it keeps edge_history in step.
func (tx *TenantTx) UpsertEvaluatorEdge(src, dst, relation string, createdAt time.Time, ev EdgeEvaluation) (bool, error) {
	if n, err := tx.count(revokedCount, sql.Named("src", src), sql.Named("dst", dst)); err != nil || n > 0 {
		return false, err
	}
	prev, err := getEdgeOrNil(tx.EdgeBetween(src, dst))
	if err != nil {
		return false, err
	}
	if _, err := tx.exec(edgesUpsertEvaluator, sql.Named("src", src), sql.Named("dst", dst), sql.Named("relation", relation),
		sql.Named("created_at", T(createdAt))); err != nil {
		return false, err
	}
	e, err := tx.EdgeBetween(src, dst)
	if err != nil {
		return false, err
	}
	if e.Source != EdgeSourceEvaluator {
		return false, nil
	}
	// the edge set changed: keep edge_history in step (a new edge opens a span,
	// a changed relation closes the old one and opens another)
	if prev == nil || prev.Relation != e.Relation {
		if prev != nil {
			if err := tx.closeSpan(src, dst, createdAt); err != nil {
				return false, err
			}
		}
		if err := tx.openSpan(e.ID, src, dst, e.Relation, e.Source, e.ExpiresAt, createdAt); err != nil {
			return false, err
		}
	}
	_, err = tx.exec(edgeEvalUpsert, sql.Named("edge_id", e.ID), sql.Named("explanation_id", ev.ExplanationID),
		sql.Named("outcome", ev.Outcome), sql.Named("fidelity", ev.Fidelity))
	return err == nil, err
}

func getEdgeOrNil(e *GrantEdge, err error) (*GrantEdge, error) {
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return e, err
}

// InsertEdge inserts a grant edge and returns its id. The edge's history span
// opens at e.CreatedAt.
func (tx *TenantTx) InsertEdge(e *GrantEdge) (int64, error) {
	if err := tx.own(e.TenantID); err != nil {
		return 0, err
	}
	id, err := tx.insert(edgesInsert, sql.Named("src", e.Src), sql.Named("dst", e.Dst), sql.Named("relation", e.Relation),
		sql.Named("source", e.Source), sql.Named("expires_at", TP(e.ExpiresAt)), sql.Named("created_at", T(e.CreatedAt)))
	if err != nil {
		return 0, err
	}
	// intent beside the live edge, in the same transaction; none for a connector edge
	if err := tx.recordEdgeIntent(id, e); err != nil {
		return 0, err
	}
	return id, tx.openSpan(id, e.Src, e.Dst, e.Relation, e.Source, e.ExpiresAt, e.CreatedAt)
}

// SetEdgeExpiry sets a grant edge's expiry as of at: the history span with
// the old expiry closes at at and a new one opens with the new expiry, and the
// intent's validity follows.
func (tx *TenantTx) SetEdgeExpiry(id int64, expires, at time.Time) error {
	e, err := getEdgeOrNil(tx.Edge(id))
	if err != nil || e == nil {
		return err
	}
	if _, err := tx.exec(edgesSetExpiry, sql.Named("expires_at", T(expires)), sql.Named("id", id)); err != nil {
		return err
	}
	if _, err := tx.exec(intendedSetExpiry, sql.Named("valid_until", T(expires)), sql.Named("edge_id", id)); err != nil {
		return err
	}
	if err := tx.closeSpan(e.Src, e.Dst, at); err != nil {
		return err
	}
	return tx.openSpan(e.ID, e.Src, e.Dst, e.Relation, e.Source, &expires, at)
}

// DeleteEdge deletes a grant edge by id (and the evaluation it carries); its
// history span and its intent close at at.
func (tx *TenantTx) DeleteEdge(id int64, at time.Time) error {
	return tx.deleteEdge(id, at, CloseRemoved)
}

// deleteEdge removes the edge, its evaluation, closes its history span and its
// intent (why: the close reason).
func (tx *TenantTx) deleteEdge(id int64, at time.Time, why string) error {
	e, err := getEdgeOrNil(tx.Edge(id))
	if err != nil || e == nil {
		return err
	}
	if _, err := tx.exec(edgeEvalDelete, sql.Named("id", id)); err != nil {
		return err
	}
	if _, err := tx.exec(edgesDelete, sql.Named("id", id)); err != nil {
		return err
	}
	if err := tx.closeSpan(e.Src, e.Dst, at); err != nil {
		return err
	}
	return tx.closeEdgeIntent(id, why, at)
}

// RevokeEdge deletes a grant edge and records a tombstone, so a later connector
// sync does not re-create it. Use DeleteEdge for removals that are not decisions.
func (tx *TenantTx) RevokeEdge(id int64, at time.Time, reason string) error {
	e, err := tx.Edge(id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.exec(revokedRecord, sql.Named("src", e.Src), sql.Named("dst", e.Dst), sql.Named("reason", reason),
		sql.Named("at", T(at))); err != nil {
		return err
	}
	return tx.deleteEdge(id, at, reasonOrDefault(reason))
}

func reasonOrDefault(r string) string {
	if r == "" {
		return CloseRemoved
	}
	return r
}

// RevokedGrant is a tombstone left by RevokeEdge.
type RevokedGrant struct {
	TenantID  tenancy.ID
	Src, Dst  string
	Reason    string
	RevokedAt time.Time
}

func scanRevoked(s scanner) (*RevokedGrant, error) {
	var r RevokedGrant
	var tid string
	var at nullTime
	if err := s.Scan(&tid, &r.Src, &r.Dst, &r.Reason, &at); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	r.RevokedAt, err = at.val()
	return &r, err
}

// RevokedGrants returns the revoked-grant tombstones, ordered by src then dst.
func (tx *TenantTx) RevokedGrants() ([]*RevokedGrant, error) {
	return collect(tx, scanRevoked, revokedList)
}

// DeleteJITEdge deletes a grant edge by id if it is a JIT edge; its history
// span and intent close at at.
func (tx *TenantTx) DeleteJITEdge(id int64, at time.Time) error {
	e, err := getEdgeOrNil(tx.Edge(id))
	if err != nil || e == nil || e.Source != "jit" {
		return err
	}
	res, err := tx.exec(edgesDeleteJIT, sql.Named("id", id))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return err
	}
	if err := tx.closeSpan(e.Src, e.Dst, at); err != nil {
		return err
	}
	return tx.closeEdgeIntent(id, CloseJITEnded, at)
}

// DeleteExpiredJITEdges deletes JIT edges that expired at or before now. Their
// history spans close at the edge's own expiry, not at the (later) sweep.
func (tx *TenantTx) DeleteExpiredJITEdges(now time.Time) (int64, error) {
	// close the intent and the history spans first: the statements read the edges the delete removes
	if _, err := tx.exec(intendedCloseExpiredJIT, sql.Named("now", T(now)), sql.Named("at", T(now))); err != nil {
		return 0, err
	}
	if _, err := tx.exec(spansCloseExpired, sql.Named("now", T(now))); err != nil {
		return 0, err
	}
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
