package store

import (
	"database/sql"
	"errors"
	"time"
)

// Statements of the groups REST API (issue #48, GR-5; schema/0376_groups_api.sql
// for the idempotency table). Searching and paging members and identities'
// groups, the point-in-time groups of an identity, the idempotency keys and the
// savepoint a simulation rolls back to. The rules live in internal/groups/api
// and internal/api; all of it is bound to the transaction's tenant.

// Idempotency is the stored answer of a write made with an Idempotency-Key.
type Idempotency struct {
	Principal   string
	Key         string
	RequestHash string
	Status      int
	Body        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// MemberSearch narrows and orders a members listing. Q is a case-insensitive
// substring of the member's name (and, for an identity, its email); Sort is
// name, -name, since or -since (empty: by id).
type MemberSearch struct {
	Group GroupID
	List  ListID
	Q     string
	Sort  string
	// Indirect keeps the effective members that have no active direct identity
	// row of their own in the group (they arrive through nesting or factors).
	Indirect bool
	// Enabled is "true" or "false" to keep the direct rows that count (or do
	// not) at Now, "" for all.
	Enabled string
	Now     time.Time
	Limit   int
	Offset  int
}

var (
	grpIdemGet = tq("grp_idempotency.get", `SELECT x.principal, x.idem_key, x.request_hash, x.status, x.body, x.created_at, x.expires_at
		FROM grp_idempotency x WHERE x.tenant_id = @tenant AND x.principal = @principal AND x.idem_key = @idem_key`)
	grpIdemInsert = tq("grp_idempotency.insert", `
		INSERT INTO grp_idempotency (tenant_id, principal, idem_key, request_hash, status, body, created_at, expires_at)
		VALUES (@tenant, @principal, @idem_key, @request_hash, @status, @body, @created_at, @expires_at)`)
	grpIdemPurge = tq("grp_idempotency.purge", `DELETE FROM grp_idempotency WHERE tenant_id = @tenant AND expires_at <= @now`)
	grpIdemCount = tq("grp_idempotency.count", `SELECT count(*) FROM grp_idempotency x WHERE x.tenant_id = @tenant`)

	// effective members, searched by name or email and ordered; an indirect member has no active direct identity row
	grpEffSearch = tq("grp_eff.search", `SELECT e.identity_id, e.support, e.since FROM grp_effective e
		JOIN identities i ON i.tenant_id = @tenant AND i.id = e.identity_id
		WHERE e.tenant_id = @tenant AND e.group_id = @group_id AND e.list_id = @list_id
		  AND (@q = '' OR instr(lower(i.name), lower(@q)) > 0 OR instr(lower(COALESCE(i.email, '')), lower(@q)) > 0)
		  AND (@indirect = 0 OR NOT EXISTS (SELECT 1 FROM grp_direct_memberships d
			WHERE d.tenant_id = @tenant AND d.group_id = e.group_id AND d.list_id = e.list_id AND d.member_type = 'identity'
			  AND d.member_identity_id = e.identity_id AND `+dmActive+`))
		ORDER BY CASE WHEN @sort = 'name' THEN lower(i.name) END, CASE WHEN @sort = '-name' THEN lower(i.name) END DESC,
			CASE WHEN @sort = 'since' THEN e.since END, CASE WHEN @sort = '-since' THEN e.since END DESC, e.identity_id
		LIMIT @limit OFFSET @offset`)
	grpEffSearchCount = tq("grp_eff.search_count", `SELECT count(*) FROM grp_effective e
		JOIN identities i ON i.tenant_id = @tenant AND i.id = e.identity_id
		WHERE e.tenant_id = @tenant AND e.group_id = @group_id AND e.list_id = @list_id
		  AND (@q = '' OR instr(lower(i.name), lower(@q)) > 0 OR instr(lower(COALESCE(i.email, '')), lower(@q)) > 0)
		  AND (@indirect = 0 OR NOT EXISTS (SELECT 1 FROM grp_direct_memberships d
			WHERE d.tenant_id = @tenant AND d.group_id = e.group_id AND d.list_id = e.list_id AND d.member_type = 'identity'
			  AND d.member_identity_id = e.identity_id AND `+dmActive+`))`)

	// direct rows, searched by the member's name and filtered by whether they count now
	grpDmSearch = tq("grp_dm.search", `SELECT `+dmCols+` FROM grp_direct_memberships d
		LEFT JOIN identities i ON i.tenant_id = @tenant AND i.id = d.member_identity_id
		LEFT JOIN grp_groups g ON g.tenant_id = @tenant AND g.id = d.member_group_id
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND (@list_id = '' OR d.list_id = @list_id)
		  AND (@enabled = '' OR (CASE WHEN `+dmActive+` THEN 'true' ELSE 'false' END) = @enabled)
		  AND (@q = '' OR instr(lower(COALESCE(i.name, g.name, '')), lower(@q)) > 0)
		ORDER BY CASE WHEN @sort = 'name' THEN lower(COALESCE(i.name, g.name, '')) END,
			CASE WHEN @sort = '-name' THEN lower(COALESCE(i.name, g.name, '')) END DESC,
			CASE WHEN @sort = 'since' THEN d.created_at END, CASE WHEN @sort = '-since' THEN d.created_at END DESC,
			d.created_at, d.id
		LIMIT @limit OFFSET @offset`)
	grpDmSearchCount = tq("grp_dm.search_count", `SELECT count(*) FROM grp_direct_memberships d
		LEFT JOIN identities i ON i.tenant_id = @tenant AND i.id = d.member_identity_id
		LEFT JOIN grp_groups g ON g.tenant_id = @tenant AND g.id = d.member_group_id
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND (@list_id = '' OR d.list_id = @list_id)
		  AND (@enabled = '' OR (CASE WHEN `+dmActive+` THEN 'true' ELSE 'false' END) = @enabled)
		  AND (@q = '' OR instr(lower(COALESCE(i.name, g.name, '')), lower(@q)) > 0)`)

	// the groups an identity is an effective member of, by name; filter is effective, direct or indirect
	grpGroupsOfIdentity = tq("grp_groups.of_identity", `SELECT `+grpGroupCols+` FROM grp_effective e
		JOIN grp_groups g ON g.tenant_id = @tenant AND g.id = e.group_id
		WHERE e.tenant_id = @tenant AND e.identity_id = @identity AND e.list_id = @list_id
		  AND (@filter <> 'direct' OR EXISTS (SELECT 1 FROM grp_direct_memberships d
			WHERE d.tenant_id = @tenant AND d.group_id = e.group_id AND d.list_id = e.list_id AND d.member_type = 'identity'
			  AND d.member_identity_id = e.identity_id AND `+dmActive+`))
		  AND (@filter <> 'indirect' OR NOT EXISTS (SELECT 1 FROM grp_direct_memberships d
			WHERE d.tenant_id = @tenant AND d.group_id = e.group_id AND d.list_id = e.list_id AND d.member_type = 'identity'
			  AND d.member_identity_id = e.identity_id AND `+dmActive+`))
		ORDER BY lower(g.name), g.id LIMIT @limit OFFSET @offset`)

	// the groups an identity was a member of at an instant (grp_pit_eff_identity)
	pitEffOfIdentity = tq("grp_pit_effective.of_identity", `SELECT `+pitEffCols+` FROM grp_pit_effective p
		WHERE p.tenant_id = @tenant AND p.identity_id = @identity AND p.list_id = @list_id
		  AND p.start_at <= @at AND (p.end_at IS NULL OR p.end_at > @at)
		ORDER BY p.group_id, p.start_seq LIMIT @limit OFFSET @offset`)
	pitEffOfIdentityCount = tq("grp_pit_effective.of_identity_count", `SELECT count(*) FROM grp_pit_effective p
		WHERE p.tenant_id = @tenant AND p.identity_id = @identity AND p.list_id = @list_id
		  AND p.start_at <= @at AND (p.end_at IS NULL OR p.end_at > @at)`)

	// identities by page, for the read-only SCIM server
	identitiesPage = tq("identities.page", `SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant
		ORDER BY i.id LIMIT @limit OFFSET @offset`)
	identitiesCount = tq("identities.count", `SELECT count(*) FROM identities i WHERE i.tenant_id = @tenant`)
)

func scanIdempotency(s scanner) (*Idempotency, error) {
	var x Idempotency
	var created, expires string
	if err := s.Scan(&x.Principal, &x.Key, &x.RequestHash, &x.Status, &x.Body, &created, &expires); err != nil {
		return nil, err
	}
	var err error
	if x.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	x.ExpiresAt, err = ParseRT(expires)
	return &x, err
}

// GrpIdempotency returns the stored answer of a principal's key, or ErrNotFound.
// An expired row is still returned: the caller compares ExpiresAt, or purges first.
func (tx *TenantTx) GrpIdempotency(principal, key string) (*Idempotency, error) {
	return one(tx, scanIdempotency, grpIdemGet, sql.Named("principal", principal), sql.Named("idem_key", key))
}

// InsertGrpIdempotency stores the answer of a keyed write. A key used twice by
// the same principal is a primary-key error.
func (tx *TenantTx) InsertGrpIdempotency(x *Idempotency) error {
	_, err := tx.exec(grpIdemInsert, sql.Named("principal", x.Principal), sql.Named("idem_key", x.Key),
		sql.Named("request_hash", x.RequestHash), sql.Named("status", x.Status), sql.Named("body", x.Body),
		sql.Named("created_at", RT(x.CreatedAt)), sql.Named("expires_at", RT(x.ExpiresAt)))
	return err
}

// PurgeGrpIdempotency deletes the tenant's expired keys and returns how many.
func (tx *TenantTx) PurgeGrpIdempotency(now time.Time) (int64, error) {
	res, err := tx.exec(grpIdemPurge, sql.Named("now", RT(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GrpIdempotencyCount counts the tenant's stored keys.
func (tx *TenantTx) GrpIdempotencyCount() (int, error) { return tx.count(grpIdemCount) }

func searchArgs(f MemberSearch) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("group_id", string(f.Group)), sql.Named("list_id", string(f.List)), sql.Named("q", f.Q),
		sql.Named("indirect", B(f.Indirect)), sql.Named("enabled", f.Enabled), sql.Named("now", RT(f.Now))}
}

// GrpEffectiveSearch pages a group's effective members that match the search
// (Q, Indirect, Sort) and counts all of them.
func (tx *TenantTx) GrpEffectiveSearch(f MemberSearch) ([]GrpEffectiveRow, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	args := searchArgs(f)
	// the effective statements do not take the enabled filter
	eff := make([]sql.NamedArg, 0, len(args)+3)
	for _, a := range args {
		if a.Name != "enabled" {
			eff = append(eff, a)
		}
	}
	rows, err := tx.query(grpEffSearch, append(eff, sql.Named("sort", f.Sort), sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []GrpEffectiveRow
	for rows.Next() {
		var r GrpEffectiveRow
		var since string
		if err := rows.Scan(&r.Identity, &r.Support, &since); err != nil {
			return nil, 0, err
		}
		if r.Since, err = ParseRT(since); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	n, err := tx.count(grpEffSearchCount, eff...)
	return out, n, err
}

// GrpDirectSearch pages a group's direct rows that match the search (Q,
// Enabled at Now, Sort) and counts all of them.
func (tx *TenantTx) GrpDirectSearch(f MemberSearch) ([]*DirectMembership, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	dm := []sql.NamedArg{sql.Named("group_id", string(f.Group)), sql.Named("list_id", string(f.List)), sql.Named("q", f.Q),
		sql.Named("enabled", f.Enabled), sql.Named("now", RT(f.Now))}
	rows, err := collect(tx, scanGrpDirect, grpDmSearch, append(dm, sql.Named("sort", f.Sort), sql.Named("limit", f.Limit),
		sql.Named("offset", f.Offset))...)
	if err != nil {
		return nil, 0, err
	}
	n, err := tx.count(grpDmSearchCount, dm...)
	return rows, n, err
}

// GrpGroupsOfIdentity pages the groups an identity is an effective member of in
// a list, by name. filter is "effective" (all), "direct" (the identity has an
// active direct row) or "indirect" (it has none: it arrives through nesting or
// a composite). Deleted groups have no effective rows.
func (tx *TenantTx) GrpGroupsOfIdentity(identity int64, list ListID, filter string, now time.Time, limit, offset int) ([]*NativeGroup, error) {
	if limit <= 0 {
		limit = 100
	}
	return collect(tx, scanGrpGroup, grpGroupsOfIdentity, sql.Named("identity", identity), sql.Named("list_id", string(list)),
		sql.Named("filter", filter), sql.Named("now", RT(now)), sql.Named("limit", limit), sql.Named("offset", offset))
}

// GrpPitGroupsOfIdentity pages the effective-membership intervals of an
// identity that were open at an instant, by group, and counts them.
func (tx *TenantTx) GrpPitGroupsOfIdentity(identity int64, list ListID, at time.Time, limit, offset int) ([]*PitEffective, int, error) {
	args := []sql.NamedArg{sql.Named("identity", identity), sql.Named("list_id", string(list)), sql.Named("at", RT(at))}
	rows, err := collect(tx, scanPitEffective, pitEffOfIdentity, append(args, sql.Named("limit", limit), sql.Named("offset", offset))...)
	if err != nil {
		return nil, 0, err
	}
	n, err := tx.count(pitEffOfIdentityCount, args...)
	return rows, n, err
}

// IdentitiesPage pages the tenant's identities in id order.
func (tx *TenantTx) IdentitiesPage(limit, offset int) ([]*Identity, error) {
	return collect(tx, scanIdentity, identitiesPage, sql.Named("limit", limit), sql.Named("offset", offset))
}

// IdentityCount counts the tenant's identities.
func (tx *TenantTx) IdentityCount() (int, error) { return tx.count(identitiesCount) }

// ---------------------------------------------------------------- savepoints

// Savepoint is a point inside the transaction that its changes can be rolled
// back to without ending it: a batch that is not atomic undoes one failed
// operation, and a simulation undoes everything it tried. The audit events
// appended since are undone with the rest and are not counted as committed.
type Savepoint struct {
	tx       *TenantTx
	appended int64
	done     bool
}

// ErrSavepointDone is returned when a Savepoint is used after Release or Rollback.
var ErrSavepointDone = errors.New("store: savepoint already released")

const (
	spOpen     = "SAVEPOINT tessera_sp"
	spRelease  = "RELEASE SAVEPOINT tessera_sp"
	spRollback = "ROLLBACK TO SAVEPOINT tessera_sp"
)

// Savepoint opens a savepoint in a write transaction (ErrReadOnly otherwise).
// Savepoints nest: Release or Rollback closes the most recent one.
func (tx *TenantTx) Savepoint() (*Savepoint, error) {
	if tx.readOnly {
		return nil, ErrReadOnly
	}
	if _, err := tx.tx.ExecContext(tx.ctx, spOpen); err != nil {
		return nil, err
	}
	return &Savepoint{tx: tx, appended: tx.appended}, nil
}

// Release keeps the changes made since the savepoint.
func (s *Savepoint) Release() error {
	if s.done {
		return ErrSavepointDone
	}
	s.done = true
	_, err := s.tx.tx.ExecContext(s.tx.ctx, spRelease)
	return err
}

// Rollback undoes every change made since the savepoint and closes it.
func (s *Savepoint) Rollback() error {
	if s.done {
		return ErrSavepointDone
	}
	s.done = true
	if _, err := s.tx.tx.ExecContext(s.tx.ctx, spRollback); err != nil {
		return err
	}
	s.tx.appended = s.appended
	_, err := s.tx.tx.ExecContext(s.tx.ctx, spRelease)
	return err
}
