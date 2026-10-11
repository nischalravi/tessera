package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// SystemTx can touch only the GlobalTables (tenants, platform_keys,
// replay_cache, schema_migrations) plus, from PR5, the two narrow hash
// lookups of design §14.2. It has no access to tenant-owned tables.
type SystemTx struct {
	ctx    context.Context
	tx     *sql.Tx
	reason string
}

func (s *SystemTx) exec(st sstmt, args ...sql.NamedArg) (sql.Result, error) {
	return s.tx.ExecContext(s.ctx, st.sql, namedArgs(args)...)
}

func (s *SystemTx) query(st sstmt, args ...sql.NamedArg) (*sql.Rows, error) {
	return s.tx.QueryContext(s.ctx, st.sql, namedArgs(args)...)
}

func namedArgs(args []sql.NamedArg) []any {
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = a
	}
	return out
}

const tenantCols = `t.id, t.slug, t.name, t.status, t.cell, t.min_admins, t.settings, t.created_at`

var (
	tenantsExists         = sq("tenants.exists", `SELECT count(*) FROM tenants t WHERE t.id = @id`)
	tenantsEnsurePlatform = sq("tenants.ensure_platform", `
		INSERT OR IGNORE INTO tenants (id, slug, name, status, cell, min_admins, created_at)
		VALUES (@id, '_platform', 'Tessera platform', 'active', 'local', 2, @created_at)`)
	tenantsInsert = sq("tenants.insert", `
		INSERT INTO tenants (id, slug, name, status, cell, min_admins, created_at)
		VALUES (@id, @slug, @name, @status, @cell, @min_admins, @created_at)`)
	tenantsList   = sq("tenants.list", `SELECT `+tenantCols+` FROM tenants t ORDER BY t.slug`)
	tenantsActive = sq("tenants.active", `
		SELECT `+tenantCols+` FROM tenants t WHERE t.status = 'active' AND t.slug != '_platform' ORDER BY t.slug`)
	tenantsBySlug      = sq("tenants.by_slug", `SELECT `+tenantCols+` FROM tenants t WHERE t.slug = @slug`)
	tenantsByID        = sq("tenants.by_id", `SELECT `+tenantCols+` FROM tenants t WHERE t.id = @id`)
	tenantsSetSettings = sq("tenants.set_settings", `
		UPDATE tenants SET settings = @settings WHERE id = @id AND slug != '_platform' AND json_valid(@settings)
			AND json_type(@settings) = 'object'`)
)

func scanTenant(s scanner) (Tenant, error) {
	var t Tenant
	var id string
	var created nullTime
	if err := s.Scan(&id, &t.Slug, &t.Name, &t.Status, &t.Cell, &t.MinAdmins, &t.Settings, &created); err != nil {
		return t, err
	}
	var err error
	if t.ID, err = tenancy.Parse(id); err != nil {
		return t, err
	}
	t.CreatedAt, err = created.val()
	return t, err
}

func (s *SystemTx) tenants(st sstmt, args ...sql.NamedArg) (out []Tenant, err error) {
	rows, err := s.query(st, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateTenant inserts a tenant. The slug must be valid and not reserved; a
// zero ID gets a fresh random one. Status defaults to active, Cell to local,
// MinAdmins to 2.
func (s *SystemTx) CreateTenant(t Tenant) (Tenant, error) {
	if !ValidSlug(t.Slug) {
		return t, fmt.Errorf("store: invalid tenant slug %q", t.Slug)
	}
	if t.ID.IsZero() {
		t.ID = tenancy.New()
	}
	if t.ID == tenancy.Platform {
		return t, errors.New("store: the platform tenant id is reserved")
	}
	if t.Status == "" {
		t.Status = "active"
	}
	if t.Cell == "" {
		t.Cell = "local"
	}
	if t.MinAdmins == 0 {
		t.MinAdmins = 2
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = nowUTC()
	}
	_, err := s.exec(tenantsInsert, sql.Named("id", t.ID.String()), sql.Named("slug", t.Slug), sql.Named("name", t.Name),
		sql.Named("status", t.Status), sql.Named("cell", t.Cell), sql.Named("min_admins", t.MinAdmins),
		sql.Named("created_at", T(t.CreatedAt)))
	return t, err
}

// Tenants lists every tenant, including _platform, ordered by slug.
func (s *SystemTx) Tenants() ([]Tenant, error) { return s.tenants(tenantsList) }

// ActiveTenants lists active tenants other than _platform, ordered by slug.
func (s *SystemTx) ActiveTenants() ([]Tenant, error) { return s.tenants(tenantsActive) }

// TenantBySlug returns one tenant (ErrNotFound if missing).
func (s *SystemTx) TenantBySlug(slug string) (Tenant, error) {
	ts, err := s.tenants(tenantsBySlug, sql.Named("slug", slug))
	if err != nil {
		return Tenant{}, err
	}
	if len(ts) == 0 {
		return Tenant{}, ErrNotFound
	}
	return ts[0], nil
}

// TenantByID returns one tenant (ErrNotFound if missing).
// SetTenantSettings replaces a tenant's settings (design §18.3; a JSON
// object). Changing them from the API is an audited admin change (PR12);
// until then only the seed and tests call this.
func (s *SystemTx) SetTenantSettings(id tenancy.ID, settings string) error {
	res, err := s.exec(tenantsSetSettings, sql.Named("id", id.String()), sql.Named("settings", settings))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SystemTx) TenantByID(id tenancy.ID) (Tenant, error) {
	ts, err := s.tenants(tenantsByID, sql.Named("id", id.String()))
	if err != nil {
		return Tenant{}, err
	}
	if len(ts) == 0 {
		return Tenant{}, ErrNotFound
	}
	return ts[0], nil
}

// ---------------------------------------------------------------- replay_cache

var (
	replayPurge  = sq("replay_cache.purge", `DELETE FROM replay_cache WHERE expires_at <= @now`)
	replayInsert = sq("replay_cache.insert", `
		INSERT INTO replay_cache (kind, key_hash, expires_at) VALUES (@kind, @key_hash, @expires_at)`)
)

// Replay kinds.
const (
	ReplaySAMLAssertion = "saml_assertion"
	ReplayCASTicket     = "cas_ticket"
	ReplayDPoPJTI       = "dpop_jti"
)

// UseOnce records that the value with keyHash (SHA-256 hex) of kind was
// used, until expires. It returns ErrDuplicate if it was already used and has
// not expired; expired entries are purged first.
func (s *SystemTx) UseOnce(kind, keyHash string, now, expires time.Time) error {
	if _, err := s.exec(replayPurge, sql.Named("now", RT(now))); err != nil {
		return err
	}
	_, err := s.exec(replayInsert, sql.Named("kind", kind), sql.Named("key_hash", keyHash),
		sql.Named("expires_at", RT(expires)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}
