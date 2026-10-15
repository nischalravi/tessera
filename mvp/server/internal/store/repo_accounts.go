package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Account is an account in one system.
type Account struct {
	ID          int64
	TenantID    tenancy.ID
	System      string
	ExternalID  string
	IdentityID  *int64
	Username    string
	Kind        string
	Status      string
	CreatedAt   *time.Time
	LastLoginAt *time.Time
}

const accountCols = `a.id, a.tenant_id, a.system, a.external_id, a.identity_id, a.username, a.kind, a.status,
	a.created_at, a.last_login_at`

var (
	accountsList = tq("accounts.list", `
		SELECT `+accountCols+` FROM accounts a WHERE a.tenant_id = @tenant ORDER BY a.id`)
	accountsSorted = tq("accounts.list_by_system_username", `
		SELECT `+accountCols+` FROM accounts a WHERE a.tenant_id = @tenant ORDER BY a.system, a.username, a.id`)
	accountsSortedSystem = tq("accounts.list_by_system_username_in_system", `
		SELECT `+accountCols+` FROM accounts a WHERE a.tenant_id = @tenant AND a.system = @system
		ORDER BY a.system, a.username, a.id`)
	accountsGet = tq("accounts.get", `
		SELECT `+accountCols+` FROM accounts a WHERE a.tenant_id = @tenant AND a.id = @id`)
	accountsByXID = tq("accounts.by_xid", `
		SELECT `+accountCols+` FROM accounts a WHERE a.tenant_id = @tenant AND a.system = @system AND a.external_id = @external_id`)
	accountsByIdentity = tq("accounts.by_identity", `
		SELECT `+accountCols+` FROM accounts a WHERE a.tenant_id = @tenant AND a.identity_id = @identity_id ORDER BY a.id`)
	accountsUpsert = tq("accounts.upsert", `
		INSERT INTO accounts (tenant_id, system, external_id, username, identity_id, kind, status, created_at, last_login_at)
		VALUES (@tenant, @system, @external_id, @username, @identity_id, @kind, @status, @created_at, @last_login_at)
		ON CONFLICT (tenant_id, system, external_id) DO UPDATE SET username = excluded.username,
			identity_id = excluded.identity_id, kind = excluded.kind,
			status = CASE WHEN accounts.status = 'disabled' THEN accounts.status ELSE excluded.status END, -- a disable decision sticks
			created_at = excluded.created_at, last_login_at = excluded.last_login_at`)
	accountsInsert = tq("accounts.insert", `
		INSERT INTO accounts (tenant_id, system, external_id, identity_id, username, kind, status, created_at, last_login_at)
		VALUES (@tenant, @system, @external_id, @identity_id, @username, @kind, @status, @created_at, @last_login_at)`)
	accountsDisable = tq("accounts.disable", `
		UPDATE accounts SET status = 'disabled' WHERE tenant_id = @tenant AND id = @id`)
	accountsCount = tq("accounts.count", `
		SELECT count(a.id) FROM accounts a WHERE a.tenant_id = @tenant`)
	accountsCountSystems = tq("accounts.count_systems", `
		SELECT count(DISTINCT a.system) FROM accounts a WHERE a.tenant_id = @tenant`)
	accountsCountInSystem = tq("accounts.count_in_system", `
		SELECT count(a.id) FROM accounts a WHERE a.tenant_id = @tenant AND a.system = @system`)
)

func scanAccount(s scanner) (*Account, error) {
	var a Account
	var tid string
	var iid sql.NullInt64
	var created, last nullTime
	if err := s.Scan(&a.ID, &tid, &a.System, &a.ExternalID, &iid, &a.Username, &a.Kind, &a.Status, &created, &last); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	a.IdentityID = intp(iid)
	if a.CreatedAt, err = created.ptr(); err != nil {
		return nil, err
	}
	a.LastLoginAt, err = last.ptr()
	return &a, err
}

// Accounts returns every account, in id order.
func (tx *TenantTx) Accounts() ([]*Account, error) { return collect(tx, scanAccount, accountsList) }

// AccountsBySystemUsername returns accounts ordered by system then username,
// optionally only those in one system.
func (tx *TenantTx) AccountsBySystemUsername(system *string) ([]*Account, error) {
	if system != nil {
		return collect(tx, scanAccount, accountsSortedSystem, sql.Named("system", *system))
	}
	return collect(tx, scanAccount, accountsSorted)
}

// Account returns one account by id.
func (tx *TenantTx) Account(id int64) (*Account, error) {
	return one(tx, scanAccount, accountsGet, sql.Named("id", id))
}

// AccountByXID returns the account with the system and external id, or ErrNotFound.
func (tx *TenantTx) AccountByXID(system, externalID string) (*Account, error) {
	return one(tx, scanAccount, accountsByXID, sql.Named("system", system), sql.Named("external_id", externalID))
}

// IdentityAccounts returns an identity's accounts in id order.
func (tx *TenantTx) IdentityAccounts(identityID int64) ([]*Account, error) {
	return collect(tx, scanAccount, accountsByIdentity, sql.Named("identity_id", identityID))
}

// UpsertAccount inserts an account or updates the one with the same system and external id.
func (tx *TenantTx) UpsertAccount(a *Account) error {
	if err := tx.own(a.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(accountsUpsert, sql.Named("system", a.System), sql.Named("external_id", a.ExternalID),
		sql.Named("username", a.Username), sql.Named("identity_id", IP(a.IdentityID)), sql.Named("kind", a.Kind),
		sql.Named("status", a.Status), sql.Named("created_at", TP(a.CreatedAt)), sql.Named("last_login_at", TP(a.LastLoginAt)))
	return err
}

// InsertAccount inserts a new account and returns its id.
func (tx *TenantTx) InsertAccount(a *Account) (int64, error) {
	if err := tx.own(a.TenantID); err != nil {
		return 0, err
	}
	return tx.insert(accountsInsert, sql.Named("system", a.System), sql.Named("external_id", a.ExternalID),
		sql.Named("identity_id", IP(a.IdentityID)), sql.Named("username", a.Username), sql.Named("kind", a.Kind),
		sql.Named("status", a.Status), sql.Named("created_at", TP(a.CreatedAt)), sql.Named("last_login_at", TP(a.LastLoginAt)))
}

// DisableAccount sets an account's status to disabled.
func (tx *TenantTx) DisableAccount(id int64) error {
	_, err := tx.exec(accountsDisable, sql.Named("id", id))
	return err
}

// CountAccounts counts accounts.
func (tx *TenantTx) CountAccounts() (int, error) { return tx.count(accountsCount) }

// CountAccountSystems counts the distinct systems with accounts.
func (tx *TenantTx) CountAccountSystems() (int, error) { return tx.count(accountsCountSystems) }

// SystemCounts is the number of objects one connector system contributed.
type SystemCounts struct{ Accounts, Groups, Resources, Permissions int }

// CountSystem counts accounts, groups, resources and permissions in a system.
func (tx *TenantTx) CountSystem(system string) (SystemCounts, error) {
	var c SystemCounts
	for _, x := range []struct {
		s   tstmt
		dst *int
	}{{accountsCountInSystem, &c.Accounts}, {groupsCountInSystem, &c.Groups},
		{resourcesCountInSystem, &c.Resources}, {permissionsCountInSystem, &c.Permissions}} {
		n, err := tx.count(x.s, sql.Named("system", system))
		if err != nil {
			return c, err
		}
		*x.dst = n
	}
	return c, nil
}
