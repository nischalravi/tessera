package store

import (
	"database/sql"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Identity is a person, service account or AI agent.
type Identity struct {
	ID           int64
	TenantID     tenancy.ID
	ExternalID   string
	Name         string
	Email        *string
	Type         string
	Department   *string
	Title        *string
	Status       string
	ManagerID    *int64
	OwnerID      *int64
	Source       *string
	Description  *string
	HiredAt      *time.Time
	TerminatedAt *time.Time
	CreatedAt    time.Time
}

const identityCols = `i.id, i.tenant_id, i.external_id, i.name, i.email, i.type, i.department, i.title, i.status,
	i.manager_id, i.owner_id, i.source, i.description, i.hired_at, i.terminated_at, i.created_at`

var (
	identitiesList = tq("identities.list", `
		SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant ORDER BY i.id`)
	identitiesGet = tq("identities.get", `
		SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant AND i.id = @id`)
	identitiesByXID = tq("identities.by_external_id", `
		SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant AND i.external_id = @external_id`)
	// An empty @email or @external_id matches nothing. lower() is SQLite's (ASCII).
	identitiesActiveMatch = tq("identities.active_match", `
		SELECT `+identityCols+` FROM identities i
		WHERE i.tenant_id = @tenant AND i.status = 'active'
			AND ((@email <> '' AND lower(trim(i.email)) = lower(@email))
				OR (@external_id <> '' AND i.external_id = @external_id))
		ORDER BY i.id LIMIT 1`)
	identitiesOwnedBy = tq("identities.owned_by", `
		SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant AND i.owner_id = @owner_id ORDER BY i.id`)
	identitiesManagedBy = tq("identities.managed_by", `
		SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant AND i.manager_id = @manager_id ORDER BY i.id`)
	identitiesUpsert = tq("identities.upsert", `
		INSERT INTO identities (tenant_id, external_id, name, email, type, department, title, status, description,
			hired_at, terminated_at, created_at)
		VALUES (@tenant, @external_id, @name, @email, @type, @department, @title, @status, @description,
			@hired_at, @terminated_at, @created_at)
		ON CONFLICT (tenant_id, external_id) DO UPDATE SET name = excluded.name, email = excluded.email,
			type = excluded.type, department = excluded.department, title = excluded.title,
			-- Tessera-side decisions win over the connector: a merged identity stays merged
			-- until unmerged (repo_correlation.go), a terminated one stays terminated (UAT #134),
			-- and a disabled one stays disabled until Enable (repo_identity_disables.go)
			status = CASE WHEN identities.status IN ('merged', 'terminated', 'disabled') THEN identities.status ELSE excluded.status END,
			description = excluded.description, hired_at = excluded.hired_at,
			terminated_at = CASE WHEN identities.status = 'terminated' THEN identities.terminated_at ELSE excluded.terminated_at END`)
	identitiesInsert = tq("identities.insert", `
		INSERT INTO identities (tenant_id, external_id, name, email, type, department, title, status, manager_id,
			owner_id, source, description, hired_at, terminated_at, created_at)
		VALUES (@tenant, @external_id, @name, @email, @type, @department, @title, @status, @manager_id,
			@owner_id, @source, @description, @hired_at, @terminated_at, @created_at)`)
	identitiesSetRefsByXID = tq("identities.set_manager_owner_by_external_id", `
		UPDATE identities SET manager_id = @manager_id,
			owner_id = CASE WHEN EXISTS (SELECT 1 FROM ownerships o WHERE o.tenant_id = @tenant
				AND o.object_kind = 'identity' AND o.object_key = CAST(identities.id AS TEXT)) THEN owner_id ELSE @owner_id END
		WHERE identities.tenant_id = @tenant AND identities.external_id = @external_id`)
	identitiesSetOwner = tq("identities.set_owner", `
		UPDATE identities SET owner_id = @owner_id WHERE tenant_id = @tenant AND id = @id`)
	identitiesSetManager = tq("identities.set_manager", `
		UPDATE identities SET manager_id = @manager_id WHERE tenant_id = @tenant AND id = @id`)
	identitiesTerminate = tq("identities.terminate", `
		UPDATE identities SET status = 'terminated', terminated_at = @at WHERE tenant_id = @tenant AND id = @id`)
	identitiesSetDeptTitle = tq("identities.set_department_title", `
		UPDATE identities SET department = @department, title = @title WHERE tenant_id = @tenant AND id = @id`)
)

func scanIdentity(s scanner) (*Identity, error) {
	var i Identity
	var tid string
	var email, dept, title, source, desc sql.NullString
	var mgr, owner sql.NullInt64
	var hired, term, created nullTime
	if err := s.Scan(&i.ID, &tid, &i.ExternalID, &i.Name, &email, &i.Type, &dept, &title, &i.Status, &mgr, &owner,
		&source, &desc, &hired, &term, &created); err != nil {
		return nil, err
	}
	var err error
	if i.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	i.Email, i.Department, i.Title, i.Source, i.Description = strp(email), strp(dept), strp(title), strp(source), strp(desc)
	i.ManagerID, i.OwnerID = intp(mgr), intp(owner)
	if i.HiredAt, err = hired.ptr(); err != nil {
		return nil, err
	}
	if i.TerminatedAt, err = term.ptr(); err != nil {
		return nil, err
	}
	i.CreatedAt, err = created.val()
	return &i, err
}

// Identities returns every identity, in id order.
func (tx *TenantTx) Identities() ([]*Identity, error) {
	return collect(tx, scanIdentity, identitiesList)
}

// Identity returns one identity by id (ErrNotFound if missing or another tenant's).
func (tx *TenantTx) Identity(id int64) (*Identity, error) {
	return one(tx, scanIdentity, identitiesGet, sql.Named("id", id))
}

// IdentityByExternalID returns one identity by external id.
func (tx *TenantTx) IdentityByExternalID(xid string) (*Identity, error) {
	return one(tx, scanIdentity, identitiesByXID, sql.Named("external_id", xid))
}

// ActiveIdentityMatching returns the lowest-id active identity whose email
// equals email (case-insensitive, trimmed) or whose external (HR) id equals
// externalID; an empty argument matches nothing. ErrNotFound if none. Called
// in the write transaction that then inserts, it is the joiner uniqueness
// guard: writes are serialized, so no second insert can slip between the two.
func (tx *TenantTx) ActiveIdentityMatching(email, externalID string) (*Identity, error) {
	return one(tx, scanIdentity, identitiesActiveMatch, sql.Named("email", strings.TrimSpace(email)),
		sql.Named("external_id", strings.TrimSpace(externalID)))
}

// IdentitiesOwnedBy returns the identities whose owner is ownerID, in id order.
func (tx *TenantTx) IdentitiesOwnedBy(ownerID int64) ([]*Identity, error) {
	return collect(tx, scanIdentity, identitiesOwnedBy, sql.Named("owner_id", ownerID))
}

// IdentitiesManagedBy returns the identities whose manager is managerID, in id order.
func (tx *TenantTx) IdentitiesManagedBy(managerID int64) ([]*Identity, error) {
	return collect(tx, scanIdentity, identitiesManagedBy, sql.Named("manager_id", managerID))
}

// IdentityMap returns all identities keyed by id plus the id order.
func (tx *TenantTx) IdentityMap() (map[int64]*Identity, []*Identity, error) {
	all, err := tx.Identities()
	if err != nil {
		return nil, nil, err
	}
	m := make(map[int64]*Identity, len(all))
	for _, i := range all {
		m[i.ID] = i
	}
	return m, all, nil
}

// UpsertIdentity inserts an identity or updates the connector-owned fields of
// the one with the same external id (manager, owner and source are kept).
func (tx *TenantTx) UpsertIdentity(i *Identity) error {
	if err := tx.own(i.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(identitiesUpsert, sql.Named("external_id", i.ExternalID), sql.Named("name", i.Name),
		sql.Named("email", SP(i.Email)), sql.Named("type", i.Type), sql.Named("department", SP(i.Department)),
		sql.Named("title", SP(i.Title)), sql.Named("status", i.Status), sql.Named("description", SP(i.Description)),
		sql.Named("hired_at", TP(i.HiredAt)), sql.Named("terminated_at", TP(i.TerminatedAt)),
		sql.Named("created_at", T(i.CreatedAt)))
	return err
}

// InsertIdentity inserts a new identity and returns its id.
func (tx *TenantTx) InsertIdentity(i *Identity) (int64, error) {
	if err := tx.own(i.TenantID); err != nil {
		return 0, err
	}
	return tx.insert(identitiesInsert, sql.Named("external_id", i.ExternalID), sql.Named("name", i.Name),
		sql.Named("email", SP(i.Email)), sql.Named("type", i.Type), sql.Named("department", SP(i.Department)),
		sql.Named("title", SP(i.Title)), sql.Named("status", i.Status), sql.Named("manager_id", IP(i.ManagerID)),
		sql.Named("owner_id", IP(i.OwnerID)), sql.Named("source", SP(i.Source)),
		sql.Named("description", SP(i.Description)), sql.Named("hired_at", TP(i.HiredAt)),
		sql.Named("terminated_at", TP(i.TerminatedAt)), sql.Named("created_at", T(i.CreatedAt)))
}

// SetIdentityRefsByExternalID sets manager and owner of the identity with the external id.
// An owner set in Tessera (an ownerships row, #167) is kept.
func (tx *TenantTx) SetIdentityRefsByExternalID(xid string, managerID, ownerID *int64) error {
	_, err := tx.exec(identitiesSetRefsByXID, sql.Named("manager_id", IP(managerID)), sql.Named("owner_id", IP(ownerID)),
		sql.Named("external_id", xid))
	return err
}

// SetIdentityOwner sets (or clears, for nil) an identity's owner.
func (tx *TenantTx) SetIdentityOwner(id int64, ownerID *int64) error {
	_, err := tx.exec(identitiesSetOwner, sql.Named("owner_id", IP(ownerID)), sql.Named("id", id))
	return err
}

// SetIdentityManager sets (or clears, for nil) an identity's manager.
func (tx *TenantTx) SetIdentityManager(id int64, managerID *int64) error {
	_, err := tx.exec(identitiesSetManager, sql.Named("manager_id", IP(managerID)), sql.Named("id", id))
	return err
}

// TerminateIdentity marks an identity terminated at.
func (tx *TenantTx) TerminateIdentity(id int64, at time.Time) error {
	_, err := tx.exec(identitiesTerminate, sql.Named("at", T(at)), sql.Named("id", id))
	return err
}

// SetIdentityDepartmentTitle sets department and title (nil stores NULL).
func (tx *TenantTx) SetIdentityDepartmentTitle(id int64, department, title *string) error {
	_, err := tx.exec(identitiesSetDeptTitle, sql.Named("department", SP(department)), sql.Named("title", SP(title)),
		sql.Named("id", id))
	return err
}
