package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Guest access bundles, assurance and catalog populations
// (schema/0362_guest_access.sql, issue #75). Every statement binds @tenant.

// Bundle item statuses.
const (
	BundlePending  = "pending"
	BundleGranted  = "granted"
	BundleRemoving = "removing"
	BundleRemoved  = "removed"
)

// EdgeSourceGuest is the source of the grant edges an access bundle writes.
const EdgeSourceGuest = "guest_sponsorship"

// EdgeSourceRefGroup is the source of the membership edges of the
// system-managed reference groups.
const EdgeSourceRefGroup = "refgroup"

// BundleItem is one catalog item of one sponsorship's access bundle.
type BundleItem struct {
	ID            string
	SponsorshipID string
	GuestID       int64
	GroupID       int64
	System        string
	Status        string
	AccountOpID   *string
	GrantOpID     *string
	RemoveOpID    *string
	EdgeID        *int64
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	GrantedAt     *time.Time
	RemovedAt     *time.Time
}

// BundleItemFilter selects bundle items; zero fields match everything.
type BundleItemFilter struct {
	Sponsorship string
	Guest       int64
	Group       int64
	Status      string
	Edge        int64
}

// Assurance is the identity assurance a person reached.
type Assurance struct {
	TenantID   tenancy.ID
	IdentityID int64
	IAL        int
	AAL        int
	Source     string
	RecordedAt time.Time
}

// CatalogPopulation names a guest population a catalog item is open to.
type CatalogPopulation struct {
	ItemID     string
	Population string
}

const bundleCols = `b.id, b.sponsorship_id, b.guest_identity_id, b.group_id, b.system, b.status, b.account_op_id,
	b.grant_op_id, b.remove_op_id, b.edge_id, b.expires_at, b.created_at, b.updated_at, b.granted_at, b.removed_at`

var (
	bundleInsert = tq("guest_bundle_items.insert", `
		INSERT INTO guest_bundle_items (id, tenant_id, sponsorship_id, guest_identity_id, group_id, system, status,
			account_op_id, grant_op_id, remove_op_id, edge_id, expires_at, created_at, updated_at, granted_at, removed_at)
		VALUES (@id, @tenant, @sponsorship_id, @guest_identity_id, @group_id, @system, @status, @account_op_id,
			@grant_op_id, @remove_op_id, @edge_id, @expires_at, @created_at, @updated_at, @granted_at, @removed_at)`)
	bundleGet = tq("guest_bundle_items.get", `
		SELECT `+bundleCols+` FROM guest_bundle_items b WHERE b.tenant_id = @tenant AND b.id = @id`)
	bundleFiltered = tq("guest_bundle_items.filtered", `
		SELECT `+bundleCols+` FROM guest_bundle_items b WHERE b.tenant_id = @tenant
			AND (@sponsorship = '' OR b.sponsorship_id = @sponsorship)
			AND (@guest = 0 OR b.guest_identity_id = @guest)
			AND (@group = 0 OR b.group_id = @group)
			AND (@status = '' OR b.status = @status)
			AND (@edge = 0 OR b.edge_id = @edge)
		ORDER BY b.created_at, b.id`)
	bundleSave = tq("guest_bundle_items.save", `
		UPDATE guest_bundle_items SET status = @status, account_op_id = @account_op_id, grant_op_id = @grant_op_id,
			remove_op_id = @remove_op_id, edge_id = @edge_id, expires_at = @expires_at, updated_at = @updated_at,
			granted_at = @granted_at, removed_at = @removed_at
		WHERE tenant_id = @tenant AND id = @id AND status <> 'removed'`)

	assuranceGet = tq("identity_assurance.get", `
		SELECT a.tenant_id, a.identity_id, a.ial, a.aal, a.source, a.recorded_at FROM identity_assurance a
		WHERE a.tenant_id = @tenant AND a.identity_id = @identity_id`)
	assuranceList = tq("identity_assurance.list", `
		SELECT a.tenant_id, a.identity_id, a.ial, a.aal, a.source, a.recorded_at FROM identity_assurance a
		WHERE a.tenant_id = @tenant ORDER BY a.identity_id`)
	// a level only goes up
	assurancePut = tq("identity_assurance.put", `
		INSERT INTO identity_assurance (tenant_id, identity_id, ial, aal, source, recorded_at)
		VALUES (@tenant, @identity_id, @ial, @aal, @source, @recorded_at)
		ON CONFLICT (tenant_id, identity_id) DO UPDATE SET
			source = CASE WHEN excluded.ial > identity_assurance.ial THEN excluded.source ELSE identity_assurance.source END,
			recorded_at = CASE WHEN excluded.ial > identity_assurance.ial THEN excluded.recorded_at ELSE identity_assurance.recorded_at END,
			aal = CASE WHEN excluded.aal > identity_assurance.aal THEN excluded.aal ELSE identity_assurance.aal END,
			ial = CASE WHEN excluded.ial > identity_assurance.ial THEN excluded.ial ELSE identity_assurance.ial END`)

	catalogPopsList = tq("catalog_item_populations.list", `
		SELECT p.catalog_item_id, p.population FROM catalog_item_populations p
		WHERE p.tenant_id = @tenant AND (@item = '' OR p.catalog_item_id = @item)
		ORDER BY p.catalog_item_id, p.population`)
	catalogPopsClear = tq("catalog_item_populations.clear", `
		DELETE FROM catalog_item_populations WHERE tenant_id = @tenant AND catalog_item_id = @item`)
	catalogPopsInsert = tq("catalog_item_populations.insert", `
		INSERT INTO catalog_item_populations (tenant_id, catalog_item_id, population) VALUES (@tenant, @item, @population)`)

	edgesBySource = tq("grant_edges.by_source", `
		SELECT `+edgeCols+edgeFrom+`WHERE e.tenant_id = @tenant AND e.source = @source ORDER BY e.id`)
)

func scanBundleItem(s scanner) (*BundleItem, error) {
	var b BundleItem
	var acct, grant, remove sql.NullString
	var edge sql.NullInt64
	var exp, created, updated, granted, removed nullTime
	if err := s.Scan(&b.ID, &b.SponsorshipID, &b.GuestID, &b.GroupID, &b.System, &b.Status, &acct, &grant, &remove, &edge,
		&exp, &created, &updated, &granted, &removed); err != nil {
		return nil, err
	}
	b.AccountOpID, b.GrantOpID, b.RemoveOpID, b.EdgeID = strp(acct), strp(grant), strp(remove), intp(edge)
	var err error
	if b.ExpiresAt, err = exp.val(); err != nil {
		return nil, err
	}
	if b.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if b.UpdatedAt, err = updated.val(); err != nil {
		return nil, err
	}
	if b.GrantedAt, err = granted.ptr(); err != nil {
		return nil, err
	}
	b.RemovedAt, err = removed.ptr()
	return &b, err
}

func scanAssurance(s scanner) (*Assurance, error) {
	var a Assurance
	var tid string
	var at nullTime
	if err := s.Scan(&tid, &a.IdentityID, &a.IAL, &a.AAL, &a.Source, &at); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	a.RecordedAt, err = at.val()
	return &a, err
}

func bundleArgs(b *BundleItem) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", b.ID), sql.Named("status", b.Status), sql.Named("account_op_id", optStr(b.AccountOpID)),
		sql.Named("grant_op_id", optStr(b.GrantOpID)), sql.Named("remove_op_id", optStr(b.RemoveOpID)),
		sql.Named("edge_id", IP(b.EdgeID)), sql.Named("expires_at", T(b.ExpiresAt)), sql.Named("updated_at", T(b.UpdatedAt)),
		sql.Named("granted_at", TP(b.GrantedAt)), sql.Named("removed_at", TP(b.RemovedAt))}
}

// InsertBundleItem records one item of a sponsorship's access bundle.
func (tx *TenantTx) InsertBundleItem(b *BundleItem) error {
	args := append(bundleArgs(b), sql.Named("sponsorship_id", b.SponsorshipID), sql.Named("guest_identity_id", b.GuestID),
		sql.Named("group_id", b.GroupID), sql.Named("system", b.System), sql.Named("created_at", T(b.CreatedAt)))
	_, err := tx.exec(bundleInsert, args...)
	return err
}

// BundleItem returns one item, or ErrNotFound.
func (tx *TenantTx) BundleItem(id string) (*BundleItem, error) {
	return one(tx, scanBundleItem, bundleGet, sql.Named("id", id))
}

// BundleItems returns the items matching f, oldest first.
func (tx *TenantTx) BundleItems(f BundleItemFilter) ([]*BundleItem, error) {
	return collect(tx, scanBundleItem, bundleFiltered, sql.Named("sponsorship", f.Sponsorship), sql.Named("guest", f.Guest),
		sql.Named("group", f.Group), sql.Named("status", f.Status), sql.Named("edge", f.Edge))
}

// SaveBundleItem writes an item's changeable fields; ErrNotFound if it is
// unknown or already removed (a removed item is final).
func (tx *TenantTx) SaveBundleItem(b *BundleItem) error {
	res, err := tx.exec(bundleSave, bundleArgs(b)...)
	return affectedOne(res, err)
}

// IdentityAssurance returns the assurance a person reached, or ErrNotFound.
func (tx *TenantTx) IdentityAssurance(identityID int64) (*Assurance, error) {
	return one(tx, scanAssurance, assuranceGet, sql.Named("identity_id", identityID))
}

// IdentityAssurances returns every recorded assurance.
func (tx *TenantTx) IdentityAssurances() ([]*Assurance, error) {
	return collect(tx, scanAssurance, assuranceList)
}

// PutIdentityAssurance records the assurance a person reached. A level never
// goes down: a lower value than the one on record changes nothing.
func (tx *TenantTx) PutIdentityAssurance(a *Assurance) error {
	_, err := tx.exec(assurancePut, sql.Named("identity_id", a.IdentityID), sql.Named("ial", a.IAL),
		sql.Named("aal", a.AAL), sql.Named("source", a.Source), sql.Named("recorded_at", T(a.RecordedAt)))
	return err
}

// CatalogPopulations lists the guest populations catalog items are open to;
// item "" lists them all.
func (tx *TenantTx) CatalogPopulations(item string) ([]*CatalogPopulation, error) {
	return collect(tx, func(s scanner) (*CatalogPopulation, error) {
		var p CatalogPopulation
		return &p, s.Scan(&p.ItemID, &p.Population)
	}, catalogPopsList, sql.Named("item", item))
}

// SetCatalogPopulations replaces the populations an item is open to.
func (tx *TenantTx) SetCatalogPopulations(item string, populations []string) error {
	if _, err := tx.exec(catalogPopsClear, sql.Named("item", item)); err != nil {
		return err
	}
	for _, p := range populations {
		if _, err := tx.exec(catalogPopsInsert, sql.Named("item", item), sql.Named("population", p)); err != nil {
			return err
		}
	}
	return nil
}

// EdgesBySource returns the grant edges with this source.
func (tx *TenantTx) EdgesBySource(source string) ([]*GrantEdge, error) {
	return collect(tx, scanEdge, edgesBySource, sql.Named("source", source))
}
