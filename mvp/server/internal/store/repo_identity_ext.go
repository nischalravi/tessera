package store

import (
	"database/sql"
	"errors"
	"time"
)

// Guest populations, source records, identifiers and affiliations
// (schema/0226_identity_model.sql). Every statement binds @tenant.

// ErrIdentifierTaken is an identifier (type, issuer, hash) another row already holds.
var ErrIdentifierTaken = errors.New("store: identifier already recorded")

const popCols = `p.key, p.name, p.max_duration_days, p.default_ial, p.default_aal, p.created_at`

const srcCols = `s.id, s.identity_id, s.sor, s.sorid, s.attributes, s.status, s.received_at`

const identCols = `x.id, x.identity_id, x.type, x.issuer, x.value_norm, x.value_hmac, x.verified_at, x.verified_by,
	x.source_record_id, x.status, x.created_at`

const affCols = `a.id, a.identity_id, a.type, a.source, a.source_ref, a.org_unit, a.partner_org_id, a.population,
	a.starts_at, a.ends_at, a.status, a.created_by, a.created_at, a.ended_by, a.end_reason`

var (
	populationsList = tq("guest_populations.list", `
		SELECT `+popCols+` FROM guest_populations p WHERE p.tenant_id = @tenant ORDER BY p.key`)
	populationsGet = tq("guest_populations.get", `
		SELECT `+popCols+` FROM guest_populations p WHERE p.tenant_id = @tenant AND p.key = @key`)
	populationsPut = tq("guest_populations.put", `
		INSERT INTO guest_populations (tenant_id, key, name, max_duration_days, default_ial, default_aal, created_at)
		VALUES (@tenant, @key, @name, @max_duration_days, @default_ial, @default_aal, @created_at)
		ON CONFLICT (tenant_id, key) DO UPDATE SET name = excluded.name, max_duration_days = excluded.max_duration_days,
			default_ial = excluded.default_ial, default_aal = excluded.default_aal`)

	sourceRecordsInsert = tq("identity_source_records.insert", `
		INSERT INTO identity_source_records (id, tenant_id, identity_id, sor, sorid, attributes, status, received_at)
		VALUES (@id, @tenant, @identity_id, @sor, @sorid, @attributes, @status, @received_at)`)
	sourceRecordsList = tq("identity_source_records.list", `
		SELECT `+srcCols+` FROM identity_source_records s WHERE s.tenant_id = @tenant ORDER BY s.sor, s.sorid`)
	sourceRecordsByIdentity = tq("identity_source_records.by_identity", `
		SELECT `+srcCols+` FROM identity_source_records s WHERE s.tenant_id = @tenant AND s.identity_id = @identity_id
		ORDER BY s.sor, s.sorid`)
	sourceRecordsGet = tq("identity_source_records.get", `
		SELECT `+srcCols+` FROM identity_source_records s WHERE s.tenant_id = @tenant AND s.id = @id`)

	identifiersInsert = tq("identity_identifiers.insert", `
		INSERT INTO identity_identifiers (id, tenant_id, identity_id, type, issuer, value_norm, value_hmac, verified_at,
			verified_by, source_record_id, status, created_at)
		VALUES (@id, @tenant, @identity_id, @type, @issuer, @value_norm, @value_hmac, @verified_at, @verified_by,
			@source_record_id, @status, @created_at)`)
	identifiersByIdentity = tq("identity_identifiers.by_identity", `
		SELECT `+identCols+` FROM identity_identifiers x WHERE x.tenant_id = @tenant AND x.identity_id = @identity_id
		ORDER BY x.type, x.issuer, x.created_at, x.id`)
	identifiersList = tq("identity_identifiers.list", `
		SELECT `+identCols+` FROM identity_identifiers x WHERE x.tenant_id = @tenant ORDER BY x.identity_id, x.type, x.id`)
	identifiersByHMAC = tq("identity_identifiers.by_hmac", `
		SELECT `+identCols+` FROM identity_identifiers x WHERE x.tenant_id = @tenant AND x.type = @type
			AND x.issuer = @issuer AND x.value_hmac = @value_hmac`)

	affiliationsInsert = tq("affiliations.insert", `
		INSERT INTO affiliations (id, tenant_id, identity_id, type, source, source_ref, org_unit, partner_org_id,
			population, starts_at, ends_at, status, created_by, created_at)
		VALUES (@id, @tenant, @identity_id, @type, @source, @source_ref, @org_unit, @partner_org_id, @population,
			@starts_at, @ends_at, @status, @created_by, @created_at)`)
	affiliationsList = tq("affiliations.list", `
		SELECT `+affCols+` FROM affiliations a WHERE a.tenant_id = @tenant ORDER BY a.identity_id, a.starts_at, a.id`)
	affiliationsByIdentity = tq("affiliations.by_identity", `
		SELECT `+affCols+` FROM affiliations a WHERE a.tenant_id = @tenant AND a.identity_id = @identity_id
		ORDER BY a.starts_at, a.id`)
	affiliationsGet = tq("affiliations.get", `
		SELECT `+affCols+` FROM affiliations a WHERE a.tenant_id = @tenant AND a.id = @id`)
	affiliationsEnd = tq("affiliations.end", `
		UPDATE affiliations SET status = @status, ends_at = @ends_at, ended_by = @ended_by, end_reason = @end_reason
		WHERE tenant_id = @tenant AND id = @id AND status IN ('pending','active')`)
)

func scanPopulation(s scanner) (*GuestPopulation, error) {
	var p GuestPopulation
	var at nullTime
	if err := s.Scan(&p.Key, &p.Name, &p.MaxDurationDays, &p.DefaultIAL, &p.DefaultAAL, &at); err != nil {
		return nil, err
	}
	var err error
	p.CreatedAt, err = at.val()
	return &p, err
}

func scanSourceRecord(s scanner) (*SourceRecord, error) {
	var r SourceRecord
	var iid sql.NullInt64
	var at nullTime
	if err := s.Scan(&r.ID, &iid, &r.SOR, &r.SORID, &r.Attributes, &r.Status, &at); err != nil {
		return nil, err
	}
	r.IdentityID = intp(iid)
	var err error
	r.ReceivedAt, err = at.val()
	return &r, err
}

func scanIdentifier(s scanner) (*Identifier, error) {
	var x Identifier
	var norm, by, src sql.NullString
	var ver, created nullTime
	if err := s.Scan(&x.ID, &x.IdentityID, &x.Type, &x.Issuer, &norm, &x.ValueHMAC, &ver, &by, &src, &x.Status,
		&created); err != nil {
		return nil, err
	}
	x.ValueNorm, x.VerifiedBy, x.SourceRecordID = strp(norm), strp(by), strp(src)
	var err error
	if x.VerifiedAt, err = ver.ptr(); err != nil {
		return nil, err
	}
	x.CreatedAt, err = created.val()
	return &x, err
}

func scanAffiliation(s scanner) (*Affiliation, error) {
	var a Affiliation
	var ref, unit, partner, pop, by, reason, endedBy sql.NullString
	var starts, ends, created nullTime
	if err := s.Scan(&a.ID, &a.IdentityID, &a.Type, &a.Source, &ref, &unit, &partner, &pop, &starts, &ends, &a.Status,
		&by, &created, &endedBy, &reason); err != nil {
		return nil, err
	}
	a.SourceRef, a.OrgUnit, a.PartnerOrgID, a.Population = strp(ref), strp(unit), strp(partner), strp(pop)
	a.CreatedBy, a.EndedBy, a.EndReason = strp(by), strp(endedBy), strp(reason)
	var err error
	if a.StartsAt, err = starts.val(); err != nil {
		return nil, err
	}
	if a.EndsAt, err = ends.ptr(); err != nil {
		return nil, err
	}
	a.CreatedAt, err = created.val()
	return &a, err
}

// optStr stores an optional string (NULL for nil).
func optStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// GuestPopulations lists the populations by key.
func (tx *TenantTx) GuestPopulations() ([]*GuestPopulation, error) {
	return collect(tx, scanPopulation, populationsList)
}

// GuestPopulation returns one population, or ErrNotFound.
func (tx *TenantTx) GuestPopulation(key string) (*GuestPopulation, error) {
	return one(tx, scanPopulation, populationsGet, sql.Named("key", key))
}

// PutGuestPopulation creates or updates a population's settings.
func (tx *TenantTx) PutGuestPopulation(p *GuestPopulation) error {
	_, err := tx.exec(populationsPut, sql.Named("key", p.Key), sql.Named("name", p.Name),
		sql.Named("max_duration_days", p.MaxDurationDays), sql.Named("default_ial", p.DefaultIAL),
		sql.Named("default_aal", p.DefaultAAL), sql.Named("created_at", T(p.CreatedAt)))
	return err
}

// InsertSourceRecord records what a system of record said. The (sor, sorid)
// pair is unique per tenant.
func (tx *TenantTx) InsertSourceRecord(r *SourceRecord) error {
	_, err := tx.exec(sourceRecordsInsert, sql.Named("id", r.ID), sql.Named("identity_id", IP(r.IdentityID)),
		sql.Named("sor", r.SOR), sql.Named("sorid", r.SORID), sql.Named("attributes", r.Attributes),
		sql.Named("status", r.Status), sql.Named("received_at", T(r.ReceivedAt)))
	return err
}

// SourceRecords lists every source record.
func (tx *TenantTx) SourceRecords() ([]*SourceRecord, error) {
	return collect(tx, scanSourceRecord, sourceRecordsList)
}

// SourceRecordsFor lists the source records attached to a person.
func (tx *TenantTx) SourceRecordsFor(identityID int64) ([]*SourceRecord, error) {
	return collect(tx, scanSourceRecord, sourceRecordsByIdentity, sql.Named("identity_id", identityID))
}

// SourceRecord returns one source record, or ErrNotFound.
func (tx *TenantTx) SourceRecord(id string) (*SourceRecord, error) {
	return one(tx, scanSourceRecord, sourceRecordsGet, sql.Named("id", id))
}

// InsertIdentifier records an identifier; ErrIdentifierTaken if the tenant
// already holds the same (type, issuer, value hash), on any person.
func (tx *TenantTx) InsertIdentifier(x *Identifier) error {
	var ver any
	if x.VerifiedAt != nil {
		ver = T(*x.VerifiedAt)
	}
	_, err := tx.exec(identifiersInsert, sql.Named("id", x.ID), sql.Named("identity_id", x.IdentityID),
		sql.Named("type", x.Type), sql.Named("issuer", x.Issuer), sql.Named("value_norm", optStr(x.ValueNorm)),
		sql.Named("value_hmac", x.ValueHMAC), sql.Named("verified_at", ver), sql.Named("verified_by", optStr(x.VerifiedBy)),
		sql.Named("source_record_id", optStr(x.SourceRecordID)), sql.Named("status", x.Status),
		sql.Named("created_at", T(x.CreatedAt)))
	if isUnique(err) {
		return ErrIdentifierTaken
	}
	return err
}

// IdentifiersFor lists a person's identifiers.
func (tx *TenantTx) IdentifiersFor(identityID int64) ([]*Identifier, error) {
	return collect(tx, scanIdentifier, identifiersByIdentity, sql.Named("identity_id", identityID))
}

// Identifiers lists every identifier.
func (tx *TenantTx) Identifiers() ([]*Identifier, error) {
	return collect(tx, scanIdentifier, identifiersList)
}

// IdentifierByHMAC returns the identifier with this (type, issuer, hash), or ErrNotFound.
func (tx *TenantTx) IdentifierByHMAC(typ, issuer, hmac string) (*Identifier, error) {
	return one(tx, scanIdentifier, identifiersByHMAC, sql.Named("type", typ), sql.Named("issuer", issuer),
		sql.Named("value_hmac", hmac))
}

// InsertAffiliation records a relationship.
func (tx *TenantTx) InsertAffiliation(a *Affiliation) error {
	_, err := tx.exec(affiliationsInsert, sql.Named("id", a.ID), sql.Named("identity_id", a.IdentityID),
		sql.Named("type", a.Type), sql.Named("source", a.Source), sql.Named("source_ref", optStr(a.SourceRef)),
		sql.Named("org_unit", optStr(a.OrgUnit)), sql.Named("partner_org_id", optStr(a.PartnerOrgID)),
		sql.Named("population", optStr(a.Population)), sql.Named("starts_at", T(a.StartsAt)),
		sql.Named("ends_at", TP(a.EndsAt)), sql.Named("status", a.Status), sql.Named("created_by", optStr(a.CreatedBy)),
		sql.Named("created_at", T(a.CreatedAt)))
	return err
}

// Affiliations lists every affiliation, by person then start.
func (tx *TenantTx) Affiliations() ([]*Affiliation, error) {
	return collect(tx, scanAffiliation, affiliationsList)
}

// AffiliationsFor lists a person's affiliations, oldest first.
func (tx *TenantTx) AffiliationsFor(identityID int64) ([]*Affiliation, error) {
	return collect(tx, scanAffiliation, affiliationsByIdentity, sql.Named("identity_id", identityID))
}

// Affiliation returns one affiliation, or ErrNotFound.
func (tx *TenantTx) Affiliation(id string) (*Affiliation, error) {
	return one(tx, scanAffiliation, affiliationsGet, sql.Named("id", id))
}

// EndAffiliation ends a pending or active affiliation at endsAt with status
// ended or revoked; ErrNotFound if it is unknown or already final.
func (tx *TenantTx) EndAffiliation(id, status string, endsAt time.Time, by *string, reason string) error {
	res, err := tx.exec(affiliationsEnd, sql.Named("id", id), sql.Named("status", status),
		sql.Named("ends_at", T(endsAt)), sql.Named("ended_by", optStr(by)), sql.Named("end_reason", reason))
	return affectedOne(res, err)
}
