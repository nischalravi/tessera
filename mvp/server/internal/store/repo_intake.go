package store

import (
	"database/sql"
	"errors"
	"time"
)

// SIS and HRIS intake (schema/0310_intake.sql, issue #67): organizational
// sponsors, intake records and conversions. Every statement binds @tenant.

// Intake channels and matching modes (design §4.1, §5.2).
const (
	ChannelSIS  = "sis"
	ChannelHRIS = "hris"

	MatchAuthoritative = "authoritative"
)

// Intake statuses.
const (
	IntakeReceived = "received"
	IntakeReview   = "review" // the person cannot be decided without matching (GU-5)
	IntakeResolved = "resolved"
	IntakeRejected = "rejected"
)

// Conversion triggers.
const (
	ConvSISStatus = "sis_status"
	ConvHRISHire  = "hris_hire"
)

// ErrIntakeSeen is an intake event (by event key) the tenant already recorded.
var ErrIntakeSeen = errors.New("store: intake event already recorded")

// OrgSponsor is an organizational sponsor (admissions, HR).
type OrgSponsor struct {
	Key        string
	Name       string
	Population string
	CreatedAt  time.Time
}

// IntakeRecord is one feed event received. Detail is a JSON object without
// personal data.
type IntakeRecord struct {
	ID             string
	Channel        string
	MatchMode      string
	SourceRecordID *string
	IdentityID     *int64
	SponsorOrg     *string
	SubmittedBy    *string
	EventKey       string
	EventType      string
	EffectiveAt    *time.Time
	Status         string
	Detail         string
	CreatedAt      time.Time
}

// Conversion records one affiliation ending and another starting on the same person.
type Conversion struct {
	ID                string
	IdentityID        int64
	FromAffiliationID string
	ToAffiliationID   string
	FromType          string
	ToType            string
	Trigger           string
	IntakeID          *string
	EffectiveAt       time.Time
	CreatedAt         time.Time
}

const orgSponsorCols = `o.key, o.name, o.population, o.created_at`

const intakeCols = `r.id, r.channel, r.match_mode, r.source_record_id, r.identity_id, r.sponsor_org, r.submitted_by,
	r.event_key, r.event_type, r.effective_at, r.status, r.detail, r.created_at`

const convCols = `v.id, v.identity_id, v.from_affiliation_id, v.to_affiliation_id, v.from_type, v.to_type, v.trigger,
	v.intake_id, v.effective_at, v.created_at`

var (
	orgSponsorsList = tq("org_sponsors.list", `
		SELECT `+orgSponsorCols+` FROM org_sponsors o WHERE o.tenant_id = @tenant ORDER BY o.key`)
	orgSponsorsGet = tq("org_sponsors.get", `
		SELECT `+orgSponsorCols+` FROM org_sponsors o WHERE o.tenant_id = @tenant AND o.key = @key`)
	orgSponsorsPut = tq("org_sponsors.put", `
		INSERT INTO org_sponsors (tenant_id, key, name, population, created_at)
		VALUES (@tenant, @key, @name, @population, @created_at)
		ON CONFLICT (tenant_id, key) DO UPDATE SET name = excluded.name, population = excluded.population`)

	intakeInsert = tq("intake_records.insert", `
		INSERT INTO intake_records (id, tenant_id, channel, match_mode, source_record_id, identity_id, sponsor_org,
			submitted_by, event_key, event_type, effective_at, status, detail, created_at)
		VALUES (@id, @tenant, @channel, @match_mode, @source_record_id, @identity_id, @sponsor_org, @submitted_by,
			@event_key, @event_type, @effective_at, @status, @detail, @created_at)`)
	intakeList = tq("intake_records.list", `
		SELECT `+intakeCols+` FROM intake_records r WHERE r.tenant_id = @tenant ORDER BY r.created_at, r.id`)
	intakeGet = tq("intake_records.get", `
		SELECT `+intakeCols+` FROM intake_records r WHERE r.tenant_id = @tenant AND r.id = @id`)
	intakeByEvent = tq("intake_records.by_event", `
		SELECT `+intakeCols+` FROM intake_records r WHERE r.tenant_id = @tenant AND r.event_key = @event_key`)
	intakeSetOutcome = tq("intake_records.set_outcome", `
		UPDATE intake_records SET status = @status, identity_id = @identity_id, source_record_id = @source_record_id,
			detail = @detail
		WHERE tenant_id = @tenant AND id = @id`)

	conversionsInsert = tq("identity_conversions.insert", `
		INSERT INTO identity_conversions (id, tenant_id, identity_id, from_affiliation_id, to_affiliation_id, from_type,
			to_type, trigger, intake_id, effective_at, created_at)
		VALUES (@id, @tenant, @identity_id, @from_affiliation_id, @to_affiliation_id, @from_type, @to_type, @trigger,
			@intake_id, @effective_at, @created_at)`)
	conversionsList = tq("identity_conversions.list", `
		SELECT `+convCols+` FROM identity_conversions v WHERE v.tenant_id = @tenant ORDER BY v.effective_at, v.id`)
	conversionsByIdentity = tq("identity_conversions.by_identity", `
		SELECT `+convCols+` FROM identity_conversions v WHERE v.tenant_id = @tenant AND v.identity_id = @identity_id
		ORDER BY v.effective_at, v.id`)

	sourceRecordsBySOR = tq("identity_source_records.by_sor", `
		SELECT `+srcCols+` FROM identity_source_records s WHERE s.tenant_id = @tenant AND s.sor = @sor AND s.sorid = @sorid`)
	sourceRecordsSetAttrs = tq("identity_source_records.set_attributes", `
		UPDATE identity_source_records SET attributes = @attributes, received_at = @received_at
		WHERE tenant_id = @tenant AND id = @id`)
)

func scanOrgSponsor(s scanner) (*OrgSponsor, error) {
	var o OrgSponsor
	var at nullTime
	if err := s.Scan(&o.Key, &o.Name, &o.Population, &at); err != nil {
		return nil, err
	}
	var err error
	o.CreatedAt, err = at.val()
	return &o, err
}

func scanIntake(s scanner) (*IntakeRecord, error) {
	var r IntakeRecord
	var src, sponsor, by sql.NullString
	var iid sql.NullInt64
	var eff, created nullTime
	if err := s.Scan(&r.ID, &r.Channel, &r.MatchMode, &src, &iid, &sponsor, &by, &r.EventKey, &r.EventType, &eff,
		&r.Status, &r.Detail, &created); err != nil {
		return nil, err
	}
	r.SourceRecordID, r.IdentityID, r.SponsorOrg, r.SubmittedBy = strp(src), intp(iid), strp(sponsor), strp(by)
	var err error
	if r.EffectiveAt, err = eff.ptr(); err != nil {
		return nil, err
	}
	r.CreatedAt, err = created.val()
	return &r, err
}

func scanConversion(s scanner) (*Conversion, error) {
	var v Conversion
	var intake sql.NullString
	var eff, created nullTime
	if err := s.Scan(&v.ID, &v.IdentityID, &v.FromAffiliationID, &v.ToAffiliationID, &v.FromType, &v.ToType, &v.Trigger,
		&intake, &eff, &created); err != nil {
		return nil, err
	}
	v.IntakeID = strp(intake)
	var err error
	if v.EffectiveAt, err = eff.val(); err != nil {
		return nil, err
	}
	v.CreatedAt, err = created.val()
	return &v, err
}

// OrgSponsors lists the organizational sponsors by key.
func (tx *TenantTx) OrgSponsors() ([]*OrgSponsor, error) {
	return collect(tx, scanOrgSponsor, orgSponsorsList)
}

// OrgSponsor returns one organizational sponsor, or ErrNotFound.
func (tx *TenantTx) OrgSponsor(key string) (*OrgSponsor, error) {
	return one(tx, scanOrgSponsor, orgSponsorsGet, sql.Named("key", key))
}

// PutOrgSponsor creates or updates an organizational sponsor.
func (tx *TenantTx) PutOrgSponsor(o *OrgSponsor) error {
	_, err := tx.exec(orgSponsorsPut, sql.Named("key", o.Key), sql.Named("name", o.Name),
		sql.Named("population", o.Population), sql.Named("created_at", T(o.CreatedAt)))
	return err
}

// InsertIntakeRecord records a feed event; ErrIntakeSeen if the tenant already
// holds the same event key.
func (tx *TenantTx) InsertIntakeRecord(r *IntakeRecord) error {
	_, err := tx.exec(intakeInsert, sql.Named("id", r.ID), sql.Named("channel", r.Channel),
		sql.Named("match_mode", r.MatchMode), sql.Named("source_record_id", optStr(r.SourceRecordID)),
		sql.Named("identity_id", IP(r.IdentityID)), sql.Named("sponsor_org", optStr(r.SponsorOrg)),
		sql.Named("submitted_by", optStr(r.SubmittedBy)), sql.Named("event_key", r.EventKey),
		sql.Named("event_type", r.EventType), sql.Named("effective_at", TP(r.EffectiveAt)),
		sql.Named("status", r.Status), sql.Named("detail", r.Detail), sql.Named("created_at", T(r.CreatedAt)))
	if isUnique(err) {
		return ErrIntakeSeen
	}
	return err
}

// IntakeRecords lists every intake record, oldest first.
func (tx *TenantTx) IntakeRecords() ([]*IntakeRecord, error) {
	return collect(tx, scanIntake, intakeList)
}

// IntakeRecord returns one intake record, or ErrNotFound.
func (tx *TenantTx) IntakeRecord(id string) (*IntakeRecord, error) {
	return one(tx, scanIntake, intakeGet, sql.Named("id", id))
}

// IntakeRecordByEvent returns the intake record of an event key, or ErrNotFound.
func (tx *TenantTx) IntakeRecordByEvent(key string) (*IntakeRecord, error) {
	return one(tx, scanIntake, intakeByEvent, sql.Named("event_key", key))
}

// SetIntakeOutcome records what became of an intake record; ErrNotFound if unknown.
func (tx *TenantTx) SetIntakeOutcome(id, status string, identityID *int64, sourceRecordID *string, detail string) error {
	res, err := tx.exec(intakeSetOutcome, sql.Named("id", id), sql.Named("status", status),
		sql.Named("identity_id", IP(identityID)), sql.Named("source_record_id", optStr(sourceRecordID)),
		sql.Named("detail", detail))
	return affectedOne(res, err)
}

// InsertConversion records a conversion.
func (tx *TenantTx) InsertConversion(v *Conversion) error {
	_, err := tx.exec(conversionsInsert, sql.Named("id", v.ID), sql.Named("identity_id", v.IdentityID),
		sql.Named("from_affiliation_id", v.FromAffiliationID), sql.Named("to_affiliation_id", v.ToAffiliationID),
		sql.Named("from_type", v.FromType), sql.Named("to_type", v.ToType), sql.Named("trigger", v.Trigger),
		sql.Named("intake_id", optStr(v.IntakeID)), sql.Named("effective_at", T(v.EffectiveAt)),
		sql.Named("created_at", T(v.CreatedAt)))
	return err
}

// Conversions lists every conversion, oldest first.
func (tx *TenantTx) Conversions() ([]*Conversion, error) {
	return collect(tx, scanConversion, conversionsList)
}

// ConversionsFor lists a person's conversions, oldest first.
func (tx *TenantTx) ConversionsFor(identityID int64) ([]*Conversion, error) {
	return collect(tx, scanConversion, conversionsByIdentity, sql.Named("identity_id", identityID))
}

// SourceRecordBySOR returns the source record a system of record holds for
// sorid, or ErrNotFound.
func (tx *TenantTx) SourceRecordBySOR(sor, sorid string) (*SourceRecord, error) {
	return one(tx, scanSourceRecord, sourceRecordsBySOR, sql.Named("sor", sor), sql.Named("sorid", sorid))
}

// UpdateSourceRecord replaces what a source record says (the system of record
// sent a newer version); ErrNotFound if unknown.
func (tx *TenantTx) UpdateSourceRecord(id, attributes string, at time.Time) error {
	res, err := tx.exec(sourceRecordsSetAttrs, sql.Named("id", id), sql.Named("attributes", attributes),
		sql.Named("received_at", T(at)))
	return affectedOne(res, err)
}
