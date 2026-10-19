package store

import "time"

// Identity data model for affiliations, source records and identifiers
// (schema/0226_identity_model.sql, issue #64).

// Affiliation types (the kind of relationship).
const (
	AffEmployee     = "employee"
	AffStudent      = "student"
	AffApplicant    = "applicant"
	AffAdmit        = "admit"
	AffPrehire      = "prehire"
	AffContractor   = "contractor"
	AffGuestVisitor = "guest_visitor"
	AffVolunteer    = "volunteer"
	AffPartner      = "partner"
	AffAlum         = "alum"
	AffRetiree      = "retiree"
)

// Affiliation sources.
const (
	AffSourceHRIS        = "hris"
	AffSourceSIS         = "sis"
	AffSourceSponsorship = "sponsorship"
	AffSourcePartnerOrg  = "partner_org"
	AffSourceManual      = "manual"
)

// Affiliation statuses. Pending has not started; ended and revoked are final.
const (
	AffPending = "pending"
	AffActive  = "active"
	AffEnded   = "ended"
	AffRevoked = "revoked"
)

// Identifier types.
const (
	IdentEmail        = "email"
	IdentPhone        = "phone"
	IdentEmployeeID   = "employee_id"
	IdentStudentID    = "student_id"
	IdentApplicantID  = "applicant_id"
	IdentNetID        = "netid"
	IdentEPPN         = "eppn"
	IdentSAMLSubject  = "saml_subject_id"
	IdentSAMLPairwise = "saml_pairwise_id"
	IdentOIDCSub      = "oidc_sub"
	IdentNationalHMAC = "national_id_hmac"
)

// How an identifier was verified.
const (
	VerifiedByCode     = "confirmation_code"
	VerifiedByFed      = "federation"
	VerifiedBySource   = "authoritative_source"
	VerifiedByProofing = "proofing_agent"
)

// Statuses of source records and identifiers.
const (
	RecordActive  = "active"
	RecordRetired = "retired"
)

// GuestPopulation is the typed settings of one population (design §3).
type GuestPopulation struct {
	Key             string
	Name            string
	MaxDurationDays int
	DefaultIAL      int
	DefaultAAL      int
	CreatedAt       time.Time
}

// SourceRecord is what one system of record said about a person.
type SourceRecord struct {
	ID         string
	IdentityID *int64 // nil while pending review
	SOR        string
	SORID      string
	Attributes string // JSON object, no sensitive values in clear
	Status     string
	ReceivedAt time.Time
}

// Identifier is a value a person is known by. ValueNorm is nil for
// hashed-only types; ValueHMAC is the keyed hash used for matching.
type Identifier struct {
	ID             string
	IdentityID     int64
	Type           string
	Issuer         string
	ValueNorm      *string
	ValueHMAC      string
	VerifiedAt     *time.Time
	VerifiedBy     *string
	SourceRecordID *string
	Status         string
	CreatedAt      time.Time
}

// Affiliation is one relationship between a person and the organization.
type Affiliation struct {
	ID           string
	IdentityID   int64
	Type         string
	Source       string
	SourceRef    *string
	OrgUnit      *string
	PartnerOrgID *string
	Population   *string
	StartsAt     time.Time
	EndsAt       *time.Time
	Status       string
	CreatedBy    *string
	CreatedAt    time.Time
	EndedBy      *string
	EndReason    *string
}
