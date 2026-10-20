package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Rotation job states (schema/0225_rotation.sql).
const (
	RotPending     = "pending"
	RotCreated     = "created"
	RotHandedOver  = "handed_over"
	RotOldDisabled = "old_disabled"
	RotVerified    = "verified"
	RotOldDeleted  = "old_deleted"
	RotFailed      = "failed"
	RotCancelled   = "cancelled"
)

// Rotation job origins.
const (
	RotOriginManual = "manual"
	RotOriginPolicy = "policy"
	RotOriginVendor = "vendor_compromise"
	RotOriginJML    = "jml"
)

// RotationAdapter holds the connection details and the sealed credential of
// one rotation adapter. SecretEnc is sealed JSON (internal/seal); nothing
// outside internal/rotation opens it and no API returns it.
type RotationAdapter struct {
	ID        string
	TenantID  tenancy.ID
	Name      string
	Type      string
	Config    string // JSON, non-secret settings
	SecretEnc []byte
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RotationPolicy is the max age, grace period and adapter for a secret kind
// (and optionally one system; System "" is every system).
type RotationPolicy struct {
	ID            string
	TenantID      tenancy.ID
	Kind          string
	System        string
	MaxAgeDays    int
	GraceHours    int
	AdapterID     *string // nil: manual rotation, the policy only tracks age
	DestAdapterID *string
	DestPath      string
	AutoRotate    bool
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RotationBulk is one confirmed "vendor compromised" run.
type RotationBulk struct {
	ID          string
	TenantID    tenancy.ID
	System      string
	Reason      string
	Plan        string // JSON of the confirmed plan (no secret material)
	PlanHash    string
	RequestedBy string
	CreatedAt   time.Time
}

// RotationJob is one secret's rotation.
type RotationJob struct {
	ID            string
	TenantID      tenancy.ID
	SecretID      int64
	BulkID        *string
	Origin        string
	AdapterID     string
	AdapterType   string
	DestAdapterID *string
	DestPath      string
	State         string
	FailedState   *string
	OldRef        string
	NewRef        *string
	GraceHours    int
	Attempts      int
	LastError     *string
	NextStepAt    time.Time
	LeaseUntil    *time.Time
	HandedOverAt  *time.Time
	DisabledAt    *time.Time
	VerifiedAt    *time.Time
	CompletedAt   *time.Time
	Verification  *string // JSON: the re-read of the old credential
	RequestedBy   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RotationJobFilter narrows RotationJobs; zero fields do not filter.
type RotationJobFilter struct {
	State    string
	SecretID int64
	BulkID   string
	Limit    int
}
