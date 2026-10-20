package store

import (
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Conditional access (issue #163, schema/0222_conditional_access.sql).

// Policy scopes: where a policy is evaluated.
const (
	AccessScopeSignin     = "signin"     // the Tessera sign-in (OIDC and SAML)
	AccessScopePrivileged = "privileged" // routes that need a step-up (JIT decisions, admin changes)
)

// Policy modes. report_only evaluates and audits but never changes the outcome.
const (
	AccessModeDisabled   = "disabled"
	AccessModeReportOnly = "report_only"
	AccessModeEnforce    = "enforce"
)

// Policy outcomes.
const (
	AccessAllow  = "allow"
	AccessStepUp = "step_up"
	AccessDeny   = "deny"
)

// Network condition operators.
const (
	NetworkAny   = "any"
	NetworkIn    = "in"
	NetworkNotIn = "not_in"
)

// Device conditions: unmanaged matches a device the IdP did not assert as
// managed; not_compliant matches one that is not known to be compliant.
const (
	DeviceAny          = "any"
	DeviceUnmanaged    = "unmanaged"
	DeviceNotCompliant = "not_compliant"
)

// Device signal values and sources.
const (
	DeviceCompliant    = "compliant"
	DeviceNonCompliant = "not_compliant"
	DeviceSourceManual = "manual"
	DeviceSourceCAEP   = "caep"
)

// NetworkRange is a named set of CIDRs.
type NetworkRange struct {
	ID          uuid.UUID
	TenantID    tenancy.ID
	Name        string
	Description string
	CIDRs       []string // canonical (masked) prefixes
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AccessPolicy is one conditional access policy.
type AccessPolicy struct {
	ID              uuid.UUID
	TenantID        tenancy.ID
	Name            string
	Description     string
	Scope           string // signin | privileged
	Mode            string // disabled | report_only | enforce
	Outcome         string // allow | step_up | deny
	StepUpACR       *string
	StepUpMaxAge    int // seconds, 0 = none
	NetworkOp       string
	NetworkRangeIDs []uuid.UUID
	Device          string
	Priority        int
	CreatedBy       *uuid.UUID
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// DeviceSignal is the latest device-compliance verdict for a user.
type DeviceSignal struct {
	TenantID  tenancy.ID
	UserID    uuid.UUID
	Status    string // compliant | not_compliant
	Source    string // manual | caep
	Reason    string
	SetBy     *uuid.UUID
	SetAt     time.Time
	ExpiresAt *time.Time
}
