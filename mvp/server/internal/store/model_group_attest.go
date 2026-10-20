package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Group attestation, deprovisioning, the groups Inbox and saved reports
// (schema/0292_group_attestation.sql, issue #57, GR-14; design
// docs/design/groups-grouper-parity.md §10.4, §10.5, §10.7). The rules live in
// internal/groups/{inbox,attest,deprov,reports}; these are the stored rows.

// Inbox task kinds and statuses.
const (
	TaskDeprovisioning     = "deprovisioning"
	TaskRule               = "rule"
	TaskMicroCertification = "micro_certification"
	TaskAttestation        = "attestation"
	TaskAttestationOverdue = "attestation_overdue"

	// TaskOpen and TaskDone ("open", "done") are declared with the guest lifecycle tasks and mean the
	// same here
	TaskDismissed = "dismissed"
)

// GrpTask is one row of grp_inbox_tasks. Detail is JSON.
type GrpTask struct {
	ID         string
	TenantID   tenancy.ID
	Kind       string
	Title      string
	Detail     string
	ObjectType string // folder | group
	ObjectID   string
	Subject    *int64 // the identity the task is about
	Assignee   *int64 // a named assignee; nil: whoever administers the object
	Status     string
	DedupeKey  *string
	DueAt      *time.Time
	CreatedAt  time.Time
	ClosedAt   *time.Time
	ClosedBy   *string
}

// GrpTaskFilter selects tasks. Empty fields do not filter.
type GrpTaskFilter struct {
	Status     string
	Kind       string
	ObjectType string
	ObjectID   string
	Limit      int
	Offset     int
}

// Attestation values.
const (
	AttestPeriodic = "periodic"
	AttestMicro    = "micro"

	AttestOpen           = "open"
	AttestCompleted      = "completed"
	AttestOverdueApplied = "overdue_applied"
	AttestCancelled      = "cancelled"

	OverdueNone     = "none"
	OverdueDisable  = "disable_group"
	OverdueRemove   = "remove_unattested"
	ReviewersAdmins = "admins"
	ReviewersGroup  = "group"

	ApplyPending = "pending"
	ApplyApplied = "applied"
	ApplyDenied  = "denied"
	ApplySkipped = "skipped"
	ApplyFailed  = "failed"
)

// GrpAttestSettings is the attestation setting of a folder or a group.
// ReminderDays is a JSON list of days before the due date.
type GrpAttestSettings struct {
	TenantID      tenancy.ID
	OwnerType     string
	OwnerID       string
	IntervalDays  int
	WindowDays    int
	ReviewerType  string
	ReviewerGroup *GroupID
	ReminderDays  string
	OverdueAction string
	Enabled       bool
	UpdatedBy     string
	UpdatedAt     time.Time
}

// GrpAttestCampaign links a group to a review campaign and freezes what it was
// started with.
type GrpAttestCampaign struct {
	ID              string
	TenantID        tenancy.ID
	GroupID         GroupID
	Kind            string
	ReviewCampaign  *int64
	Status          string
	StartedAt       time.Time
	DueAt           time.Time
	ClosedAt        *time.Time
	OverdueAction   string
	ReviewerType    string
	ReviewerGroup   *GroupID
	ReminderDays    string
	ActsAs          string
	PopulationCount int
	PopulationHash  string
	RemindersSent   int
	LastReminderAt  *time.Time
	StartedBy       *string
	RuleID          *string
}

// GrpAttestFilter selects campaigns. Empty fields do not filter.
type GrpAttestFilter struct {
	Group  GroupID
	Status string
	Limit  int
	Offset int
}

// GrpAttestItem is one identity of a campaign's frozen population.
type GrpAttestItem struct {
	ID          string
	TenantID    tenancy.ID
	CampaignID  string
	GroupID     GroupID
	Identity    int64
	How         string // direct | nested
	ReviewItem  *int64
	ApplyState  string
	ApplyDetail string
	AppliedAt   *time.Time
}

// Deprovisioning values.
const (
	DeprovNotify    = "notify"
	DeprovAutoAfter = "auto_after"
	DeprovAutoNow   = "auto_now"

	DeprovOpen      = "open"
	DeprovRemoved   = "removed"
	DeprovDismissed = "dismissed"

	DeprovAffiliationLost = "affiliation_lost"
	DeprovLeaver          = "leaver"
)

// GrpDeprovSettings is the tenant's deprovisioning setting. Affiliations is a
// JSON list of group ids.
type GrpDeprovSettings struct {
	Affiliations string
	VetoEnabled  bool
	UpdatedAt    time.Time
	UpdatedBy    *string
}

// GrpDeprovFolder is a folder's deprovisioning mode.
type GrpDeprovFolder struct {
	FolderID  FolderID
	Mode      string
	Days      int
	UpdatedBy string
	UpdatedAt time.Time
}

// GrpDeprovMark says an identity is deprovisioned.
type GrpDeprovMark struct {
	Identity int64
	Since    time.Time
	Reason   string
}

// GrpDeprovItem is the open work for one identity in one folder.
type GrpDeprovItem struct {
	ID         string
	TenantID   tenancy.ID
	Identity   int64
	FolderID   FolderID
	TaskID     *string
	Status     string
	Mode       string
	Detail     string // JSON: the groups and privileges found
	OpenedAt   time.Time
	DueAt      *time.Time
	ResolvedAt *time.Time
	ResolvedBy *string
	Reason     string
}

// GrpDeprovFilter selects items. Empty fields do not filter.
type GrpDeprovFilter struct {
	Status   string
	FolderID FolderID
	Identity int64
	Limit    int
	Offset   int
}

// GrpReport is a saved report of the catalogue.
type GrpReport struct {
	ID        string
	TenantID  tenancy.ID
	Name      string
	Kind      string
	Params    string // JSON
	Format    string // csv | json
	Schedule  string // none | daily | weekly | monthly
	Delivery  string // store | email
	NextRunAt *time.Time
	LastRunAt *time.Time
	CreatedBy string // platform user id: scheduled runs act with this user's privileges
	CreatedAt time.Time
	UpdatedAt time.Time
}

// GrpReportRun is the output of one run.
type GrpReportRun struct {
	ID        string
	TenantID  tenancy.ID
	ReportID  string
	RanAt     time.Time
	RanBy     string
	Trigger   string // manual | schedule
	Status    string // ok | failed
	Format    string
	RowCount  int
	Truncated bool
	SHA256    string
	Content   string
	Error     string
}
