package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Group rules (schema/0288_group_rules.sql, issue #56, GR-13; design
// docs/design/groups-grouper-parity.md §10.3). The vocabulary and the checks
// live in internal/groups/rules; this is the stored row.

// Rule owner types.
const (
	RuleOwnerFolder = "folder"
	RuleOwnerGroup  = "group"
)

// GrpRule is one row of grp_rules. Conditions and Params are JSON the rules
// package validated against its closed vocabulary; SecretEnc is the sealed
// signing secret of a webhook action.
type GrpRule struct {
	ID         string
	TenantID   tenancy.ID
	OwnerType  string // folder | group
	OwnerID    string
	Scope      string // self (a group's rule) | one | sub (a folder's rule)
	Name       string
	Trigger    string
	Conditions string
	Action     string
	Params     string
	Enabled    bool
	SecretEnc  []byte
	CreatedBy  string // platform user id
	CreatedAt  time.Time
	UpdatedBy  string // platform user id: the rule acts with this user's authority
	UpdatedAt  time.Time
	// ActiveSeq: the rule reacts only to group events after this seq (the last
	// one when it was saved), so it never acts on history.
	ActiveSeq int64
}

// GrpRuleSettings is the tenant's rule settings.
type GrpRuleSettings struct {
	EmailEnabled bool
	UpdatedAt    time.Time
	UpdatedBy    *string
}
