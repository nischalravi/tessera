package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Deployment-readiness rows (design §8). New tables use UUID text keys,
// RFC 3339 UTC timestamps and carry tenant_id; they are reached only through
// a *TenantTx like every other tenant table.

// Revision states (§4.1).
const (
	StateDraft            = "draft"
	StateReadyToValidate  = "ready_to_validate"
	StateValidated        = "validated"
	StateDryRunReconciled = "dry_run_reconciled"
	StateActive           = "active"
	StateDegraded         = "degraded"
	StateRetired          = "retired"
	StateSuperseded       = "superseded"
)

// RT formats a timestamp as RFC 3339 UTC with fixed microseconds, so text
// order is time order.
func RT(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }

// ParseRT parses a timestamp written by RT.
func ParseRT(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

func rtp(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	t, err := ParseRT(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// RTP stores an optional RFC 3339 timestamp.
func RTP(t *time.Time) any {
	if t == nil {
		return nil
	}
	return RT(*t)
}

// NewID returns a random (version 4) UUID.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("store: random id: %w", err)) // crypto/rand does not fail on supported platforms
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ErrStateConflict is returned by SetRevisionState when the revision is no
// longer in the expected state (compare-and-set lost a race).
var ErrStateConflict = errors.New("store: revision state changed concurrently")

// ErrDuplicate is returned when a unique constraint rejects a row.
var ErrDuplicate = errors.New("store: duplicate")

// Connection is a governed customer system (design K1).
type Connection struct {
	ID               string
	TenantID         tenancy.ID // zero on insert means "this transaction's tenant"
	Name             string
	ConnectorType    string
	System           string
	Role             string
	ActiveRevisionID *string
	Health           string
	TechnicalOwner   *string
	BusinessOwner    *string
	AgentID          *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	RetiredAt        *time.Time
}

// ConnectionRevision is one configuration of a connection and its lifecycle state.
type ConnectionRevision struct {
	ID              string
	TenantID        tenancy.ID // zero on insert means "this transaction's tenant"
	ConnectionID    string
	Rev             int
	State           string
	TemplateID      string
	TemplateVersion string // major.minor pin, e.g. "1.0"
	OverlayVersion  int
	Config          string // typed JSON, no secrets
	SecretRef       *string
	SecretVersion   *string
	ConfigHash      string
	EvidenceSeq     int64
	WriteMode       string
	ExpectedCounts  *string
	GateReport      *string
	ActivatedAt     *time.Time
	ActivatedBy     *string
	CreatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Attestation is a named person's confirmation of a checklist item.
type Attestation struct {
	RevisionID, ItemID string
	ActorID, Note      string
	ActorUserID        *string // platform user id of the attester (nil: recorded before #425)
	ItemHash           string
	ConfigHash         string
	AttestedAt         time.Time
}

// LiveAttestation stands in for a live check the system reported unsupported:
// a named attester, the reason and the evidence they relied on. ActorID is who
// recorded it.
type LiveAttestation struct {
	RevisionID, ItemID string
	ActorID, Attester  string
	Reason, Evidence   string
	ItemHash           string
	ConfigHash         string
	AttestedAt         time.Time
}

// Skip is a Recommended item skipped with a reason (an accepted gap).
type Skip struct {
	RevisionID, ConnectionID, ItemID string
	Level                            string
	ActorID, Reason                  string
	ReviewBy                         time.Time
	TemplateVersion                  string
	SkippedAt                        time.Time
}

// ItemState is the stored result of the latest checklist evaluation.
type ItemState struct {
	RevisionID, ItemID string
	Level, Status      string
	Source             string
	ActorID, Note      *string
	ReviewBy           *time.Time
	CheckRunID         *string
	ConfigHash         string
	UpdatedAt          time.Time
}

// OverlayRow is a stored tenant overlay version.
type OverlayRow struct {
	ID            string
	ConnectorType string // template id
	ConnectionID  *string
	Version       int
	Body          string
	UpdatedBy     string
	UpdatedAt     time.Time
}
