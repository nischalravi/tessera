package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The audit ledger's row types (design §7.4, §13). The hash contract lives in
// internal/audit/canon; these types are what the store reads and writes.
type (
	AuditActor = canon.Actor
	AuditAuthn = canon.Authn
	AuditHTTP  = canon.HTTP
)

// Actor types.
const (
	ActorUser      = "user"
	ActorAPIClient = "api_client"
	ActorSystem    = "system"
	ActorOperator  = "operator"
	ActorAnonymous = "anonymous"
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailure = "failure"
	OutcomeError   = "error"
)

// ActionHTTPRequest is the action of the one event every audited HTTP request writes.
const ActionHTTPRequest = "http.request"

// AuditEvent is one entry of a tenant's hash chain.
type AuditEvent struct {
	ID              uuid.UUID
	TenantID        tenancy.ID
	Seq             int64     // 1..n per tenant, gapless
	OccurredAt      time.Time // microsecond precision, UTC
	ActorType       string    // user | api_client | system | operator | anonymous
	ActorID         *string
	ActorDisplay    *string
	SessionID       *string
	ClientID        *string
	Authn           json.RawMessage // canon.Authn as JSON; nil when there is no authenticated principal
	Action          string          // e.g. http.request, grant.revoke
	TargetType      *string
	TargetID        *string
	Outcome         string // success | denied | failure | error
	RequestID       *string
	HTTP            json.RawMessage // canon.HTTP as JSON; only on http.request
	IP              *string
	UserAgentSHA256 *string
	PolicyVersion   *string
	Detail          json.RawMessage // a JSON object, JCS-safe (canon.Detail)
	SchemaVersion   int             // 1
	PrevHash        string
	Hash            string
}

// Body is the hashed form of e (canon.Body).
func (e *AuditEvent) Body() canon.Body {
	detail := e.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	return canon.Body{
		V: canon.Version, TenantID: e.TenantID.String(), Seq: e.Seq, ID: e.ID.String(),
		OccurredAt: canon.FormatTime(e.OccurredAt),
		Actor:      canon.Actor{Type: e.ActorType, ID: e.ActorID, Display: e.ActorDisplay},
		SessionID:  e.SessionID, ClientID: e.ClientID, Authn: nullJSON(e.Authn), Action: e.Action,
		Target:  canon.Target{Type: e.TargetType, ID: e.TargetID},
		Outcome: e.Outcome, RequestID: e.RequestID, HTTP: nullJSON(e.HTTP), IP: e.IP, UA: e.UserAgentSHA256,
		PolicyVersion: e.PolicyVersion, Detail: detail, PrevHash: e.PrevHash,
	}
}

func nullJSON(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return nil
	}
	return r
}

// AuditEventHash recomputes e's hash from its fields.
func AuditEventHash(e *AuditEvent) (string, error) { return canon.Hash(e.Body()) }

// AuditChainHead is a tenant's chain head: the last seq and hash.
type AuditChainHead struct {
	TenantID  tenancy.ID
	LastSeq   int64
	LastHash  string // canon.Genesis(tenant) before the first event
	UpdatedAt time.Time
}

// Anchor states of a checkpoint.
const (
	AnchorPending  = "pending"
	AnchorAnchored = "anchored"
	AnchorFailed   = "failed"
)

// AuditCheckpoint is a signed statement of a chain head (compact JWS, EdDSA,
// the platform audit key), anchored outside the database.
type AuditCheckpoint struct {
	ID             uuid.UUID
	TenantID       tenancy.ID
	Seq            int64
	HeadHash       string
	CreatedAt      time.Time
	JWS            string
	AnchorStatus   string // pending | anchored | failed
	AnchorRef      *string
	AnchoredAt     *time.Time
	AnchorAttempts int
}

// AuditFilter selects events for the audit log (newest first). Zero values
// mean "no filter". http.request events are left out unless IncludeHTTP is
// set or Action asks for them.
type AuditFilter struct {
	Limit       int // <= 0: no limit
	BeforeSeq   int64
	Action      string
	ActorID     string
	TargetType  string
	TargetID    string
	From, To    time.Time
	IncludeHTTP bool
}

// AuditContext is who and what an event is attributed to, carried in the
// request context: the audit middleware sets it for every HTTP request (the
// actor is "anonymous" until authentication lands in PR5), background jobs set
// a system actor. Domain events written through a TenantTx opened with that
// context take their actor from it, never from a caller-supplied string.
type AuditContext struct {
	Actor     AuditActor
	SessionID *string
	ClientID  *string
	Authn     json.RawMessage
	RequestID *string
	IP        *string
	UAHash    *string
}

type auditCtxKey struct{}

// WithAuditContext returns ctx carrying ac.
func WithAuditContext(ctx context.Context, ac AuditContext) context.Context {
	return context.WithValue(ctx, auditCtxKey{}, ac)
}

// AuditContextFrom returns the audit context of ctx.
func AuditContextFrom(ctx context.Context) (AuditContext, bool) {
	ac, ok := ctx.Value(auditCtxKey{}).(AuditContext)
	return ac, ok
}

// AuditRecord is a domain event to append (TenantTx.RecordAudit).
type AuditRecord struct {
	At     time.Time // when it happened (the caller's clock); zero = now
	Action string
	// LegacyActor is the actor string of the MVP audit helper. It is the
	// actor only when the context has no AuditContext (system jobs, seeding,
	// the CLI); otherwise, unless it is "system", it is kept in detail as
	// claimed_actor, unverified.
	LegacyActor   string
	Outcome       string // default success
	TargetType    string
	TargetID      string
	PolicyVersion string
	Detail        any // see canon.Detail
}
