// Package events is the change outbox of native groups (design
// docs/design/groups-grouper-parity.md §10.1): every committed change writes a
// row to grp_events in the same transaction, with a per-tenant gap-free
// sequence number. Consumers (the point-in-time writer, the graph projection,
// provisioners, webhooks) keep a cursor in grp_event_cursors and read the
// events after it; external delivery encodes them as CloudEvents 1.0 JSON.
//
// The package does not decide what a change is: callers (internal/groups/model,
// internal/groups/engine) name the event. It only checks the name against the
// catalogue, stamps the cause and appends.
package events

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The catalogue of event types (design §10.1). Each type belongs to one object
// type; Append refuses a mismatch so consumers can rely on it.
const (
	FolderCreated = "folder.created"
	FolderUpdated = "folder.updated"
	FolderRenamed = "folder.renamed"
	FolderMoved   = "folder.moved"
	FolderDeleted = "folder.deleted"

	GroupCreated           = "group.created"
	GroupUpdated           = "group.updated"
	GroupRenamed           = "group.renamed"
	GroupMoved             = "group.moved"
	GroupDeleted           = "group.deleted"
	GroupRestored          = "group.restored"
	GroupPurged            = "group.purged"
	GroupDisabled          = "group.disabled"
	GroupEnabled           = "group.enabled"
	GroupDefinitionChanged = "group.definition_changed"

	MembershipDirectAdded        = "membership.direct.added"
	MembershipDirectRemoved      = "membership.direct.removed"
	MembershipDirectDatesChanged = "membership.direct.dates_changed"
	MembershipEffectiveAdded     = "membership.effective.added"
	MembershipEffectiveRemoved   = "membership.effective.removed"

	PrivilegeGranted = "privilege.granted"
	PrivilegeRevoked = "privilege.revoked"

	AttributeAssigned     = "attribute.assigned"
	AttributeRemoved      = "attribute.removed"
	AttributeValueChanged = "attribute.value_changed"

	LoaderRunApplied  = "loader.run.applied"
	LoaderRunHeld     = "loader.run.held"
	LoaderRunApproved = "loader.run.approved"
	LoaderRunRejected = "loader.run.rejected"

	ProvisioningOpVerified = "provisioning.op.verified"
	ProvisioningOpFailed   = "provisioning.op.failed"
	ProvisioningOpDrift    = "provisioning.op.drift"

	AttestationDue           = "attestation.due"
	AttestationCompleted     = "attestation.completed"
	AttestationOverdueAction = "attestation.overdue_action"

	RuleFired = "rule.fired"
)

// objectOf maps every type of the catalogue to its object type.
var objectOf = func() map[string]string {
	m := map[string]string{}
	add := func(object string, types ...string) {
		for _, t := range types {
			m[t] = object
		}
	}
	add(store.EventObjFolder, FolderCreated, FolderUpdated, FolderRenamed, FolderMoved, FolderDeleted)
	add(store.EventObjGroup, GroupCreated, GroupUpdated, GroupRenamed, GroupMoved, GroupDeleted, GroupRestored, GroupPurged,
		GroupDisabled, GroupEnabled, GroupDefinitionChanged, MembershipDirectAdded, MembershipDirectRemoved,
		MembershipDirectDatesChanged, MembershipEffectiveAdded, MembershipEffectiveRemoved)
	add(store.EventObjPrivilege, PrivilegeGranted, PrivilegeRevoked)
	add(store.EventObjAttribute, AttributeAssigned, AttributeRemoved, AttributeValueChanged)
	add(store.EventObjLoader, LoaderRunApplied, LoaderRunHeld, LoaderRunApproved, LoaderRunRejected)
	add(store.EventObjProvisioning, ProvisioningOpVerified, ProvisioningOpFailed, ProvisioningOpDrift)
	add(store.EventObjAttestation, AttestationDue, AttestationCompleted, AttestationOverdueAction)
	add(store.EventObjRule, RuleFired)
	return m
}()

// ObjectType returns the object type of an event type, and whether the type is
// in the catalogue.
func ObjectType(typ string) (string, bool) {
	o, ok := objectOf[typ]
	return o, ok
}

// Types lists the catalogue.
func Types() []string {
	out := make([]string, 0, len(objectOf))
	for t := range objectOf {
		out = append(out, t)
	}
	return out
}

// MaxDataBytes bounds one event's data.
const MaxDataBytes = 64 << 10

// Event is the stored row (store.GrpEvent): Seq, TenantID are set by Append.
type Event = store.GrpEvent

// New starts an event of the catalogue's type for an object.
func New(typ, objectID string, now time.Time, cause string) *Event {
	obj, _ := ObjectType(typ)
	return &Event{Type: typ, ObjectType: obj, ObjectID: objectID, OccurredAt: now, CauseType: cause}
}

// Data encodes an event's data object. Keys come out sorted, so the encoding
// is deterministic.
func Data(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// callers pass maps and structs of strings, numbers and times
		panic(fmt.Errorf("events: data: %w", err))
	}
	return b
}

// Append validates e and writes it in tx as the tenant's next event, setting
// e.Seq. Everything is checked before a sequence number is taken, so a refused
// event leaves no gap. The request id of the audit context, when there is one,
// becomes the cause reference, so an event can be traced to the request that
// made it.
//
// The groups code does not call Append itself: it calls pit.Emit, which also
// applies the event to the PIT tables and moves the "pit" cursor.
func Append(tx *store.TenantTx, e *Event) error {
	want, ok := ObjectType(e.Type)
	if !ok {
		return fmt.Errorf("events: unknown type %q", e.Type)
	}
	if e.ObjectType == "" {
		e.ObjectType = want
	}
	if e.ObjectType != want {
		return fmt.Errorf("events: %s is an event of a %s, not a %s", e.Type, want, e.ObjectType)
	}
	if e.ObjectID == "" {
		return fmt.Errorf("events: %s has no object id", e.Type)
	}
	if e.CauseType == "" {
		e.CauseType = store.CauseEngine
	}
	switch e.CauseType {
	case store.CauseAPI, store.CauseLoader, store.CauseRule, store.CauseEngine, store.CauseTimewheel, store.CausePolicyRepo,
		store.CauseImport, store.CauseRetention:
	default:
		return fmt.Errorf("events: %s has cause %q", e.Type, e.CauseType)
	}
	if len(e.Data) > MaxDataBytes {
		return fmt.Errorf("events: %s data is %d bytes (at most %d)", e.Type, len(e.Data), MaxDataBytes)
	}
	if len(e.Data) > 0 && !json.Valid(e.Data) {
		return fmt.Errorf("events: %s data is not JSON", e.Type)
	}
	if e.CauseRef == "" {
		if ac, ok := store.AuditContextFrom(tx.Context()); ok && ac.RequestID != nil {
			e.CauseRef = *ac.RequestID
		}
	}
	return tx.AppendGrpEvent(e)
}
