// Package attrs is the attribute framework of native groups (issue #50, GR-7;
// design docs/design/groups-grouper-parity.md §10.9, §3.5):
//
//   - defs.go, names.go, actions.go: attribute definitions (which live in
//     folders and carry the attr_* privileges), their names and actions.
//   - implies.go: the implication closures of names and of actions, rebuilt from
//     the direct edges after every change.
//   - assign.go, value.go: assignments on a folder, group, identity, direct
//     membership, attribute definition or another assignment, with dates, and
//     their typed values (floating values are decimal strings, never floats).
//   - access.go: the privileges an assignment needs on the definition and on its
//     owner (GR-4's checker; the rules of the privilege model stay in
//     internal/groups/privs).
//   - objecttypes.go, lint.go, services.go: the built-in object types
//     definition, the lint rules that read it, and service folders.
//
// Every change writes its audit event, and every assignment change its change
// event (attribute.assigned, attribute.removed, attribute.value_changed), in the
// caller's transaction. The package reads and writes only through
// *store.TenantTx, so every query is scoped to the request's tenant.
package attrs

import (
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits.
const (
	MaxDescription = 4096
	// MaxValues bounds the values of one assignment.
	MaxValues = 100
	// MaxValueLen bounds a string value.
	MaxValueLen = 4096
	// MaxAssignDepth bounds assignments on assignments: an assignment's owner
	// chain holds at most this many assignments (an assignment on a group is
	// depth 1).
	MaxAssignDepth = 3
	// DefaultAction is the action every definition has from its creation.
	DefaultAction = "assign"
	maxActionName = 64
)

// Env is one operation's context: the tenant transaction, the clock reading and
// the acting platform user. ByIdentity is the identity behind the user (it
// receives the creator privileges of a definition it creates) and TenantAdmin
// says the user holds an active tenant_admin role. The package does not check
// privileges for the caller: the API does, with the Require functions of
// access.go, before it calls the service.
type Env struct {
	Tx          *store.TenantTx
	Now         time.Time
	By          *string
	ByIdentity  *int64
	TenantAdmin bool
	// Cause and CauseRef stamp the operation's events (api when empty).
	Cause, CauseRef string
}

func (e Env) privs() privs.Env {
	return privs.Env{Tx: e.Tx, Now: e.Now, By: e.By, ByIdentity: e.ByIdentity, TenantAdmin: e.TenantAdmin,
		Cause: e.Cause, CauseRef: e.CauseRef}
}

func (e Env) audit(action, targetType, targetID string, detail ojson.Object) error {
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups",
		TargetType: targetType, TargetID: targetID, Detail: detail})
	return err
}

// Kind classifies an Error; the API maps it to 403, 404, 409 or 422.
type Kind int

// Error kinds.
const (
	NotFound Kind = iota + 1
	Conflict
	Invalid
	Forbidden
)

// Error is a refused operation. Code is the API's "error" field; Extra is
// merged into the response body.
type Error struct {
	Kind  Kind
	Code  string
	Msg   string
	Extra map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func notFound(format string, args ...any) *Error {
	return &Error{Kind: NotFound, Code: "not_found", Msg: fmt.Sprintf(format, args...)}
}

func conflict(code, format string, args ...any) *Error {
	return &Error{Kind: Conflict, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func invalid(code, format string, args ...any) *Error {
	return &Error{Kind: Invalid, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func withExtra(e *Error, k string, v any) *Error {
	if e.Extra == nil {
		e.Extra = map[string]any{}
	}
	e.Extra[k] = v
	return e
}

// wrap maps the naming and store errors an operation can meet to an Error.
func wrap(err error) error {
	var ne *naming.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ne):
		return &Error{Kind: Invalid, Code: ne.Code, Msg: ne.Msg}
	case errors.Is(err, store.ErrVersionConflict):
		return conflict("version_conflict", "the object changed since it was read; reload it and retry")
	}
	return err
}

func checkText(field, s string, max int) error {
	if len(s) > max {
		return invalid("invalid_"+field, "%s is at most %d characters", field, max)
	}
	return nil
}

// ---------------------------------------------------------------- vocabularies

// Attribute definition types (G-43).
var AttrTypes = []string{store.AttrTypeAttr, store.AttrTypeLimit, store.AttrTypePerm, store.AttrTypeType, store.AttrTypeService}

// Value types of a definition.
var ValueTypes = []string{store.AttrValueMarker, store.AttrValueString, store.AttrValueInteger, store.AttrValueFloating,
	store.AttrValueTimestamp, store.AttrValueMemberID}

// OwnerTypes are the owner types a definition may list in assign_to. Of them an
// effective membership is read-only: no assignment can be made on one.
var OwnerTypes = []string{store.AttrOwnerFolder, store.AttrOwnerGroup, store.AttrOwnerIdentity, store.AttrOwnerMembership,
	store.AttrOwnerEffectiveMembership, store.AttrOwnerAttrDef, store.AttrOwnerAssignment}
