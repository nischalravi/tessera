// Package tenancy defines the tenant identifier.
//
// A tenancy.ID is deliberately a distinct type with no exported field and no
// conversion from uuid.UUID or string other than Parse, so the compiler stops
// a user, identity or row id being passed where a tenant id belongs. The zero
// value is invalid: store.InTenant rejects it (fail closed).
//
// The package does not implement driver.Valuer or sql.Scanner: only
// internal/store may import database/sql (enforced by internal/archtest), and
// it binds String() and reads values back with Parse.
package tenancy

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ID identifies a tenant. The zero value is invalid.
type ID struct{ u uuid.UUID }

// Platform is the reserved "_platform" tenant. It owns events that have no
// tenant (operator actions, isolation violations such as a missing tenant
// context).
var Platform = MustParse("00000000-0000-0000-0000-000000000001")

// ErrInvalid is returned by Parse for anything that is not a canonical,
// non-nil UUID.
var ErrInvalid = errors.New("tenancy: invalid tenant id")

// Parse parses the canonical lower-case UUID form. It is meant for values read
// back from trusted rows (a tenants row, a session row, a verified token) and
// for fixed ids in seed data. The nil UUID is rejected.
func Parse(s string) (ID, error) {
	u, err := uuid.Parse(s)
	if err != nil || u == uuid.Nil || u.String() != s {
		return ID{}, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	return ID{u}, nil
}

// MustParse is Parse that panics; for package-level constants only.
func MustParse(s string) ID {
	id, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

// New returns a fresh random (v4) tenant id.
func New() ID { return ID{uuid.New()} }

// String returns the canonical lower-case UUID ("" for the zero value).
func (id ID) String() string {
	if id.IsZero() {
		return ""
	}
	return id.u.String()
}

// IsZero reports whether id is the invalid zero value.
func (id ID) IsZero() bool { return id.u == uuid.Nil }
