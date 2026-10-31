package policybundle

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// ErrEntitlementAbsent: the role file does not list the entitlement.
var ErrEntitlementAbsent = errors.New("policybundle: the role does not list the entitlement")

// ErrRoleUnreadable: the text is not a role file the strict reader accepts (not YAML, an unknown field, an anchor, a
// second document, or another schema). The wrapped error says why.
var ErrRoleUnreadable = errors.New("policybundle: the role file cannot be read")

// RemoveRoleEntitlement returns the roles/<key>.yaml text without entitlement (a system:name reference). The file is read
// with the loader's strict reader (unknown fields, anchors and a second document are refused) and written as the roles
// export writes it, so an edited file loads and plans like any other. Comments in the file are not kept.
func RemoveRoleEntitlement(text []byte, entitlement string) ([]byte, error) {
	var r Role
	if err := decode(text, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRoleUnreadable, err)
	}
	if r.Schema != TagRole {
		return nil, fmt.Errorf("%w: schema is %q; expected %q", ErrRoleUnreadable, r.Schema, TagRole)
	}
	kept := make([]string, 0, len(r.Entitlements))
	found := false
	for _, e := range r.Entitlements {
		if e == entitlement {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return nil, ErrEntitlementAbsent
	}
	r.Entitlements = kept
	return yaml.Marshal(r)
}

// NormalizeRole is the role file as Tessera writes it back: decoded with the strict reader and rendered again, so
// comments and formatting that the renderer does not reproduce are gone. It fails as RemoveRoleEntitlement does when the
// file is not a role Tessera can read.
func NormalizeRole(text []byte) ([]byte, error) {
	var r Role
	if err := decode(text, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRoleUnreadable, err)
	}
	if r.Schema != TagRole {
		return nil, fmt.Errorf("%w: schema is %q; expected %q", ErrRoleUnreadable, r.Schema, TagRole)
	}
	return yaml.Marshal(r)
}
