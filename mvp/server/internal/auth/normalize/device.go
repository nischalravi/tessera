package normalize

import (
	"encoding/json"
	"strings"
)

// Device is what the IdP asserted about the device the user signed in from
// (issue #163): whether it is managed, and whether it is compliant. nil means
// the IdP said nothing, which is not the same as "no".
//
// The claims are read from the validated ID token (OIDC) or the verified
// assertion's attributes (SAML), by the names in the connection's
// authn_mapping (device_managed_claim, device_compliant_claim; defaults
// device_managed and device_compliant). A value is a boolean, or one of the
// strings true/false, managed/unmanaged, compliant/non_compliant
// (non-compliant, noncompliant).
type Device struct {
	Managed   *bool `json:"managed,omitempty"`
	Compliant *bool `json:"compliant,omitempty"`
}

// Default claim names for the device claims.
const (
	DefaultDeviceManagedClaim   = "device_managed"
	DefaultDeviceCompliantClaim = "device_compliant"
)

// IsZero reports whether the IdP asserted nothing.
func (d Device) IsZero() bool { return d.Managed == nil && d.Compliant == nil }

// JSON is the stored form of d, or nil when the IdP asserted nothing.
func (d Device) JSON() *string {
	if d.IsZero() {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil // two optional booleans cannot fail to encode
	}
	s := string(b)
	return &s
}

// ParseDevice reads the stored form; anything unreadable is "nothing asserted".
func ParseDevice(s *string) Device {
	var d Device
	if s == nil || *s == "" {
		return d
	}
	if err := json.Unmarshal([]byte(*s), &d); err != nil {
		return Device{}
	}
	return d
}

func parseDeviceBool(v string) *bool {
	var b bool
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "managed", "compliant":
		b = true
	case "false", "unmanaged", "non_compliant", "non-compliant", "noncompliant":
	default:
		return nil
	}
	return &b
}

// deviceFrom reads the device claims of c under mapping m.
func deviceFrom(m Mapping, c Claims) Device {
	managed, compliant := m.DeviceManagedClaim, m.DeviceCompliantClaim
	if managed == "" {
		managed = DefaultDeviceManagedClaim
	}
	if compliant == "" {
		compliant = DefaultDeviceCompliantClaim
	}
	if c.Attributes != nil { // SAML: the first value of the attribute
		first := func(name string) *bool {
			if v := c.Attributes[name]; len(v) > 0 {
				return parseDeviceBool(v[0])
			}
			return nil
		}
		return Device{Managed: first(managed), Compliant: first(compliant)}
	}
	var raw map[string]json.RawMessage
	if len(c.Raw) == 0 || json.Unmarshal(c.Raw, &raw) != nil {
		return Device{}
	}
	get := func(name string) *bool {
		v, ok := raw[name]
		if !ok {
			return nil
		}
		var b bool
		if json.Unmarshal(v, &b) == nil {
			return &b
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			return parseDeviceBool(s)
		}
		return nil
	}
	return Device{Managed: get(managed), Compliant: get(compliant)}
}
