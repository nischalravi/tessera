package devidp

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"

	"go.yaml.in/yaml/v3"
)

//go:embed users.yaml
var defaultUsersYAML []byte

// maxUsersFile caps the users file so a mistake cannot exhaust memory.
const maxUsersFile = 1 << 20

// User is one entry of users.yaml.
type User struct {
	Sub            string   `yaml:"sub"`
	Email          string   `yaml:"email"`
	Name           string   `yaml:"name"`
	Tenant         string   `yaml:"tenant"`
	Groups         []string `yaml:"groups"`
	Roles          []string `yaml:"roles"`
	Authenticators []Method `yaml:"authenticators"`
	// Device is the device posture the IdP asserts for the user, emitted as
	// the device_managed and device_compliant claims (SAML attributes of the
	// same names); nil emits none. Conditional access (issue #163) reads them.
	Device *Device `yaml:"device"`
}

// Device is a user's device posture; a nil field is not asserted.
type Device struct {
	Managed   *bool `yaml:"managed"`
	Compliant *bool `yaml:"compliant"`
}

// DefaultUsers returns the embedded users.yaml.
func DefaultUsers() ([]User, error) { return ParseUsers(defaultUsersYAML) }

// ParseUsers decodes and validates a users file: unknown fields are rejected,
// subjects are unique, and every authenticator is a known method.
func ParseUsers(b []byte) ([]User, error) {
	if len(b) > maxUsersFile {
		return nil, fmt.Errorf("users file is larger than %d bytes", maxUsersFile)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var users []User
	if err := dec.Decode(&users); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("users file is empty")
		}
		return nil, fmt.Errorf("users file: %w", err)
	}
	if len(users) == 0 {
		return nil, errors.New("users file has no users")
	}
	seen := map[string]bool{}
	for i, u := range users {
		switch {
		case u.Sub == "":
			return nil, fmt.Errorf("user %d: sub is required", i)
		case seen[u.Sub]:
			return nil, fmt.Errorf("user %q: duplicate sub", u.Sub)
		case u.Email == "" || u.Name == "" || u.Tenant == "":
			return nil, fmt.Errorf("user %q: email, name and tenant are required", u.Sub)
		case len(u.Authenticators) == 0:
			return nil, fmt.Errorf("user %q: at least one authenticator is required", u.Sub)
		}
		for _, m := range u.Authenticators {
			if !slices.Contains(Methods(), m) {
				return nil, fmt.Errorf("user %q: unknown authenticator %q (have %v)", u.Sub, m, Methods())
			}
		}
		seen[u.Sub] = true
	}
	return users, nil
}

func (u *User) has(m Method) bool { return slices.Contains(u.Authenticators, m) }
