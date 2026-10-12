// Package identifiers normalizes and hashes the identifiers a person is known
// by (guest design §5.3 and §9.1, issue #64). Matching compares keyed hashes,
// so a lookup never needs the value, and a stolen copy of the table cannot be
// checked against a list of guesses without the tenant's key.
//
// The key is derived from the KEK per tenant (HKDF, label
// "identifier-hmac/<tenant>"), so one tenant's hashes mean nothing in
// another, and it is never stored. The hash covers the type and issuer as
// well as the value, so an employee id and a student id with the same text
// do not collide.
package identifiers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// MaxValue caps an identifier's length (an email address is at most 254).
const MaxValue = 320

// Types lists the identifier types in display order.
var Types = []string{store.IdentEmail, store.IdentPhone, store.IdentEmployeeID, store.IdentStudentID,
	store.IdentApplicantID, store.IdentNetID, store.IdentEPPN, store.IdentSAMLSubject, store.IdentSAMLPairwise,
	store.IdentOIDCSub, store.IdentNationalHMAC}

// Valid reports whether typ is an identifier type.
func Valid(typ string) bool {
	for _, t := range Types {
		if t == typ {
			return true
		}
	}
	return false
}

// HashedOnly reports whether the value of typ is never stored, only its hash.
func HashedOnly(typ string) bool { return typ == store.IdentNationalHMAC }

// Federated reports whether typ names a subject at an issuer: the pair
// (issuer, value) is the identifier, never the value alone (design §6.6).
func Federated(typ string) bool {
	switch typ {
	case store.IdentSAMLSubject, store.IdentSAMLPairwise, store.IdentOIDCSub, store.IdentEPPN:
		return true
	}
	return false
}

// Normalize returns the canonical form of value for typ, or an error that is
// safe to show (it never echoes the value).
//
//   - email, eppn, netid, employee_id, student_id, applicant_id, saml_*:
//     trimmed and lower-cased (SAML subject ids are case-insensitive by
//     specification). email needs exactly one "@" with text on both sides;
//     eppn must be scoped (user@scope), an unscoped eppn is refused.
//   - oidc_sub: trimmed only; subjects are case-sensitive.
//   - phone: digits with an optional leading "+", separators removed, 7 to 15 digits.
//   - national_id_hmac: letters and digits, upper-cased, separators removed.
func Normalize(typ, value string) (string, error) {
	if !Valid(typ) {
		return "", fmt.Errorf("unknown identifier type %q", typ)
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "", errors.New("identifier is empty")
	}
	if len(v) > MaxValue || !utf8.ValidString(v) {
		return "", errors.New("identifier is too long or not valid text")
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "", errors.New("identifier contains control characters")
		}
	}
	switch typ {
	case store.IdentOIDCSub:
		return v, nil
	case store.IdentPhone:
		return normalizePhone(v)
	case store.IdentNationalHMAC:
		return normalizeNational(v)
	case store.IdentEmail, store.IdentEPPN:
		v = strings.ToLower(v)
		at := strings.Index(v, "@")
		if at <= 0 || at != strings.LastIndex(v, "@") || at == len(v)-1 || strings.ContainsAny(v, " \t") {
			if typ == store.IdentEPPN {
				return "", errors.New("eppn must be scoped (user@scope)")
			}
			return "", errors.New("email must be local@domain")
		}
		return v, nil
	}
	return strings.ToLower(v), nil
}

func normalizePhone(v string) (string, error) {
	var b strings.Builder
	for i, r := range v {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '.' || r == '(' || r == ')':
		default:
			return "", errors.New("phone has characters other than digits and separators")
		}
	}
	out := b.String()
	if n := len(strings.TrimPrefix(out, "+")); n < 7 || n > 15 {
		return "", errors.New("phone must have 7 to 15 digits")
	}
	return out, nil
}

func normalizeNational(v string) (string, error) {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			b.WriteRune(unicode.ToUpper(r))
		case r == ' ' || r == '-':
		default:
			return "", errors.New("national id has characters other than letters, digits and separators")
		}
	}
	if b.Len() < 4 {
		return "", errors.New("national id is too short")
	}
	return b.String(), nil
}

// CheckIssuer enforces that federated types carry the issuer they are
// scoped to, and that an issuer is plain text.
func CheckIssuer(typ, issuer string) error {
	if issuer != strings.TrimSpace(issuer) || len(issuer) > 512 {
		return errors.New("issuer is not trimmed or too long")
	}
	for _, r := range issuer {
		if unicode.IsControl(r) {
			return errors.New("issuer contains control characters")
		}
	}
	if Federated(typ) && issuer == "" {
		return fmt.Errorf("%s needs the issuer it was asserted by", typ)
	}
	return nil
}

// Keyer computes identifier hashes under per-tenant keys derived from the KEK.
type Keyer struct{ sealer *seal.Sealer }

// NewKeyer returns a Keyer over the KEK sealer.
func NewKeyer(s *seal.Sealer) *Keyer { return &Keyer{sealer: s} }

// String and GoString keep the sealer out of logs.
func (k *Keyer) String() string { return "identifiers.Keyer{REDACTED}" }

// GoString is String.
func (k *Keyer) GoString() string { return k.String() }

// Prepare validates and normalizes an identifier and returns the value to
// store (nil for hashed-only types) with its hash.
func (k *Keyer) Prepare(tenant tenancy.ID, typ, issuer, value string) (norm *string, mac string, err error) {
	if k == nil || k.sealer == nil {
		return nil, "", errors.New("identifiers: no key")
	}
	n, err := Normalize(typ, value)
	if err != nil {
		return nil, "", err
	}
	if err := CheckIssuer(typ, issuer); err != nil {
		return nil, "", err
	}
	key, err := k.sealer.DeriveKey("identifier-hmac/"+tenant.String(), 32)
	if err != nil {
		return nil, "", err
	}
	h := hmac.New(sha256.New, key)
	// NUL separates the fields: none of them can contain it (control characters are refused).
	h.Write([]byte(typ + "\x00" + issuer + "\x00" + n))
	mac = hex.EncodeToString(h.Sum(nil))
	if HashedOnly(typ) {
		return nil, mac, nil
	}
	return &n, mac, nil
}
