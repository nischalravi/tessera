package attrs

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Values (G-46). A value is typed by its definition: string, integer,
// timestamp (RFC 3339), member id (an identity of the tenant) or floating.
//
// A floating value is a decimal string, never a float: it is sent and returned
// as a JSON string, stored as text in value_string, and canonicalized ("1.50" is
// "1.5") so the audit hash and the change events carry the same bytes whatever
// the platform's float formatting. A JSON number for a floating attribute is
// refused, and so is a fraction or an exponent for an integer.

var (
	intRE   = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,18})$`)
	floatRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
)

// maxFloatLen bounds a decimal string.
const maxFloatLen = 40

// CanonicalFloat returns the canonical form of a decimal string: an optional
// minus sign, digits, and a fraction with no trailing zeros ("-0" is "0").
// Exponents, "NaN", "Inf" and anything else are refused.
func CanonicalFloat(s string) (string, error) {
	if len(s) > maxFloatLen || !floatRE.MatchString(s) {
		return "", invalid("invalid_value", "a floating value is a decimal string such as \"12.5\" (at most %d characters, no exponent)", maxFloatLen)
	}
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	if s == "-0" {
		s = "0"
	}
	return s, nil
}

func isNumberToken(raw []byte) bool {
	return len(raw) > 0 && (raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9'))
}

// ParseValue reads one JSON value of a definition's type. It reads the raw JSON,
// not a decoded float64, so a number is judged by its text.
func ParseValue(tx *store.TenantTx, def *store.GrpAttrDef, raw json.RawMessage) (*store.GrpAttrValue, error) {
	raw = bytes.TrimSpace(raw)
	bad := func(format string, args ...any) error { return invalid("invalid_value", format, args...) }
	str := func() (string, error) {
		var s string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
			return "", bad("a %s value is a JSON string", def.ValueType)
		}
		return s, nil
	}
	v := &store.GrpAttrValue{}
	switch def.ValueType {
	case store.AttrValueMarker:
		return nil, invalid("marker_has_no_values", "a marker attribute has no values")
	case store.AttrValueString:
		s, err := str()
		if err != nil {
			return nil, err
		}
		if s == "" || len(s) > MaxValueLen || !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return nil, bad("a string value is 1 to %d characters of text with no control characters", MaxValueLen)
		}
		v.ValueString, v.Key = &s, "s:"+s
	case store.AttrValueFloating:
		if isNumberToken(raw) {
			return nil, invalid("float_must_be_string", "send a floating value as a decimal string (\"12.5\"), not a JSON number")
		}
		s, err := str()
		if err != nil {
			return nil, err
		}
		if s, err = CanonicalFloat(s); err != nil {
			return nil, err
		}
		v.ValueString, v.Key = &s, "f:"+s
	case store.AttrValueInteger, store.AttrValueMemberID:
		if !isNumberToken(raw) || !intRE.Match(raw) {
			return nil, bad("a %s value is a JSON integer (no fraction, exponent or quotes)", def.ValueType)
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return nil, bad("a %s value does not fit 64 bits", def.ValueType)
		}
		if def.ValueType == store.AttrValueInteger {
			v.ValueInteger, v.Key = &n, "i:"+strconv.FormatInt(n, 10)
			break
		}
		if _, err := tx.Identity(n); errors.Is(err, store.ErrNotFound) {
			return nil, invalid("unknown_identity", "no such identity: %d", n)
		} else if err != nil {
			return nil, err
		}
		v.ValueMemberID, v.Key = &n, "m:"+strconv.FormatInt(n, 10)
	case store.AttrValueTimestamp:
		s, err := str()
		if err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, bad("a timestamp value is an RFC 3339 time")
		}
		t = t.UTC()
		v.ValueTimestamp, v.Key = &t, "t:"+store.RT(t)
	default:
		return nil, bad("unknown value type %q", def.ValueType)
	}
	return v, nil
}

// ParseValues reads the values of one assignment and applies the definition's
// limits: a marker has none, a single-valued attribute at most one, and no
// assignment more than MaxValues or the same value twice.
func ParseValues(tx *store.TenantTx, def *store.GrpAttrDef, raws []json.RawMessage) ([]*store.GrpAttrValue, error) {
	switch {
	case def.ValueType == store.AttrValueMarker && len(raws) > 0:
		return nil, invalid("marker_has_no_values", "a marker attribute has no values")
	case !def.MultiValued && len(raws) > 1:
		return nil, invalid("single_valued", "the attribute %q takes one value", def.Name())
	case len(raws) > MaxValues:
		return nil, invalid("too_many_values", "an assignment has at most %d values", MaxValues)
	}
	out := make([]*store.GrpAttrValue, 0, len(raws))
	seen := map[string]bool{}
	for i, raw := range raws {
		v, err := ParseValue(tx, def, raw)
		if err != nil {
			return nil, err
		}
		if seen[v.Key] {
			return nil, invalid("duplicate_value", "the value %q is given twice", v.Key[2:])
		}
		seen[v.Key] = true
		v.Position = i
		out = append(out, v)
	}
	return out, nil
}

// JSON is a value as the API returns it: a string for a string, floating or
// timestamp value, an integer for an integer or member id.
func JSON(v *store.GrpAttrValue) any {
	switch {
	case v.ValueString != nil:
		return *v.ValueString
	case v.ValueInteger != nil:
		return *v.ValueInteger
	case v.ValueMemberID != nil:
		return *v.ValueMemberID
	case v.ValueTimestamp != nil:
		return store.RT(*v.ValueTimestamp)
	}
	return nil
}

// Keys returns the canonical keys of a list of values (what events and audit
// events carry).
func Keys(vs []*store.GrpAttrValue) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Key
	}
	return out
}
