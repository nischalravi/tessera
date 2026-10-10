// Package canon is the byte-level contract of the audit hash chain, version 1
// (docs/design/phase-0-platform-security.md §13.2): the genesis hash, the
// hashed body, its RFC 8785 (JCS) canonicalization and the rules for the
// free-form detail object.
//
// It is a leaf package (it imports neither the store nor the audit package),
// so the store can stamp hashes inside the same transaction as the change an
// event describes, and any other verifier can reproduce a hash from an
// exported event alone: hash = SHA-256("tessera-audit-v1" 0x00 ||
// JCS(body)), lower-case hex. testdata/golden/audit_v1.json in the server
// module is the cross-language test vector.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// Version is the hash body version ("v").
const Version = 1

// TimeLayout is the timestamp format inside hashed bodies and detail values:
// UTC with exactly six fractional digits.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

// MaxSafeInt is the largest integer magnitude allowed in a detail object
// (2^53 - 1), so every JCS implementation reads it back exactly.
const MaxSafeInt = 1<<53 - 1

// MaxDetailBytes caps an encoded detail object.
const MaxDetailBytes = 64 << 10

const (
	hashDomain    = "tessera-audit-v1\x00"
	genesisPrefix = "tessera-audit-genesis-v1:"
)

// Actor is who did it. Type is user | api_client | system | operator | anonymous.
type Actor struct {
	Type    string  `json:"type"`
	ID      *string `json:"id"`
	Display *string `json:"display"`
}

// Target is what it was done to.
type Target struct {
	Type *string `json:"type"`
	ID   *string `json:"id"`
}

// Authn is the authentication context of the actor (from PR5 on).
type Authn struct {
	CtxID    *string `json:"ctx_id"`
	AAL      *int    `json:"aal"`
	Phr      *bool   `json:"phr"`
	ACR      *string `json:"acr"`
	AuthTime *string `json:"auth_time"`
	AuthAgeS *int64  `json:"auth_age_s"`
}

// HTTP describes the request of an http.request event. Route is the
// registered pattern, never the raw path; QueryKeys holds sorted keys only.
type HTTP struct {
	Method     string            `json:"method"`
	Route      *string           `json:"route"`
	PathParams map[string]string `json:"path_params"`
	QueryKeys  []string          `json:"query_keys"`
	Status     int               `json:"status"`
	LatencyMS  int64             `json:"latency_ms"`
}

// Body is exactly what is hashed. Field names are the JSON keys; JCS sorts
// them. Authn, HTTP and Detail are JSON values (null when absent; Detail is
// an object).
type Body struct {
	V             int             `json:"v"`
	TenantID      string          `json:"tenant_id"`
	Seq           int64           `json:"seq"`
	ID            string          `json:"id"`
	OccurredAt    string          `json:"occurred_at"`
	Actor         Actor           `json:"actor"`
	SessionID     *string         `json:"session_id"`
	ClientID      *string         `json:"client_id"`
	Authn         json.RawMessage `json:"authn"`
	Action        string          `json:"action"`
	Target        Target          `json:"target"`
	Outcome       string          `json:"outcome"`
	RequestID     *string         `json:"request_id"`
	HTTP          json.RawMessage `json:"http"`
	IP            *string         `json:"ip"`
	UA            *string         `json:"ua"`
	PolicyVersion *string         `json:"policy_version"`
	Detail        json.RawMessage `json:"detail"`
	PrevHash      string          `json:"prev_hash"`
}

// Genesis is the prev_hash of a tenant's first event.
func Genesis(tenantID string) string {
	sum := sha256.Sum256([]byte(genesisPrefix + tenantID))
	return hex.EncodeToString(sum[:])
}

// Canonical returns the RFC 8785 canonical form of b.
func Canonical(b Body) ([]byte, error) {
	if len(b.Detail) == 0 {
		return nil, errors.New("canon: detail must be a JSON object")
	}
	raw, err := json.Marshal(b) // nil RawMessages and pointers serialize as null
	if err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	return out, nil
}

// Hash returns the event hash of b: lower-case hex SHA-256 over the domain
// separator and the canonical body.
func Hash(b Body) (string, error) {
	c, err := Canonical(b)
	if err != nil {
		return "", err
	}
	return HashCanonical(c), nil
}

// HashCanonical hashes an already canonical body.
func HashCanonical(canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(hashDomain))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// FormatTime renders t in TimeLayout (UTC, microseconds).
func FormatTime(t time.Time) string { return t.UTC().Format(TimeLayout) }

// ParseTime parses a TimeLayout timestamp.
func ParseTime(s string) (time.Time, error) { return time.Parse(TimeLayout, s) }

// IsHash reports whether s looks like an event hash (64 lower-case hex digits).
func IsHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ErrDetail is wrapped by every detail validation error.
var ErrDetail = errors.New("canon: detail value not allowed")

// Detail validates a detail object and encodes it (member order kept, for
// display; the hash does not depend on order). Allowed values: string, bool,
// nil, integers within ±(2^53-1), time.Time (rendered in TimeLayout),
// fmt.Stringer (rendered with String), objects (ojson.Object, map[string]V)
// and slices of those, and structs or json.Marshalers whose JSON encoding
// holds only those. Floats are refused, so every JCS
// implementation reproduces the hash. nil encodes as {}.
func Detail(v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("{}"), nil
	}
	n, err := normalize(v, 0)
	if err != nil {
		return nil, err
	}
	switch n.(type) {
	case ojson.Object:
	default:
		return nil, fmt.Errorf("%w: detail must be an object, got %T", ErrDetail, v)
	}
	b, err := ojson.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDetail, err)
	}
	if len(b) > MaxDetailBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrDetail, len(b), MaxDetailBytes)
	}
	return b, nil
}

// DetailJSON validates an already encoded detail object (from the database or
// an export) against the same rules.
func DetailJSON(raw []byte) (json.RawMessage, error) {
	v, err := ojson.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDetail, err)
	}
	return Detail(v)
}

const maxDepth = 32

func normalize(v any, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested deeper than %d", ErrDetail, maxDepth)
	}
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return x, nil
	case bool:
		return x, nil
	case int:
		return checkInt(int64(x))
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return checkInt(x)
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint:
		if uint64(x) > MaxSafeInt {
			return nil, fmt.Errorf("%w: integer %d outside ±2^53", ErrDetail, x)
		}
		return int64(x), nil // #nosec G115 -- range checked above
	case uint64:
		if x > MaxSafeInt {
			return nil, fmt.Errorf("%w: integer %d outside ±2^53", ErrDetail, x)
		}
		return int64(x), nil // #nosec G115 -- range checked above
	case json.Number:
		i, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: number %s is not an integer", ErrDetail, x)
		}
		return checkInt(i)
	case float32, float64, ojson.Float:
		return nil, fmt.Errorf("%w: floats are not allowed (got %v); use an integer or a string", ErrDetail, x)
	case time.Time:
		return FormatTime(x), nil
	case json.RawMessage:
		d, err := ojson.Decode(x)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDetail, err)
		}
		return normalize(d, depth+1)
	case ojson.Object:
		out := make(ojson.Object, 0, len(x))
		seen := make(map[string]bool, len(x))
		for _, kv := range x {
			if seen[kv.Key] {
				return nil, fmt.Errorf("%w: duplicate key %q", ErrDetail, kv.Key)
			}
			seen[kv.Key] = true
			nv, err := normalize(kv.Value, depth+1)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", kv.Key, err)
			}
			out = append(out, ojson.KV{Key: kv.Key, Value: nv})
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			nv, err := normalize(e, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	case json.Marshaler:
		return viaJSON(x, depth)
	case fmt.Stringer:
		return x.String(), nil
	}
	// maps with string keys and other slices, by reflection
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("%w: map keys must be strings (%T)", ErrDetail, v)
		}
		keys := rv.MapKeys()
		names := make([]string, len(keys))
		for i, k := range keys {
			names[i] = k.String()
		}
		slices.Sort(names)
		out := make(ojson.Object, 0, len(names))
		for _, k := range names {
			nv, err := normalize(rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key())).Interface(), depth+1)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out = append(out, ojson.KV{Key: k, Value: nv})
		}
		return out, nil
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return []any{}, nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			nv, err := normalize(rv.Index(i).Interface(), depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	case reflect.Pointer:
		if rv.IsNil() {
			return nil, nil
		}
		return normalize(rv.Elem().Interface(), depth+1)
	case reflect.Struct:
		return viaJSON(v, depth)
	}
	return nil, fmt.Errorf("%w: %T", ErrDetail, v)
}

// viaJSON normalizes a struct or json.Marshaler through its JSON encoding, so
// its numbers are checked like any other (a float field is refused).
func viaJSON(v any, depth int) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %T: %v", ErrDetail, v, err)
	}
	d, err := ojson.Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %T: %v", ErrDetail, v, err)
	}
	return normalize(d, depth+1)
}

func checkInt(i int64) (any, error) {
	if i > MaxSafeInt || i < -MaxSafeInt {
		return nil, fmt.Errorf("%w: integer %d outside ±2^53", ErrDetail, i)
	}
	return i, nil
}

// Equal reports whether two JSON values are equal after canonicalization.
func Equal(a, b []byte) bool {
	ca, err1 := jcs.Transform(a)
	cb, err2 := jcs.Transform(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}
