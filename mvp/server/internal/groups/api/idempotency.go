// Package api holds what the groups REST API needs that is not tied to net/http
// (issue #48, GR-5; design docs/design/groups-grouper-parity.md §10.11):
// idempotency keys, the read-only SCIM resources and filter, and the OpenAPI
// document of the groups routes. The handlers themselves are in internal/api
// (groups_*.go, scim.go), next to the routing, authentication and audit they
// depend on, as the other group routes are.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// IdempotencyTTL is how long a stored answer is replayed.
const IdempotencyTTL = 24 * time.Hour

// MaxKeyLen bounds an Idempotency-Key.
const MaxKeyLen = 255

var keyRE = regexp.MustCompile(`^[A-Za-z0-9._~:+=-]{1,255}$`)

// ValidKey reports whether k is an acceptable Idempotency-Key: 1 to 255
// characters of letters, digits and . _ ~ : + = -.
func ValidKey(k string) bool { return keyRE.MatchString(k) }

// ErrKeyReused is returned when a key is presented again with a different request.
var ErrKeyReused = errors.New("idempotency key used with a different request")

// Key identifies a keyed request: the caller, the key and a fingerprint of the
// request. Principal is "user:<id>" or "client:<id>", so a key is private to the
// caller that made it (and, through the transaction, to the tenant).
type Key struct {
	Principal string
	Key       string
	Hash      string
}

// RequestHash fingerprints a request: its method, its path with the ids it
// names, and its body.
func RequestHash(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Replay is a stored answer.
type Replay struct {
	Status int
	Body   []byte
}

// Lookup returns the stored answer of the key, or nil when there is none (or it
// has expired). It first purges the tenant's expired keys, so the table does not
// grow without bound. The same key with another request is ErrKeyReused. It must
// run in a write transaction.
func Lookup(tx *store.TenantTx, now time.Time, k Key) (*Replay, error) {
	if _, err := tx.PurgeGrpIdempotency(now); err != nil {
		return nil, err
	}
	x, err := tx.GrpIdempotency(k.Principal, k.Key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if x.RequestHash != k.Hash {
		return nil, ErrKeyReused
	}
	return &Replay{Status: x.Status, Body: []byte(x.Body)}, nil
}

// Save stores the answer of a keyed request, in the transaction of the change it describes.
func Save(tx *store.TenantTx, now time.Time, k Key, status int, body []byte) error {
	return tx.InsertGrpIdempotency(&store.Idempotency{Principal: k.Principal, Key: k.Key, RequestHash: k.Hash,
		Status: status, Body: string(body), CreatedAt: now, ExpiresAt: now.Add(IdempotencyTTL)})
}
