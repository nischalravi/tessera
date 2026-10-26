// Package target is the contract between the provisioning engine and the
// connectors that talk to a target system (a SCIM 2.0 service or a native
// API such as Okta's).
//
// A connector does two things: Apply sends one change, and Verify re-reads the
// target to see whether the change is really there. Apply returning nil only
// means the target accepted the request; the engine treats the change as done
// only when Verify agrees.
package target

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Operation kinds.
const (
	CreateAccount     = "create_account"
	UpdateAccount     = "update_account"
	DisableAccount    = "disable_account"
	DeleteAccount     = "delete_account"
	AddEntitlement    = "add_entitlement"
	RemoveEntitlement = "remove_entitlement"
)

// Kinds lists every operation kind.
var Kinds = []string{CreateAccount, UpdateAccount, DisableAccount, DeleteAccount, AddEntitlement, RemoveEntitlement}

// Account identifies the account an operation acts on.
type Account struct {
	Username    string            `json:"username"`
	ExternalID  string            `json:"external_id,omitempty"`
	Email       string            `json:"email,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	Attrs       map[string]string `json:"attrs,omitempty"` // update_account: attribute path -> new value
}

// Group identifies the entitlement of an add or remove operation.
type Group struct {
	ExternalID string `json:"external_id,omitempty"`
	Name       string `json:"name,omitempty"`
}

// Request is one change to make.
type Request struct {
	Kind string `json:"-"`
	// Key is the operation's idempotency key, sent to the target as the
	// Idempotency-Key header. Every connector also makes each change
	// idempotent by reading first, so a repeated request converges.
	Key     string  `json:"-"`
	Account Account `json:"account"`
	Group   Group   `json:"group,omitempty"`
	// AWS is the change of an AWS kind (aws.go); nil for every other.
	AWS *AWSChange `json:"aws,omitempty"`
}

// Verdict is the outcome of a re-read.
type Verdict struct {
	OK                 bool
	Expected, Observed string
	// Waiting says a person has to act (a ticket is open): the engine keeps the operation pending and re-reads
	// later without counting the wait against its verification limit.
	Waiting bool
}

// Connector applies and verifies changes in one target system.
type Connector interface {
	// Apply sends the change. It returns an *Error when the target refused it
	// or could not be reached.
	Apply(ctx context.Context, r Request) error
	// Verify re-reads the target and reports whether the change is visible.
	// An error means the read itself failed (try again later).
	Verify(ctx context.Context, r Request) (Verdict, error)
}

// Error is a failed call to a target.
type Error struct {
	Status    int  // HTTP status, 0 for a transport failure
	Retryable bool // a later attempt may succeed (transport failure, 429, 5xx)
	Msg       string
}

func (e *Error) Error() string { return e.Msg }

// Retryable reports whether err is a target error a later attempt may fix.
// Unknown errors are retryable: the engine's attempt limit ends them.
func Retryable(err error) bool {
	var te *Error
	if errors.As(err, &te) {
		return te.Retryable
	}
	return true
}

// Fail builds the Error for an unexpected status. detail is the target's own
// explanation, if it gave one; it is shortened and never contains credentials
// (the engine never puts any in a request body it echoes).
func Fail(op string, status int, detail string) *Error {
	detail = strings.Join(strings.Fields(detail), " ")
	if len(detail) > 200 {
		detail = detail[:200] + "…"
	}
	msg := fmt.Sprintf("%s: target answered HTTP %d", op, status)
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		msg = fmt.Sprintf("%s: target refused the credential (HTTP %d)", op, status)
	}
	if detail != "" {
		msg += ": " + detail
	}
	return &Error{Status: status, Retryable: status == http.StatusTooManyRequests || status >= 500, Msg: msg}
}

// Transport wraps a transport failure (retryable).
func Transport(op string, err error) *Error {
	return &Error{Retryable: true, Msg: fmt.Sprintf("%s: %v", op, err)}
}

// Permanent is an error no retry fixes (the target has no such group, the
// request is malformed).
func Permanent(format string, a ...any) *Error {
	return &Error{Msg: fmt.Sprintf(format, a...)}
}

// ReadBody reads at most limit bytes of a response body.
func ReadBody(resp *http.Response, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
