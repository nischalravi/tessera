// Package gov holds what the governance parts of native groups share (issue
// #57, GR-14): the error type of attestation, deprovisioning, the Inbox and
// reports, which the API maps to 403, 404, 409 or 422.
package gov

import "fmt"

// Kind classifies an Error.
type Kind int

// Error kinds.
const (
	KindNotFound Kind = iota + 1
	KindConflict
	KindInvalid
	KindForbidden
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

// NotFound is a 404.
func NotFound(format string, args ...any) *Error {
	return &Error{Kind: KindNotFound, Code: "not_found", Msg: fmt.Sprintf(format, args...)}
}

// Conflict is a 409 with its own code.
func Conflict(code, format string, args ...any) *Error {
	return &Error{Kind: KindConflict, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Invalid is a 422 with its own code.
func Invalid(code, format string, args ...any) *Error {
	return &Error{Kind: KindInvalid, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Forbidden is a 403 with its own code.
func Forbidden(code, format string, args ...any) *Error {
	return &Error{Kind: KindForbidden, Code: code, Msg: fmt.Sprintf(format, args...)}
}
