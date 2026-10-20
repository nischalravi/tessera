package privs

import "fmt"

// Kind classifies an Error; the API maps it to 403, 404, 409 or 422.
type Kind int

// Error kinds.
const (
	NotFound Kind = iota + 1
	Conflict
	Invalid
	Forbidden
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

func notFound(format string, args ...any) *Error {
	return &Error{Kind: NotFound, Code: "not_found", Msg: fmt.Sprintf(format, args...)}
}

func conflict(code, format string, args ...any) *Error {
	return &Error{Kind: Conflict, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func invalid(code, format string, args ...any) *Error {
	return &Error{Kind: Invalid, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func forbidden(code, format string, args ...any) *Error {
	return &Error{Kind: Forbidden, Code: code, Msg: fmt.Sprintf(format, args...)}
}
