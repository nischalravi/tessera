// Package cfgerr is the refused-change error of the tenant configuration
// packages (issue #298: SoD page, step-up policy, review types, preferences,
// organization settings). Code is stable for API clients; the API renders it with
// Status.
package cfgerr

import "fmt"

// Error is a refused change.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// Refuse builds an Error.
func Refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Conflict is the 409 of a save made against a settings version that has moved on.
func Conflict(read, cur int) error {
	return Refuse(409, "version_conflict", "the settings changed since version %d (now %d); reload them", read, cur)
}
