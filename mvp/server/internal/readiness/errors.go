package readiness

import (
	"fmt"
	"net/http"
)

// Error is a refused readiness operation with its HTTP status and a stable
// machine-readable code. A refused transition carries the gate report.
type Error struct {
	Status int
	Code   string
	Msg    string
	Report *GateReport
	Fields []FieldError
	Extra  map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func newErr(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func notFound(format string, args ...any) *Error {
	return newErr(http.StatusNotFound, "not_found", format, args...)
}

func unprocessable(code, format string, args ...any) *Error {
	return newErr(http.StatusUnprocessableEntity, code, format, args...)
}

func conflict(code, format string, args ...any) *Error {
	return newErr(http.StatusConflict, code, format, args...)
}

func blocked(code string, g *GateReport) *Error {
	g.Error = code
	return &Error{Status: http.StatusConflict, Code: code, Msg: fmt.Sprintf("%d blocking item(s)", len(g.Blocking)), Report: g}
}
