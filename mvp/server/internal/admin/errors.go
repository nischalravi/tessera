package admin

import (
	"fmt"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
)

// Error is a refusal the API renders as {"error": Code, "detail": Msg} with
// Status, or, when Denial is set, as the step-up / forbidden contract of
// design §16.2 (auth.WriteDenial).
type Error struct {
	Status int
	Code   string
	Msg    string
	Denial *auth.Denial
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func newErr(status int, code, format string, a ...any) *Error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

func invalid(format string, a ...any) *Error {
	return newErr(http.StatusUnprocessableEntity, "invalid_payload", format, a...)
}

func conflict(code, format string, a ...any) *Error {
	return newErr(http.StatusConflict, code, format, a...)
}

func notFound(what string) *Error {
	return newErr(http.StatusNotFound, "not_found", "no such %s", what)
}

// denied turns an authorization refusal into an Error carrying it.
func denied(d *auth.Denial) *Error {
	return &Error{Status: d.Status, Code: d.Error, Msg: d.Error, Denial: d}
}
