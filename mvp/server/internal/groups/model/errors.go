package model

import (
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Kind classifies an Error; the API maps it to 404, 409 or 422.
type Kind int

// Error kinds.
const (
	NotFound Kind = iota + 1
	Conflict
	Invalid
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

// wrap maps the naming and store errors an operation can meet to an Error.
func wrap(err error) error {
	var ne *naming.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ne):
		if ne.Code == naming.CodeInvalidName {
			return &Error{Kind: Invalid, Code: ne.Code, Msg: ne.Msg}
		}
		return &Error{Kind: Conflict, Code: ne.Code, Msg: ne.Msg}
	case errors.Is(err, store.ErrVersionConflict):
		return conflict("version_conflict", "the object changed since it was read; reload it and retry")
	}
	return err
}
