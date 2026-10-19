// Package naming holds the pure rules for native group and folder names
// (design docs/design/groups-grouper-parity.md §5, G-01..G-04): the ':' path
// syntax, the allowed characters, case-insensitive uniqueness and aliases (old
// names kept after a move or rename). It has no storage; the model layer
// supplies an Index.
package naming

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits.
const (
	Sep          = ":"
	MaxExtension = 255
	MaxName      = 1024
	MaxDisplay   = 255
	MaxDepth     = 32
)

// Error codes (the API returns them as the "error" field).
const (
	CodeInvalidName = "invalid_name"
	CodeNameTaken   = "name_taken"
	CodeNameAlias   = "name_reserved_by_alias"
)

// Error is a naming rule violation.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func invalid(format string, args ...any) *Error {
	return &Error{Code: CodeInvalidName, Msg: fmt.Sprintf(format, args...)}
}

func allowed(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.'
}

// ValidateExtension checks one path segment: 1 to 255 characters from
// [A-Za-z0-9_.-], and not "." or "..".
func ValidateExtension(ext string) error {
	switch {
	case ext == "":
		return invalid("a name segment cannot be empty")
	case len(ext) > MaxExtension:
		return invalid("a name segment is at most %d characters", MaxExtension)
	case ext == "." || ext == "..":
		return invalid("a name segment cannot be %q", ext)
	}
	for _, r := range ext {
		if !allowed(r) {
			return invalid("%q is not allowed in a name: use letters, digits, '_', '-' and '.'", string(r))
		}
	}
	return nil
}

// ValidateDisplay checks a display name or extension: at most 255 characters,
// valid UTF-8, no control characters.
func ValidateDisplay(s string) error {
	if len(s) > MaxDisplay || !utf8.ValidString(s) {
		return invalid("a display name is at most %d characters of valid UTF-8", MaxDisplay)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return invalid("a display name cannot contain control characters")
		}
	}
	return nil
}

// Parse splits a full name into validated segments. The empty name is the
// root and has no segments.
func Parse(name string) ([]string, error) {
	if name == "" {
		return nil, nil
	}
	if len(name) > MaxName {
		return nil, invalid("a name is at most %d characters", MaxName)
	}
	segs := strings.Split(name, Sep)
	if len(segs) > MaxDepth {
		return nil, invalid("a name has at most %d levels", MaxDepth)
	}
	for _, s := range segs {
		if err := ValidateExtension(s); err != nil {
			return nil, err
		}
	}
	return segs, nil
}

// Join returns the full name of a child of parent (the root's name is "").
func Join(parent, ext string) (string, error) {
	if err := ValidateExtension(ext); err != nil {
		return "", err
	}
	name := ext
	if parent != "" {
		name = parent + Sep + ext
	}
	if _, err := Parse(name); err != nil {
		return "", err
	}
	return name, nil
}

// Split returns the parent name and last segment of a full name.
func Split(name string) (parent, ext string) {
	if i := strings.LastIndex(name, Sep); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// Fold is the case-insensitive comparison key of a name. Names are ASCII, so
// it agrees with SQLite's lower().
func Fold(name string) string { return strings.ToLower(name) }

// Equal compares two names case-insensitively.
func Equal(a, b string) bool { return Fold(a) == Fold(b) }

// IsWithin reports whether name is prefix itself or below it, on a segment
// boundary, case-insensitively. The root ("") contains every name.
func IsWithin(name, prefix string) bool {
	if prefix == "" {
		return true
	}
	n, p := Fold(name), Fold(prefix)
	return n == p || strings.HasPrefix(n, p+Sep)
}

// Rebase replaces the prefix oldPrefix of name by newPrefix, keeping the rest
// of the name as written. ok is false when name is not within oldPrefix.
func Rebase(name, oldPrefix, newPrefix string) (string, bool) {
	if !IsWithin(name, oldPrefix) {
		return "", false
	}
	rest := name[len(oldPrefix):] // empty, or starts with ':'
	if oldPrefix == "" {
		rest = Sep + name
	}
	if newPrefix == "" {
		return strings.TrimPrefix(rest, Sep), true
	}
	return newPrefix + rest, true
}

// Index answers the two questions uniqueness needs. Both match names
// case-insensitively and return the id of the object that holds the name.
type Index interface {
	// Live finds a folder or group currently named name (deleted groups
	// included: they keep their name until purged).
	Live(name string) (id string, ok bool, err error)
	// Alias finds the object that used to be named name.
	Alias(name string) (id string, ok bool, err error)
}

// CheckAvailable returns nil when name may be taken by the object self ("" for
// a new object). A live holder other than self gives name_taken; an alias of
// another object gives name_reserved_by_alias, so an old name is never handed
// to a different object while it still resolves to the first.
func CheckAvailable(ix Index, name, self string) error {
	if id, ok, err := ix.Live(name); err != nil {
		return err
	} else if ok && id != self {
		return &Error{Code: CodeNameTaken, Msg: fmt.Sprintf("the name %q is already in use", name)}
	}
	if id, ok, err := ix.Alias(name); err != nil {
		return err
	} else if ok && id != self {
		return &Error{Code: CodeNameAlias, Msg: fmt.Sprintf("the name %q is an old name of another object", name)}
	}
	return nil
}
