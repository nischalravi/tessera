package vms

import (
	"bytes"
	"encoding/json"
	"errors"
)

// unmarshalSettings reads a source's settings object, refusing unknown fields
// and trailing data.
func unmarshalSettings(raw string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("the source's settings are unreadable")
	}
	return nil
}
