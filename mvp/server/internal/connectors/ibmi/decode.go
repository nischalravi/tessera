package ibmi

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// reply is the part of a Mapepire reply the transport reads. "error", "job" and
// the metadata are deliberately absent: they are server text.
type reply struct {
	ID      string
	Success bool
	IsDone  bool
	Data    []Profile // at most pageRows
}

// decodeReply parses one reply message and checks it answers wantID and
// succeeded. It streams the JSON: a row is decoded into the seven columns the
// transport needs and nothing else, and the "data" array is refused as soon as
// it holds more than pageRows rows, so the memory a reply can cost is bounded by
// the row cap, not by its size. Keys are matched exactly: a duplicate, or a key
// that differs from a known one only by case, is a malformed reply.
func decodeReply(b []byte, wantID string) (*reply, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, errProtocol
	}
	var r reply
	seen := map[string]bool{}
	for d.More() {
		k, err := keyToken(d)
		if err != nil {
			return nil, err
		}
		switch k {
		case "id", "success", "is_done", "data":
			if seen[k] {
				return nil, errProtocol
			}
			seen[k] = true
		default:
			if isKnownFold(k, "id", "success", "is_done", "data") {
				return nil, errProtocol
			}
			if err := skipValue(d); err != nil {
				return nil, err
			}
			continue
		}
		switch k {
		case "id":
			err = d.Decode(&r.ID)
		case "success":
			err = d.Decode(&r.Success)
		case "is_done":
			err = d.Decode(&r.IsDone)
		case "data":
			r.Data, err = decodeRows(d)
		}
		if err != nil {
			return nil, errProtocolOr(err)
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, errProtocol
	}
	if _, err := d.Token(); err != io.EOF || r.ID != wantID || !r.Success {
		return nil, errProtocol
	}
	return &r, nil
}

// errProtocolOr keeps the oversize error, and makes every JSON error the fixed one.
func errProtocolOr(err error) error {
	if err == errOversize {
		return err
	}
	return errProtocol
}

func keyToken(d *json.Decoder) (string, error) {
	t, err := d.Token()
	k, ok := t.(string)
	if err != nil || !ok {
		return "", errProtocol
	}
	return k, nil
}

func isKnownFold(k string, known ...string) bool {
	for _, n := range known {
		if strings.EqualFold(k, n) {
			return true
		}
	}
	return false
}

// skipValue consumes one JSON value of any shape without keeping it.
func skipValue(d *json.Decoder) error {
	depth := 0
	for {
		t, err := d.Token()
		if err != nil {
			return errProtocol
		}
		if dl, ok := t.(json.Delim); ok {
			if dl == '{' || dl == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// decodeRows reads the "data" array: null or an array of at most pageRows rows.
func decodeRows(d *json.Decoder) ([]Profile, error) {
	t, err := d.Token()
	if err != nil {
		return nil, errProtocol
	}
	if t == nil {
		return nil, nil
	}
	if t != json.Delim('[') {
		return nil, errProtocol
	}
	var out []Profile
	for d.More() {
		if len(out) >= pageRows {
			return nil, errOversize
		}
		p, err := decodeRow(d)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if t, err := d.Token(); err != nil || t != json.Delim(']') {
		return nil, errProtocol
	}
	return out, nil
}

var rowColumns = []string{"AUTHORIZATION_NAME", "STATUS", "USER_CLASS_NAME", "SPECIAL_AUTHORITIES", "GROUP_PROFILE_NAME",
	"SUPPLEMENTAL_GROUP_LIST", "TEXT_DESCRIPTION"}

// decodeRow reads one row object. Each wanted column is a string or null, at
// most maxFieldLen bytes; the name must be a valid profile name.
func decodeRow(d *json.Decoder) (Profile, error) {
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return Profile{}, errProtocol
	}
	vals := map[string]string{}
	for d.More() {
		k, err := keyToken(d)
		if err != nil {
			return Profile{}, err
		}
		col := ""
		for _, c := range rowColumns {
			if k == c {
				col = c
			} else if strings.EqualFold(k, c) {
				return Profile{}, errProtocol
			}
		}
		if col == "" {
			if err := skipValue(d); err != nil {
				return Profile{}, err
			}
			continue
		}
		if _, dup := vals[col]; dup {
			return Profile{}, errProtocol
		}
		var v *string
		if err := d.Decode(&v); err != nil {
			return Profile{}, errProtocol
		}
		vals[col] = ""
		if v != nil {
			if len(*v) > maxFieldLen {
				return Profile{}, errProtocol
			}
			vals[col] = strings.TrimSpace(*v)
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return Profile{}, errProtocol
	}
	p := Profile{Name: vals["AUTHORIZATION_NAME"], Status: vals["STATUS"], UserClass: vals["USER_CLASS_NAME"],
		GroupProfile: vals["GROUP_PROFILE_NAME"], Text: vals["TEXT_DESCRIPTION"],
		SpecialAuthorities: splitList(vals["SPECIAL_AUTHORITIES"]), SupplementalGroups: splitList(vals["SUPPLEMENTAL_GROUP_LIST"])}
	if !nameRE.MatchString(p.Name) {
		return Profile{}, errProtocol
	}
	return p, nil
}
