package readiness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// HashInput is everything evidence is bound to (design §4.5, K5).
type HashInput struct {
	Config         ConnConfig
	Role           string
	SecretRef      string
	SecretVersion  string
	TemplatePin    string // "ad@1.0"
	OverlayVersion int

	canon map[string]json.RawMessage // cached by Normalize
}

// Normalize caches the canonical form; call it again after changing a field.
func (in *HashInput) Normalize() error {
	in.canon = nil
	m, err := in.canonical()
	in.canon = m
	return err
}

// canonical returns the config as a JSON object with sorted keys (JCS for the
// value types ConnConfig uses: strings, integers, booleans, arrays, objects),
// plus role, write mode and the credential reference.
func (in HashInput) canonical() (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(in.Config)
	if err != nil {
		return nil, err
	}
	m := map[string]json.RawMessage{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	for k, v := range generic {
		b, err := json.Marshal(v) // re-marshal sorts nested object keys
		if err != nil {
			return nil, err
		}
		m[k] = b
	}
	put := func(k, v string) {
		b, _ := json.Marshal(v) // marshalling a string cannot fail
		m[k] = b
	}
	put("role", in.Role)
	if in.Config.WriteMode == "" {
		put("write_mode", "off")
	}
	put("credential", in.SecretRef+"#"+in.SecretVersion)
	return m, nil
}

func (in HashInput) digest(fields []string) (string, error) {
	m := in.canon
	if m == nil {
		var err error
		if m, err = in.canonical(); err != nil {
			return "", err
		}
	}
	sel := m
	if len(fields) > 0 {
		sel = map[string]json.RawMessage{}
		for _, f := range fields {
			if v, ok := m[f]; ok {
				sel[f] = v
			} else if f == "tls_mode" {
				continue // unset (inferred from the port): the hash of a connection saved before tls_mode existed
			} else {
				sel[f] = json.RawMessage("null")
			}
		}
	}
	body, err := json.Marshal(sel) // map keys are sorted
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(body)
	h.Write([]byte{0})
	h.Write([]byte(in.TemplatePin))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(in.OverlayVersion)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ConfigHash is SHA-256(JCS(config without secrets) || secret version ||
// template@version || overlay version).
func (in HashInput) ConfigHash() (string, error) { return in.digest(nil) }

// ItemHash binds an item's evidence to only the config fields the item
// declares, so changing the sync schedule does not invalidate the TLS check
// but changing the host does. No declared fields means every field.
func (in HashInput) ItemHash(fields []string) (string, error) { return in.digest(fields) }
