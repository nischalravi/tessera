package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// Config is the agent's own configuration file (JSON). It is the agent's
// authority: allowed_targets is the local allowlist, and the file must be
// editable only by a local administrator (LoadConfig refuses a file that
// group or others can write). Nothing Tessera sends can change it.
type Config struct {
	// ServerURL is Tessera's agent endpoint, https://host[:port].
	ServerURL string `json:"server_url"`
	// ServerCAFile is the PEM CA bundle that signs Tessera's agent endpoint
	// certificate; the agent trusts no other CA.
	ServerCAFile string `json:"server_ca_file"`
	// StateDir holds the client key and the credential store (0700).
	StateDir string `json:"state_dir"`
	// AllowedTargets are the host:port pairs (host name, IP, or CIDR:port;
	// ports 389 and 636) the agent may contact. Anything else is refused.
	AllowedTargets []string `json:"allowed_targets"`

	allow []safedial.AllowEntry
}

// LoadConfig reads and validates the configuration file at path.
func LoadConfig(path string) (*Config, error) {
	if err := requireAdminOwned(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator names their own configuration file
	if err != nil {
		return nil, err
	}
	return ParseConfig(raw)
}

// ParseConfig validates configuration JSON.
func ParseConfig(raw []byte) (*Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("agent: configuration: %w", err)
	}
	if dec.More() {
		return nil, errors.New("agent: configuration: trailing data after the JSON object")
	}
	if c.ServerURL == "" || c.ServerCAFile == "" || c.StateDir == "" {
		return nil, errors.New("agent: configuration needs server_url, server_ca_file and state_dir")
	}
	allow, err := safedial.ParseAllow(strings.Join(c.AllowedTargets, ","))
	if err != nil {
		return nil, fmt.Errorf("agent: allowed_targets: %w", err)
	}
	for _, t := range c.AllowedTargets {
		if strings.Contains(t, ",") {
			return nil, fmt.Errorf("agent: allowed_targets: %q must be one entry", t)
		}
	}
	c.allow = allow
	return &c, nil
}

// Allow returns the parsed local allowlist.
func (c *Config) Allow() []safedial.AllowEntry { return c.allow }

// AllowlistHash is a stable SHA-256 (hex) of the allowlist, reported in
// heartbeats so Admin shows when it changes. The list itself is not sent.
func (c *Config) AllowlistHash() string {
	l := make([]string, 0, len(c.AllowedTargets))
	for _, t := range c.AllowedTargets {
		l = append(l, strings.ToLower(strings.TrimSpace(t)))
	}
	sort.Strings(l)
	h := sha256.Sum256([]byte(strings.Join(l, "\n")))
	return hex.EncodeToString(h[:])
}
