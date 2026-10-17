// Package cliauth is the reference client of Tessera's OAuth authorization
// server (design docs/design/phase-0-platform-security.md §9.3, §19 PR10): the
// device authorization grant with DPoP, refresh-token rotation, and calls to
// the API with DPoP-bound access tokens. cmd/tessera-cli is a thin command
// line over it.
//
// The DPoP key and the refresh token live in credentials.json (mode 0600, in a
// 0700 directory; an OS keychain comes later). The file is the only state:
// refreshing is serialized with a lock file so that two CLI processes never
// present the same refresh token (the second use would be read as theft and
// revoke the session).
package cliauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// CredentialsVersion is the file format version.
const CredentialsVersion = 1

// Credentials is the CLI's signed-in state for one tenant.
type Credentials struct {
	Version  int    `json:"version"`
	Server   string `json:"server"` // the server's public URL (TESSERA_PUBLIC_URL)
	Tenant   string `json:"tenant"` // tenant slug
	Issuer   string `json:"issuer"` // Server + /t/ + Tenant
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	// DPoPKey is the private JWK (ES256) every token is bound to.
	DPoPKey json.RawMessage `json:"dpop_key"`
	// RefreshToken rotates on every use; the latest is always the one stored.
	RefreshToken string `json:"refresh_token"`
	// AccessToken and AccessExpiresAt cache the current access token so that
	// most invocations need no refresh.
	AccessToken     string    `json:"access_token,omitempty"`
	AccessExpiresAt time.Time `json:"access_expires_at,omitempty"`
	// Nonce is the last DPoP server nonce seen.
	Nonce string `json:"dpop_nonce,omitempty"`
	// SignedInAt is when the device flow completed.
	SignedInAt time.Time `json:"signed_in_at"`
}

// Key returns the DPoP private key.
func (c *Credentials) Key() (*ecdsa.PrivateKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(c.DPoPKey, &jwk); err != nil {
		return nil, fmt.Errorf("cliauth: the DPoP key in the credentials file is unreadable: %w", err)
	}
	k, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, errors.New("cliauth: the DPoP key in the credentials file is not an EC P-256 private key")
	}
	return k, nil
}

// NewKey generates a DPoP key and its JWK form.
func NewKey() (*ecdsa.PrivateKey, json.RawMessage, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(jose.JSONWebKey{Key: k, Algorithm: string(jose.ES256), Use: "sig"})
	return k, b, err
}

// ErrNotLoggedIn means there is no credentials file.
var ErrNotLoggedIn = errors.New("not signed in: run `tessera-cli login`")

// Store is the credentials file in Dir.
type Store struct {
	Dir string
}

// DefaultDir is where credentials live: $TESSERA_CONFIG_DIR, else
// $XDG_CONFIG_HOME/tessera, else ~/.config/tessera.
func DefaultDir(getenv func(string) string) (string, error) {
	if d := getenv("TESSERA_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "tessera"), nil
	}
	home := getenv("HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("cliauth: cannot find a home directory: set TESSERA_CONFIG_DIR")
		}
		home = h
	}
	return filepath.Join(home, ".config", "tessera"), nil
}

func (s *Store) path() string { return filepath.Join(s.Dir, "credentials.json") }

// Path is the credentials file's path.
func (s *Store) Path() string { return s.path() }

// Load reads the credentials. It refuses a file other users can read or
// write (like ssh does with a private key): the file is a bearer credential
// for a refresh token.
func (s *Store) Load() (*Credentials, error) {
	f, err := os.Open(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("cliauth: %s is not a regular file", s.path())
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		return nil, fmt.Errorf("cliauth: %s has mode %04o: it holds a refresh token and a private key; run `chmod 600 %s` or sign in again",
			s.path(), m, s.path())
	}
	var c Credentials
	dec := json.NewDecoder(f)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("cliauth: %s is not valid: %w", s.path(), err)
	}
	if c.Version != CredentialsVersion || c.Server == "" || c.Tenant == "" || c.RefreshToken == "" || len(c.DPoPKey) == 0 ||
		c.Issuer != c.Server+"/t/"+c.Tenant {
		return nil, fmt.Errorf("cliauth: %s is incomplete or from another version; sign in again", s.path())
	}
	if srv, err := NormalizeServer(c.Server); err != nil || srv != c.Server {
		return nil, fmt.Errorf("cliauth: %s names an invalid server; sign in again", s.path())
	}
	if _, err := c.Key(); err != nil {
		return nil, fmt.Errorf("%w; sign in again", err)
	}
	return &c, nil
}

// Save writes the credentials atomically (a temporary file in the same
// directory, mode 0600, then a rename), creating the directory with mode 0700.
func (s *Store) Save(c *Credentials) error {
	c.Version = CredentialsVersion
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	// #nosec G117 -- holding the refresh token is the file's purpose: it is written mode 0600 in a 0700
	// directory, and Load refuses it if it is ever looser
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".credentials-*.tmp") // created with mode 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, s.path()); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Delete removes the credentials file (no error if there is none).
func (s *Store) Delete() error {
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Lock serializes the processes that may refresh. It takes a lock file next
// to the credentials (created exclusively), waiting up to wait and treating a
// lock older than staleAfter as abandoned. The returned function releases it.
func (s *Store) Lock(wait, staleAfter time.Duration) (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	lock := filepath.Join(s.Dir, "credentials.lock")
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- a path in the config directory
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		// the file's own timestamp is wall-clock time, whatever clock the client runs on
		if st, err := os.Stat(lock); err == nil && time.Since(st.ModTime()) > staleAfter {
			_ = os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("cliauth: another tessera-cli is refreshing the credentials (%s is locked)", lock)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
