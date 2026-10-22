package agent

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
)

// FileStore keeps secrets as one file per name in a private directory
// (mode 0700; each file 0600). On non-Windows hosts it refuses to read from a
// directory or file that is readable by group or others. On Windows the
// platform store wraps each value with DPAPI (store_windows.go) and the
// directory's NTFS ACL is the access control.
//
// It implements CredentialStore. Secrets are never logged or listed: List
// returns names only.
type FileStore struct {
	dir       string
	protect   func([]byte) ([]byte, error)
	unprotect func([]byte) ([]byte, error)
}

const credExt = ".cred"

const maxSecret = 8 << 10

// NewFileStore opens (creating it 0700 if needed) a plain file store.
func NewFileStore(dir string) (*FileStore, error) {
	return newFileStore(dir, nil, nil)
}

func newFileStore(dir string, protect, unprotect func([]byte) ([]byte, error)) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("agent: the credential directory is not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: credential directory: %w", err)
	}
	if err := requirePrivate(dir, true); err != nil {
		return nil, err
	}
	id := func(b []byte) ([]byte, error) { return b, nil }
	if protect == nil {
		protect = id
	}
	if unprotect == nil {
		unprotect = id
	}
	return &FileStore{dir: dir, protect: protect, unprotect: unprotect}, nil
}

func (s *FileStore) path(name string) (string, error) {
	if !ValidCredName(name) {
		return "", fmt.Errorf("agent: %q is not a valid credential name", name)
	}
	return filepath.Join(s.dir, name+credExt), nil
}

// Get returns the secret stored under name (ErrNoCredential if none).
func (s *FileStore) Get(name string) (string, error) {
	p, err := s.path(name)
	if err != nil {
		return "", ErrNoCredential
	}
	b, err := readPrivateFile(p, maxSecret)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoCredential
	}
	if err != nil {
		return "", err
	}
	pt, err := s.unprotect(b)
	if err != nil {
		return "", fmt.Errorf("agent: the stored credential cannot be opened: %w", err)
	}
	return string(pt), nil
}

// Set stores (or replaces) a secret. The file is created with mode 0600 and
// replaced atomically.
func (s *FileStore) Set(name, secret string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if secret == "" || len(secret) > maxSecret {
		return errors.New("agent: a credential must be 1 byte to 8 KiB")
	}
	b, err := s.protect([]byte(secret))
	if err != nil {
		return err
	}
	return writePrivateFile(p, b)
}

// Delete removes a secret (no error if it is absent).
func (s *FileStore) Delete(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// List returns the stored names, sorted.
func (s *FileStore) List() ([]string, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), credExt); ok && !e.IsDir() && ValidCredName(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// readPrivateFile reads a regular file (not a symlink) that only its owner may
// access, of at most max bytes.
func readPrivateFile(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("agent: %s is not a regular file", filepath.Base(path))
	}
	if err := requirePrivate(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- path is built from a validated name under the private directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("agent: %s is larger than %d bytes", filepath.Base(path), max)
	}
	return b, nil
}

// writePrivateFile writes data to path with mode 0600 through a temporary
// file in the same directory, then renames it into place.
func writePrivateFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil && !isWindows() {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ---------------------------------------------------------------- identity

// Identity is the agent's client key pair: an ECDSA P-256 key and a
// self-signed certificate that serves only to carry the public key. Tessera
// pins the key (PinOf), not the certificate, so its validity period and issuer
// do not matter. The private key never leaves the agent's state directory.
const (
	keyFile  = "client.key"
	certFile = "client.crt"
)

// LoadOrCreateIdentity returns the agent's client certificate from dir,
// generating the key pair on first use (the key file is mode 0600).
func LoadOrCreateIdentity(dir string) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	if err := requirePrivate(dir, true); err != nil {
		return tls.Certificate{}, err
	}
	kp, cp := filepath.Join(dir, keyFile), filepath.Join(dir, certFile)
	if _, err := os.Lstat(kp); errors.Is(err, os.ErrNotExist) {
		certPEM, keyPEM, err := generateIdentity(time.Now())
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := writePrivateFile(kp, keyPEM); err != nil {
			return tls.Certificate{}, err
		}
		if err := writePrivateFile(cp, certPEM); err != nil {
			return tls.Certificate{}, err
		}
	}
	keyPEM, err := readPrivateFile(kp, 16<<10)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := readPrivateFile(cp, 16<<10)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func generateIdentity(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tessera-directory-agent"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), nil
}

const sealKeyFile = "seal.key"

// LoadOrCreateSealKey returns the agent's private sealing key from dir (the
// identity directory), generating it on first use (mode 0600). Its public half
// is what Tessera seals a server-held credential to (PathSealKey); the private
// half never leaves this file.
func LoadOrCreateSealKey(dir string) (*ecdh.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := requirePrivate(dir, true); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, sealKeyFile)
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		k, err := seal.GenerateAgentKey()
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := writePrivateFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
	}
	raw, err := readPrivateFile(p, 4<<10)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("agent: the sealing key file is not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent: the sealing key file: %w", err)
	}
	priv, ok := k.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return nil, errors.New("agent: the sealing key file does not hold an X25519 key")
	}
	return priv, nil
}
