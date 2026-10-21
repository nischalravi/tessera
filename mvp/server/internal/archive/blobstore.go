package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// MaxBlobBytes bounds one sealed segment, written or read back.
const MaxBlobBytes = 24 << 20

// ErrMissing is returned by Get for an object that is not there.
var ErrMissing = errors.New("archive: object not found")

// ErrExists is returned by Put for a key that already holds other bytes.
var ErrExists = errors.New("archive: object already exists (archive objects are write-once)")

// BlobStore keeps the sealed segments. The blobs are ciphertext under the KEK
// (internal/seal), so the store needs no trust: it can only lose or alter them,
// and both are detected when a segment is read back (checksum, then seal).
type BlobStore interface {
	// Location is store.LocationLocal or store.LocationRemote.
	Location() string
	// Put creates the object under key and never replaces one: a key that
	// exists fails with ErrExists, unless it already holds exactly these bytes
	// (a retry of the same write). Every segment has a fresh key, so a
	// collision with different bytes is an overwrite attempt, not a retry.
	Put(ctx context.Context, key string, data []byte) error
	// Get returns the object, or ErrMissing.
	Get(ctx context.Context, key string) ([]byte, error)
}

// keyRE is the only shape of an object key: <tenant>/<class>/<segment>.seg,
// all fixed-alphabet, so a key can never leave the store's directory or URL.
var keyRE = regexp.MustCompile(`^[0-9a-f-]{36}/[a-z_]{1,32}/[0-9a-f-]{36}\.seg$`)

func checkKey(key string) error {
	if !keyRE.MatchString(key) {
		return fmt.Errorf("archive: invalid object key %q", key)
	}
	return nil
}

// LocalStore keeps segments as files under Dir (mode 0600, directories 0700).
type LocalStore struct{ Dir string }

// NewLocalStore creates the directory when it is missing.
func NewLocalStore(dir string) (*LocalStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("archive: no directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	return &LocalStore{Dir: abs}, nil
}

// Location implements BlobStore.
func (l *LocalStore) Location() string { return store.LocationLocal }

func (l *LocalStore) path(key string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	return filepath.Join(l.Dir, filepath.FromSlash(key)), nil
}

// Put writes the file and syncs it before it is linked into place, so a
// crash leaves no object or the whole one, never a torn file. It does not
// replace an existing object (ErrExists).
func (l *LocalStore) Put(_ context.Context, key string, data []byte) error {
	if len(data) > MaxBlobBytes {
		return fmt.Errorf("archive: segment of %d bytes is over the %d byte limit", len(data), MaxBlobBytes)
	}
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after a successful rename the name is gone and this is a no-op
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Chmod(0o600); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// link, unlike rename, never replaces an existing object
	if err := os.Link(name, p); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		if old, gerr := l.Get(context.Background(), key); gerr == nil && bytes.Equal(old, data) {
			return nil
		}
		return ErrExists
	}
	if d, err := os.Open(filepath.Dir(p)); err == nil { // #nosec G304 -- the directory of a path built by path()
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Get implements BlobStore.
func (l *LocalStore) Get(_ context.Context, key string) ([]byte, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p) // #nosec G304 -- p is built from a validated key under Dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxBlobBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBlobBytes {
		return nil, fmt.Errorf("archive: object %s is over the %d byte limit", key, MaxBlobBytes)
	}
	return b, nil
}

// HTTPStore keeps segments in an object store reached over HTTP(S): PUT and
// GET of Base + "/" + key, with a bearer token when one is set (prod requires
// it, see internal/config). Writes are create-only (If-None-Match: *) and are
// read back and compared. Client must be the SSRF-guarded client of
// internal/safehttp (safehttp.ForConfigLimits, with a body limit of at least
// MaxBlobBytes): the archive URL is operator configuration, but the guard
// still applies to every call.
type HTTPStore struct {
	Base   *url.URL
	Client *http.Client
	token  string
}

// NewHTTPStore validates base (http or https, no credentials, query or fragment).
// token, when not empty, is sent as "Authorization: Bearer" on every call; it
// must be visible ASCII.
func NewHTTPStore(base string, client *http.Client, token string) (*HTTPStore, error) {
	if client == nil {
		return nil, errors.New("archive: an HTTP archive store needs the safehttp client")
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("archive: %q is not an http(s) base URL without credentials, query or fragment", base)
	}
	for _, c := range token {
		if c <= ' ' || c > '~' {
			return nil, errors.New("archive: the store token has a character that is not allowed in a header")
		}
	}
	return &HTTPStore{Base: u, Client: client, token: token}, nil
}

// String omits the token.
func (h *HTTPStore) String() string { return "archive.HTTPStore{" + h.Base.Redacted() + "}" }

// GoString omits the token.
func (h *HTTPStore) GoString() string { return h.String() }

func (h *HTTPStore) auth(req *http.Request) {
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
}

// tokenAAD binds a sealed store token to its purpose.
func tokenAAD() []byte { return seal.AAD(tenancy.Platform, "archive", "token") }

// SealToken seals the object store's bearer token for
// TESSERA_ARCHIVE_TOKEN_SEALED (base64). `tessera archive seal-token` calls it.
func SealToken(s *seal.Sealer, token string) (string, error) {
	if token == "" {
		return "", errors.New("archive: empty token")
	}
	b, err := s.Seal([]byte(token), tokenAAD())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// OpenToken opens the value SealToken produced. An empty input is no token.
func OpenToken(s *seal.Sealer, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", errors.New("archive: the sealed store token is not base64")
	}
	b, err := s.Open(raw, tokenAAD())
	if err != nil {
		return "", errors.New("archive: cannot open the sealed store token (wrong KEK, or not sealed with `tessera archive seal-token`)")
	}
	return string(b), nil
}

// Location implements BlobStore.
func (h *HTTPStore) Location() string { return store.LocationRemote }

func (h *HTTPStore) url(key string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	return h.Base.String() + "/" + key, nil
}

// Put implements BlobStore.
func (h *HTTPStore) Put(ctx context.Context, key string, data []byte) error {
	if len(data) > MaxBlobBytes {
		return fmt.Errorf("archive: segment of %d bytes is over the %d byte limit", len(data), MaxBlobBytes)
	}
	u, err := h.url(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("If-None-Match", "*") // create-only: the store refuses a key that exists
	h.auth(req)
	resp, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("archive: upload: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusConflict:
		// the key exists: fine only when it is these very bytes (a retry)
		if old, gerr := h.Get(ctx, key); gerr == nil && sha256.Sum256(old) == sha256.Sum256(data) {
			return nil
		}
		return ErrExists
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("archive: upload: %s", resp.Status)
	}
	// read back and compare: a store that drops, truncates or ignores the
	// write (or ignored If-None-Match and replaced an object) is caught here
	got, err := h.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("archive: verify after upload: %w", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		return errors.New("archive: verify after upload: the stored object differs from what was written")
	}
	return nil
}

// Get implements BlobStore.
func (h *HTTPStore) Get(ctx context.Context, key string) ([]byte, error) {
	u, err := h.url(key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	h.auth(req)
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("archive: download: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrMissing
	case resp.StatusCode/100 != 2:
		return nil, fmt.Errorf("archive: download: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBlobBytes+1))
	if err != nil {
		return nil, fmt.Errorf("archive: download: %w", err)
	}
	if len(b) > MaxBlobBytes {
		return nil, fmt.Errorf("archive: object %s is over the %d byte limit", key, MaxBlobBytes)
	}
	return b, nil
}
