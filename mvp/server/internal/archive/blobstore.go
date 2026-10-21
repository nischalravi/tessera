package archive

import (
	"bytes"
	"context"
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

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// MaxBlobBytes bounds one sealed segment, written or read back.
const MaxBlobBytes = 24 << 20

// ErrMissing is returned by Get for an object that is not there.
var ErrMissing = errors.New("archive: object not found")

// BlobStore keeps the sealed segments. The blobs are ciphertext under the KEK
// (internal/seal), so the store needs no trust: it can only lose or alter them,
// and both are detected when a segment is read back (checksum, then seal).
type BlobStore interface {
	// Location is store.LocationLocal or store.LocationRemote.
	Location() string
	// Put writes the object under key, replacing a same-named one (a retry of a
	// segment writes the same key with new bytes only before it is catalogued).
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

// Put writes the file and syncs it before it is renamed into place, so a
// crash leaves the old object or the new one, never a torn file.
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
	if err := os.Rename(name, p); err != nil {
		return err
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
// GET of Base + "/" + key. Client must be the SSRF-guarded client of
// internal/safehttp (safehttp.ForConfigLimits, with a body limit of at least
// MaxBlobBytes): the archive URL is operator configuration, but the guard
// still applies to every call.
type HTTPStore struct {
	Base   *url.URL
	Client *http.Client
}

// NewHTTPStore validates base (http or https, no credentials, query or fragment).
func NewHTTPStore(base string, client *http.Client) (*HTTPStore, error) {
	if client == nil {
		return nil, errors.New("archive: an HTTP archive store needs the safehttp client")
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("archive: %q is not an http(s) base URL without credentials, query or fragment", base)
	}
	return &HTTPStore{Base: u, Client: client}, nil
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
	resp, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("archive: upload: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("archive: upload: %s", resp.Status)
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
