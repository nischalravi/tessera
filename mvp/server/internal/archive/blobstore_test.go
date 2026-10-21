package archive_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
)

const (
	keyOK = "00000000-0000-4000-8000-0000000000d1/audit/00000000-0000-4000-8000-0000000000e1.seg"
)

func TestLocalStore(t *testing.T) {
	dir := t.TempDir()
	s, err := archive.NewLocalStore(filepath.Join(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.Get(ctx, keyOK); !errors.Is(err, archive.ErrMissing) {
		t.Errorf("Get of a missing object = %v", err)
	}
	if err := s.Put(ctx, keyOK, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, keyOK, []byte("one")); err != nil {
		t.Errorf("a retry of the same bytes = %v", err)
	}
	if err := s.Put(ctx, keyOK, []byte("two")); !errors.Is(err, archive.ErrExists) {
		t.Errorf("an overwrite = %v, want ErrExists", err)
	}
	if b, err := s.Get(ctx, keyOK); err != nil || string(b) != "one" {
		t.Errorf("Get = %q, %v", b, err)
	}
	fi, err := os.Stat(filepath.Join(s.Dir, filepath.FromSlash(keyOK)))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("object mode = %v, %v", fi, err)
	}
	// no key can leave the directory
	for _, k := range []string{"../x", "a/b", "", keyOK + "/..", "00000000-0000-4000-8000-0000000000d1/../../etc/passwd.seg",
		"00000000-0000-4000-8000-0000000000d1/Audit/00000000-0000-4000-8000-0000000000e1.seg", "/" + keyOK} {
		if err := s.Put(ctx, k, []byte("x")); err == nil {
			t.Errorf("Put(%q) accepted", k)
		}
		if _, err := s.Get(ctx, k); err == nil || errors.Is(err, archive.ErrMissing) {
			t.Errorf("Get(%q) = %v", k, err)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(s.Dir, "00000000-0000-4000-8000-0000000000d1", "audit")); len(entries) != 1 {
		t.Errorf("a failed or replaced Put left files behind: %v", entries)
	}
	if _, err := archive.NewLocalStore(" "); err == nil {
		t.Error("an empty directory was accepted")
	}
}

func TestHTTPStore(t *testing.T) {
	var mu sync.Mutex
	objects := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if _, ok := objects[r.URL.Path]; ok && r.Header.Get("If-None-Match") == "*" {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			b, _ := io.ReadAll(r.Body)
			objects[r.URL.Path] = b
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			b, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if _, err := archive.NewHTTPStore(srv.URL, nil, ""); err == nil {
		t.Error("a store with no client was accepted")
	}
	for _, bad := range []string{"", "ftp://x/y", "https://user:pw@host/p", "https://host/p?x=1", "https://host/p#f", "/relative"} {
		if _, err := archive.NewHTTPStore(bad, srv.Client(), ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	s, err := archive.NewHTTPStore(srv.URL+"/archive/", srv.Client(), "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, keyOK); !errors.Is(err, archive.ErrMissing) {
		t.Errorf("Get of a missing object = %v", err)
	}
	if err := s.Put(ctx, keyOK, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Get(ctx, keyOK); err != nil || string(b) != "sealed" {
		t.Errorf("Get = %q, %v", b, err)
	}
	if _, ok := objects["/archive/"+keyOK]; !ok {
		t.Errorf("object paths = %v", objects)
	}
	if err := s.Put(ctx, keyOK, []byte("sealed")); err != nil {
		t.Errorf("a retry of the same bytes = %v", err)
	}
	if err := s.Put(ctx, keyOK, []byte("other")); !errors.Is(err, archive.ErrExists) {
		t.Errorf("an overwrite = %v, want ErrExists", err)
	}
	if string(objects["/archive/"+keyOK]) != "sealed" {
		t.Error("the object was overwritten")
	}
	if err := s.Put(ctx, "../x", []byte("x")); err == nil {
		t.Error("a key outside the shape was accepted")
	}
	// no or a wrong token is refused on both calls
	for _, tok := range []string{"", "wrong"} {
		n, _ := archive.NewHTTPStore(srv.URL+"/archive/", srv.Client(), tok)
		if err := n.Put(ctx, "00000000-0000-4000-8000-0000000000d1/audit/00000000-0000-4000-8000-0000000000e2.seg", []byte("x")); err == nil {
			t.Errorf("token %q: Put accepted", tok)
		}
		if _, err := n.Get(ctx, keyOK); err == nil {
			t.Errorf("token %q: Get accepted", tok)
		}
	}
	if _, err := archive.NewHTTPStore(srv.URL, srv.Client(), "a b\n"); err == nil {
		t.Error("a token with whitespace was accepted")
	}
	// an unhappy server is an error, not a missing object
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer bad.Close()
	b, _ := archive.NewHTTPStore(bad.URL, bad.Client(), "")
	if err := b.Put(ctx, keyOK, []byte("x")); err == nil {
		t.Error("a 500 on upload was accepted")
	}
	if _, err := b.Get(ctx, keyOK); err == nil || errors.Is(err, archive.ErrMissing) {
		t.Errorf("a 500 on download = %v", err)
	}
}

// TestHTTPStoreVerifiesAfterWrite: a store that acknowledges a write but keeps
// other bytes (or ignores If-None-Match and overwrites) is an error.
func TestHTTPStoreVerifiesAfterWrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusCreated)
			return
		}
		_, _ = w.Write([]byte("truncated"))
	}))
	defer srv.Close()
	s, _ := archive.NewHTTPStore(srv.URL, srv.Client(), "")
	if err := s.Put(context.Background(), keyOK, []byte("sealed")); err == nil {
		t.Error("a write the store did not keep was accepted")
	}
}

func testSealer(t *testing.T) *seal.Sealer {
	t.Helper()
	sl, err := seal.New([]byte("0123456789abcdef0123456789ABCDEF"))
	if err != nil {
		t.Fatal(err)
	}
	return sl
}

func TestStoreToken(t *testing.T) {
	sl := testSealer(t)
	enc, err := archive.SealToken(sl, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := archive.OpenToken(sl, enc); err != nil || got != "tok" {
		t.Errorf("OpenToken = %q, %v", got, err)
	}
	if got, err := archive.OpenToken(sl, ""); err != nil || got != "" {
		t.Errorf("empty = %q, %v", got, err)
	}
	if _, err := archive.OpenToken(sl, "%%%"); err == nil {
		t.Error("bad base64 accepted")
	}
	if _, err := archive.SealToken(sl, ""); err == nil {
		t.Error("empty token sealed")
	}
}
