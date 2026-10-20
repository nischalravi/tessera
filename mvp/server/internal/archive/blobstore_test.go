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
	if err := s.Put(ctx, keyOK, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Get(ctx, keyOK); err != nil || string(b) != "two" {
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
		switch r.Method {
		case http.MethodPut:
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
	if _, err := archive.NewHTTPStore(srv.URL, nil); err == nil {
		t.Error("a store with no client was accepted")
	}
	for _, bad := range []string{"", "ftp://x/y", "https://user:pw@host/p", "https://host/p?x=1", "https://host/p#f", "/relative"} {
		if _, err := archive.NewHTTPStore(bad, srv.Client()); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	s, err := archive.NewHTTPStore(srv.URL+"/archive/", srv.Client())
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
	if err := s.Put(ctx, "../x", []byte("x")); err == nil {
		t.Error("a key outside the shape was accepted")
	}
	// an unhappy server is an error, not a missing object
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer bad.Close()
	b, _ := archive.NewHTTPStore(bad.URL, bad.Client())
	if err := b.Put(ctx, keyOK, []byte("x")); err == nil {
		t.Error("a 500 on upload was accepted")
	}
	if _, err := b.Get(ctx, keyOK); err == nil || errors.Is(err, archive.ErrMissing) {
		t.Errorf("a 500 on download = %v", err)
	}
}
