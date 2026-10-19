package catalog

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	fixtureCommit  = "0123456789abcdef0123456789abcdef01234567"
	fixtureRepo    = "iann0036/iam-dataset"
	datasetFixture = "testdata/upstream-v1/" + fixtureRepo + "/" + fixtureCommit + "/aws/iam_definition.json"
	realOverlays   = "../../../catalog/aws/overlays"
)

// reply replaces the response for one URL path.
type reply struct {
	status int
	body   string
}

// fixtureServer serves testdata/<dir> as the upstream sources (index at "/",
// service files under /v1/, the RCP page at /rcp.md). The pinned iam-dataset
// file always comes from upstream-v1. Tests are offline: this is a local TLS
// server and nothing else.
func fixtureServer(t *testing.T, dir string, overrides map[string]reply) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if o, ok := overrides[r.URL.Path]; ok {
			w.WriteHeader(o.status)
			_, _ = w.Write([]byte(o.body))
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.json"
		}
		for _, d := range []string{dir, "upstream-v1"} {
			if b, err := os.ReadFile(filepath.Join("testdata", d, filepath.FromSlash(p))); err == nil { // #nosec G304 -- test fixture
				_, _ = w.Write(b)
				return
			}
		}
		http.NotFound(w, r)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // clients hang up mid-handshake in some tests
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func fixtureFetcher(srv *httptest.Server) *Fetcher {
	return &Fetcher{
		Client:         srv.Client(),
		IndexURL:       srv.URL + "/",
		RCPPageURL:     srv.URL + "/rcp.md",
		DatasetBaseURL: srv.URL,
	}
}

func fixturePin(t *testing.T) *DatasetPin {
	t.Helper()
	b, err := os.ReadFile(datasetFixture)
	if err != nil {
		t.Fatal(err)
	}
	return &DatasetPin{Repo: fixtureRepo, Commit: fixtureCommit, Path: "aws/iam_definition.json", SHA256: sha256Hex(b)}
}

// fetchFixture fetches testdata/<dir> into a snapshot dated date. withPin
// includes the iam-dataset fixture.
func fetchFixture(t *testing.T, dir, date string, withPin bool) *RawSnapshot {
	t.Helper()
	srv := fixtureServer(t, dir, nil)
	var pin *DatasetPin
	if withPin {
		pin = fixturePin(t)
	}
	snap, err := fixtureFetcher(srv).Fetch(context.Background(), date, pin)
	if err != nil {
		t.Fatalf("Fetch(%s): %v", dir, err)
	}
	return snap
}

// readFixture fetches, writes and re-reads (verifying) a snapshot under a
// fresh catalog directory.
func readFixture(t *testing.T, dir, date string, withPin bool) (*Snapshot, string) {
	t.Helper()
	cat := t.TempDir()
	if err := WriteSnapshot(cat, fetchFixture(t, dir, date, withPin)); err != nil {
		t.Fatal(err)
	}
	snap, err := ReadSnapshot(cat, date)
	if err != nil {
		t.Fatal(err)
	}
	return snap, cat
}

// testOverlays loads the real overlays and narrows the RCP list to the
// services of the fixtures.
func testOverlays(t *testing.T, rcp ...string) *Overlays {
	t.Helper()
	ov, err := LoadOverlays(realOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if rcp == nil {
		rcp = []string{"kms", "s3", "sqs"}
	}
	ov.RCP.Services = rcp
	return ov
}

func compileFixture(t *testing.T, dir, date string, withPin bool) *Result {
	t.Helper()
	snap, _ := readFixture(t, dir, date, withPin)
	res, err := Compile(snap, testOverlays(t))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func fixtureCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := New(compileFixture(t, "upstream-v1", "2026-10-01", true).Compiled)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func names(c *Catalog, s *ActionSet) []string {
	var out []string
	for _, id := range s.IDs() {
		out = append(out, c.ActionName(id))
	}
	return out
}
