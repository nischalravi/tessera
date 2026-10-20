package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
)

const (
	catFixtures = "../../internal/aws/catalog/testdata"
	catCommit   = "0123456789abcdef0123456789abcdef01234567"
	catOverlays = "../../catalog/aws/overlays"
)

// catalogServer serves one upstream fixture; the iam-dataset file always
// comes from upstream-v1.
func catalogServer(t *testing.T, fixture string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.json"
		}
		for _, d := range []string{fixture, "upstream-v1"} {
			if b, err := os.ReadFile(filepath.Join(catFixtures, d, filepath.FromSlash(p))); err == nil { // #nosec G304 -- test fixture
				_, _ = w.Write(b)
				return
			}
		}
		http.NotFound(w, r)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func useFixtureFetcher(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := newCatalogFetcher
	newCatalogFetcher = func() (*catalog.Fetcher, error) {
		return &catalog.Fetcher{Client: srv.Client(), IndexURL: srv.URL + "/", RCPPageURL: srv.URL + "/rcp.md", DatasetBaseURL: srv.URL}, nil
	}
	t.Cleanup(func() { newCatalogFetcher = old })
}

func catalogDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ents, err := os.ReadDir(catOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(catOverlays, e.Name())) // #nosec G304 -- repo file
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, "overlays", e.Name()), string(b))
	}
	ds, err := os.ReadFile(filepath.Join(catFixtures, "upstream-v1/iann0036/iam-dataset", catCommit, "aws/iam_definition.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ds)
	writeTestFile(t, filepath.Join(dir, "iam-dataset.lock"),
		`{"repo":"iann0036/iam-dataset","commit":"`+catCommit+`","path":"aws/iam_definition.json","sha256":"`+hex.EncodeToString(sum[:])+`"}`)
	return dir
}

func writeTestFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runCatalog(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(context.Background(), append([]string{"catalog"}, args...), &out, &errb)
	return out.String(), err
}

func field(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, name+": "); ok {
			return v
		}
	}
	return ""
}

func TestCatalogRefreshAndCompile(t *testing.T) {
	dir := catalogDir(t)

	useFixtureFetcher(t, catalogServer(t, "upstream-v1"))
	if out, err := runCatalog(t, "refresh", "-dir", dir, "-date", "2026-10-01"); err != nil || !strings.Contains(out, "snapshot: 2026-10-01") {
		t.Fatalf("refresh = %q, %v", out, err)
	}
	// snapshots are immutable
	if _, err := runCatalog(t, "refresh", "-dir", dir, "-date", "2026-10-01"); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("second refresh = %v", err)
	}

	out, err := runCatalog(t, "compile", "-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	v1 := field(out, "version")
	if !strings.HasPrefix(v1, "2026-10-01-") || field(out, "changed") != "true" || !strings.HasPrefix(field(out, "title"), "catalog: 2026-10-01 (+11 actions") {
		t.Errorf("first compile:\n%s", out)
	}
	artifact := catalog.CompiledPath(dir, v1)
	first, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	// the artifact loads
	if c, err := catalog.Load(dir, v1); err != nil || c.Expand("s3:Get*").Len() != 2 {
		t.Fatalf("Load = %v", err)
	}

	// compiling again is a no-op: same version, same bytes
	out2, err := runCatalog(t, "compile", "-dir", dir, "-snapshot", "2026-10-01")
	if err != nil || field(out2, "version") != v1 {
		t.Fatalf("second compile: %q, %v", out2, err)
	}
	if again, _ := os.ReadFile(artifact); !bytes.Equal(first, again) {
		t.Error("recompiling changed the artifact")
	}

	// a later snapshot: diff against the earlier artifact, with a report
	useFixtureFetcher(t, catalogServer(t, "upstream-v2"))
	if _, err := runCatalog(t, "refresh", "-dir", dir, "-date", "2026-10-08"); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "sub", "report.md")
	out3, err := runCatalog(t, "compile", "-dir", dir, "-report", report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(field(out3, "version"), "2026-10-08-") || field(out3, "version") == v1 ||
		!strings.Contains(field(out3, "title"), "catalog: 2026-10-08 (+3 actions, -3 actions") {
		t.Errorf("v2 compile:\n%s", out3)
	}
	md, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(md), "`sns:Publish`") || !strings.Contains(string(md), "from `"+v1+"`") {
		t.Errorf("report: %v\n%s", err, md)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(report), ".tmp-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}

	// a snapshot edited after the fetch is refused
	f := filepath.Join(dir, "snapshots", "2026-10-08", "services", "s3.json")
	b, _ := os.ReadFile(f)
	writeTestFile(t, f, string(b)+" ")
	if _, err := runCatalog(t, "compile", "-dir", dir); err == nil || !strings.Contains(err.Error(), "manifest digest") {
		t.Errorf("compile of a damaged snapshot = %v", err)
	}
}

func TestCatalogRefreshWritesNothingOnFailure(t *testing.T) {
	dir := catalogDir(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/s3.json") {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.json"
		}
		b, err := os.ReadFile(filepath.Join(catFixtures, "upstream-v1", filepath.FromSlash(p))) // #nosec G304 -- test fixture
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	useFixtureFetcher(t, srv)
	if _, err := runCatalog(t, "refresh", "-dir", dir, "-date", "2026-10-01"); err == nil {
		t.Fatal("refresh must fail when a service file fails")
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshots")); err == nil {
		ents, _ := os.ReadDir(filepath.Join(dir, "snapshots"))
		if len(ents) != 0 {
			t.Errorf("a failed refresh left %v", ents)
		}
	}
}

func TestCatalogUsageErrors(t *testing.T) {
	dir := catalogDir(t)
	for name, args := range map[string][]string{
		"no subcommand":           {},
		"unknown subcommand":      {"publish"},
		"bad flag":                {"compile", "-nope"},
		"compile with no data":    {"compile", "-dir", dir},
		"compile bad snapshot":    {"compile", "-dir", dir, "-snapshot", "../x"},
		"refresh bad date":        {"refresh", "-dir", dir, "-date", "today"},
		"refresh without a pin":   {"refresh", "-dir", t.TempDir(), "-date", "2026-10-01"},
		"compile missing overlay": {"compile", "-dir", t.TempDir(), "-snapshot", "2026-10-01"},
	} {
		if _, err := runCatalog(t, args...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCatalogDefaultFetcherIsGuarded(t *testing.T) {
	f, err := newCatalogFetcher()
	if err != nil {
		t.Fatal(err)
	}
	// the production client is safehttp's: it refuses a loopback destination
	srv := catalogServer(t, "upstream-v1")
	f.IndexURL = srv.URL + "/"
	if _, err := f.Fetch(context.Background(), "2026-10-01", nil); err == nil {
		t.Fatal("the default fetcher reached a loopback server")
	}
}
