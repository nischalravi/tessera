package catalog

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func TestFetchSnapshot(t *testing.T) {
	snap := fetchFixture(t, "upstream-v1", "2026-10-01", true)
	var files []string
	for f := range snap.Files {
		files = append(files, f)
	}
	sort.Strings(files)
	want := []string{"MANIFEST.json", "iam-dataset-extract.json", "index.json", "rcp_services.json",
		"services/kms.json", "services/s3.json", "services/sqs.json"}
	if !equalStrings(files, want) {
		t.Fatalf("files = %v, want %v", files, want)
	}
	// service files are stored verbatim
	orig, err := os.ReadFile("testdata/upstream-v1/v1/s3/s3.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(snap.Files["services/s3.json"]) != string(orig) {
		t.Error("service file must be stored verbatim")
	}
	cat := t.TempDir()
	if err := WriteSnapshot(cat, snap); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSnapshot(cat, "2026-10-01")
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got.Index, []string{"kms", "s3", "sqs"}) || len(got.Services) != 3 {
		t.Errorf("index = %v", got.Index)
	}
	if got.Dataset == nil || got.Dataset.Commit != fixtureCommit || got.Dataset.UpstreamSHA != fixturePin(t).SHA256 {
		t.Fatalf("dataset = %+v", got.Dataset)
	}
	var acts []string
	for _, a := range got.Dataset.Actions {
		acts = append(acts, a.Action)
	}
	// the hostile privilege name is dropped; "Unknown" levels are cleared
	if !equalStrings(acts, []string{"kms:CreateGrant", "s3:GetObject", "s3:Mystery", "s3:PutObject"}) {
		t.Errorf("dataset actions = %v", acts)
	}
	for _, a := range got.Dataset.Actions {
		switch a.Action {
		case "s3:Mystery":
			if a.AccessLevel != "" || a.Dependent != nil {
				t.Errorf("Mystery = %+v", a)
			}
		case "s3:PutObject":
			if !equalStrings(a.Dependent, []string{"kms:Decrypt", "s3:PutObjectTagging"}) || a.AccessLevel != "Write" {
				t.Errorf("PutObject = %+v", a)
			}
		}
	}
	if got.RCPPage == nil || got.RCPPage.FetchedOn != "2026-10-01" {
		t.Errorf("RCP page = %+v", got.RCPPage)
	}
}

func TestFetchWithoutPin(t *testing.T) {
	snap := fetchFixture(t, "upstream-v2", "2026-10-08", false)
	if _, ok := snap.Files["iam-dataset-extract.json"]; ok {
		t.Error("no pin, no dataset")
	}
	cat := t.TempDir()
	if err := WriteSnapshot(cat, snap); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSnapshot(cat, "2026-10-08")
	if err != nil || got.Dataset != nil || len(got.Index) != 4 {
		t.Errorf("ReadSnapshot = %+v, %v", got, err)
	}
}

func TestFetchRejects(t *testing.T) {
	good := fixturePin(t)
	badDigest := *good
	badDigest.SHA256 = strings.Repeat("0", 64)
	shortCommit := *good
	shortCommit.Commit = "abc123"
	badPath := *good
	badPath.Path = "../etc/passwd"
	badRepo := *good
	badRepo.Repo = "a/b/c"

	tests := []struct {
		name      string
		overrides map[string]reply
		pin       *DatasetPin
		date      string
		mutate    func(*Fetcher)
		want      string
	}{
		{name: "service 404", overrides: map[string]reply{"/v1/s3/s3.json": {404, "gone"}}, pin: good, want: "status 404"},
		{name: "service not JSON", overrides: map[string]reply{"/v1/s3/s3.json": {200, "<html>"}}, pin: good, want: "service s3"},
		{name: "service wrong shape", overrides: map[string]reply{"/v1/s3/s3.json": {200, `{"Actions": "x"}`}}, pin: good, want: "service s3"},
		{name: "index not JSON", overrides: map[string]reply{"/": {200, "nope"}}, pin: good, want: "index"},
		{name: "index empty", overrides: map[string]reply{"/": {200, "[]"}}, pin: good, want: "0 services"},
		{name: "index traversal", overrides: map[string]reply{"/": {200, `[{"service":"../../etc"}]`}}, pin: good, want: "invalid service name"},
		{name: "index upper case", overrides: map[string]reply{"/": {200, `[{"service":"S3"}]`}}, pin: good, want: "invalid service name"},
		{name: "index 500", overrides: map[string]reply{"/": {500, "x"}}, pin: good, want: "status 500"},
		{name: "rcp page without services", overrides: map[string]reply{"/rcp.md": {200, "# a page that changed shape"}}, pin: good, want: "no service prefixes"},
		{name: "rcp page 403", overrides: map[string]reply{"/rcp.md": {403, ""}}, pin: good, want: "status 403"},
		{name: "dataset digest mismatch", pin: &badDigest, want: "does not match the pin"},
		{name: "dataset tampered upstream", overrides: map[string]reply{"/" + datasetURLPath(): {200, "[]"}}, pin: good, want: "does not match the pin"},
		{name: "dataset 404", overrides: map[string]reply{"/" + datasetURLPath(): {404, ""}}, pin: good, want: "status 404"},
		{name: "pin short commit", pin: &shortCommit, want: "40-hex"},
		{name: "pin path traversal", pin: &badPath, want: "invalid path"},
		{name: "pin repo", pin: &badRepo, want: "invalid repo"},
		{name: "bad date", pin: good, date: "yesterday", want: "invalid snapshot date"},
		{name: "service over cap", pin: good, mutate: func(f *Fetcher) { f.MaxServiceBytes = 100 }, want: "too large"},
		{name: "dataset over cap", pin: good, mutate: func(f *Fetcher) { f.MaxDatasetBytes = 100 }, want: "too large"},
		{name: "no client", pin: good, mutate: func(f *Fetcher) { f.Client = nil }, want: "Client is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := fixtureServer(t, "upstream-v1", tc.overrides)
			f := fixtureFetcher(srv)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			date := tc.date
			if date == "" {
				date = "2026-10-01"
			}
			snap, err := f.Fetch(context.Background(), date, tc.pin)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Fetch = %v, %v; want an error containing %q", snap, err, tc.want)
			}
			if snap != nil {
				t.Error("a failed fetch must return no snapshot")
			}
		})
	}
}

func datasetURLPath() string {
	return fixtureRepo + "/" + fixtureCommit + "/aws/iam_definition.json"
}

func TestFetchNeverFollowsIndexURLs(t *testing.T) {
	// the fixture index's "url" fields point at the real AWS host; the fetch
	// succeeds offline only because service URLs are built from the index host
	hits := fetchFixture(t, "upstream-v1", "2026-10-01", false)
	if len(hits.Files) == 0 {
		t.Fatal("no files")
	}
	idx := string(hits.Files["index.json"])
	if !strings.Contains(idx, "https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json") {
		t.Fatal("fixture no longer exercises hostile index URLs")
	}
}

func TestFetchUsesGuardedClient(t *testing.T) {
	// a client from safehttp refuses the loopback test server: the fetcher
	// adds no way around the SSRF guard
	srv := fixtureServer(t, "upstream-v1", nil)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	// allow the test server's port so the address guard, not the port guard, refuses it
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod, RootCAs: pool, AllowedPorts: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	f := fixtureFetcher(srv)
	f.Client = c
	_, err = f.Fetch(context.Background(), "2026-10-01", nil)
	if !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Fatalf("Fetch through a safehttp client = %v, want ErrBlockedAddress", err)
	}
}

func TestWriteSnapshotImmutable(t *testing.T) {
	snap := fetchFixture(t, "upstream-v1", "2026-10-01", false)
	cat := t.TempDir()
	if err := WriteSnapshot(cat, snap); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(cat, snap); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("second write: %v", err)
	}
	ents, err := os.ReadDir(filepath.Join(cat, "snapshots"))
	if err != nil || len(ents) != 1 || ents[0].Name() != "2026-10-01" {
		t.Errorf("snapshots dir = %v, %v (a temporary directory was left behind?)", ents, err)
	}
	bad := &RawSnapshot{Date: "2026-10-02", Files: map[string][]byte{"../escape.json": []byte("x")}}
	if err := WriteSnapshot(cat, bad); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("path escape: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cat, "escape.json")); err == nil {
		t.Error("file escaped the snapshot directory")
	}
	ents, _ = os.ReadDir(filepath.Join(cat, "snapshots"))
	if len(ents) != 1 {
		t.Errorf("failed write left %d entries", len(ents))
	}
	if err := WriteSnapshot(cat, &RawSnapshot{Date: "bad"}); err == nil {
		t.Error("invalid date")
	}
	if err := WriteSnapshot(cat, nil); err == nil {
		t.Error("nil snapshot")
	}
}

func TestReadSnapshotVerifiesManifest(t *testing.T) {
	write := func(t *testing.T) string {
		cat := t.TempDir()
		if err := WriteSnapshot(cat, fetchFixture(t, "upstream-v1", "2026-10-01", true)); err != nil {
			t.Fatal(err)
		}
		return cat
	}
	root := func(cat string, rel ...string) string {
		return filepath.Join(append([]string{cat, "snapshots", "2026-10-01"}, rel...)...)
	}
	tests := []struct {
		name   string
		damage func(t *testing.T, cat string)
		want   string
	}{
		{"edited service file", func(t *testing.T, cat string) {
			appendTo(t, root(cat, "services", "s3.json"), " ")
		}, "manifest digest"},
		{"edited index", func(t *testing.T, cat string) {
			appendTo(t, root(cat, "index.json"), " ")
		}, "manifest digest"},
		{"edited dataset", func(t *testing.T, cat string) {
			appendTo(t, root(cat, "iam-dataset-extract.json"), " ")
		}, "manifest digest"},
		{"extra file", func(t *testing.T, cat string) {
			writeFile(t, root(cat, "services", "evil.json"), "{}")
		}, "differ from the manifest"},
		{"missing file", func(t *testing.T, cat string) {
			if err := os.Remove(root(cat, "services", "kms.json")); err != nil {
				t.Fatal(err)
			}
		}, "differ from the manifest"},
		{"no manifest", func(t *testing.T, cat string) {
			if err := os.Remove(root(cat, "MANIFEST.json")); err != nil {
				t.Fatal(err)
			}
		}, "MANIFEST.json"},
		{"manifest for another date", func(t *testing.T, cat string) {
			b, _ := os.ReadFile(root(cat, "MANIFEST.json"))
			writeFile(t, root(cat, "MANIFEST.json"), strings.Replace(string(b), `"2026-10-01"`, `"2026-09-30"`, 1))
		}, "names snapshot"},
		{"manifest with unknown field", func(t *testing.T, cat string) {
			b, _ := os.ReadFile(root(cat, "MANIFEST.json"))
			writeFile(t, root(cat, "MANIFEST.json"), strings.Replace(string(b), `"snapshot"`, `"extra": 1, "snapshot"`, 1))
		}, "unknown field"},
		{"symlink", func(t *testing.T, cat string) {
			if err := os.Symlink("/etc/hostname", root(cat, "link")); err != nil {
				t.Skip("no symlinks")
			}
		}, "not a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cat := write(t)
			tc.damage(t, cat)
			_, err := ReadSnapshot(cat, "2026-10-01")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadSnapshot = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	if _, err := ReadSnapshot(write(t), "../2026-10-01"); err == nil {
		t.Error("a snapshot date must not be a path")
	}
	if _, err := ReadSnapshot(write(t), "2026-10-02"); err == nil {
		t.Error("missing snapshot")
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b)+s)
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseRCPPage(t *testing.T) {
	tests := []struct {
		name, page string
		want       []string
		wantErr    bool
	}{
		{"list", "+ [A](u) `(prefix:s3)`\n+ [B](u) `(prefix:kms)`\n", []string{"kms", "s3"}, false},
		{"duplicates", "(prefix:s3) (prefix:s3)", []string{"s3"}, false},
		{"hyphen and digits", "(prefix:cognito-idp) (prefix:ecr-public) (prefix:s3express)", []string{"cognito-idp", "ecr-public", "s3express"}, false},
		{"invalid names dropped", "(prefix:S3) (prefix:a b) (prefix:) (prefix:ok)", []string{"ok"}, false},
		{"unterminated", "(prefix:s3", nil, true},
		{"overlong", "(prefix:" + strings.Repeat("a", 100) + ")", nil, true},
		{"none", "nothing here", nil, true},
		{"empty", "", nil, true},
	}
	for _, tc := range tests {
		got, err := ParseRCPPage([]byte(tc.page))
		if (err != nil) != tc.wantErr || !equalStrings(got, tc.want) {
			t.Errorf("%s: ParseRCPPage = %v, %v", tc.name, got, err)
		}
	}
}

func TestExtractDatasetIsDefensive(t *testing.T) {
	for _, in := range []string{"", "{}", "[]", "null", `[{"prefix": 5}]`, "[1,2]", strings.Repeat("[", 100000)} {
		if ex, err := ExtractDataset([]byte(in)); err == nil {
			t.Errorf("ExtractDataset(%.20q) = %+v, want an error", in, ex)
		}
	}
	ex, err := ExtractDataset([]byte(`[{"prefix":"BAD PREFIX","privileges":[{"privilege":"X"}]},
		{"prefix":"a","privileges":[{"privilege":"P","access_level":"Read"},{"privilege":"p","access_level":"Write"}]}]`))
	if err != nil || len(ex.Actions) != 1 || ex.Actions[0].Action != "a:P" || ex.Actions[0].AccessLevel != "Read" {
		t.Errorf("ExtractDataset = %+v, %v", ex, err)
	}
}

func TestLoadDatasetPin(t *testing.T) {
	pin, err := LoadDatasetPin("../../../catalog/aws")
	if err != nil {
		t.Fatal(err)
	}
	if pin.Repo != "iann0036/iam-dataset" || len(pin.Commit) != 40 || len(pin.SHA256) != 64 {
		t.Errorf("pin = %+v", pin)
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"unknown field": `{"repo":"a/b","commit":"` + strings.Repeat("a", 40) + `","path":"p","sha256":"` + strings.Repeat("a", 64) + `","x":1}`,
		"branch":        `{"repo":"a/b","commit":"main","path":"p","sha256":"` + strings.Repeat("a", 64) + `"}`,
		"upper hex":     `{"repo":"a/b","commit":"` + strings.Repeat("A", 40) + `","path":"p","sha256":"` + strings.Repeat("a", 64) + `"}`,
		"no digest":     `{"repo":"a/b","commit":"` + strings.Repeat("a", 40) + `","path":"p"}`,
		"query in path": `{"repo":"a/b","commit":"` + strings.Repeat("a", 40) + `","path":"p?x=1","sha256":"` + strings.Repeat("a", 64) + `"}`,
	} {
		writeFile(t, filepath.Join(dir, "iam-dataset.lock"), content)
		if _, err := LoadDatasetPin(dir); err == nil {
			t.Errorf("%s: pin accepted", name)
		}
	}
	if _, err := LoadDatasetPin(t.TempDir()); err == nil {
		t.Error("missing lock")
	}
}
