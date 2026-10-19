package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Pinned upstream sources. Nothing else is ever fetched: the per-service URLs
// are built from the index host and a validated service prefix, never taken
// from the downloaded index.
const (
	DefaultIndexURL       = "https://servicereference.us-east-1.amazonaws.com/"
	DefaultRCPPageURL     = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.md"
	DefaultDatasetBaseURL = "https://raw.githubusercontent.com"

	defaultMaxIndexBytes   = 4 << 20
	defaultMaxServiceBytes = 16 << 20
	defaultMaxPageBytes    = 2 << 20
	defaultMaxDatasetBytes = 32 << 20
	defaultConcurrency     = 8
)

// Fetcher downloads a snapshot. Client must come from safehttp.New (it holds
// the SSRF guard and the response size limit; for production use give it a
// MaxBodyBytes of at least 32 MiB). Tests pass a client for an httptest
// server. The Fetcher also enforces its own per-file caps.
type Fetcher struct {
	Client         *http.Client
	IndexURL       string // default DefaultIndexURL
	RCPPageURL     string // default DefaultRCPPageURL
	DatasetBaseURL string // default DefaultDatasetBaseURL

	MaxServiceBytes int64 // per Service Reference file; default 16 MiB
	MaxDatasetBytes int64 // iam-dataset file; default 32 MiB
	Concurrency     int   // default 8
}

// RawSnapshot is a fetched snapshot, ready for WriteSnapshot. Files are
// keyed by their path relative to snapshots/<date>/.
type RawSnapshot struct {
	Date  string
	Files map[string][]byte
}

func (f *Fetcher) get(ctx context.Context, url string, max int64) ([]byte, error) {
	if f.Client == nil {
		return nil, errors.New("catalog: Fetcher.Client is required (use safehttp.New)")
	}
	resp, err := safehttp.Get(ctx, f.Client, url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	if int64(len(resp.Body)) > max {
		return nil, fmt.Errorf("fetch %s: %w", url, safehttp.ErrTooLarge)
	}
	return resp.Body, nil
}

// Fetch downloads the index, every service file, the RCP page and, when pin is
// not nil, the pinned iam-dataset file, and verifies them: every file must
// parse, the iam-dataset file must match the pin's SHA-256, and the RCP page
// must yield at least one service. Nothing is written; any failure fails the
// whole fetch so a partial snapshot never exists.
func (f *Fetcher) Fetch(ctx context.Context, date string, pin *DatasetPin) (*RawSnapshot, error) {
	if !validDate(date) {
		return nil, fmt.Errorf("catalog: invalid snapshot date %q", date)
	}
	indexURL := f.IndexURL
	if indexURL == "" {
		indexURL = DefaultIndexURL
	}
	base := strings.TrimRight(indexURL, "/")
	idx, err := f.get(ctx, indexURL, defaultMaxIndexBytes)
	if err != nil {
		return nil, err
	}
	services, err := parseIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	maxSvc := f.MaxServiceBytes
	if maxSvc <= 0 {
		maxSvc = defaultMaxServiceBytes
	}
	files := map[string][]byte{snapIndex: idx}

	// service files, a few at a time
	n := f.Concurrency
	if n <= 0 {
		n = defaultConcurrency
	}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
		sem      = make(chan struct{}, n)
	)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, svc := range services {
		sem <- struct{}{}
		wg.Add(1)
		go func(svc string) {
			defer wg.Done()
			defer func() { <-sem }()
			b, err := f.get(ctx, base+"/v1/"+svc+"/"+svc+".json", maxSvc)
			if err == nil {
				var probe srService
				if jerr := json.Unmarshal(b, &probe); jerr != nil {
					err = fmt.Errorf("service %s: %w", svc, jerr)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				return
			}
			files[snapServices+"/"+svc+".json"] = b
		}(svc)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	// RCP page
	pageURL := f.RCPPageURL
	if pageURL == "" {
		pageURL = DefaultRCPPageURL
	}
	page, err := f.get(ctx, pageURL, defaultMaxPageBytes)
	if err != nil {
		return nil, err
	}
	rcp, err := ParseRCPPage(page)
	if err != nil {
		return nil, err
	}
	if files[snapRCP], err = marshalFile(&RCPScrape{Source: pageURL, FetchedOn: date, Services: rcp}); err != nil {
		return nil, err
	}

	// iam-dataset, pinned by commit and digest
	if pin != nil {
		ex, err := f.fetchDataset(ctx, pin)
		if err != nil {
			return nil, err
		}
		if files[snapDataset], err = marshalFile(ex); err != nil {
			return nil, err
		}
	}

	man := Manifest{Snapshot: date, Source: indexURL, Files: make(map[string]string, len(files))}
	for name, b := range files {
		man.Files[name] = sha256Hex(b)
	}
	if files[snapManifest], err = marshalFile(&man); err != nil {
		return nil, err
	}
	return &RawSnapshot{Date: date, Files: files}, nil
}

// marshalFile writes stable, indented JSON (map keys sorted by encoding/json).
func marshalFile(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// LoadDatasetPin reads and validates <dir>/iam-dataset.lock.
func LoadDatasetPin(dir string) (*DatasetPin, error) {
	raw, err := readCapped(filepath.Join(dir, "iam-dataset.lock"), maxOverlayBytes)
	if err != nil {
		return nil, fmt.Errorf("catalog: iam-dataset.lock: %w", err)
	}
	var p DatasetPin
	if err := strictUnmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("catalog: iam-dataset.lock: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *DatasetPin) validate() error {
	owner, name, ok := strings.Cut(p.Repo, "/")
	okName := func(s string) bool {
		if s == "" || len(s) > 100 {
			return false
		}
		for _, c := range []byte(s) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
		return true
	}
	switch {
	case !ok || !okName(owner) || !okName(name):
		return fmt.Errorf("catalog: iam-dataset pin: invalid repo %q", p.Repo)
	case !isHex(p.Commit, 40):
		return errors.New("catalog: iam-dataset pin: commit must be a full 40-hex SHA")
	case !isHex(p.SHA256, 64):
		return errors.New("catalog: iam-dataset pin: sha256 must be 64 hex characters")
	case !safeRel(p.Path) || strings.ContainsAny(p.Path, "?#%"):
		return fmt.Errorf("catalog: iam-dataset pin: invalid path %q", p.Path)
	}
	return nil
}

type datasetService struct {
	Prefix     string `json:"prefix"`
	Privileges []struct {
		Privilege     string `json:"privilege"`
		AccessLevel   string `json:"access_level"`
		ResourceTypes []struct {
			DependentActions []string `json:"dependent_actions"`
		} `json:"resource_types"`
	} `json:"privileges"`
}

func (f *Fetcher) fetchDataset(ctx context.Context, pin *DatasetPin) (*DatasetExtract, error) {
	if err := pin.validate(); err != nil {
		return nil, err
	}
	base := f.DatasetBaseURL
	if base == "" {
		base = DefaultDatasetBaseURL
	}
	max := f.MaxDatasetBytes
	if max <= 0 {
		max = defaultMaxDatasetBytes
	}
	raw, err := f.get(ctx, strings.TrimRight(base, "/")+"/"+pin.Repo+"/"+pin.Commit+"/"+pin.Path, max)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(raw); got != pin.SHA256 {
		return nil, fmt.Errorf("catalog: iam-dataset digest %s does not match the pin %s", got, pin.SHA256)
	}
	ex, err := ExtractDataset(raw)
	if err != nil {
		return nil, err
	}
	ex.Commit, ex.UpstreamSHA = pin.Commit, pin.SHA256
	return ex, nil
}

// ExtractDataset condenses iam-dataset's iam_definition.json to the access
// level and dependent actions of each action. The input is untrusted: it is
// parsed into fixed types and entries that are not well formed are dropped.
func ExtractDataset(raw []byte) (*DatasetExtract, error) {
	var svcs []datasetService
	if err := json.Unmarshal(raw, &svcs); err != nil {
		return nil, fmt.Errorf("catalog: iam-dataset: %w", err)
	}
	if len(svcs) == 0 || len(svcs) > maxServices {
		return nil, fmt.Errorf("catalog: iam-dataset: %d services", len(svcs))
	}
	ex := &DatasetExtract{Actions: []DatasetAction{}}
	seen := map[string]bool{}
	for _, s := range svcs {
		if !validPrefix(s.Prefix) || len(s.Privileges) > maxActionsPerSvc {
			continue
		}
		for _, p := range s.Privileges {
			if !validActionName(p.Privilege) {
				continue
			}
			name := s.Prefix + ":" + p.Privilege
			if seen[asciiLower(name)] {
				continue
			}
			seen[asciiLower(name)] = true
			a := DatasetAction{Action: name}
			if p.AccessLevel != "Unknown" {
				a.AccessLevel = clip(p.AccessLevel, 32)
			}
			var dep []string
			for _, rt := range p.ResourceTypes {
				dep = append(dep, rt.DependentActions...)
			}
			a.Dependent = cleanDependent(dep)
			ex.Actions = append(ex.Actions, a)
		}
	}
	sort.Slice(ex.Actions, func(i, j int) bool {
		return asciiLower(ex.Actions[i].Action) < asciiLower(ex.Actions[j].Action)
	})
	return ex, nil
}

// ParseRCPPage extracts the service prefixes from the Organizations user
// guide page "Resource control policies (RCPs)", where each supported service
// is listed as "(prefix:<name>)". It returns them sorted. A page with none
// is an error: it means the format changed, not that RCPs support nothing.
func ParseRCPPage(page []byte) ([]string, error) {
	const marker = "(prefix:"
	s := string(page)
	seen := map[string]bool{}
	for {
		i := strings.Index(s, marker)
		if i < 0 {
			break
		}
		s = s[i+len(marker):]
		j := strings.IndexByte(s, ')')
		if j < 0 || j > 65 {
			continue
		}
		if p := s[:j]; validPrefix(p) {
			seen[p] = true
		}
	}
	if len(seen) == 0 {
		return nil, errors.New("catalog: RCP page lists no service prefixes (page format changed?)")
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// WriteSnapshot stores a fetched snapshot at dir/snapshots/<date>. Snapshots
// are immutable: an existing date is an error. The files are written to a
// temporary directory and moved into place, so a failure leaves nothing behind.
func WriteSnapshot(dir string, snap *RawSnapshot) error {
	if snap == nil || !validDate(snap.Date) {
		return errors.New("catalog: invalid snapshot")
	}
	parent := filepath.Join(dir, "snapshots")
	target := filepath.Join(parent, snap.Date)
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("catalog: snapshot %s already exists (snapshots are immutable)", snap.Date)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".tmp-"+snap.Date+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp) // no-op after a successful rename
	names := make([]string, 0, len(snap.Files))
	for name := range snap.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !safeRel(name) {
			return fmt.Errorf("catalog: unsafe snapshot file name %q", name)
		}
		p := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, snap.Files[name], 0o600); err != nil {
			return err
		}
	}
	return os.Rename(tmp, target)
}
