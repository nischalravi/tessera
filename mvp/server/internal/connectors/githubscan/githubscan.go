package githubscan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the connector's system name. It reports MCP findings only: no
// identity, account or grant comes from a code scan.
const System = "github-scan"

// maxFilesPerRepo bounds the files fetched and scanned in one repository.
const maxFilesPerRepo = 100

// Connector implements connectors.Connector over a Source.
type Connector struct {
	src Source
	now func() time.Time
}

// New builds a connector over src.
func New(src Source, now func() time.Time) (*Connector, error) {
	if src == nil {
		return nil, errors.New("githubscan: a source is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Connector{src: src, now: now}, nil
}

// FromEnv builds the connector from the environment:
//
//	TESSERA_GITHUB_SCAN_ORG       the organization to scan
//	TESSERA_GITHUB_SCAN_TOKEN     reference to a read-only token: file:/abs/path or env:NAME
//	TESSERA_GITHUB_SCAN_API_URL   default https://api.github.com (GitHub Enterprise Server: https://host/api/v3)
//
// rt and hc come from the validated server configuration; FromEnv never builds a client.
func FromEnv(getenv func(string) string, now time.Time, rt connsync.Runtime, hc *http.Client) (connectors.Connector, error) {
	cfg, err := RESTConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	clock := func() time.Time { return time.Now().UTC() }
	src, err := NewREST(cfg, rt, hc, clock)
	if err != nil {
		return nil, err
	}
	return New(src, clock)
}

// RESTConfigFromEnv is the environment mapping of FromEnv on its own, so a
// governed connection (internal/connectors/governed) reads its settings the same way.
func RESTConfigFromEnv(getenv func(string) string) (RESTConfig, error) {
	ref := getenv("TESSERA_GITHUB_SCAN_TOKEN")
	if ref == "" {
		return RESTConfig{}, errors.New("TESSERA_GITHUB_SCAN_TOKEN (a file: or env: reference) is required")
	}
	tok, err := connsync.ResolveSecret(ref, getenv)
	if err != nil {
		return RESTConfig{}, fmt.Errorf("TESSERA_GITHUB_SCAN_TOKEN: %w", err)
	}
	return RESTConfig{APIURL: getenv("TESSERA_GITHUB_SCAN_API_URL"), Org: getenv("TESSERA_GITHUB_SCAN_ORG"), Token: tok}, nil
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "GitHub code scan" }
func (*Connector) TypeName() string    { return "GitHubScanConnector" }

// StreamEvents has no events.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// Discover scans every repository and returns the findings. A repository that
// cannot be read fails the scan: a partial snapshot would make ingest remove
// the findings of the repositories it missed.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	repos, err := c.src.Repos(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(repos, func(i, j int) bool { return repos[i].Name < repos[j].Name })
	res := &connectors.DiscoveryResult{AgentSnapshotOf: []string{System}}
	for _, r := range repos {
		recs, err := c.scanRepo(ctx, r)
		if err != nil {
			return nil, err
		}
		res.MCPFindings = append(res.MCPFindings, recs...)
	}
	return res, nil
}

func (c *Connector) scanRepo(ctx context.Context, r Repo) ([]connectors.MCPFindingRecord, error) {
	tree, err := c.src.Tree(ctx, r)
	if errors.Is(err, ErrEmptyRepo) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	var candidates []string
	for _, e := range tree {
		have[e.Path] = true
		if e.Size <= MaxFileBytes && Classify(e.Path) != classNone {
			candidates = append(candidates, e.Path)
		}
	}
	sort.Strings(candidates)
	if len(candidates) > maxFilesPerRepo {
		candidates = candidates[:maxFilesPerRepo]
	}
	var out []connectors.MCPFindingRecord
	var owners *Codeowners
	ownersLoaded := false
	for _, p := range candidates {
		content, err := c.src.File(ctx, r, p)
		if errors.Is(err, ErrNoFile) {
			continue
		}
		if err != nil {
			return nil, err
		}
		found := Scan(p, content)
		if len(found) == 0 {
			continue
		}
		if !ownersLoaded {
			ownersLoaded = true
			if owners, err = c.loadCodeowners(ctx, r, have); err != nil {
				return nil, err
			}
		}
		commit, err := c.src.LastCommit(ctx, r, p)
		if err != nil {
			return nil, err
		}
		ref, how, id := linkOwner(owners.OwnersOf(p), commit)
		sha := ""
		if commit != nil {
			sha = commit.SHA
		}
		for _, f := range found {
			out = append(out, connectors.MCPFindingRecord{System: System, Kind: f.Kind, Org: r.Org, Repo: r.Name, Path: p,
				Location: f.Location, Server: f.Server, Transport: f.Transport, Target: f.Target, SecretType: f.SecretType,
				Fingerprint: f.Fingerprint, OwnerRef: ref, OwnerSource: how, Owner: id, CommitSHA: sha})
		}
	}
	return out, nil
}

func (c *Connector) loadCodeowners(ctx context.Context, r Repo, have map[string]bool) (*Codeowners, error) {
	for _, p := range CodeownersPaths {
		if !have[p] {
			continue
		}
		b, err := c.src.File(ctx, r, p)
		if errors.Is(err, ErrNoFile) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(b) > MaxFileBytes {
			return nil, nil
		}
		return ParseCodeowners(string(b)), nil
	}
	return nil, nil
}

var noreply = regexp.MustCompile(`(?i)^(?:\d+\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com$`)

// linkOwner picks the owner of a file: the CODEOWNERS owner when there is one
// (a person's e-mail address first, else the first listed), otherwise the
// author of the last commit that touched it. The reference is a source-side
// name; the identity reference is what ingest tries to resolve (an e-mail
// address, or "github:<login>").
func linkOwner(owners []string, commit *Commit) (ref, how string, id *connectors.IdentityRef) {
	pick := ""
	for _, o := range owners {
		if strings.Contains(o, "@") && !strings.HasPrefix(o, "@") {
			pick = o
			break
		}
	}
	if pick == "" && len(owners) > 0 {
		pick = owners[0]
	}
	switch {
	case pick == "":
	case strings.HasPrefix(pick, "@") && strings.Contains(pick, "/"):
		return "github-team:" + strings.TrimPrefix(pick, "@"), "codeowners", nil
	case strings.HasPrefix(pick, "@"):
		login := strings.TrimPrefix(pick, "@")
		return "github:" + login, "codeowners", &connectors.IdentityRef{ExternalID: "github:" + login}
	default:
		return pick, "codeowners", &connectors.IdentityRef{Email: pick}
	}
	if commit == nil {
		return "", "none", nil
	}
	login, email := commit.Login, commit.Email
	if m := noreply.FindStringSubmatch(email); m != nil {
		if login == "" {
			login = m[1]
		}
		email = ""
	}
	switch {
	case email != "" && login != "":
		return email, "committer", &connectors.IdentityRef{ExternalID: "github:" + login, Email: email}
	case email != "":
		return email, "committer", &connectors.IdentityRef{Email: email}
	case login != "":
		return "github:" + login, "committer", &connectors.IdentityRef{ExternalID: "github:" + login}
	}
	return "", "none", nil
}
