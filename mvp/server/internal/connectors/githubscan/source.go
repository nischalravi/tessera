package githubscan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Repo is a repository of the scanned organization.
type Repo struct {
	Org, Name, DefaultBranch string
}

// TreeEntry is one file of a repository's default branch.
type TreeEntry struct {
	Path string
	Size int64
}

// Commit is the last commit that touched a file.
type Commit struct {
	SHA, Login, Email string
}

// ErrEmptyRepo and ErrNoFile are the answers for a repository without commits
// and a file that is gone.
var (
	ErrEmptyRepo = errors.New("githubscan: repository is empty")
	ErrNoFile    = errors.New("githubscan: no such file")
)

// Source is the read-only view of GitHub the scanner needs. REST is the live
// implementation; tests use a fake.
type Source interface {
	// Repos lists the organization's repositories (not archived, disabled or forks).
	Repos(ctx context.Context) ([]Repo, error)
	// Tree lists the files of the default branch.
	Tree(ctx context.Context, r Repo) ([]TreeEntry, error)
	// File returns a file's content on the default branch (ErrNoFile if gone).
	File(ctx context.Context, r Repo, path string) ([]byte, error)
	// LastCommit returns the last commit that touched path; nil if unknown.
	LastCommit(ctx context.Context, r Repo, path string) (*Commit, error)
}

var (
	orgRE    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	branchRE = regexp.MustCompile(`^[A-Za-z0-9._/\-]{1,255}$`)
)

// RESTConfig configures the GitHub REST source. The token needs read access to
// repository contents and metadata only (a fine-grained token with
// Contents: read and Metadata: read, or a GitHub App installation).
type RESTConfig struct {
	APIURL string // default https://api.github.com; a GitHub Enterprise Server URL ends in /api/v3
	Org    string
	Token  connsync.Secret
	// MaxRepos bounds one scan (default 1000).
	MaxRepos int
}

// REST reads GitHub over its REST API through internal/safehttp. It only
// sends GET requests.
type REST struct {
	cfg  RESTConfig
	base *url.URL
	api  *connsync.Client
}

// DefaultAPIURL is GitHub.com's REST API.
const DefaultAPIURL = "https://api.github.com"

// NewREST builds the source. hc must come from connsync.NewHTTPClient.
func NewREST(cfg RESTConfig, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*REST, error) {
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	base, err := connsync.ParseBaseURL(cfg.APIURL, rt)
	if err != nil {
		return nil, fmt.Errorf("githubscan: API URL: %w", err)
	}
	if !orgRE.MatchString(cfg.Org) {
		return nil, errors.New("githubscan: the organization name is not valid")
	}
	if cfg.Token.Empty() {
		return nil, errors.New("githubscan: a token is required")
	}
	if hc == nil {
		return nil, errors.New("githubscan: an internal/safehttp client is required")
	}
	if cfg.MaxRepos <= 0 {
		cfg.MaxRepos = 1000
	}
	r := &REST{cfg: cfg, base: base}
	auth := "Bearer " + cfg.Token.Reveal()
	r.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/vnd.github+json"}, "X-Github-Api-Version": {"2022-11-28"},
		"User-Agent": {"tessera-connector/github-scan"}},
		Authorize: func(context.Context) (string, error) { return auth, nil }}
	return r, nil
}

// url builds an absolute API URL from path segments (each escaped).
func (g *REST) url(query url.Values, segs ...string) string {
	u := *g.base
	esc := make([]string, len(segs))
	raw := make([]string, len(segs))
	for i, s := range segs {
		raw[i] = s
		esc[i] = url.PathEscape(s)
	}
	u.Path = strings.TrimRight(g.base.Path, "/") + "/" + strings.Join(raw, "/")
	u.RawPath = strings.TrimRight(g.base.EscapedPath(), "/") + "/" + strings.Join(esc, "/")
	if query != nil {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

// nextLink returns the rel="next" target of the Link headers.
func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			if i, j := strings.Index(part, "<"), strings.Index(part, ">"); i == 0 && j > 1 {
				return part[1:j]
			}
		}
	}
	return ""
}

type apiRepo struct {
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
}

// Repos implements Source.
func (g *REST) Repos(ctx context.Context) ([]Repo, error) {
	var out []Repo
	first := g.url(url.Values{"per_page": {"100"}, "type": {"all"}}, "orgs", g.cfg.Org, "repos")
	err := connsync.Walk(ctx, g.base, first, func(ctx context.Context, pageURL string) (string, error) {
		var page []apiRepo
		h, err := g.api.GetJSON(ctx, pageURL, nil, &page)
		if err != nil {
			return "", err
		}
		for _, r := range page {
			if r.Archived || r.Disabled || r.Fork || !repoRE.MatchString(r.Name) || !branchRE.MatchString(r.DefaultBranch) ||
				strings.Contains(r.DefaultBranch, "..") {
				continue
			}
			if len(out) >= g.cfg.MaxRepos {
				return "", nil
			}
			out = append(out, Repo{Org: g.cfg.Org, Name: r.Name, DefaultBranch: r.DefaultBranch})
		}
		return nextLink(h), nil
	})
	if err != nil {
		return nil, fmt.Errorf("githubscan: repositories: %w", err)
	}
	return out, nil
}

// Tree implements Source.
func (g *REST) Tree(ctx context.Context, r Repo) ([]TreeEntry, error) {
	var doc struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Size int64  `json:"size"`
		} `json:"tree"`
	}
	_, err := g.api.GetJSON(ctx, g.url(url.Values{"recursive": {"1"}}, "repos", r.Org, r.Name, "git", "trees", r.DefaultBranch), nil, &doc)
	if err != nil {
		if connsync.Status(err) == http.StatusConflict {
			return nil, ErrEmptyRepo
		}
		return nil, fmt.Errorf("githubscan: tree of %s/%s: %w", r.Org, r.Name, err)
	}
	var out []TreeEntry
	for _, e := range doc.Tree {
		if e.Type == "blob" && e.Path != "" && len(e.Path) <= 512 {
			out = append(out, TreeEntry{Path: e.Path, Size: e.Size})
		}
	}
	return out, nil
}

// File implements Source.
func (g *REST) File(ctx context.Context, r Repo, p string) ([]byte, error) {
	segs := append([]string{"repos", r.Org, r.Name, "contents"}, strings.Split(p, "/")...)
	for _, s := range segs {
		if s == "" || s == ".." || s == "." {
			return nil, fmt.Errorf("githubscan: path %q is not valid", p)
		}
	}
	resp, err := g.api.Do(ctx, http.MethodGet, g.url(url.Values{"ref": {r.DefaultBranch}}, segs...),
		http.Header{"Accept": {"application/vnd.github.raw+json"}}, nil)
	if err != nil {
		if connsync.Status(err) == http.StatusNotFound {
			return nil, ErrNoFile
		}
		return nil, fmt.Errorf("githubscan: file of %s/%s: %w", r.Org, r.Name, err)
	}
	return resp.Body, nil
}

// LastCommit implements Source.
func (g *REST) LastCommit(ctx context.Context, r Repo, p string) (*Commit, error) {
	var page []struct {
		SHA    string `json:"sha"`
		Author *struct {
			Login string `json:"login"`
		} `json:"author"`
		Commit struct {
			Author struct {
				Email string `json:"email"`
			} `json:"author"`
		} `json:"commit"`
	}
	q := url.Values{"path": {p}, "sha": {r.DefaultBranch}, "per_page": {"1"}}
	if _, err := g.api.GetJSON(ctx, g.url(q, "repos", r.Org, r.Name, "commits"), nil, &page); err != nil {
		if s := connsync.Status(err); s == http.StatusNotFound || s == http.StatusConflict {
			return nil, nil
		}
		return nil, fmt.Errorf("githubscan: commits of %s/%s: %w", r.Org, r.Name, err)
	}
	if len(page) == 0 {
		return nil, nil
	}
	c := &Commit{SHA: page[0].SHA, Email: page[0].Commit.Author.Email}
	if page[0].Author != nil {
		c.Login = page[0].Author.Login
	}
	return c, nil
}
