package ghapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Repository writes for a pull request (issue #665, LP-9): the default branch, a branch cut from its head, one file read
// and committed on that branch, and the pull request opened or updated. Every call goes through Client.api, so it uses
// the installation token of the one configured repository (with Credentials.Contents set, which adds contents:write),
// the safehttp client, no redirects and a strict status check. Nothing here merges anything.

// Errors of the repository calls.
var (
	// ErrFileNotFound: the file is not on the ref.
	ErrFileNotFound = errors.New("ghapp: file not found")
	// ErrBranchNotFound: the branch does not exist.
	ErrBranchNotFound = errors.New("ghapp: branch not found")
	// ErrStaleBase: GitHub refused the commit because the file or branch moved under it (409).
	ErrStaleBase = errors.New("ghapp: the file changed on the branch while the commit was made")
	// ErrBranchConflict: the branch exists and is not one Tessera made or can show to hold only its own edit.
	ErrBranchConflict = errors.New("ghapp: the branch exists and is not Tessera's")
	// ErrPullConflict: an open pull request on the branch was not opened by the App, or is not at the branch's head.
	ErrPullConflict = errors.New("ghapp: an open pull request on the branch is not Tessera's")
	// ErrNotAFile: the path is a directory, a symlink or a file too large for the contents API.
	ErrNotAFile = errors.New("ghapp: path is not a regular file the contents API returns")
)

// MaxFileBytes is the largest policy file read or written (internal/policybundle's 256 KiB per file).
const MaxFileBytes = 256 << 10

var (
	branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
	pathRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,7}$`)
)

// ValidBranch reports whether name is a branch name Tessera pushes: plain characters, no "..", no empty, dot or lock
// segment, no trailing slash.
func ValidBranch(name string) bool {
	if !branchRE.MatchString(name) || strings.Contains(name, "..") {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || strings.HasPrefix(seg, ".") || strings.HasSuffix(seg, ".lock") {
			return false
		}
	}
	return true
}

// ValidPath reports whether p is a relative file path of plain segments (no "." or ".." segment).
func ValidPath(p string) bool {
	if !pathRE.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func escPath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// DefaultBranch returns the repository's default branch (GET /repos/{repo}).
func (c *Client) DefaultBranch(ctx context.Context, cr *Credentials) (string, error) {
	if !ValidRepo(cr.Repo) {
		return "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo, nil, http.StatusOK, "the repository read")
	if err != nil {
		return "", err
	}
	var out struct {
		DefaultBranch string `json:"default_branch"`
	}
	if json.Unmarshal(r.body, &out) != nil || !ValidBranch(out.DefaultBranch) {
		return "", errors.New("ghapp: GitHub returned no usable default branch")
	}
	return out.DefaultBranch, nil
}

// BranchHead returns the commit a branch points at (GET /repos/{repo}/git/ref/heads/{branch}).
func (c *Client) BranchHead(ctx context.Context, cr *Credentials, branch string) (string, error) {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) {
		return "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/git/ref/heads/"+escPath(branch), nil, http.StatusOK, "the branch read")
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return "", ErrBranchNotFound
		}
		return "", err
	}
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if json.Unmarshal(r.body, &out) != nil || !ValidSHA(out.Object.SHA) {
		return "", errors.New("ghapp: GitHub returned no usable branch head")
	}
	return out.Object.SHA, nil
}

// CreateBranch creates refs/heads/{branch} at sha. created is false when the branch already exists (422: reference
// already exists), which is not an error: the caller reuses it.
func (c *Client) CreateBranch(ctx context.Context, cr *Credentials, branch, sha string) (created bool, err error) {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) || !ValidSHA(sha) {
		return false, ErrBadInput
	}
	_, err = c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/git/refs", map[string]string{"ref": "refs/heads/" + branch, "sha": sha},
		http.StatusCreated, "the branch create")
	switch {
	case err == nil:
		return true, nil
	case IsStatus(err, http.StatusUnprocessableEntity):
		return false, nil
	}
	return false, err
}

// File is a file at a ref: its text and the blob id a commit must name to replace it.
type File struct {
	Content []byte
	SHA     string
}

// GetFile reads path at ref (a branch or commit): GET /repos/{repo}/contents/{path}?ref=. A directory, symlink or a file
// over MaxFileBytes is ErrNotAFile; a missing file ErrFileNotFound.
func (c *Client) GetFile(ctx context.Context, cr *Credentials, path, ref string) (*File, error) {
	if !ValidRepo(cr.Repo) || !ValidPath(path) || !(ValidBranch(ref) || ValidSHA(ref)) {
		return nil, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/contents/"+escPath(path)+"?ref="+url.QueryEscape(ref), nil, http.StatusOK, "the file read")
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	var out struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
		SHA      string `json:"sha"`
		Content  string `json:"content"`
	}
	if json.Unmarshal(r.body, &out) != nil || out.Type != "file" || out.Encoding != "base64" || out.Size > MaxFileBytes || !ValidSHA(out.SHA) {
		return nil, ErrNotAFile
	}
	b, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(out.Content))
	if err != nil || len(b) > MaxFileBytes {
		return nil, ErrNotAFile
	}
	return &File{Content: b, SHA: out.SHA}, nil
}

// PutFile commits content as the new text of an existing file on branch (PUT /repos/{repo}/contents/{path}), naming
// blobSHA, the blob it replaces, so a concurrent change is refused (ErrStaleBase) rather than overwritten. It returns
// the new commit.
func (c *Client) PutFile(ctx context.Context, cr *Credentials, path, branch, message string, content []byte, blobSHA string) (string, error) {
	if !ValidRepo(cr.Repo) || !ValidPath(path) || !ValidBranch(branch) || !ValidSHA(blobSHA) || message == "" || len(content) > MaxFileBytes {
		return "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPut, "/repos/"+cr.Repo+"/contents/"+escPath(path), map[string]string{
		"message": message, "content": base64.StdEncoding.EncodeToString(content), "branch": branch, "sha": blobSHA}, http.StatusOK, "the file commit")
	if err != nil {
		if IsStatus(err, http.StatusConflict) {
			return "", ErrStaleBase
		}
		return "", err
	}
	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if json.Unmarshal(r.body, &out) != nil || !ValidSHA(out.Commit.SHA) {
		return "", errors.New("ghapp: GitHub committed the file but returned no commit id")
	}
	return out.Commit.SHA, nil
}

// Pull is a pull request as the client reads it.
type Pull struct {
	Number  int
	HTMLURL string
	State   string // open, closed
	HeadSHA string
	// Author is the login of whoever opened it (the App's bot is "<slug>[bot]").
	Author string
}

type pullJSON struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Head    struct {
		SHA string `json:"sha"`
	} `json:"head"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
}

// htmlHosts are the hosts a pull request link may name: github.com and the host of the configured API base.
func (c *Client) htmlHosts() []string {
	hosts := []string{"github.com"}
	if u, err := url.Parse(c.APIBase); err == nil && c.APIBase != "" && u.Host != "" {
		hosts = append(hosts, u.Host)
	}
	return hosts
}

// pull reads a pull request; its link is kept only when it names a known host and is /<owner>/<repo>/pull/<number>.
func (c *Client) pull(p *pullJSON, repo string) *Pull {
	u := ""
	if pu, err := url.Parse(p.HTMLURL); err == nil && pu.Scheme == "https" && len(p.HTMLURL) <= 300 && pu.User == nil && pu.RawQuery == "" &&
		pu.Fragment == "" && slices.Contains(c.htmlHosts(), pu.Host) && pu.Path == "/"+repo+"/pull/"+strconv.Itoa(p.Number) {
		u = p.HTMLURL
	}
	return &Pull{Number: p.Number, HTMLURL: u, State: p.State, HeadSHA: p.Head.SHA, Author: p.User.Login}
}

// FindOpenPull returns the open pull request whose head is branch of this repository, or nil.
func (c *Client) FindOpenPull(ctx context.Context, cr *Credentials, branch string) (*Pull, error) {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) {
		return nil, ErrBadInput
	}
	owner, _, _ := strings.Cut(cr.Repo, "/")
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/pulls?state=open&per_page=1&head="+url.QueryEscape(owner+":"+branch), nil, http.StatusOK, "the pull request search")
	if err != nil {
		return nil, err
	}
	var out []pullJSON
	if json.Unmarshal(r.body, &out) != nil {
		return nil, errors.New("ghapp: unreadable pull request list")
	}
	if len(out) == 0 || out[0].Number < 1 {
		return nil, nil
	}
	return c.pull(&out[0], cr.Repo), nil
}

// GetPull reads pull request number (ErrPullNotFound when it does not exist).
func (c *Client) GetPull(ctx context.Context, cr *Credentials, number int) (*Pull, error) {
	if !ValidRepo(cr.Repo) || number < 1 || number > 1<<31-1 {
		return nil, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/pulls/"+strconv.Itoa(number), nil, http.StatusOK, "the pull request read")
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return nil, ErrPullNotFound
		}
		return nil, err
	}
	var out pullJSON
	if json.Unmarshal(r.body, &out) != nil || out.Number != number {
		return nil, errors.New("ghapp: unreadable pull request")
	}
	return c.pull(&out, cr.Repo), nil
}

// CreatePull opens a pull request from branch into base. exists is true when GitHub answers 422 because one is open
// already (the caller then finds and updates it).
func (c *Client) CreatePull(ctx context.Context, cr *Credentials, title, branch, base, body string) (p *Pull, exists bool, err error) {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) || !ValidBranch(base) || title == "" {
		return nil, false, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/pulls", map[string]any{"title": title, "head": branch, "base": base,
		"body": clip(body), "draft": false, "maintainer_can_modify": false}, http.StatusCreated, "the pull request create")
	if err != nil {
		if IsStatus(err, http.StatusUnprocessableEntity) {
			return nil, true, nil
		}
		return nil, false, err
	}
	var out pullJSON
	if json.Unmarshal(r.body, &out) != nil || out.Number < 1 {
		return nil, false, errors.New("ghapp: GitHub created the pull request but returned no number")
	}
	return c.pull(&out, cr.Repo), false, nil
}

// UpdatePull replaces the title and body of an open pull request in place.
func (c *Client) UpdatePull(ctx context.Context, cr *Credentials, number int, title, body string) (*Pull, error) {
	if !ValidRepo(cr.Repo) || number < 1 || number > 1<<31-1 || title == "" {
		return nil, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPatch, "/repos/"+cr.Repo+"/pulls/"+strconv.Itoa(number), map[string]string{"title": title, "body": clip(body)}, http.StatusOK, "the pull request update")
	if err != nil {
		return nil, err
	}
	var out pullJSON
	if json.Unmarshal(r.body, &out) != nil || out.Number != number {
		return nil, errors.New("ghapp: unreadable pull request")
	}
	return c.pull(&out, cr.Repo), nil
}

// AppSlug returns the App's slug (GET /app, authenticated with the App JWT, not an installation token), so the login of
// the pull requests it opens, "<slug>[bot]", is known.
func (c *Client) AppSlug(ctx context.Context, cr *Credentials) (string, error) {
	jwt, err := AppJWT(cr.AppID, cr.Key, c.now())
	if err != nil {
		return "", err
	}
	r, err := c.do(ctx, http.MethodGet, "/app", jwt, nil)
	if err != nil {
		return "", err
	}
	switch r.status {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return "", ErrAppAuth
	default:
		return "", &StatusError{Status: r.status, Op: "the App read"}
	}
	var out struct {
		Slug string `json:"slug"`
	}
	if json.Unmarshal(r.body, &out) != nil || !slugRE.MatchString(out.Slug) {
		return "", errors.New("ghapp: GitHub returned no usable App slug")
	}
	return out.Slug, nil
}

var slugRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,99}$`)

// Compare is what a branch has that its base does not: the files changed and how many commits it is ahead.
type Compare struct {
	Files   []string
	AheadBy int
}

// CompareBranch reads GET /repos/{repo}/compare/{base}...{head}: the files the head changed against the merge base. A
// comparison of more files than the answer holds (300) is ErrNotAFile, so it is never read as a short list.
func (c *Client) CompareBranch(ctx context.Context, cr *Credentials, base, head string) (*Compare, error) {
	if !ValidRepo(cr.Repo) || !ValidBranch(base) || !(ValidBranch(head) || ValidSHA(head)) {
		return nil, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/compare/"+escPath(base)+"..."+escPath(head)+"?per_page=100", nil, http.StatusOK, "the comparison")
	if err != nil {
		return nil, err
	}
	var out struct {
		AheadBy int `json:"ahead_by"`
		Files   []struct {
			Filename string `json:"filename"`
			Previous string `json:"previous_filename"`
		} `json:"files"`
		TotalCommits int `json:"total_commits"`
	}
	if json.Unmarshal(r.body, &out) != nil || len(out.Files) >= 100 || out.AheadBy < 0 {
		return nil, ErrNotAFile
	}
	cmp := &Compare{AheadBy: out.AheadBy}
	for _, f := range out.Files {
		cmp.Files = append(cmp.Files, f.Filename)
		if f.Previous != "" { // a rename touches two paths
			cmp.Files = append(cmp.Files, f.Previous)
		}
	}
	return cmp, nil
}
