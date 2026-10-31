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

// CommitFile commits content as the new text of path on top of parent, through the Git Data API: a blob, a tree whose base
// is the parent's tree, and a commit whose parents are exactly [parent] (the answer is checked). It moves no ref, so nothing
// is visible until PublishCommit or the ref calls below. Unlike the contents API, which checks only the file's blob, the
// commit is made on a parent the caller has verified.
func (c *Client) CommitFile(ctx context.Context, cr *Credentials, path, parent, message string, content []byte) (string, error) {
	if !ValidRepo(cr.Repo) || !ValidPath(path) || !ValidSHA(parent) || message == "" || len(content) > MaxFileBytes {
		return "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/git/commits/"+parent, nil, http.StatusOK, "the parent commit read")
	if err != nil {
		return "", err
	}
	var pc struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if json.Unmarshal(r.body, &pc) != nil || !ValidSHA(pc.Tree.SHA) {
		return "", errors.New("ghapp: GitHub returned no usable tree for the parent commit")
	}
	r, err = c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/git/blobs", map[string]string{"content": base64.StdEncoding.EncodeToString(content), "encoding": "base64"}, http.StatusCreated, "the blob create")
	if err != nil {
		return "", err
	}
	var obj struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(r.body, &obj) != nil || !ValidSHA(obj.SHA) {
		return "", errors.New("ghapp: GitHub returned no blob id")
	}
	blob := obj.SHA
	r, err = c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/git/trees", map[string]any{"base_tree": pc.Tree.SHA,
		"tree": []map[string]string{{"path": path, "mode": "100644", "type": "blob", "sha": blob}}}, http.StatusCreated, "the tree create")
	if err != nil {
		return "", err
	}
	if json.Unmarshal(r.body, &obj) != nil || !ValidSHA(obj.SHA) {
		return "", errors.New("ghapp: GitHub returned no tree id")
	}
	r, err = c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/git/commits", map[string]any{"message": message, "tree": obj.SHA, "parents": []string{parent}},
		http.StatusCreated, "the commit create")
	if err != nil {
		return "", err
	}
	var cm struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if json.Unmarshal(r.body, &cm) != nil || !ValidSHA(cm.SHA) {
		return "", errors.New("ghapp: GitHub returned no commit id")
	}
	if len(cm.Parents) != 1 || cm.Parents[0].SHA != parent {
		return "", ErrBranchConflict // the commit does not sit on exactly the verified parent
	}
	return cm.SHA, nil
}

// MoveBranch moves refs/heads/{branch} to commit with force:false, so GitHub refuses (422) unless the commit is a
// fast-forward of where the branch is now: a push that landed after the branch was verified is ErrBranchConflict, and the
// commit is never made the branch's head over it. The answer must name the commit.
func (c *Client) MoveBranch(ctx context.Context, cr *Credentials, branch, commit string) error {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) || !ValidSHA(commit) {
		return ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPatch, "/repos/"+cr.Repo+"/git/refs/heads/"+escPath(branch), map[string]any{"sha": commit, "force": false}, http.StatusOK, "the branch update")
	if err != nil {
		if IsStatus(err, http.StatusUnprocessableEntity) || IsStatus(err, http.StatusConflict) {
			return ErrBranchConflict
		}
		return err
	}
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if json.Unmarshal(r.body, &out) != nil || out.Object.SHA != commit {
		return ErrBranchConflict
	}
	return nil
}

// CreateBranchAt creates refs/heads/{branch} at commit (a commit made by CommitFile on the base head): the branch never
// exists at the base with Tessera committing afterwards. A branch that exists already (422) is ErrBranchConflict.
func (c *Client) CreateBranchAt(ctx context.Context, cr *Credentials, branch, commit string) error {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) || !ValidSHA(commit) {
		return ErrBadInput
	}
	_, err := c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/git/refs", map[string]string{"ref": "refs/heads/" + branch, "sha": commit},
		http.StatusCreated, "the branch create")
	if IsStatus(err, http.StatusUnprocessableEntity) {
		return ErrBranchConflict
	}
	return err
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

// FindOpenPulls returns the open pull requests whose head is branch of this repository and whose base is base (at most
// 30; the caller picks the App's own).
func (c *Client) FindOpenPulls(ctx context.Context, cr *Credentials, branch, base string) ([]*Pull, error) {
	if !ValidRepo(cr.Repo) || !ValidBranch(branch) || !ValidBranch(base) {
		return nil, ErrBadInput
	}
	owner, _, _ := strings.Cut(cr.Repo, "/")
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/pulls?state=open&per_page=30&base="+url.QueryEscape(base)+"&head="+url.QueryEscape(owner+":"+branch), nil, http.StatusOK, "the pull request search")
	if err != nil {
		return nil, err
	}
	var out []pullJSON
	if json.Unmarshal(r.body, &out) != nil {
		return nil, errors.New("ghapp: unreadable pull request list")
	}
	var pulls []*Pull
	for i := range out {
		if out[i].Number >= 1 {
			pulls = append(pulls, c.pull(&out[i], cr.Repo))
		}
	}
	return pulls, nil
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
	Status  string // identical, ahead, behind or diverged
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
		AheadBy int    `json:"ahead_by"`
		Status  string `json:"status"`
		Files   []struct {
			Filename string `json:"filename"`
			Previous string `json:"previous_filename"`
		} `json:"files"`
		TotalCommits int `json:"total_commits"`
	}
	if json.Unmarshal(r.body, &out) != nil || len(out.Files) >= 100 || out.AheadBy < 0 {
		return nil, ErrNotAFile
	}
	switch out.Status {
	case "identical", "ahead", "behind", "diverged":
	default:
		return nil, ErrNotAFile
	}
	// commits the branch has with no file changed (an empty commit) or files without commits are not a state Tessera made
	if (out.AheadBy > 0 && len(out.Files) == 0) || (out.AheadBy == 0 && len(out.Files) > 0) {
		return nil, ErrBranchConflict
	}
	cmp := &Compare{AheadBy: out.AheadBy, Status: out.Status}
	for _, f := range out.Files {
		cmp.Files = append(cmp.Files, f.Filename)
		if f.Previous != "" { // a rename touches two paths
			cmp.Files = append(cmp.Files, f.Previous)
		}
	}
	return cmp, nil
}
