package ghapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
)

// Reading a policy bundle at a commit, and asking how a commit relates to a branch (issue #657, AC-11). Every call goes
// through Client.api: the installation token of the one configured repository (with Credentials.ContentsRead set, which
// asks for contents:read and nothing else), the safehttp client, no redirects and a strict status check. Nothing here
// writes to the repository.

// ErrBundleTooLarge: the bundle at the commit has more files or bytes than the limits allow, or GitHub cut a tree.
var ErrBundleTooLarge = errors.New("ghapp: the policy bundle is larger than the limits allow")

// BundleLimits bound what ReadBundle fetches (internal/policybundle's limits).
type BundleLimits struct {
	MaxFiles     int
	MaxBytes     int
	MaxFileBytes int
}

type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
}

// readTree reads one tree. A tree GitHub cut (truncated) is ErrBundleTooLarge: it is never read as a short list.
func (c *Client) readTree(ctx context.Context, cr *Credentials, sha string, recursive bool) ([]treeEntry, error) {
	path := "/repos/" + cr.Repo + "/git/trees/" + sha
	if recursive {
		path += "?recursive=1"
	}
	r, err := c.api(ctx, cr, http.MethodGet, path, nil, http.StatusOK, "the tree read")
	if err != nil {
		return nil, err
	}
	var out struct {
		Tree      []treeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if json.Unmarshal(r.body, &out) != nil {
		return nil, errors.New("ghapp: unreadable tree")
	}
	if out.Truncated {
		return nil, ErrBundleTooLarge
	}
	return out.Tree, nil
}

// ReadBundle reads the files of the commit that keep accepts, below the top-level names in tops (a file such as
// tessera.yaml, or a folder such as roles, read recursively): the tree of the commit, then the tree of each folder, then each
// file as a blob (the contents API stops at 1 MB and is addressed by path; a blob is addressed by its id). Files that keep
// refuses are never fetched. A symlink or submodule, a path the client does not accept or a folder that is a file is
// ErrNotAFile; more files or bytes than lim is ErrBundleTooLarge, checked before the blobs are fetched.
func (c *Client) ReadBundle(ctx context.Context, cr *Credentials, commit string, tops []string, keep func(path string) bool, lim BundleLimits) (map[string][]byte, error) {
	if !ValidRepo(cr.Repo) || !ValidSHA(commit) {
		return nil, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/git/commits/"+commit, nil, http.StatusOK, "the commit read")
	if err != nil {
		return nil, err
	}
	var cm struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if json.Unmarshal(r.body, &cm) != nil || !ValidSHA(cm.Tree.SHA) || (cm.SHA != "" && cm.SHA != commit) {
		return nil, errors.New("ghapp: GitHub returned no usable tree for the commit")
	}
	root, err := c.readTree(ctx, cr, cm.Tree.SHA, false)
	if err != nil {
		return nil, err
	}
	type want struct{ path, sha string }
	var wants []want
	declared := 0
	add := func(path string, e treeEntry) error {
		if !keep(path) {
			return nil
		}
		if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") || !ValidPath(path) || !ValidSHA(e.SHA) {
			return ErrNotAFile
		}
		if e.Size < 0 || e.Size > lim.MaxFileBytes {
			return ErrBundleTooLarge
		}
		if declared += e.Size; declared > lim.MaxBytes || len(wants) >= lim.MaxFiles {
			return ErrBundleTooLarge
		}
		wants = append(wants, want{path, e.SHA})
		return nil
	}
	isTop := map[string]bool{}
	for _, t := range tops {
		isTop[t] = true
	}
	for _, e := range root {
		if !isTop[e.Path] {
			continue
		}
		switch e.Type {
		case "blob":
			if err := add(e.Path, e); err != nil {
				return nil, err
			}
		case "tree":
			if !ValidSHA(e.SHA) {
				return nil, ErrNotAFile
			}
			sub, err := c.readTree(ctx, cr, e.SHA, true)
			if err != nil {
				return nil, err
			}
			for _, s := range sub {
				if s.Type == "tree" {
					continue
				}
				if err := add(e.Path+"/"+s.Path, s); err != nil {
					return nil, err
				}
			}
		default: // a submodule
			return nil, ErrNotAFile
		}
	}
	sort.Slice(wants, func(i, j int) bool { return wants[i].path < wants[j].path })
	total := 0
	out := make(map[string][]byte, len(wants))
	for _, w := range wants {
		b, err := c.readBlob(ctx, cr, w.sha, lim.MaxFileBytes)
		if err != nil {
			return nil, err
		}
		if total += len(b); total > lim.MaxBytes {
			return nil, ErrBundleTooLarge
		}
		out[w.path] = b
	}
	return out, nil
}

// readBlob reads a blob: GET /repos/{repo}/git/blobs/{sha}.
func (c *Client) readBlob(ctx context.Context, cr *Credentials, sha string, max int) ([]byte, error) {
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/git/blobs/"+sha, nil, http.StatusOK, "the blob read")
	if err != nil {
		return nil, err
	}
	var out struct {
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
		Content  string `json:"content"`
	}
	if json.Unmarshal(r.body, &out) != nil || out.Encoding != "base64" || out.Size < 0 || out.Size > max {
		return nil, ErrNotAFile
	}
	b, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(out.Content))
	if err != nil || len(b) != out.Size || len(b) > max {
		return nil, ErrNotAFile
	}
	return b, nil
}

// Relation is how a head relates to a base, as GitHub's comparison says it.
type Relation struct {
	// Status is identical, ahead (head has commits base does not, and base is its ancestor), behind (head is an ancestor
	// of base) or diverged.
	Status   string
	AheadBy  int
	BehindBy int
}

// Relate reads GET /repos/{repo}/compare/{base}...{head} for its relation only (no files, one commit): base and head are
// each a branch or a commit.
func (c *Client) Relate(ctx context.Context, cr *Credentials, base, head string) (*Relation, error) {
	ok := func(s string) bool { return ValidBranch(s) || ValidSHA(s) }
	if !ValidRepo(cr.Repo) || !ok(base) || !ok(head) {
		return nil, ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/compare/"+escPath(base)+"..."+escPath(head)+"?per_page=1", nil, http.StatusOK, "the comparison")
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return nil, ErrCommitNotFound
		}
		return nil, err
	}
	var out struct {
		Status   string `json:"status"`
		AheadBy  int    `json:"ahead_by"`
		BehindBy int    `json:"behind_by"`
	}
	if json.Unmarshal(r.body, &out) != nil || out.AheadBy < 0 || out.BehindBy < 0 {
		return nil, errors.New("ghapp: unreadable comparison")
	}
	switch out.Status {
	case "identical", "ahead", "behind", "diverged":
	default:
		return nil, errors.New("ghapp: unreadable comparison")
	}
	return &Relation{Status: out.Status, AheadBy: out.AheadBy, BehindBy: out.BehindBy}, nil
}

// ErrCommitNotFound: GitHub does not know the commit.
var ErrCommitNotFound = errors.New("ghapp: commit not found")

// OnBranch reports whether commit is the head of branch or one of its ancestors: the comparison commit...branch is
// identical or the branch is ahead of the commit.
func (c *Client) OnBranch(ctx context.Context, cr *Credentials, commit, branch string) (bool, error) {
	rel, err := c.Relate(ctx, cr, commit, branch)
	if err != nil {
		return false, err
	}
	return rel.Status == "identical" || (rel.Status == "ahead" && rel.BehindBy == 0), nil
}
