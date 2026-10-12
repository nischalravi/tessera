package rotation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// githubAdapter rotates a repository deploy key.
//
// What the GitHub API allows, and what it does not:
//
//   - Deploy keys can be created (POST /repos/{owner}/{repo}/keys), read
//     (they carry created_at and last_used) and deleted. They cannot be
//     deactivated, so the old key stays valid until it is deleted.
//   - Personal access tokens (classic and fine-grained) cannot be created,
//     rotated or revoked through the API: they are issued in the web UI and
//     expire. Tessera tracks their age, flags them and notifies the owner.
//   - GitHub App private keys can only be generated in the web UI. An App's
//     installation tokens last one hour and need no rotation.
//   - OAuth app tokens can be reset or revoked only with the app's client
//     secret and the token itself, which Tessera does not hold.
//
// Target: Ref is "<owner>/<repo>#<deploy key id>".
type githubAdapter struct {
	http  *http.Client
	api   string // base URL, no trailing slash
	token string
	now   func() time.Time
}

func newGitHub(c *http.Client, apiURL, token string, now func() time.Time) *githubAdapter {
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &githubAdapter{http: c, api: strings.TrimRight(apiURL, "/"), token: token, now: now}
}

var (
	ghOwnerRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	ghRepoRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	ghKeyIDRE = regexp.MustCompile(`^[0-9]{1,20}$`)
)

func (*githubAdapter) Type() string { return TypeGitHub }
func (*githubAdapter) Capabilities() Capabilities {
	return Capabilities{CanDisable: false, ReportsLastUsed: true, NeedsDestination: true}
}

// ghRef splits "<owner>/<repo>#<id>".
func ghRef(ref string) (owner, repo, id string, err error) {
	loc, id, ok := splitRef(ref)
	if ok {
		var found bool
		owner, repo, found = strings.Cut(loc, "/")
		ok = found && ghOwnerRE.MatchString(owner) && ghRepoRE.MatchString(repo) && ghKeyIDRE.MatchString(id) &&
			repo != "." && repo != ".."
	}
	if !ok {
		return "", "", "", badRef("github", "<owner>/<repo>#<deploy key id>")
	}
	return owner, repo, id, nil
}

func (g *githubAdapter) Validate(t Target) error {
	_, _, _, err := ghRef(t.Ref)
	return err
}

type ghResult struct {
	status int
	body   []byte
}

func (g *githubAdapter) call(ctx context.Context, op, method, path string, in any) (ghResult, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return ghResult{}, fail(op, "bad_request", "", false)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, g.api+path, bytes.NewReader(body))
	if err != nil {
		return ghResult{}, fail(op, "bad_address", "", false)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "tessera-rotation")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, resp, err := send(g.http, op, req)
	if err != nil {
		return ghResult{}, err
	}
	return ghResult{status, resp}, nil
}

func ghErr(op string, r ghResult) error {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(r.body, &e)
	transient := transientStatus(r.status) || (r.status == http.StatusForbidden && strings.Contains(strings.ToLower(e.Message), "rate limit"))
	return fail(op, http.StatusText(r.status), e.Message, transient)
}

type ghKey struct {
	ID        int64   `json:"id"`
	ReadOnly  bool    `json:"read_only"`
	CreatedAt string  `json:"created_at"`
	LastUsed  *string `json:"last_used"`
}

func (g *githubAdapter) get(ctx context.Context, owner, repo, id string) (*ghKey, error) {
	const op = "github get deploy key"
	r, err := g.call(ctx, op, http.MethodGet, "/repos/"+owner+"/"+repo+"/keys/"+id, nil)
	if err != nil {
		return nil, err
	}
	if r.status == http.StatusNotFound {
		return nil, nil
	}
	if r.status/100 != 2 {
		return nil, ghErr(op, r)
	}
	var k ghKey
	if err := json.Unmarshal(r.body, &k); err != nil {
		return nil, fail(op, "bad_response", "", false)
	}
	return &k, nil
}

func (g *githubAdapter) Create(ctx context.Context, t Target) (*Minted, error) {
	const op = "github create deploy key"
	owner, repo, id, err := ghRef(t.Ref)
	if err != nil {
		return nil, err
	}
	old, err := g.get(ctx, owner, repo, id)
	if err != nil {
		return nil, err
	}
	readOnly := true // least privilege unless the old key could write
	if old != nil {
		readOnly = old.ReadOnly
	}
	stamp := g.now().UTC().Format("2006-01-02")
	pub, priv, err := newSSHKeyPair("tessera-" + stamp)
	if err != nil {
		return nil, fail(op, "key_generation", "", false)
	}
	r, err := g.call(ctx, op, http.MethodPost, "/repos/"+owner+"/"+repo+"/keys", map[string]any{
		"title": "tessera-rotated-" + stamp, "key": pub, "read_only": readOnly})
	if err != nil {
		return nil, err
	}
	if r.status/100 != 2 {
		return nil, ghErr(op, r)
	}
	var k ghKey
	if err := json.Unmarshal(r.body, &k); err != nil || k.ID == 0 {
		return nil, fail(op, "bad_response", "no key id in the response", false)
	}
	newRef := owner + "/" + repo + hashSeparator + strconv.FormatInt(k.ID, 10)
	return &Minted{Ref: newRef, Material: map[string]string{"private_key": priv, "public_key": pub,
		"repository": owner + "/" + repo}}, nil
}

func (*githubAdapter) HandOver(ctx context.Context, t Target, m *Minted, dest Destination, path string) error {
	return handOverToDestination(ctx, t, m, dest, path)
}

func (*githubAdapter) DisableOld(context.Context, Target) error { return ErrUnsupported }

func (g *githubAdapter) ObserveOld(ctx context.Context, t Target) (Observation, error) {
	owner, repo, id, err := ghRef(t.Ref)
	if err != nil {
		return Observation{}, err
	}
	k, err := g.get(ctx, owner, repo, id)
	if err != nil {
		return Observation{}, err
	}
	if k == nil {
		return Observation{LastUsedKnown: true, Detail: "the deploy key no longer exists"}, nil
	}
	obs := Observation{Exists: true, Active: true, LastUsedKnown: true, CreatedAt: parseAWSTime(k.CreatedAt)}
	if k.LastUsed != nil {
		obs.LastUsedAt = parseAWSTime(*k.LastUsed)
	}
	return obs, nil
}

func (g *githubAdapter) DeleteOld(ctx context.Context, t Target) error { return g.delete(ctx, t.Ref) }

func (g *githubAdapter) DeleteNew(ctx context.Context, _ Target, newRef string) error {
	return g.delete(ctx, newRef)
}

func (g *githubAdapter) delete(ctx context.Context, ref string) error {
	const op = "github delete deploy key"
	owner, repo, id, err := ghRef(ref)
	if err != nil {
		return err
	}
	r, err := g.call(ctx, op, http.MethodDelete, "/repos/"+owner+"/"+repo+"/keys/"+id, nil)
	if err != nil {
		return err
	}
	if r.status/100 == 2 || r.status == http.StatusNotFound {
		return nil
	}
	return ghErr(op, r)
}

func (*githubAdapter) InventoryRef(_, newRef string) string { return newRef }
