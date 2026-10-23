package ghtokens

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
)

// DefaultAPIURL is GitHub.com's REST API (a GitHub Enterprise Server credential
// names its own base URL).
const DefaultAPIURL = "https://api.github.com"

// Reader reads one GitHub organization. It only sends GET requests.
type Reader struct {
	c   *containment.Client
	org string
}

var (
	orgRE   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	loginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})(?:\[bot\])?$`)
	nameRE  = regexp.MustCompile(`^[A-Za-z0-9_]{1,100}$`)
)

// NewReader builds the reader over a containment client, which sends through
// internal/safehttp (containment.NewClient with containment.Service.Outbound).
func NewReader(c *containment.Client, org string) (*Reader, error) {
	if c == nil || !orgRE.MatchString(org) {
		return nil, errors.New("ghtokens: a client and a GitHub organization are required")
	}
	return &Reader{c: c, org: org}, nil
}

type ghCredential struct {
	Login        string   `json:"login"`
	CredentialID int64    `json:"credential_id"`
	Type         string   `json:"credential_type"`
	AuthorizedAt string   `json:"credential_authorized_at"`
	AccessedAt   string   `json:"credential_accessed_at"`
	Title        string   `json:"authorized_credential_title"`
	ExpiresAt    string   `json:"authorized_credential_expires_at"`
	Scopes       []string `json:"scopes"`
}

type ghPAT struct {
	ID    int64 `json:"id"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	Name        string                       `json:"token_name"`
	Permissions map[string]map[string]string `json:"permissions"`
	GrantedAt   string                       `json:"access_granted_at"`
	ExpiresAt   string                       `json:"token_expires_at"`
	LastUsedAt  string                       `json:"token_last_used_at"`
}

type ghSecret struct {
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Visibility string `json:"visibility"`
}

// pages reads a list GitHub pages with ?page=N: a short page is the last.
func pages[T any](ctx context.Context, r *Reader, path string, items func(*T) int, each func(*T)) error {
	for n := 1; ; n++ {
		if n > MaxPages {
			return errors.New("ghtokens: GitHub lists more pages than one read follows")
		}
		var out T
		q := url.Values{"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(n)}}
		if err := r.c.Do(ctx, "GET", path, q, nil, &out); err != nil {
			return err
		}
		each(&out)
		if items(&out) < perPage {
			return nil
		}
	}
}

// Read lists the credentials. A credential authorization needs SAML SSO: an
// organization without it answers 404, which is a note, not a failure. Any
// other failure fails the read: a partial list would look like credentials
// that were removed.
func (r *Reader) Read(ctx context.Context) (*Snapshot, error) {
	snap := &Snapshot{}
	base := "/orgs/" + containment.Esc(r.org)

	err := pages(ctx, r, base+"/credential-authorizations", func(p *[]ghCredential) int { return len(*p) },
		func(p *[]ghCredential) {
			for _, c := range *p {
				if t, ok := r.credential(c); ok {
					snap.Tokens = append(snap.Tokens, t)
				}
			}
		})
	switch {
	case errors.Is(err, containment.ErrNotFound):
		snap.Notes = append(snap.Notes, "the organization has no SAML SSO, so GitHub lists no classic personal access tokens or OAuth app tokens")
	case err != nil:
		return nil, err
	}

	if err := pages(ctx, r, base+"/personal-access-tokens", func(p *[]ghPAT) int { return len(*p) },
		func(p *[]ghPAT) {
			for _, t := range *p {
				if tok, ok := r.fineGrained(t); ok {
					snap.Tokens = append(snap.Tokens, tok)
				}
			}
		}); err != nil {
		return nil, err
	}

	type secretPage struct {
		Secrets []ghSecret `json:"secrets"`
	}
	if err := pages(ctx, r, base+"/actions/secrets", func(p *secretPage) int { return len(p.Secrets) },
		func(p *secretPage) {
			for _, s := range p.Secrets {
				if nameRE.MatchString(s.Name) {
					snap.Tokens = append(snap.Tokens, Token{Key: "secret:org:" + s.Name, Kind: ActionsSecret, Name: s.Name,
						Visibility: s.Visibility, CreatedAt: parseTime(s.CreatedAt), RotatedAt: parseTime(s.UpdatedAt)})
				}
			}
		}); err != nil {
		return nil, err
	}
	snap.Notes = append(snap.Notes, "repository and environment Actions secrets are not read: only organization secrets are listed")
	sort.SliceStable(snap.Tokens, func(i, j int) bool { return snap.Tokens[i].Key < snap.Tokens[j].Key })
	return snap, nil
}

// defaultNames label a credential GitHub gives no title.
var defaultNames = map[string]string{ClassicPAT: "Classic personal access token", OAuthAppToken: "OAuth app token"} // #nosec G101 -- labels, not credentials

func (r *Reader) credential(c ghCredential) (Token, bool) {
	var kind string
	switch strings.ToLower(c.Type) {
	case "personal access token":
		kind = ClassicPAT
	case "oauth app token":
		kind = OAuthAppToken
	default:
		return Token{}, false // an SSH key is not a token
	}
	if !loginRE.MatchString(c.Login) || c.CredentialID < 1 {
		return Token{}, false
	}
	name := clip(strings.TrimSpace(c.Title), 100)
	if name == "" {
		name = defaultNames[kind]
	}
	return Token{Key: "cred:" + strconv.FormatInt(c.CredentialID, 10), Kind: kind, Name: name, OwnerLogin: c.Login,
		Scopes: c.Scopes, CreatedAt: parseTime(c.AuthorizedAt), ExpiresAt: parseTime(c.ExpiresAt), LastUsedAt: parseTime(c.AccessedAt)}, true
}

func (r *Reader) fineGrained(t ghPAT) (Token, bool) {
	if !loginRE.MatchString(t.Owner.Login) || t.ID < 1 {
		return Token{}, false
	}
	var perms []string
	for _, group := range t.Permissions {
		for name, level := range group {
			perms = append(perms, name+":"+level)
		}
	}
	sort.Strings(perms)
	name := clip(strings.TrimSpace(t.Name), 100)
	if name == "" {
		name = "Fine-grained personal access token"
	}
	return Token{Key: "fgpat:" + strconv.FormatInt(t.ID, 10), Kind: FineGrainedPAT, Name: name,
		OwnerLogin: t.Owner.Login, Scopes: perms, CreatedAt: parseTime(t.GrantedAt), ExpiresAt: parseTime(t.ExpiresAt),
		LastUsedAt: parseTime(t.LastUsedAt)}, true
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
