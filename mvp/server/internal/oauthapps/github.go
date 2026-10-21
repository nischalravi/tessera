package oauthapps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
)

// githubProv reads a GitHub organization: the GitHub Apps installed in it, and
// the SAML SSO credential authorizations (the OAuth tokens and personal access
// tokens members authorized for the organization). The credential is the
// kill switch's: an owner's token with admin:org.
//
// GitHub offers an organization owner no API to uninstall an app, so revoking
// an installation is a manual task; a credential authorization is revoked by
// API.
type githubProv struct {
	c   *containment.Client
	org string
}

type ghInstallation struct {
	ID          int64             `json:"id"`
	AppSlug     string            `json:"app_slug"`
	Permissions map[string]string `json:"permissions"`
	CreatedAt   string            `json:"created_at"`
	SuspendedAt string            `json:"suspended_at"`
}

type ghCredential struct {
	Login        string   `json:"login"`
	CredentialID int64    `json:"credential_id"`
	Type         string   `json:"credential_type"`
	AuthorizedAt string   `json:"credential_authorized_at"`
	AccessedAt   string   `json:"credential_accessed_at"`
	Scopes       []string `json:"scopes"`
}

const githubPerPage = "100"

// ghPaged reads a list that GitHub pages with ?page=N and no link header the
// client sees: a short page is the last.
func ghPaged[T any](ctx context.Context, g *githubProv, path string, each func(T) error) error {
	pageNo := 1
	return listPages(ctx, g.c, path, url.Values{"per_page": {githubPerPage}, "page": {"1"}},
		func(out *[]T, q url.Values) (string, url.Values, error) {
			if len(*out) < 100 {
				return "", nil, nil
			}
			pageNo++
			nq := url.Values{"per_page": q["per_page"], "page": {strconv.Itoa(pageNo)}}
			return path, nq, nil
		},
		func(out *[]T) error {
			for _, it := range *out {
				if err := each(it); err != nil {
					return err
				}
			}
			return nil
		})
}

func (g *githubProv) installations(ctx context.Context) ([]ghInstallation, error) {
	type page struct {
		Installations []ghInstallation `json:"installations"`
	}
	var all []ghInstallation
	pageNo := 1
	path := "/orgs/" + containment.Esc(g.org) + "/installations"
	err := listPages(ctx, g.c, path, url.Values{"per_page": {githubPerPage}, "page": {"1"}},
		func(p *page, q url.Values) (string, url.Values, error) {
			if len(p.Installations) < 100 {
				return "", nil, nil
			}
			pageNo++
			return path, url.Values{"per_page": q["per_page"], "page": {strconv.Itoa(pageNo)}}, nil
		},
		func(p *page) error { all = append(all, p.Installations...); return nil })
	return all, err
}

func (g *githubProv) credentials(ctx context.Context) ([]ghCredential, error) {
	var all []ghCredential
	err := ghPaged(ctx, g, "/orgs/"+containment.Esc(g.org)+"/credential-authorizations",
		func(c ghCredential) error { all = append(all, c); return nil })
	return all, err
}

func (g *githubProv) appOwner(ctx context.Context, slug string) string {
	var a struct {
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := g.c.Do(ctx, http.MethodGet, "/apps/"+containment.Esc(slug), nil, nil, &a); err != nil {
		return "" // the publisher is a nice-to-have; a failure here must not fail the read
	}
	return a.Owner.Login
}

func credApp(credType string) (clientID, name string) {
	slug := strings.Trim(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return '_'
	}, credType), "_")
	if slug == "" {
		slug = "unknown"
	}
	return "credential:" + slug, "GitHub " + credType
}

// Read lists the installed apps and the credential authorizations. A
// credential authorization needs SAML SSO: an organization without it answers
// 404, which is reported as a note, not a failure.
func (g *githubProv) Read(ctx context.Context) (*Snapshot, error) {
	ins, err := g.installations(ctx)
	if err != nil {
		return nil, err
	}
	set := newAppSet()
	owners := map[string]string{}
	for _, in := range ins {
		if !idRE.MatchString(in.AppSlug) {
			return nil, errors.New("github returned an unexpected app slug")
		}
		if _, ok := owners[in.AppSlug]; !ok {
			owners[in.AppSlug] = g.appOwner(ctx, in.AppSlug)
		}
		a := set.get(GitHub, "app:"+in.AppSlug, in.AppSlug)
		a.Publisher = owners[in.AppSlug]
		var scopes []string
		for name, level := range in.Permissions {
			scopes = append(scopes, name+":"+level)
		}
		sort.Strings(scopes)
		id := strconv.FormatInt(in.ID, 10)
		a.Grants = append(a.Grants, Grant{Key: "installation:" + id, Ref: id, Kind: KindInstallation, Scopes: scopes,
			Consent: ConsentAdmin, GrantedAt: parseTime(in.CreatedAt)})
	}
	notes := []string{"github does not report when an installed app was last used"}
	creds, err := g.credentials(ctx)
	switch {
	case errors.Is(err, containment.ErrNotFound):
		notes = append(notes, "the organization has no SAML SSO, so GitHub lists no credential authorizations")
	case err != nil:
		return nil, err
	}
	for _, c := range creds {
		if !idRE.MatchString(c.Login) {
			return nil, errors.New("github returned an unexpected login")
		}
		cid, name := credApp(c.Type)
		a := set.get(GitHub, cid, name)
		a.Publisher, a.Verified = "GitHub", true
		id := strconv.FormatInt(c.CredentialID, 10)
		a.Grants = append(a.Grants, Grant{Key: id, Ref: id, Kind: KindCredential, UserRef: c.Login, UserEmail: c.Login,
			Scopes: c.Scopes, Consent: ConsentUser, GrantedAt: parseTime(c.AuthorizedAt), LastUsed: parseTime(c.AccessedAt)})
	}
	return set.snapshot(GitHub, notes...), nil
}

func (g *githubProv) RevokeGrant(ctx context.Context, _ string, gr Grant) error {
	id, err := strconv.ParseInt(gr.Ref, 10, 64)
	if err != nil || id < 1 {
		return errors.New("oauthapps: invalid github grant id")
	}
	if gr.Kind == KindInstallation {
		return &ManualError{Msg: fmt.Sprintf("GitHub has no API for an organization owner to uninstall an app. Uninstall installation %d "+
			"(or suspend it) in GitHub: organization settings, Installed GitHub Apps, Configure, Uninstall.", id)}
	}
	err = g.c.Do(ctx, http.MethodDelete, fmt.Sprintf("/orgs/%s/credential-authorizations/%d", containment.Esc(g.org), id), nil, nil, nil)
	if errors.Is(err, containment.ErrNotFound) {
		return nil
	}
	return err
}

func (g *githubProv) Present(ctx context.Context, _ string, gr Grant) (bool, error) {
	id, err := strconv.ParseInt(gr.Ref, 10, 64)
	if err != nil || id < 1 {
		return false, errors.New("oauthapps: invalid github grant id")
	}
	if gr.Kind == KindInstallation {
		ins, err := g.installations(ctx)
		if err != nil {
			return false, err
		}
		for _, in := range ins {
			if in.ID == id {
				return true, nil
			}
		}
		return false, nil
	}
	cs, err := g.credentials(ctx)
	if errors.Is(err, containment.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.CredentialID == id {
			return true, nil
		}
	}
	return false, nil
}
