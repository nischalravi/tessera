package oauthapps

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
)

// googleProv reads Google Workspace through the Admin SDK Directory API: the
// users, then each user's OAuth tokens (a token is a grant). The credential is
// the one of the kill switch: an admin (or a service account with domain-wide
// delegation) bearer token with admin.directory.user.readonly and
// admin.directory.user.security.
type googleProv struct{ c *containment.Client }

type googleUser struct {
	ID               string `json:"id"`
	PrimaryEmail     string `json:"primaryEmail"`
	IsAdmin          bool   `json:"isAdmin"`
	IsDelegatedAdmin bool   `json:"isDelegatedAdmin"`
}

type googleToken struct {
	ClientID    string   `json:"clientId"`
	DisplayText string   `json:"displayText"`
	Anonymous   bool     `json:"anonymous"`
	Scopes      []string `json:"scopes"`
}

func (g *googleProv) users(ctx context.Context) ([]googleUser, error) {
	type page struct {
		Users []googleUser `json:"users"`
		Next  string       `json:"nextPageToken"`
	}
	var all []googleUser
	err := listPages(ctx, g.c, "/admin/directory/v1/users",
		url.Values{"customer": {"my_customer"}, "maxResults": {"500"}, "projection": {"basic"}},
		func(p *page, q url.Values) (string, url.Values, error) {
			if p.Next == "" {
				return "", nil, nil
			}
			nq := url.Values{}
			for k, v := range q {
				nq[k] = v
			}
			nq.Set("pageToken", p.Next)
			return "/admin/directory/v1/users", nq, nil
		},
		func(p *page) error {
			all = append(all, p.Users...)
			if len(all) > MaxUsers {
				return ErrTooLarge
			}
			return nil
		})
	return all, err
}

func (g *googleProv) tokens(ctx context.Context, userID string) ([]googleToken, error) {
	var out struct {
		Items []googleToken `json:"items"`
	}
	err := g.c.Do(ctx, http.MethodGet, "/admin/directory/v1/users/"+containment.Esc(userID)+"/tokens", nil, nil, &out)
	return out.Items, err
}

// Read lists every user's tokens. Google reports neither the publisher, the
// grant date nor the last use of a token, so those stay empty; an app that
// Google marks anonymous (no registered client) counts as unverified.
func (g *googleProv) Read(ctx context.Context) (*Snapshot, error) {
	users, err := g.users(ctx)
	if err != nil {
		return nil, err
	}
	set := newAppSet()
	for _, u := range users {
		if !idRE.MatchString(u.ID) {
			return nil, errors.New("google returned an unexpected user id")
		}
		ts, err := g.tokens(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if !idRE.MatchString(t.ClientID) {
				return nil, errors.New("google returned an unexpected client id")
			}
			name := t.DisplayText
			if name == "" {
				name = t.ClientID
			}
			a := set.get(Google, t.ClientID, name)
			a.Verified = !t.Anonymous
			a.Grants = append(a.Grants, Grant{Key: u.ID, Ref: u.ID, Kind: KindToken, UserRef: u.ID, UserEmail: u.PrimaryEmail,
				GranterAdmin: u.IsAdmin || u.IsDelegatedAdmin, Scopes: t.Scopes, Consent: ConsentUser})
		}
	}
	return set.snapshot(Google, "google does not report the publisher, grant date or last use of a token"), nil
}

func (g *googleProv) RevokeGrant(ctx context.Context, clientID string, gr Grant) error {
	if !idRE.MatchString(clientID) || !idRE.MatchString(gr.Ref) {
		return errors.New("oauthapps: invalid google client or user id")
	}
	err := g.c.Do(ctx, http.MethodDelete, "/admin/directory/v1/users/"+containment.Esc(gr.Ref)+"/tokens/"+containment.Esc(clientID), nil, nil, nil)
	if errors.Is(err, containment.ErrNotFound) {
		return nil
	}
	return err
}

func (g *googleProv) Present(ctx context.Context, clientID string, gr Grant) (bool, error) {
	if !idRE.MatchString(gr.Ref) {
		return false, errors.New("oauthapps: invalid google user id")
	}
	ts, err := g.tokens(ctx, gr.Ref)
	if errors.Is(err, containment.ErrNotFound) {
		return false, nil // the user is gone, so is the token
	}
	if err != nil {
		return false, err
	}
	for _, t := range ts {
		if t.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}
