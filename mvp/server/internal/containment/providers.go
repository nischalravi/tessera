package containment

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// clockSkew is how far before the revoke started an Entra "sessions valid
// from" time may be and still count as set by it (Graph stamps it with its own clock).
const clockSkew = time.Minute

// ---------------------------------------------------------------- Okta

type oktaRevoker struct{ a *api }

// NewOkta returns the Okta revoker. cred.BaseURL is the org URL
// (https://example.okta.com) and cred.Token an API token.
func newOkta(hc *http.Client, c Credential, sleep sleepFunc) (Revoker, error) {
	a, err := newAPI(hc, c.BaseURL, "", "SSWS", c.Token, sleep)
	return &oktaRevoker{a}, err
}

// RevokeSessions clears the user's Okta sessions and, with oauthTokens=true,
// their OAuth refresh and access tokens.
func (o *oktaRevoker) RevokeSessions(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	err := o.a.do(ctx, http.MethodDelete, "/api/v1/users/"+esc(t.UserID)+"/sessions",
		url.Values{"oauthTokens": {"true"}}, nil, nil)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Revoked: 1}, nil
}

type oktaGrant struct {
	ID string `json:"id"`
}

func (o *oktaRevoker) grants(ctx context.Context, userID string) ([]oktaGrant, error) {
	var gs []oktaGrant
	err := o.a.do(ctx, http.MethodGet, "/api/v1/users/"+esc(userID)+"/grants", url.Values{"limit": {"200"}}, nil, &gs)
	return gs, err
}

// RevokeGrants revokes the user's OAuth consents (all grants of the user).
func (o *oktaRevoker) RevokeGrants(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	gs, err := o.grants(ctx, t.UserID)
	if err != nil {
		return Outcome{}, err
	}
	if len(gs) == 0 {
		return Outcome{}, nil
	}
	if err := o.a.do(ctx, http.MethodDelete, "/api/v1/users/"+esc(t.UserID)+"/grants", nil, nil, nil); err != nil {
		return Outcome{}, err
	}
	return Outcome{Revoked: len(gs)}, nil
}

type oktaClient struct {
	ClientID string `json:"client_id"`
}

type oktaToken struct {
	ID string `json:"id"`
}

// Verify re-reads grants and, for sessions, the user's refresh tokens (per
// client). Okta has no API that lists a user's IdP sessions, so that part is
// reported as unverified.
func (o *oktaRevoker) Verify(ctx context.Context, t Target, _ time.Time, c Check) (Remaining, error) {
	var r Remaining
	if err := t.check(); err != nil {
		return r, err
	}
	if c&CheckGrants != 0 {
		gs, err := o.grants(ctx, t.UserID)
		if err != nil {
			return r, err
		}
		r.Grants = len(gs)
	}
	if c&CheckSessions != 0 {
		var cs []oktaClient
		if err := o.a.do(ctx, http.MethodGet, "/api/v1/users/"+esc(t.UserID)+"/clients", nil, nil, &cs); err != nil {
			return r, err
		}
		for _, cl := range cs {
			if !userIDRE.MatchString(cl.ClientID) {
				return r, fmt.Errorf("okta returned an unexpected client id")
			}
			var ts []oktaToken
			if err := o.a.do(ctx, http.MethodGet, "/api/v1/users/"+esc(t.UserID)+"/clients/"+esc(cl.ClientID)+"/tokens",
				nil, nil, &ts); err != nil {
				return r, err
			}
			r.Sessions += len(ts)
		}
		r.Unverified = append(r.Unverified, "okta idp sessions: Okta has no API that lists a user's sessions; refresh tokens were re-read")
	}
	return r, nil
}

// ---------------------------------------------------------------- Entra

type entraRevoker struct{ a *api }

func newEntra(hc *http.Client, c Credential, sleep sleepFunc) (Revoker, error) {
	a, err := newAPI(hc, c.BaseURL, "https://graph.microsoft.com", "Bearer", c.Token, sleep)
	return &entraRevoker{a}, err
}

// RevokeSessions invalidates the user's refresh tokens and session cookies.
func (e *entraRevoker) RevokeSessions(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	var out struct {
		Value bool `json:"value"`
	}
	if err := e.a.do(ctx, http.MethodPost, "/v1.0/users/"+esc(t.UserID)+"/revokeSignInSessions", nil, nil, &out); err != nil {
		return Outcome{}, err
	}
	if !out.Value {
		return Outcome{}, errors.New("entra did not confirm the revoke (value is not true)")
	}
	return Outcome{Revoked: 1}, nil
}

type entraGrant struct {
	ID string `json:"id"`
}

func (e *entraRevoker) grants(ctx context.Context, userID string) ([]entraGrant, error) {
	var out struct {
		Value []entraGrant `json:"value"`
	}
	err := e.a.do(ctx, http.MethodGet, "/v1.0/oauth2PermissionGrants",
		url.Values{"$filter": {"principalId eq '" + userID + "'"}}, nil, &out)
	return out.Value, err
}

// RevokeGrants deletes the user's delegated OAuth consents (oauth2PermissionGrants
// whose principal is the user). Tenant-wide admin consents are not the user's.
func (e *entraRevoker) RevokeGrants(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	n := 0
	for round := 0; round < 5; round++ { // a page holds up to 100; Verify catches any left
		gs, err := e.grants(ctx, t.UserID)
		if err != nil {
			return Outcome{Revoked: n}, err
		}
		if len(gs) == 0 {
			break
		}
		for _, g := range gs {
			if !userIDRE.MatchString(g.ID) {
				return Outcome{Revoked: n}, errors.New("entra returned an unexpected grant id")
			}
			if err := e.a.do(ctx, http.MethodDelete, "/v1.0/oauth2PermissionGrants/"+esc(g.ID), nil, nil, nil); err != nil && !errors.Is(err, ErrNotFound) {
				return Outcome{Revoked: n}, err
			}
			n++
		}
	}
	return Outcome{Revoked: n}, nil
}

// Verify re-reads the user's signInSessionsValidFromDateTime (it must be at or
// after the revoke) and the user's grants.
func (e *entraRevoker) Verify(ctx context.Context, t Target, since time.Time, c Check) (Remaining, error) {
	var r Remaining
	if err := t.check(); err != nil {
		return r, err
	}
	if c&CheckSessions != 0 {
		var u struct {
			ValidFrom string `json:"signInSessionsValidFromDateTime"`
		}
		err := e.a.do(ctx, http.MethodGet, "/v1.0/users/"+esc(t.UserID),
			url.Values{"$select": {"id,signInSessionsValidFromDateTime"}}, nil, &u)
		if err != nil {
			return r, err
		}
		from, perr := time.Parse(time.RFC3339, u.ValidFrom)
		switch {
		case perr != nil:
			return r, errors.New("entra did not report signInSessionsValidFromDateTime")
		case from.Before(since.Add(-clockSkew)):
			r.Sessions = 1 // sessions issued before the revoke are still valid
		}
	}
	if c&CheckGrants != 0 {
		gs, err := e.grants(ctx, t.UserID)
		if err != nil {
			return r, err
		}
		r.Grants = len(gs)
	}
	return r, nil
}

// ---------------------------------------------------------------- Google

type googleRevoker struct{ a *api }

// newGoogle takes a bearer access token of an admin (or a service account
// with domain-wide delegation) holding the admin.directory.user.security scope.
func newGoogle(hc *http.Client, c Credential, sleep sleepFunc) (Revoker, error) {
	a, err := newAPI(hc, c.BaseURL, "https://admin.googleapis.com", "Bearer", c.Token, sleep)
	return &googleRevoker{a}, err
}

type googleToken struct {
	ClientID string `json:"clientId"`
}

func (g *googleRevoker) tokens(ctx context.Context, key string) ([]googleToken, error) {
	var out struct {
		Items []googleToken `json:"items"`
	}
	err := g.a.do(ctx, http.MethodGet, "/admin/directory/v1/users/"+esc(key)+"/tokens", nil, nil, &out)
	return out.Items, err
}

func (g *googleRevoker) deleteTokens(ctx context.Context, key string) (int, error) {
	ts, err := g.tokens(ctx, key)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, tk := range ts {
		if !userIDRE.MatchString(tk.ClientID) {
			return n, errors.New("google returned an unexpected client id")
		}
		err := g.a.do(ctx, http.MethodDelete, "/admin/directory/v1/users/"+esc(key)+"/tokens/"+esc(tk.ClientID), nil, nil, nil)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return n, err
		}
		n++
	}
	return n, nil
}

// RevokeSessions signs the user out of every Google session and deletes each
// OAuth token (refresh tokens) the user has issued.
func (g *googleRevoker) RevokeSessions(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	if err := g.a.do(ctx, http.MethodPost, "/admin/directory/v1/users/"+esc(t.UserID)+"/signOut", nil, nil, nil); err != nil {
		return Outcome{}, err
	}
	n, err := g.deleteTokens(ctx, t.UserID)
	return Outcome{Revoked: 1 + n}, err
}

// RevokeGrants deletes the user's OAuth tokens (Google's consents are the tokens).
func (g *googleRevoker) RevokeGrants(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	n, err := g.deleteTokens(ctx, t.UserID)
	return Outcome{Revoked: n}, err
}

// Verify re-reads the user's tokens. Google has no API that lists sessions,
// so a sign-out is verified through the 2xx answer only, and says so.
func (g *googleRevoker) Verify(ctx context.Context, t Target, _ time.Time, c Check) (Remaining, error) {
	var r Remaining
	if err := t.check(); err != nil {
		return r, err
	}
	ts, err := g.tokens(ctx, t.UserID)
	if err != nil {
		return r, err
	}
	if c&CheckSessions != 0 {
		r.Sessions = len(ts)
		r.Unverified = append(r.Unverified, "google sessions: Google has no API that lists a user's sessions; OAuth tokens were re-read")
	}
	if c&CheckGrants != 0 {
		r.Grants = len(ts)
	}
	return r, nil
}

// ---------------------------------------------------------------- GitHub

type githubRevoker struct {
	a   *api
	org string
}

// newGitHub revokes the SAML SSO credential authorizations (SSO-authorized
// PATs and SSH keys) of an organization member. It needs an owner's token
// with admin:org, and an organization with SAML SSO.
func newGitHub(hc *http.Client, c Credential, sleep sleepFunc) (Revoker, error) {
	if !userIDRE.MatchString(c.Org) {
		return &githubRevoker{}, errors.New("containment: a GitHub organization is required")
	}
	a, err := newAPI(hc, c.BaseURL, "https://api.github.com", "Bearer", c.Token, sleep)
	return &githubRevoker{a: a, org: c.Org}, err
}

// RevokeSessions: GitHub has no API for web sessions; they end with the IdP's.
func (g *githubRevoker) RevokeSessions(context.Context, Target) (Outcome, error) {
	return Outcome{Manual: []string{"GitHub web sessions cannot be revoked by API. Ending the user's sessions at the IdP and removing them from the organization ends them."}}, nil
}

type githubCred struct {
	CredentialID int64 `json:"credential_id"`
}

func (g *githubRevoker) creds(ctx context.Context, login string) ([]githubCred, error) {
	var cs []githubCred
	err := g.a.do(ctx, http.MethodGet, "/orgs/"+esc(g.org)+"/credential-authorizations",
		url.Values{"login": {login}, "per_page": {"100"}}, nil, &cs)
	return cs, err
}

// RevokeGrants removes the member's SSO credential authorizations. Personal
// access tokens and SSH keys that are not SSO-authorized stay the user's:
// GitHub offers no API to delete another account's, so they are a manual task.
func (g *githubRevoker) RevokeGrants(ctx context.Context, t Target) (Outcome, error) {
	if err := t.check(); err != nil {
		return Outcome{}, err
	}
	manual := []string{fmt.Sprintf("Check GitHub user %s for personal access tokens and SSH keys that are not SSO-authorized: GitHub has no API to delete another account's. Removing the user from the organization (or suspending them in GitHub Enterprise) ends their use.", t.UserID)}
	cs, err := g.creds(ctx, t.UserID)
	if err != nil {
		return Outcome{Manual: manual}, err
	}
	n := 0
	for _, c := range cs {
		path := fmt.Sprintf("/orgs/%s/credential-authorizations/%d", esc(g.org), c.CredentialID)
		if err := g.a.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil && !errors.Is(err, ErrNotFound) {
			return Outcome{Revoked: n, Manual: manual}, err
		}
		n++
	}
	return Outcome{Revoked: n, Manual: manual}, nil
}

// Verify re-reads the member's credential authorizations.
func (g *githubRevoker) Verify(ctx context.Context, t Target, _ time.Time, c Check) (Remaining, error) {
	var r Remaining
	if err := t.check(); err != nil {
		return r, err
	}
	if c&CheckGrants != 0 {
		cs, err := g.creds(ctx, t.UserID)
		if err != nil {
			return r, err
		}
		r.Grants = len(cs)
		r.Unverified = append(r.Unverified, "github PATs and SSH keys that are not SSO-authorized cannot be listed by API")
	}
	return r, nil
}
