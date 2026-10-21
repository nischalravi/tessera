package oauthapps

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
)

// entraProv reads Microsoft Entra ID through Microsoft Graph: service
// principals, their delegated consents (oauth2PermissionGrants, per user or
// tenant-wide) and their application permissions (appRoleAssignments). The
// credential is the kill switch's Graph token, which needs
// Application.Read.All, DelegatedPermissionGrant.ReadWrite.All and
// AppRoleAssignment.ReadWrite.All.
type entraProv struct {
	c     *containment.Client
	roles map[string]map[string]string // resource service principal -> app role id -> value
	users map[string]string            // user id -> user principal name ("" when unknown)
}

type entraSP struct {
	ID                string `json:"id"`
	AppID             string `json:"appId"`
	DisplayName       string `json:"displayName"`
	PublisherName     string `json:"publisherName"`
	VerifiedPublisher *struct {
		ID string `json:"verifiedPublisherId"`
	} `json:"verifiedPublisher"`
}

type entraDelegated struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"` // the client service principal's object id
	ConsentType string `json:"consentType"`
	PrincipalID string `json:"principalId"`
	Scope       string `json:"scope"`
}

type entraRoleAssignment struct {
	ID                   string `json:"id"`
	AppRoleID            string `json:"appRoleId"`
	ResourceID           string `json:"resourceId"`
	ResourceDisplayName  string `json:"resourceDisplayName"`
	CreatedDateTime      string `json:"createdDateTime"`
	PrincipalDisplayName string `json:"principalDisplayName"`
}

type entraPage[T any] struct {
	Value []T    `json:"value"`
	Next  string `json:"@odata.nextLink"`
}

func entraAll[T any](ctx context.Context, e *entraProv, path string, q url.Values) ([]T, error) {
	var all []T
	err := listPages(ctx, e.c, path, q,
		func(p *entraPage[T], _ url.Values) (string, url.Values, error) {
			if p.Next == "" {
				return "", nil, nil
			}
			return follow(e.c, p.Next)
		},
		func(p *entraPage[T]) error { all = append(all, p.Value...); return nil })
	return all, err
}

func (e *entraProv) roleValue(ctx context.Context, resourceID, roleID string) (string, error) {
	if e.roles == nil {
		e.roles = map[string]map[string]string{}
	}
	m, ok := e.roles[resourceID]
	if !ok {
		var sp struct {
			AppRoles []struct {
				ID    string `json:"id"`
				Value string `json:"value"`
			} `json:"appRoles"`
		}
		err := e.c.Do(ctx, http.MethodGet, "/v1.0/servicePrincipals/"+containment.Esc(resourceID),
			url.Values{"$select": {"id,appRoles"}}, nil, &sp)
		if err != nil && !errors.Is(err, containment.ErrNotFound) {
			return "", err
		}
		m = map[string]string{}
		for _, r := range sp.AppRoles {
			m[r.ID] = r.Value
		}
		e.roles[resourceID] = m
	}
	if v := m[roleID]; v != "" {
		return v, nil
	}
	return "role:" + roleID, nil // a role the resource no longer defines: kept visible, scored as unknown
}

func (e *entraProv) upn(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	if e.users == nil {
		e.users = map[string]string{}
	}
	if v, ok := e.users[id]; ok {
		return v, nil
	}
	var u struct {
		UPN string `json:"userPrincipalName"`
	}
	err := e.c.Do(ctx, http.MethodGet, "/v1.0/users/"+containment.Esc(id), url.Values{"$select": {"id,userPrincipalName"}}, nil, &u)
	if err != nil && !errors.Is(err, containment.ErrNotFound) {
		return "", err
	}
	e.users[id] = u.UPN
	return u.UPN, nil
}

// Read lists the service principals that hold at least one grant. Graph
// reports no grant date for a delegated consent and no sign-in time without
// the beta API, so those stay empty.
func (e *entraProv) Read(ctx context.Context) (*Snapshot, error) {
	sps, err := entraAll[entraSP](ctx, e, "/v1.0/servicePrincipals",
		url.Values{"$select": {"id,appId,displayName,publisherName,verifiedPublisher"}, "$top": {"999"}})
	if err != nil {
		return nil, err
	}
	deleg, err := entraAll[entraDelegated](ctx, e, "/v1.0/oauth2PermissionGrants", url.Values{"$top": {"999"}})
	if err != nil {
		return nil, err
	}
	byObj := map[string]*entraSP{}
	for i := range sps {
		if !idRE.MatchString(sps[i].ID) || !idRE.MatchString(sps[i].AppID) {
			return nil, errors.New("entra returned an unexpected service principal id")
		}
		byObj[sps[i].ID] = &sps[i]
	}
	set := newAppSet()
	touch := func(sp *entraSP) *App {
		a := set.get(Entra, sp.AppID, sp.DisplayName)
		a.Publisher = sp.PublisherName
		a.Verified = sp.VerifiedPublisher != nil && sp.VerifiedPublisher.ID != ""
		return a
	}
	for _, d := range deleg {
		sp := byObj[d.ClientID]
		if sp == nil {
			continue // a client that is not a service principal of this tenant
		}
		if !idRE.MatchString(d.ID) {
			return nil, errors.New("entra returned an unexpected grant id")
		}
		g := Grant{Key: d.ID, Ref: d.ID, Kind: KindDelegated, Scopes: strings.Fields(d.Scope), Consent: ConsentUser}
		if d.ConsentType == "AllPrincipals" {
			g.Consent = ConsentAdmin
		} else {
			g.UserRef = d.PrincipalID
			if g.UserEmail, err = e.upn(ctx, d.PrincipalID); err != nil {
				return nil, err
			}
		}
		a := touch(sp)
		a.Grants = append(a.Grants, g)
	}
	for _, sp := range sps {
		ras, err := entraAll[entraRoleAssignment](ctx, e, "/v1.0/servicePrincipals/"+containment.Esc(sp.ID)+"/appRoleAssignments",
			url.Values{"$top": {"999"}})
		if err != nil {
			return nil, err
		}
		for _, ra := range ras {
			if !idRE.MatchString(ra.ID) || !idRE.MatchString(ra.ResourceID) {
				return nil, errors.New("entra returned an unexpected assignment id")
			}
			val, err := e.roleValue(ctx, ra.ResourceID, ra.AppRoleID)
			if err != nil {
				return nil, err
			}
			a := touch(&sp)
			a.Grants = append(a.Grants, Grant{Key: "role:" + ra.ID, Ref: sp.ID + "/" + ra.ID, Kind: KindAppRole,
				Scopes: []string{val}, Consent: ConsentAdmin, GrantedAt: parseTime(ra.CreatedDateTime)})
		}
	}
	for _, a := range set.byID { // stable scope order per grant
		for i := range a.Grants {
			sort.Strings(a.Grants[i].Scopes)
		}
	}
	return set.snapshot(Entra, "entra does not report when a delegated consent was given or when an app was last used",
		"entra does not report whether the user who consented is an administrator"), nil
}

func (e *entraProv) RevokeGrant(ctx context.Context, _ string, g Grant) error {
	path, err := entraGrantPath(g)
	if err != nil {
		return err
	}
	err = e.c.Do(ctx, http.MethodDelete, path, nil, nil, nil)
	if errors.Is(err, containment.ErrNotFound) {
		return nil
	}
	return err
}

func entraGrantPath(g Grant) (string, error) {
	if g.Kind == KindAppRole {
		sp, id, ok := strings.Cut(g.Ref, "/")
		if !ok || !idRE.MatchString(sp) || !idRE.MatchString(id) {
			return "", errors.New("oauthapps: invalid entra assignment reference")
		}
		return "/v1.0/servicePrincipals/" + containment.Esc(sp) + "/appRoleAssignments/" + containment.Esc(id), nil
	}
	if !idRE.MatchString(g.Ref) {
		return "", errors.New("oauthapps: invalid entra grant id")
	}
	return "/v1.0/oauth2PermissionGrants/" + containment.Esc(g.Ref), nil
}

func (e *entraProv) Present(ctx context.Context, _ string, g Grant) (bool, error) {
	if g.Kind == KindAppRole {
		sp, id, ok := strings.Cut(g.Ref, "/")
		if !ok || !idRE.MatchString(sp) || !idRE.MatchString(id) {
			return false, errors.New("oauthapps: invalid entra assignment reference")
		}
		ras, err := entraAll[entraRoleAssignment](ctx, e, "/v1.0/servicePrincipals/"+containment.Esc(sp)+"/appRoleAssignments",
			url.Values{"$top": {"999"}})
		if errors.Is(err, containment.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		for _, ra := range ras {
			if ra.ID == id {
				return true, nil
			}
		}
		return false, nil
	}
	path, err := entraGrantPath(g)
	if err != nil {
		return false, err
	}
	err = e.c.Do(ctx, http.MethodGet, path, nil, nil, nil)
	if errors.Is(err, containment.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
