package oauthapps

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
)

// salesforceProv reads the connected-app OAuth tokens of a Salesforce org
// (the OauthToken object: one row per user and app) and revokes one by
// deleting its row. The credential is the kill switch's: an instance URL and
// an API-enabled bearer token of a user who may "Manage Connected Apps".
type salesforceProv struct{ c *containment.Client }

const salesforceAPI = "/services/data/v59.0"

const salesforceQuery = "SELECT Id, AppName, AppMenuItemId, UserId, User.Username, User.Profile.PermissionsModifyAllData, " +
	"CreatedDate, LastUsedDate, UseCount, RequestedScopes FROM OauthToken"

// sfIDRE is a Salesforce record id (15 or 18 characters).
var sfIDRE = regexp.MustCompile(`^[A-Za-z0-9]{15,18}$`)

type sfToken struct {
	ID            string `json:"Id"`
	AppName       string `json:"AppName"`
	AppMenuItemID string `json:"AppMenuItemId"`
	UserID        string `json:"UserId"`
	User          *struct {
		Username string `json:"Username"`
		Profile  *struct {
			ModifyAll bool `json:"PermissionsModifyAllData"`
		} `json:"Profile"`
	} `json:"User"`
	CreatedDate     string `json:"CreatedDate"`
	LastUsedDate    string `json:"LastUsedDate"`
	RequestedScopes string `json:"RequestedScopes"`
}

type sfPage struct {
	Done    bool      `json:"done"`
	Next    string    `json:"nextRecordsUrl"`
	Records []sfToken `json:"records"`
}

// Read lists every OAuth token. The connected app's id (AppMenuItemId, else
// its name) is the client id. Salesforce names no publisher, so the
// publisher stays empty and a vendor action matches the app name.
func (s *salesforceProv) Read(ctx context.Context) (*Snapshot, error) {
	set := newAppSet()
	err := listPages(ctx, s.c, salesforceAPI+"/query", url.Values{"q": {salesforceQuery}},
		func(p *sfPage, _ url.Values) (string, url.Values, error) {
			if p.Done || p.Next == "" {
				return "", nil, nil
			}
			return follow(s.c, p.Next)
		},
		func(p *sfPage) error {
			for _, t := range p.Records {
				if !sfIDRE.MatchString(t.ID) {
					return errors.New("salesforce returned an unexpected token id")
				}
				cid := t.AppMenuItemID
				if cid == "" {
					cid = strings.ToLower(strings.Join(strings.Fields(t.AppName), "-"))
				}
				if !idRE.MatchString(cid) {
					return errors.New("salesforce returned an unexpected app id")
				}
				a := set.get(Salesforce, cid, t.AppName)
				g := Grant{Key: t.ID, Ref: t.ID, Kind: KindToken, UserRef: t.UserID, Scopes: strings.Fields(t.RequestedScopes),
					Consent: ConsentUser, GrantedAt: parseTime(t.CreatedDate), LastUsed: parseTime(t.LastUsedDate)}
				if t.User != nil {
					g.UserEmail = t.User.Username
					g.GranterAdmin = t.User.Profile != nil && t.User.Profile.ModifyAll
				}
				a.Grants = append(a.Grants, g)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return set.snapshot(Salesforce, "salesforce names no publisher for a connected app and does not report whether it is verified"), nil
}

func (s *salesforceProv) RevokeGrant(ctx context.Context, _ string, g Grant) error {
	if !sfIDRE.MatchString(g.Ref) {
		return errors.New("oauthapps: invalid salesforce token id")
	}
	err := s.c.Do(ctx, http.MethodDelete, salesforceAPI+"/sobjects/OauthToken/"+containment.Esc(g.Ref), nil, nil, nil)
	if errors.Is(err, containment.ErrNotFound) {
		return nil
	}
	return err
}

func (s *salesforceProv) Present(ctx context.Context, _ string, g Grant) (bool, error) {
	if !sfIDRE.MatchString(g.Ref) {
		return false, errors.New("oauthapps: invalid salesforce token id")
	}
	err := s.c.Do(ctx, http.MethodGet, salesforceAPI+"/sobjects/OauthToken/"+containment.Esc(g.Ref), nil, nil, nil)
	if errors.Is(err, containment.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
