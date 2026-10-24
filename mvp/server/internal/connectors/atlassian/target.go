package atlassian

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Credential is what a provisioning target keeps sealed, as JSON
//
//	{"email":"tessera@acme.example","api_token":"ATATT..."}
//
// The account needs the site administration permission to change group membership, and administer the
// project (or Administer Jira) to change a project role. Its errors never repeat the token.
type Credential struct {
	Email    string `json:"email"`
	APIToken string `json:"api_token"`
}

// ParseTargetCredential reads and checks a target credential.
func ParseTargetCredential(s string) (*Credential, error) {
	if len(s) > 8<<10 {
		return nil, errors.New("the Atlassian credential is too long")
	}
	var c Credential
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || !emailRE.MatchString(c.Email) || !strings.Contains(c.Email, "@") || c.APIToken == "" || strings.ContainsAny(c.APIToken, " \t\r\n\x00") {
		return nil, errors.New("the Atlassian credential is JSON with email and api_token")
	}
	return &c, nil
}

// OpenTarget builds the provisioning target of a site from its base URL and sealed credential.
func OpenTarget(baseURL string, cred *Credential, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Target, error) {
	c, err := Open(Config{BaseURL: baseURL, Email: cred.Email, Token: connsync.NewSecret(cred.APIToken)}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return &Target{C: c}, nil
}

// Target is the provisioning target of a site (target.Connector): group membership and project role actors.
// The entitlement is a group (its groupId) or a project role ("KEY/roleId", the id Discover reports). Product
// access is a matter of group membership in Atlassian, so it is requested as the group that grants it.
//
// Accounts are not created, changed or suspended here: use an Atlassian Cloud SCIM target for that, which the
// SCIM preset already supports. Every operation reads first, so a repeated request converges.
type Target struct{ C *Client }

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var se *connsync.StatusError
	if errors.As(err, &se) {
		return target.Fail(op, se.Status, se.Code)
	}
	return target.Transport(op, err)
}

// ref is a parsed entitlement.
type ref struct {
	group string // a groupId, or
	key   string // a project key and
	role  string // a role id
}

func parseRef(id string) (ref, error) {
	if k, r, ok := strings.Cut(id, "/"); ok {
		if projectRE.MatchString(k) && roleIDRE.MatchString(r) {
			return ref{key: k, role: r}, nil
		}
	} else if groupRE.MatchString(id) {
		return ref{group: id}, nil
	}
	return ref{}, target.Permanent("the entitlement is a group id or a project role (KEY/roleId)")
}

func checkKind(r target.Request) error {
	switch r.Kind {
	case target.AddEntitlement, target.RemoveEntitlement:
		return nil
	case target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount:
		return target.Permanent("%s is not done here: Atlassian accounts are provisioned through an Atlassian Cloud SCIM target", r.Kind)
	}
	return target.Permanent("%s is not supported by the Atlassian target", r.Kind)
}

// accountID resolves the request's account: its external id (an Atlassian account id), else the user whose
// e-mail matches exactly. "" means the site has no such user (or hides the e-mail).
func (t *Target) accountID(ctx context.Context, a target.Account) (string, error) {
	if accountRE.MatchString(a.ExternalID) {
		return a.ExternalID, nil
	}
	email := a.Email
	if email == "" {
		email = a.Username
	}
	if !emailRE.MatchString(email) || !strings.Contains(email, "@") {
		return "", target.Permanent("the account needs an Atlassian account id or an e-mail address")
	}
	var us []jiraItem
	q := url.Values{"query": {email}, "maxResults": {"20"}}
	if _, err := t.C.site.GetJSON(ctx, t.C.siteURL("/rest/api/3/user/search", q), nil, &us); err != nil {
		return "", wrap("find user", err)
	}
	for _, u := range us {
		if strings.EqualFold(u.EmailAddress, email) && accountRE.MatchString(u.AccountID) {
			return u.AccountID, nil
		}
	}
	return "", nil
}

// holds reports whether the account holds the entitlement.
func (t *Target) holds(ctx context.Context, account string, e ref) (bool, error) {
	if e.group != "" {
		var u struct {
			Groups struct {
				Items []struct {
					GroupID string `json:"groupId"`
				} `json:"items"`
			} `json:"groups"`
		}
		q := url.Values{"accountId": {account}, "expand": {"groups"}}
		if _, err := t.C.site.GetJSON(ctx, t.C.siteURL("/rest/api/3/user", q), nil, &u); err != nil {
			if connsync.Status(err) == http.StatusNotFound {
				return false, nil
			}
			return false, wrap("read user", err)
		}
		for _, g := range u.Groups.Items {
			if g.GroupID == e.group {
				return true, nil
			}
		}
		return false, nil
	}
	r, err := t.C.role(ctx, e.key, e.role)
	if err != nil {
		if connsync.Status(err) == http.StatusNotFound {
			return false, target.Permanent("%s has no such project role", System)
		}
		return false, wrap("read project role", err)
	}
	for _, a := range r.Actors {
		if a.ActorUser != nil && a.ActorUser.AccountID == account {
			return true, nil
		}
	}
	return false, nil
}

// Apply sends the change.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if err := checkKind(r); err != nil {
		return err
	}
	e, err := parseRef(r.Group.ExternalID)
	if err != nil {
		return err
	}
	acct, err := t.accountID(ctx, r.Account)
	if err != nil {
		return err
	}
	if acct == "" {
		if r.Kind == target.AddEntitlement {
			return target.Permanent("add %s: the site has no user with that e-mail address", System)
		}
		return nil
	}
	have, err := t.holds(ctx, acct, e)
	if err != nil {
		return err
	}
	add := r.Kind == target.AddEntitlement
	if have == add {
		return nil
	}
	hdr := http.Header{"Content-Type": {"application/json"}}
	switch {
	case e.group != "" && add:
		b, _ := json.Marshal(map[string]string{"accountId": acct})
		_, err = t.C.site.Do(ctx, http.MethodPost, t.C.siteURL("/rest/api/3/group/user", url.Values{"groupId": {e.group}}), hdr, b)
	case e.group != "":
		_, err = t.C.site.Do(ctx, http.MethodDelete, t.C.siteURL("/rest/api/3/group/user", url.Values{"groupId": {e.group}, "accountId": {acct}}), nil, nil)
	case add:
		b, _ := json.Marshal(map[string][]string{"user": {acct}})
		_, err = t.C.site.Do(ctx, http.MethodPost, t.C.siteURL("/rest/api/3/project/"+e.key+"/role/"+e.role, nil), hdr, b)
	default:
		_, err = t.C.site.Do(ctx, http.MethodDelete, t.C.siteURL("/rest/api/3/project/"+e.key+"/role/"+e.role, url.Values{"user": {acct}}), nil, nil)
	}
	return wrap(strings.ReplaceAll(r.Kind, "_", " "), err)
}

// Verify re-reads the site.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	if err := checkKind(r); err != nil {
		return target.Verdict{}, err
	}
	e, err := parseRef(r.Group.ExternalID)
	if err != nil {
		return target.Verdict{}, err
	}
	acct, err := t.accountID(ctx, r.Account)
	if err != nil {
		return target.Verdict{}, err
	}
	have := false
	if acct != "" {
		if have, err = t.holds(ctx, acct, e); err != nil {
			return target.Verdict{}, err
		}
	}
	obs := "does not hold the entitlement"
	if have {
		obs = "holds the entitlement"
	}
	if r.Kind == target.AddEntitlement {
		return target.Verdict{OK: have, Expected: "holds the entitlement", Observed: obs}, nil
	}
	return target.Verdict{OK: !have, Expected: "does not hold the entitlement", Observed: obs}, nil
}
