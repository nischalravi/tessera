package erp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Oracle Fusion Applications. Roles hold function-security privileges (what the
// SAP side calls t-codes) and data-security policies (authorization objects).
// The security REST contract Tessera reads and writes:
//
//	POST /oauth2/v1/token (client credentials, HTTP Basic)  -> {access_token, token_type:"Bearer"}
//	GET  <root>/roles?limit&offset -> {items:[{roleCode,roleName,description,dutyRoles:[code],privileges:[code],
//	                                          dataSecurity:[{object,condition,actions:[..]}]}],hasMore}
//	GET  <root>/users?limit&offset -> {items:[{username,displayName,email,active,roleAssignments:[{roleCode,startDate,endDate}]}],hasMore}
//	GET  <root>/users/{user}       -> one of the above
//	POST <root>/users/{user}/roleAssignments {roleCode} ; DELETE <root>/users/{user}/roleAssignments/{roleCode}
//
// A data-security policy maps to an authorization object: object, with the
// field CONDITION and the actions as ACTVT. A job role that includes duty
// roles is a composite of them. root defaults to /fscmRestApi/security/v1.
type oracle struct{ s *session }

// DefaultOracleRoot is the default path of the Oracle security service.
const DefaultOracleRoot = "/fscmRestApi/security/v1"

func (*oracle) Vendor() string { return Oracle }

func (c *oracle) page(off int) url.Values {
	return url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(off)}}
}

type oraUser struct {
	Username string `json:"username"`
	Name     string `json:"displayName"`
	Email    string `json:"email"`
	Active   *bool  `json:"active"`
	Roles    []struct {
		Code  string `json:"roleCode"`
		Start string `json:"startDate"`
		End   string `json:"endDate"`
	} `json:"roleAssignments"`
}

func (u oraUser) user() User {
	out := User{ID: u.Username, Name: u.Name, Email: u.Email, Locked: u.Active != nil && !*u.Active}
	for _, r := range u.Roles {
		out.Roles = append(out.Roles, Assignment{Role: r.Code, From: tparse(r.Start), To: tparse(r.End)})
	}
	return out
}

func (c *oracle) Roles(ctx context.Context) ([]Role, error) {
	var out []Role
	err := forPages(func(off int) (bool, error) {
		var p struct {
			Items []struct {
				Code, Name string   `json:"-"`
				RoleCode   string   `json:"roleCode"`
				RoleName   string   `json:"roleName"`
				Desc       string   `json:"description"`
				Duties     []string `json:"dutyRoles"`
				Privs      []string `json:"privileges"`
				Data       []struct {
					Object  string   `json:"object"`
					Cond    string   `json:"condition"`
					Actions []string `json:"actions"`
				} `json:"dataSecurity"`
			} `json:"items"`
			HasMore bool `json:"hasMore"`
		}
		if err := c.s.getJSON(ctx, "/roles", c.page(off), &p); err != nil {
			return false, err
		}
		for _, r := range p.Items {
			role := Role{ID: r.RoleCode, Name: r.RoleName, Description: r.Desc, Children: r.Duties, TCodes: r.Privs}
			for _, d := range r.Data {
				f := map[string][]string{"ACTVT": d.Actions}
				if d.Cond != "" {
					f["CONDITION"] = []string{d.Cond}
				}
				role.AuthObjects = append(role.AuthObjects, AuthObject{Object: d.Object, Fields: f})
			}
			out = append(out, role)
		}
		return p.HasMore && len(p.Items) > 0, nil
	})
	return out, err
}

func (c *oracle) Users(ctx context.Context) ([]User, error) {
	var out []User
	err := forPages(func(off int) (bool, error) {
		var p struct {
			Items   []oraUser `json:"items"`
			HasMore bool      `json:"hasMore"`
		}
		if err := c.s.getJSON(ctx, "/users", c.page(off), &p); err != nil {
			return false, err
		}
		for _, u := range p.Items {
			out = append(out, u.user())
		}
		return p.HasMore && len(p.Items) > 0, nil
	})
	return out, err
}

func (c *oracle) User(ctx context.Context, id string) (*User, error) {
	var u oraUser
	err := c.s.getJSON(ctx, "/users/"+url.PathEscape(id), nil, &u)
	if connsync.Status(err) == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	x := u.user()
	return &x, nil
}

func (c *oracle) AssignRole(ctx context.Context, user, role string) error {
	b, _ := json.Marshal(map[string]string{"roleCode": role})
	err := c.s.call(ctx, http.MethodPost, "/users/"+url.PathEscape(user)+"/roleAssignments", b)
	if connsync.Status(err) == http.StatusNotFound {
		return &NotFoundError{Oracle, "user " + user + " or role " + role}
	}
	return err
}

func (c *oracle) RemoveRole(ctx context.Context, user, role string) error {
	err := c.s.call(ctx, http.MethodDelete, "/users/"+url.PathEscape(user)+"/roleAssignments/"+url.PathEscape(role), nil)
	if connsync.Status(err) == http.StatusNotFound {
		return nil
	}
	return err
}
