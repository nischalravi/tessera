package erp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// SAP. SAP has no single REST API for roles: the authorization data (AGR_*
// and USR* tables) is exposed to Tessera by an OData service the SAP team
// publishes (a CDS view service on S/4HANA, or a Gateway service on ECC), with
// OAuth through SAP BTP or the Gateway. The contract Tessera reads and writes:
//
//	POST /oauth/token (client credentials, HTTP Basic)                -> {access_token, token_type:"Bearer"}
//	GET  <root>/roles?$top&$skip  -> {value:[{role,description,composite,children:[role],tcodes:[t-code],
//	                                         authObjects:[{object,fields:{FIELD:[values]}}]}]}
//	GET  <root>/users?$top&$skip  -> {value:[{user,name,email,locked,validTo,lastLogon,roles:[{role,validFrom,validTo}]}]}
//	GET  <root>/users/{user}      -> one of the above
//	PUT|DELETE <root>/users/{user}/roles/{role}
//
// root defaults to /sap/opu/odata4/tessera/authz/v1.
type sap struct{ s *session }

// DefaultSAPRoot is the default path of the SAP authorization service.
const DefaultSAPRoot = "/sap/opu/odata4/tessera/authz/v1"

func (*sap) Vendor() string { return SAP }

type sapRole struct {
	Role     string   `json:"role"`
	Desc     string   `json:"description"`
	Children []string `json:"children"`
	TCodes   []string `json:"tcodes"`
	Auth     []struct {
		Object string              `json:"object"`
		Fields map[string][]string `json:"fields"`
	} `json:"authObjects"`
}

type sapUser struct {
	User      string `json:"user"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Locked    bool   `json:"locked"`
	ValidTo   string `json:"validTo"`
	LastLogon string `json:"lastLogon"`
	Roles     []struct {
		Role string `json:"role"`
		From string `json:"validFrom"`
		To   string `json:"validTo"`
	} `json:"roles"`
}

func (u sapUser) user() User {
	out := User{ID: u.User, Name: u.Name, Email: u.Email, Locked: u.Locked, ValidTo: tparse(u.ValidTo), LastLogon: tparse(u.LastLogon)}
	for _, r := range u.Roles {
		out.Roles = append(out.Roles, Assignment{Role: r.Role, From: tparse(r.From), To: tparse(r.To)})
	}
	return out
}

func (c *sap) page(off int) url.Values {
	return url.Values{"$top": {strconv.Itoa(pageSize)}, "$skip": {strconv.Itoa(off)}}
}

func (c *sap) Roles(ctx context.Context) ([]Role, error) {
	var out []Role
	err := forPages(func(off int) (bool, error) {
		var p struct {
			Value []sapRole `json:"value"`
		}
		if err := c.s.getJSON(ctx, "/roles", c.page(off), &p); err != nil {
			return false, err
		}
		for _, r := range p.Value {
			role := Role{ID: r.Role, Name: r.Role, Description: r.Desc, Children: r.Children, TCodes: r.TCodes}
			for _, a := range r.Auth {
				role.AuthObjects = append(role.AuthObjects, AuthObject{Object: a.Object, Fields: a.Fields})
			}
			out = append(out, role)
		}
		return len(p.Value) == pageSize, nil
	})
	return out, err
}

func (c *sap) Users(ctx context.Context) ([]User, error) {
	var out []User
	err := forPages(func(off int) (bool, error) {
		var p struct {
			Value []sapUser `json:"value"`
		}
		if err := c.s.getJSON(ctx, "/users", c.page(off), &p); err != nil {
			return false, err
		}
		for _, u := range p.Value {
			out = append(out, u.user())
		}
		return len(p.Value) == pageSize, nil
	})
	return out, err
}

func (c *sap) User(ctx context.Context, id string) (*User, error) {
	var u sapUser
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

func (c *sap) AssignRole(ctx context.Context, user, role string) error {
	b, _ := json.Marshal(map[string]*time.Time{"validFrom": nil, "validTo": nil})
	err := c.s.call(ctx, http.MethodPut, "/users/"+url.PathEscape(user)+"/roles/"+url.PathEscape(role), b)
	if connsync.Status(err) == http.StatusNotFound {
		return &NotFoundError{SAP, "user " + user + " or role " + role}
	}
	return err
}

func (c *sap) RemoveRole(ctx context.Context, user, role string) error {
	err := c.s.call(ctx, http.MethodDelete, "/users/"+url.PathEscape(user)+"/roles/"+url.PathEscape(role), nil)
	if connsync.Status(err) == http.StatusNotFound {
		return nil
	}
	return err
}
