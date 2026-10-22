package pam

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Delinea Secret Server. A folder is a safe, a secret a vaulted account, a
// folder permission a member. Shapes used:
//
//	POST /oauth2/token (form grant_type=password, username, password) -> {access_token, token_type:"bearer"}
//	GET  /api/v1/folders?take&skip           -> {records:[{id,folderName,folderPath}], hasNext}
//	GET  /api/v1/secrets?filter.folderId&take&skip -> {records:[{id,name,secretTemplateName}], hasNext}
//	GET  /api/v1/folder-permissions?filter.folderId&take&skip
//	     -> {records:[{id,userName|groupName,folderAccessRoleName,secretAccessRoleName}], hasNext}
//	POST /api/v1/folder-permissions {folderId,userId|groupId,folderAccessRoleName,secretAccessRoleName}
//	PUT|DELETE /api/v1/folder-permissions/{id}
//	GET  /api/v1/users|groups?filter.searchText -> {records:[{id,userName|name}]}
//
// Secret Server has the roles List, View, Edit and Owner, not permissions: the
// reader maps them (List: list; View: read; Edit: read plus add and change;
// Owner: manage). It has no way to use a secret without seeing it, so the
// profile "use" is not supported.
type delinea struct {
	s *session
}

// DefaultDelineaRoot is the API root of Secret Server.
const DefaultDelineaRoot = "/api/v1"

func newDelinea(cfg Config, base *url.URL, hc *http.Client, now func() time.Time) (*delinea, error) {
	root := cfg.APIRoot
	if root == "" {
		root = DefaultDelineaRoot
	}
	s, err := newSession(hc, base, root, now, false)
	if err != nil {
		return nil, err
	}
	tokenAPI := *s.api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	s.login = func(ctx context.Context) (string, error) {
		tu := *base
		tu.Path = "/oauth2/token"
		form := url.Values{"grant_type": {"password"}, "username": {cfg.Username}, "password": {cfg.Secret.Reveal()}}
		resp, err := tokenAPI.Do(ctx, http.MethodPost, tu.String(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
		if err != nil {
			return "", err
		}
		var tr struct {
			Token string `json:"access_token"`
			Type  string `json:"token_type"`
		}
		if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
			return "", err
		}
		if tr.Token == "" || !strings.EqualFold(tr.Type, "bearer") {
			return "", connsync.ErrMalformed
		}
		return "Bearer " + tr.Token, nil
	}
	return &delinea{s}, nil
}

func (*delinea) Vendor() string { return Delinea }

type dlPage[T any] struct {
	Records []T  `json:"records"`
	HasNext bool `json:"hasNext"`
}

func dlAll[T any](ctx context.Context, d *delinea, path string, q url.Values, each func(T)) error {
	return forPages(func(off int) (bool, error) {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("take", strconv.Itoa(pageSize))
		qq.Set("skip", strconv.Itoa(off))
		var p dlPage[T]
		if err := d.s.getJSON(ctx, path, qq, &p); err != nil {
			return false, err
		}
		for _, r := range p.Records {
			each(r)
		}
		return p.HasNext && len(p.Records) > 0, nil
	})
}

func (d *delinea) Safes(ctx context.Context) ([]Safe, error) {
	var out []Safe
	type rec struct {
		ID   int64  `json:"id"`
		Name string `json:"folderName"`
		Path string `json:"folderPath"`
	}
	err := dlAll(ctx, d, "/folders", nil, func(r rec) {
		name := r.Path
		if name == "" {
			name = r.Name
		}
		out = append(out, Safe{ID: strconv.FormatInt(r.ID, 10), Name: name})
	})
	return out, err
}

func (d *delinea) Accounts(ctx context.Context, s Safe) ([]Account, error) {
	var out []Account
	type rec struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Template string `json:"secretTemplateName"`
	}
	err := dlAll(ctx, d, "/secrets", url.Values{"filter.folderId": {s.ID}}, func(r rec) {
		out = append(out, Account{ID: strconv.FormatInt(r.ID, 10), Name: r.Name, Username: r.Name, Platform: r.Template})
	})
	return out, err
}

type dlPerm struct {
	ID         int64  `json:"id"`
	UserName   string `json:"userName"`
	GroupName  string `json:"groupName"`
	FolderRole string `json:"folderAccessRoleName"`
	SecretRole string `json:"secretAccessRoleName"`
}

// dlPermsOf maps Secret Server roles to safe permissions.
func dlPermsOf(folderRole, secretRole string) []string {
	var p []string
	switch strings.ToLower(secretRole) {
	case "list":
		p = profilePerms[ProfileList]
	case "view":
		p = profilePerms[ProfileRead]
	case "edit":
		p = append(append([]string(nil), profilePerms[ProfileRead]...), PermAdd, PermUpdateProps, PermUpdateContent, PermRename)
	case "owner":
		p = profilePerms[ProfileManage]
	}
	if strings.EqualFold(folderRole, "owner") && len(p) > 0 {
		p = append(append([]string(nil), p...), PermManageSafe, PermManageMembers)
	}
	return dedupe(p)
}

func (d *delinea) perms(ctx context.Context, s Safe) ([]dlPerm, error) {
	var out []dlPerm
	err := dlAll(ctx, d, "/folder-permissions", url.Values{"filter.folderId": {s.ID}}, func(r dlPerm) { out = append(out, r) })
	return out, err
}

func (d *delinea) Members(ctx context.Context, s Safe) ([]Member, error) {
	ps, err := d.perms(ctx, s)
	if err != nil {
		return nil, err
	}
	var out []Member
	for _, p := range ps {
		m := Member{Name: p.UserName, Type: MemberUser, Perms: dlPermsOf(p.FolderRole, p.SecretRole)}
		if p.GroupName != "" {
			m.Name, m.Type = p.GroupName, MemberGroup
		}
		out = append(out, m)
	}
	return out, nil
}

func dlRoles(profile string) (folder, secret string, ok bool) {
	switch profile {
	case ProfileList:
		return "List", "List", true
	case ProfileRead:
		return "View", "View", true
	case ProfileManage:
		return "Owner", "Owner", true
	}
	return "", "", false
}

func (d *delinea) principalID(ctx context.Context, typ, name string) (int64, error) {
	path, field := "/users", "userName"
	if typ == MemberGroup {
		path, field = "/groups", "name"
	}
	var id int64
	found := false
	err := dlAll(ctx, d, path, url.Values{"filter.searchText": {name}}, func(r map[string]any) {
		if n, _ := r[field].(string); !found && strings.EqualFold(n, name) {
			if f, ok := r["id"].(float64); ok && f > 0 && f < 1<<53 {
				id, found = int64(f), true
			}
		}
	})
	if err == nil && !found {
		return 0, &NotFoundError{Vendor: Delinea, What: typ + " " + name}
	}
	return id, err
}

// NotFoundError: the vendor has no such principal or safe.
type NotFoundError struct{ Vendor, What string }

func (e *NotFoundError) Error() string { return e.Vendor + " has no " + e.What }

func (d *delinea) SetMember(ctx context.Context, s Safe, name, typ, profile string) error {
	fr, sr, ok := dlRoles(profile)
	if !ok {
		return &UnsupportedError{Delinea, profile}
	}
	ps, err := d.perms(ctx, s)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if strings.EqualFold(p.UserName, name) && typ != MemberGroup || strings.EqualFold(p.GroupName, name) && typ == MemberGroup {
			return d.s.send(ctx, http.MethodPut, "/folder-permissions/"+strconv.FormatInt(p.ID, 10),
				map[string]any{"folderAccessRoleName": fr, "secretAccessRoleName": sr})
		}
	}
	fid, err := strconv.ParseInt(s.ID, 10, 32)
	if err != nil {
		return err
	}
	pid, err := d.principalID(ctx, typ, name)
	if err != nil {
		return err
	}
	body := map[string]any{"folderId": fid, "folderAccessRoleName": fr, "secretAccessRoleName": sr}
	if typ == MemberGroup {
		body["groupId"] = pid
	} else {
		body["userId"] = pid
	}
	return d.s.send(ctx, http.MethodPost, "/folder-permissions", body)
}

func (d *delinea) RemoveMember(ctx context.Context, s Safe, name string) error {
	ps, err := d.perms(ctx, s)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if strings.EqualFold(p.UserName, name) || strings.EqualFold(p.GroupName, name) {
			if err := d.s.send(ctx, http.MethodDelete, "/folder-permissions/"+strconv.FormatInt(p.ID, 10), nil); err != nil && connsync.Status(err) != http.StatusNotFound {
				return err
			}
		}
	}
	return nil
}

func asNotFound(err error, out **NotFoundError) bool { return errors.As(err, out) }
