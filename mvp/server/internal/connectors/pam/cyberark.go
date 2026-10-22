package pam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// CyberArk Privileged Access Manager (PVWA REST API). Shapes used:
//
//	POST /PasswordVault/API/auth/Cyberark/Logon {username,password}  -> "<token>" (sent as the Authorization header)
//	GET  /PasswordVault/API/Safes?limit&offset            -> {value:[{safeUrlId,safeName,description}]}
//	GET  /PasswordVault/API/Safes/{id}/Members?limit&offset -> {value:[{memberName,memberType,permissions:{useAccounts:bool,...}}]}
//	GET  /PasswordVault/API/Accounts?filter=safeName eq X&limit&offset -> {value:[{id,name,userName,address,platformId,createdTime,secretManagement:{automaticManagementEnabled,lastModifiedTime}}]}
//	POST /PasswordVault/API/Safes/{id}/Members, PUT|DELETE .../Members/{name}
type cyberark struct{ s *session }

// DefaultCyberArkRoot is the PVWA API root.
const DefaultCyberArkRoot = "/PasswordVault/API"

func newCyberArk(cfg Config, base *url.URL, hc *http.Client, now func() time.Time) (*cyberark, error) {
	root := cfg.APIRoot
	if root == "" {
		root = DefaultCyberArkRoot
	}
	s, err := newSession(hc, base, root, now, false)
	if err != nil {
		return nil, err
	}
	login := &session{api: &connsync.Client{HC: s.api.HC, Now: now, Header: s.api.Header}, base: base, root: root}
	s.login = func(ctx context.Context) (string, error) {
		b, _ := json.Marshal(map[string]string{"username": cfg.Username, "password": cfg.Secret.Reveal()})
		resp, err := login.api.Do(ctx, http.MethodPost, login.u("/auth/Cyberark/Logon", nil), http.Header{"Content-Type": {"application/json"}}, b)
		if err != nil {
			return "", err
		}
		var tok string
		if err := connsync.DecodeJSON(resp.Body, &tok); err != nil || tok == "" {
			return "", connsync.ErrMalformed
		}
		return tok, nil
	}
	return &cyberark{s}, nil
}

func (*cyberark) Vendor() string { return CyberArk }

var caPerms = map[string]string{
	"listAccounts": PermList, "viewSafeMembers": PermViewMembers, "useAccounts": PermUse, "retrieveAccounts": PermRetrieve,
	"addAccounts": PermAdd, "updateAccountProperties": PermUpdateProps, "updateAccountContent": PermUpdateContent,
	"renameAccounts": PermRename, "deleteAccounts": PermDelete, "unlockAccounts": PermUnlock, "manageSafe": PermManageSafe,
	"manageSafeMembers": PermManageMembers, "viewAuditLog": PermAuditLog, "backupSafe": PermBackup,
	"accessWithoutConfirmation": PermNoConfirmation,
}

func (c *cyberark) Safes(ctx context.Context) ([]Safe, error) {
	var out []Safe
	err := forPages(func(off int) (bool, error) {
		var raw struct {
			Value []struct {
				ID   string `json:"safeUrlId"`
				Name string `json:"safeName"`
				Desc string `json:"description"`
			} `json:"value"`
		}
		if err := c.s.getJSON(ctx, "/Safes", url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(off)}}, &raw); err != nil {
			return false, err
		}
		for _, v := range raw.Value {
			out = append(out, Safe{ID: v.ID, Name: v.Name, Description: v.Desc})
		}
		return len(raw.Value) == pageSize, nil
	})
	return out, err
}

func (c *cyberark) Accounts(ctx context.Context, s Safe) ([]Account, error) {
	var out []Account
	err := forPages(func(off int) (bool, error) {
		var raw struct {
			Value []struct {
				ID, Name, Address string
				UserName          string `json:"userName"`
				Platform          string `json:"platformId"`
				Created           int64  `json:"createdTime"`
				Secret            struct {
					Auto     bool  `json:"automaticManagementEnabled"`
					Modified int64 `json:"lastModifiedTime"`
				} `json:"secretManagement"`
			} `json:"value"`
		}
		q := url.Values{"filter": {"safeName eq " + s.Name}, "limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(off)}}
		if err := c.s.getJSON(ctx, "/Accounts", q, &raw); err != nil {
			return false, err
		}
		for _, v := range raw.Value {
			out = append(out, Account{ID: v.ID, Name: v.Name, Username: v.UserName, Address: v.Address, Platform: v.Platform,
				AutoManaged: v.Secret.Auto, CreatedAt: epoch(v.Created), LastRotatedAt: epoch(v.Secret.Modified)})
		}
		return len(raw.Value) == pageSize, nil
	})
	return out, err
}

func (c *cyberark) Members(ctx context.Context, s Safe) ([]Member, error) {
	var out []Member
	err := forPages(func(off int) (bool, error) {
		var raw struct {
			Value []struct {
				Name  string          `json:"memberName"`
				Type  string          `json:"memberType"`
				Perms map[string]bool `json:"permissions"`
			} `json:"value"`
		}
		q := url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(off)}}
		if err := c.s.getJSON(ctx, "/Safes/"+url.PathEscape(s.ID)+"/Members", q, &raw); err != nil {
			return false, err
		}
		for _, v := range raw.Value {
			var ps []string
			for k, on := range v.Perms {
				if n, ok := caPerms[k]; ok && on {
					ps = append(ps, n)
				}
			}
			if v.Perms["requestsAuthorizationLevel1"] || v.Perms["requestsAuthorizationLevel2"] {
				ps = append(ps, PermApprove)
			}
			out = append(out, Member{Name: v.Name, Type: memberType(v.Type), Perms: dedupe(ps)})
		}
		return len(raw.Value) == pageSize, nil
	})
	return out, err
}

func memberType(t string) string {
	switch t {
	case "Group", "group":
		return MemberGroup
	case "Role", "role":
		return MemberRole
	}
	return MemberUser
}

func (c *cyberark) perms(profile string) map[string]bool {
	want := map[string]bool{}
	for _, p := range profilePerms[profile] {
		want[p] = true
	}
	out := map[string]bool{}
	for k, n := range caPerms {
		out[k] = want[n]
	}
	return out
}

func (c *cyberark) SetMember(ctx context.Context, s Safe, name, typ, profile string) error {
	if !ValidProfile(profile) {
		return &UnsupportedError{CyberArk, profile}
	}
	vt := map[string]string{MemberGroup: "Group", MemberRole: "Role"}[typ]
	if vt == "" {
		vt = "User"
	}
	body := map[string]any{"memberName": name, "memberType": vt, "permissions": c.perms(profile)}
	base := "/Safes/" + url.PathEscape(s.ID) + "/Members"
	ms, err := c.Members(ctx, s)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if m.Name == name {
			return c.s.send(ctx, http.MethodPut, base+"/"+url.PathEscape(name), body)
		}
	}
	return c.s.send(ctx, http.MethodPost, base, body)
}

func (c *cyberark) RemoveMember(ctx context.Context, s Safe, name string) error {
	err := c.s.send(ctx, http.MethodDelete, "/Safes/"+url.PathEscape(s.ID)+"/Members/"+url.PathEscape(name), nil)
	if connsync.Status(err) == http.StatusNotFound {
		return nil
	}
	return err
}
