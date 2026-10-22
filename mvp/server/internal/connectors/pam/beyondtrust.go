package pam

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// BeyondTrust Password Safe. A smart rule is a safe, a managed account a
// vaulted account, a user group's role on a smart rule a member. Shapes used
// (all under /BeyondTrust/api/public/v3, authenticated by the header
// "PS-Auth key=<key>; runas=<user>;" and the session cookie SignAppin sets):
//
//	POST /Auth/SignAppin                         -> the user (sets the session cookie)
//	GET  /SmartRules?limit&offset                -> [{SmartRuleID,Title,Description}]
//	GET  /SmartRules/{id}/ManagedAccounts        -> [{ManagedAccountID,AccountName,SystemName,AutoManagementFlag,LastChangeDate,CreateDate}]
//	GET  /UserGroups?limit&offset                -> [{GroupID,GroupName,GroupType}]
//	GET  /UserGroups/{gid}/SmartRules            -> [{SmartRuleID,Roles:[{RoleID,Name}]}]
//	POST /UserGroups/{gid}/SmartRules/{id}/Roles [{RoleID}] ; DELETE the same path
//	GET  /Roles                                  -> [{RoleID,Name}]
//
// The reader maps the roles "Read Only" (list), "Requestor" (use) and
// "Approver" (the approve permission). Only the profiles list and use can be
// written: Password Safe has no role that means reading or managing a safe.
type beyondtrust struct{ s *session }

// DefaultBeyondTrustRoot is the API root of Password Safe.
const DefaultBeyondTrustRoot = "/BeyondTrust/api/public/v3"

func newBeyondTrust(cfg Config, base *url.URL, hc *http.Client, now func() time.Time) (*beyondtrust, error) {
	root := cfg.APIRoot
	if root == "" {
		root = DefaultBeyondTrustRoot
	}
	s, err := newSession(hc, base, root, now, true)
	if err != nil {
		return nil, err
	}
	header := "PS-Auth key=" + cfg.Secret.Reveal() + "; runas=" + cfg.Username + ";"
	// the sign-in request carries its own header, so Authorize must not recurse
	signin := *s.api
	signin.Authorize, signin.OnUnauthorized = nil, nil
	s.login = func(ctx context.Context) (string, error) {
		_, err := signin.Do(ctx, http.MethodPost, s.u("/Auth/SignAppin", nil), http.Header{"Authorization": {header}}, nil)
		return header, err
	}
	return &beyondtrust{s}, nil
}

func (*beyondtrust) Vendor() string { return BeyondTrust }

const (
	btReadOnly  = "Read Only"
	btRequestor = "Requestor"
	btApprover  = "Approver"
)

func btAll[T any](ctx context.Context, b *beyondtrust, path string, each func(T)) error {
	return forPages(func(off int) (bool, error) {
		var page []T
		q := url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(off)}}
		if err := b.s.getJSON(ctx, path, q, &page); err != nil {
			return false, err
		}
		for _, r := range page {
			each(r)
		}
		return len(page) == pageSize, nil
	})
}

func (b *beyondtrust) Safes(ctx context.Context) ([]Safe, error) {
	var out []Safe
	type rec struct {
		ID    int64  `json:"SmartRuleID"`
		Title string `json:"Title"`
		Desc  string `json:"Description"`
	}
	err := btAll(ctx, b, "/SmartRules", func(r rec) {
		out = append(out, Safe{ID: strconv.FormatInt(r.ID, 10), Name: r.Title, Description: r.Desc})
	})
	return out, err
}

func (b *beyondtrust) Accounts(ctx context.Context, s Safe) ([]Account, error) {
	var page []struct {
		ID     int64  `json:"ManagedAccountID"`
		Name   string `json:"AccountName"`
		System string `json:"SystemName"`
		Auto   bool   `json:"AutoManagementFlag"`
		Change string `json:"LastChangeDate"`
		Create string `json:"CreateDate"`
	}
	if err := b.s.getJSON(ctx, "/SmartRules/"+url.PathEscape(s.ID)+"/ManagedAccounts", nil, &page); err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(page))
	for _, r := range page {
		a := Account{ID: strconv.FormatInt(r.ID, 10), Name: r.Name, Username: r.Name, Address: r.System, AutoManaged: r.Auto}
		if t, err := time.Parse(time.RFC3339, r.Change); err == nil {
			a.LastRotatedAt = &t
		}
		if t, err := time.Parse(time.RFC3339, r.Create); err == nil {
			a.CreatedAt = &t
		}
		out = append(out, a)
	}
	return out, nil
}

type btGroup struct {
	ID   int64  `json:"GroupID"`
	Name string `json:"GroupName"`
}

type btRule struct {
	ID    int64 `json:"SmartRuleID"`
	Roles []struct {
		ID   int64  `json:"RoleID"`
		Name string `json:"Name"`
	} `json:"Roles"`
}

func (b *beyondtrust) groups(ctx context.Context) ([]btGroup, error) {
	var out []btGroup
	err := btAll(ctx, b, "/UserGroups", func(g btGroup) { out = append(out, g) })
	return out, err
}

func btPerms(roles []string) []string {
	var p []string
	for _, r := range roles {
		switch r {
		case btReadOnly:
			p = append(p, profilePerms[ProfileList]...)
		case btRequestor:
			p = append(p, profilePerms[ProfileUse]...)
		case btApprover:
			p = append(p, PermList, PermViewMembers, PermApprove)
		}
	}
	return dedupe(p)
}

func (b *beyondtrust) Members(ctx context.Context, s Safe) ([]Member, error) {
	gs, err := b.groups(ctx)
	if err != nil {
		return nil, err
	}
	var out []Member
	for _, g := range gs {
		var rules []btRule
		if err := b.s.getJSON(ctx, "/UserGroups/"+strconv.FormatInt(g.ID, 10)+"/SmartRules", nil, &rules); err != nil {
			return nil, err
		}
		for _, r := range rules {
			if strconv.FormatInt(r.ID, 10) != s.ID {
				continue
			}
			var names []string
			for _, ro := range r.Roles {
				names = append(names, ro.Name)
			}
			if p := btPerms(names); len(p) > 0 {
				out = append(out, Member{Name: g.Name, Type: MemberGroup, Perms: p})
			}
		}
	}
	return out, nil
}

func (b *beyondtrust) roleIDs(ctx context.Context) (map[string]int64, error) {
	var rs []struct {
		ID   int64  `json:"RoleID"`
		Name string `json:"Name"`
	}
	if err := b.s.getJSON(ctx, "/Roles", nil, &rs); err != nil {
		return nil, err
	}
	m := map[string]int64{}
	for _, r := range rs {
		m[r.Name] = r.ID
	}
	return m, nil
}

func (b *beyondtrust) group(ctx context.Context, name string) (*btGroup, error) {
	gs, err := b.groups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range gs {
		if gs[i].Name == name {
			return &gs[i], nil
		}
	}
	return nil, &NotFoundError{Vendor: BeyondTrust, What: "user group " + name}
}

func (b *beyondtrust) SetMember(ctx context.Context, s Safe, name, _ string, profile string) error {
	want := map[string]string{ProfileList: btReadOnly, ProfileUse: btRequestor}[profile]
	if want == "" {
		return &UnsupportedError{BeyondTrust, profile}
	}
	g, err := b.group(ctx, name)
	if err != nil {
		return err
	}
	ids, err := b.roleIDs(ctx)
	if err != nil {
		return err
	}
	id, ok := ids[want]
	if !ok {
		return &NotFoundError{Vendor: BeyondTrust, What: "role " + want}
	}
	return b.s.send(ctx, http.MethodPost, "/UserGroups/"+strconv.FormatInt(g.ID, 10)+"/SmartRules/"+url.PathEscape(s.ID)+"/Roles",
		[]map[string]int64{{"RoleID": id}})
}

func (b *beyondtrust) RemoveMember(ctx context.Context, s Safe, name string) error {
	g, err := b.group(ctx, name)
	if err != nil {
		var nf *NotFoundError
		if asNotFound(err, &nf) {
			return nil
		}
		return err
	}
	return b.s.send(ctx, http.MethodDelete, "/UserGroups/"+strconv.FormatInt(g.ID, 10)+"/SmartRules/"+url.PathEscape(s.ID)+"/Roles", nil)
}
