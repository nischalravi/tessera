package salesforce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Target is the provisioning target of an org (target.Connector). What each operation does:
//
//	create_account      creates the User (a profile is required), or does nothing when the username exists
//	update_account      patches the attributes in userAttrs
//	disable_account     freezes the login (UserLogin.IsFrozen) and deactivates the user (IsActive=false)
//	delete_account      the same: Salesforce cannot delete a user, so a deleted account stays deactivated and frozen
//	add_entitlement     assigns a permission set (id 0PS...) or permission set group (0PG...)
//	remove_entitlement  removes that assignment
//
// Profiles and roles are not entitlements here: they are set on create or by update_account
// (ProfileId, UserRoleId). Every operation reads first, so a repeated request converges.
type Target struct {
	C *Client
	// DefaultProfileID is the profile of a created user whose request names none.
	DefaultProfileID string
}

// userAttrs are the User fields update_account and create_account may set (the request's attribute path).
var userAttrs = map[string]bool{"FirstName": true, "LastName": true, "Email": true, "Title": true, "Department": true, "Phone": true,
	"EmployeeNumber": true, "TimeZoneSidKey": true, "LocaleSidKey": true, "LanguageLocaleKey": true, "ProfileId": true, "UserRoleId": true}

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

func quote(s string) (string, error) {
	if !soqlText.MatchString(s) {
		return "", target.Permanent("invalid value in a query")
	}
	return "'" + s + "'", nil
}

// userID resolves the request's account to a User id: its external id, else a lookup by username.
// "" means the org has no such user.
func (t *Target) userID(ctx context.Context, a target.Account) (string, error) {
	if idRE.MatchString(a.ExternalID) {
		rs, err := t.C.rows(ctx, "SELECT Id FROM User WHERE Id = '"+a.ExternalID+"'")
		if err != nil {
			return "", wrap("read user", err)
		}
		if len(rs) > 0 {
			return a.ExternalID, nil
		}
		return "", nil
	}
	q, err := quote(a.Username)
	if err != nil {
		return "", err
	}
	rs, err := t.C.rows(ctx, "SELECT Id FROM User WHERE Username = "+q)
	if err != nil {
		return "", wrap("read user", err)
	}
	if len(rs) == 0 {
		return "", nil
	}
	return rs[0].str("Id"), nil
}

func (t *Target) loginState(ctx context.Context, user string) (loginID string, frozen bool, err error) {
	rs, err := t.C.rows(ctx, "SELECT Id, IsFrozen FROM UserLogin WHERE UserId = '"+user+"'")
	if err != nil {
		return "", false, wrap("read login", err)
	}
	if len(rs) == 0 {
		return "", false, nil
	}
	return rs[0].str("Id"), rs[0].flag("IsFrozen"), nil
}

func (t *Target) active(ctx context.Context, user string) (bool, error) {
	rs, err := t.C.rows(ctx, "SELECT Id, IsActive FROM User WHERE Id = '"+user+"'")
	if err != nil {
		return false, wrap("read user", err)
	}
	return len(rs) > 0 && rs[0].flag("IsActive"), nil
}

func attrNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func checkAttrs(m map[string]string) error {
	for _, k := range attrNames(m) {
		if !userAttrs[k] {
			return target.Permanent("attribute %q cannot be set on a Salesforce user", k)
		}
		if (k == "ProfileId" || k == "UserRoleId") && !idRE.MatchString(m[k]) {
			return target.Permanent("%s is not a Salesforce id", k)
		}
	}
	return nil
}

// entitlementField returns the PermissionSetAssignment field a group id belongs in.
func entitlementField(id string) (string, error) {
	if !idRE.MatchString(id) {
		return "", target.Permanent("the entitlement needs a permission set or permission set group id")
	}
	switch {
	case strings.HasPrefix(id, "0PS"):
		return "PermissionSetId", nil
	case strings.HasPrefix(id, "0PG"):
		return "PermissionSetGroupId", nil
	}
	return "", target.Permanent("only a permission set (0PS...) or permission set group (0PG...) can be assigned; set a profile or role with update_account")
}

// assignments returns the assignment rows that make a user hold the entitlement.
func (t *Target) assignments(ctx context.Context, user, field, id string) ([]record, error) {
	rs, err := t.C.rows(ctx, "SELECT Id, PermissionSetId, PermissionSetGroupId FROM PermissionSetAssignment WHERE AssigneeId = '"+user+"' AND "+field+" = '"+id+"'")
	return rs, wrap("read assignments", err)
}

func alias(first, last string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(first + last) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 8 {
		s = s[:8]
	}
	if s == "" {
		s = "user"
	}
	return s
}

func (t *Target) create(ctx context.Context, a target.Account) error {
	if err := checkAttrs(a.Attrs); err != nil {
		return err
	}
	if id, err := t.userID(ctx, target.Account{Username: a.Username}); err != nil || id != "" {
		return err
	}
	email := a.Email
	if email == "" {
		email = a.Attrs["Email"]
	}
	profile := a.Attrs["ProfileId"]
	if profile == "" {
		profile = t.DefaultProfileID
	}
	if email == "" || !idRE.MatchString(profile) {
		return target.Permanent("create user: an e-mail address and a profile (ProfileId or the target's default) are required")
	}
	first, last := a.Attrs["FirstName"], a.Attrs["LastName"]
	if last == "" {
		first, last, _ = strings.Cut(strings.TrimSpace(a.DisplayName), " ")
		if last == "" {
			first, last = "", first
		}
	}
	if last == "" {
		last = a.Username
	}
	body := map[string]any{"Username": a.Username, "Email": email, "LastName": last, "Alias": alias(first, last), "ProfileId": profile,
		"TimeZoneSidKey": "America/Los_Angeles", "LocaleSidKey": "en_US", "EmailEncodingKey": "UTF-8", "LanguageLocaleKey": "en_US"}
	if first != "" {
		body["FirstName"] = first
	}
	for _, k := range attrNames(a.Attrs) {
		if k != "FirstName" && k != "LastName" && k != "Email" && k != "ProfileId" {
			body[k] = a.Attrs[k]
		}
	}
	_, err := t.C.create(ctx, "User", body)
	return wrap("create user", err)
}

func (t *Target) update(ctx context.Context, a target.Account) error {
	if len(a.Attrs) == 0 {
		return target.Permanent("update user: no attributes to set")
	}
	if err := checkAttrs(a.Attrs); err != nil {
		return err
	}
	id, err := t.userID(ctx, a)
	if err != nil {
		return err
	}
	if id == "" {
		return target.Permanent("update user: %s has no user %s", System, a.Username)
	}
	same, err := t.sameAttrs(ctx, id, a.Attrs)
	if err != nil || same {
		return err
	}
	body := map[string]any{}
	for k, v := range a.Attrs {
		body[k] = v
	}
	return wrap("update user", t.C.update(ctx, "User", id, body))
}

func (t *Target) sameAttrs(ctx context.Context, id string, want map[string]string) (bool, error) {
	rs, err := t.C.rows(ctx, "SELECT "+strings.Join(attrNames(want), ", ")+" FROM User WHERE Id = '"+id+"'")
	if err != nil {
		return false, wrap("read user", err)
	}
	if len(rs) == 0 {
		return false, nil
	}
	for k, v := range want {
		if rs[0].str(k) != v {
			return false, nil
		}
	}
	return true, nil
}

func (t *Target) deactivate(ctx context.Context, a target.Account) error {
	id, err := t.userID(ctx, a)
	if err != nil || id == "" {
		return err // no such user: nothing to disable
	}
	login, frozen, err := t.loginState(ctx, id)
	if err != nil {
		return err
	}
	if login != "" && !frozen {
		if err := t.C.update(ctx, "UserLogin", login, map[string]any{"IsFrozen": true}); err != nil {
			return wrap("freeze user", err)
		}
	}
	on, err := t.active(ctx, id)
	if err != nil {
		return err
	}
	if on {
		return wrap("deactivate user", t.C.update(ctx, "User", id, map[string]any{"IsActive": false}))
	}
	return nil
}

func (t *Target) entitlement(ctx context.Context, r target.Request) error {
	field, err := entitlementField(r.Group.ExternalID)
	if err != nil {
		return err
	}
	user, err := t.userID(ctx, r.Account)
	if err != nil {
		return err
	}
	if user == "" {
		if r.Kind == target.AddEntitlement {
			return target.Permanent("add assignment: %s has no user %s", System, r.Account.Username)
		}
		return nil
	}
	rows, err := t.assignments(ctx, user, field, r.Group.ExternalID)
	if err != nil {
		return err
	}
	if r.Kind == target.AddEntitlement {
		if len(rows) > 0 {
			return nil
		}
		_, err := t.C.create(ctx, "PermissionSetAssignment", map[string]any{"AssigneeId": user, field: r.Group.ExternalID})
		return wrap("add assignment", err)
	}
	for _, row := range rows {
		if field == "PermissionSetGroupId" {
			// The group's own assignment is the row of its generated set; the component rows go with it.
			gen, err := t.C.rows(ctx, "SELECT Id FROM PermissionSet WHERE PermissionSetGroupId = '"+r.Group.ExternalID+"' AND Type = 'Group'")
			if err != nil {
				return wrap("read group", err)
			}
			if len(gen) == 0 || row.str("PermissionSetId") != gen[0].str("Id") {
				continue
			}
		}
		if err := t.C.remove(ctx, "PermissionSetAssignment", row.str("Id")); err != nil {
			return wrap("remove assignment", err)
		}
	}
	return nil
}

func checkKind(r target.Request) error {
	switch r.Kind {
	case target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount:
		if r.Account.Username == "" && !idRE.MatchString(r.Account.ExternalID) {
			return target.Permanent("the account needs a username or a Salesforce user id")
		}
	case target.AddEntitlement, target.RemoveEntitlement:
		if r.Account.Username == "" && !idRE.MatchString(r.Account.ExternalID) {
			return target.Permanent("the account needs a username or a Salesforce user id")
		}
	default:
		return target.Permanent("%s is not supported by the Salesforce target", r.Kind)
	}
	return nil
}

// Apply sends the change.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if err := checkKind(r); err != nil {
		return err
	}
	switch r.Kind {
	case target.CreateAccount:
		return t.create(ctx, r.Account)
	case target.UpdateAccount:
		return t.update(ctx, r.Account)
	case target.DisableAccount, target.DeleteAccount:
		return t.deactivate(ctx, r.Account)
	}
	return t.entitlement(ctx, r)
}

// Verify re-reads the org.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	if err := checkKind(r); err != nil {
		return target.Verdict{}, err
	}
	verdict := func(ok bool, expected, observed string) (target.Verdict, error) {
		return target.Verdict{OK: ok, Expected: expected, Observed: observed}, nil
	}
	id, err := t.userID(ctx, r.Account)
	if err != nil {
		return target.Verdict{}, err
	}
	switch r.Kind {
	case target.CreateAccount:
		return verdict(id != "", "the user exists", map[bool]string{true: "the user exists", false: "the user does not exist"}[id != ""])
	case target.UpdateAccount:
		if id == "" {
			return verdict(false, "the attributes are set", "the user does not exist")
		}
		same, err := t.sameAttrs(ctx, id, r.Account.Attrs)
		if err != nil {
			return target.Verdict{}, err
		}
		return verdict(same, "the attributes are set", map[bool]string{true: "the attributes are set", false: "the attributes differ"}[same])
	case target.DisableAccount, target.DeleteAccount:
		if id == "" {
			return verdict(true, "the user is inactive and frozen", "the user does not exist")
		}
		on, err := t.active(ctx, id)
		if err != nil {
			return target.Verdict{}, err
		}
		login, frozen, err := t.loginState(ctx, id)
		if err != nil {
			return target.Verdict{}, err
		}
		ok := !on && (login == "" || frozen)
		return verdict(ok, "the user is inactive and frozen", fmt.Sprintf("active=%t frozen=%t", on, frozen))
	}
	field, err := entitlementField(r.Group.ExternalID)
	if err != nil {
		return target.Verdict{}, err
	}
	have := false
	if id != "" {
		rows, err := t.assignments(ctx, id, field, r.Group.ExternalID)
		if err != nil {
			return target.Verdict{}, err
		}
		have = len(rows) > 0
	}
	obs := map[bool]string{true: "holds the assignment", false: "does not hold the assignment"}[have]
	if r.Kind == target.AddEntitlement {
		return verdict(have, "holds the assignment", obs)
	}
	return verdict(!have, "does not hold the assignment", obs)
}
