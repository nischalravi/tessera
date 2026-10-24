package servicenow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

const (
	tIncident  = "incident"
	tGroupRole = "sys_group_has_role"
)

// Target is the provisioning target of an instance (target.Connector). In direct mode each operation changes
// the instance, reading first, so a repeated request converges:
//
//	create_account      inserts the sys_user, or does nothing when the user_name exists
//	update_account      patches the attributes in userAttrs
//	disable_account     sets active=false; ServiceNow users are deactivated, not deleted
//	delete_account      the same (a deleted account stays deactivated, keeping its history)
//	add_entitlement     adds the user to a group (sys_user_grmember) or grants a role (sys_user_has_role)
//	remove_entitlement  removes that membership or that directly granted role
//
// In ticket mode no table but the incident table is written: Apply raises one incident per operation (found
// again by a correlation id derived from the operation's key, so a retry does not raise a second one), and
// Verify reports the change done once a person has resolved or closed the incident. The change itself is then
// seen by the next read of the instance, which is the proof; a closed ticket alone is a person's statement.
type Target struct {
	C *Client
	// Ticket selects ticket mode.
	Ticket bool
	// AssignmentGroup is the group (sys_id) an incident is assigned to; optional.
	AssignmentGroup string
}

// userAttrs are the sys_user columns update_account and create_account may set (the request's attribute path).
var userAttrs = map[string]bool{"first_name": true, "last_name": true, "email": true, "title": true, "phone": true, "mobile_phone": true, "employee_number": true}

const maxAttr = 256

var numberRE = regexp.MustCompile(`^[A-Z]{3}[0-9]{7,12}$`)

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

func permanent(err error) error {
	if err == nil {
		return nil
	}
	return target.Permanent("%s", err.Error())
}

func checkAttrs(m map[string]string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !userAttrs[k] {
			return target.Permanent("attribute %q cannot be set on a ServiceNow user", k)
		}
		if len(m[k]) > maxAttr || strings.ContainsAny(m[k], "\x00\r\n") {
			return target.Permanent("the value of %s is too long or has control characters", k)
		}
	}
	return nil
}

// userID resolves the request's account to a sys_user sys_id: its external id, else a lookup by user_name.
// "" means the instance has no such user.
func (t *Target) userID(ctx context.Context, a target.Account) (string, error) {
	query := ""
	if sysIDRE.MatchString(a.ExternalID) {
		query = "sys_id=" + a.ExternalID
	} else {
		v, err := Value(a.Username)
		if err != nil {
			return "", permanent(err)
		}
		query = "user_name=" + v
	}
	r, err := t.C.one(ctx, tUser, query, []string{"sys_id"})
	if err != nil {
		return "", wrap("read user", err)
	}
	if r == nil {
		return "", nil
	}
	id := r.str("sys_id")
	if !sysIDRE.MatchString(id) {
		return "", target.Permanent("the instance returned an invalid sys_id")
	}
	return id, nil
}

func (t *Target) active(ctx context.Context, id string) (bool, error) {
	r, err := t.C.one(ctx, tUser, "sys_id="+id, []string{"sys_id", "active"})
	if err != nil {
		return false, wrap("read user", err)
	}
	return r != nil && r.flag("active"), nil
}

func (t *Target) create(ctx context.Context, a target.Account) error {
	if err := checkAttrs(a.Attrs); err != nil {
		return err
	}
	if id, err := t.userID(ctx, target.Account{Username: a.Username}); err != nil || id != "" {
		return err
	}
	if len(a.Username) > maxAttr || strings.ContainsAny(a.Username, "\x00\r\n") {
		return target.Permanent("create user: the username is too long or has control characters")
	}
	email := a.Email
	if email == "" {
		email = a.Attrs["email"]
	}
	first, last := a.Attrs["first_name"], a.Attrs["last_name"]
	if last == "" {
		first, last, _ = strings.Cut(strings.TrimSpace(a.DisplayName), " ")
		if last == "" {
			first, last = "", first
		}
	}
	if last == "" {
		last = a.Username
	}
	body := map[string]any{"user_name": a.Username, "last_name": last, "active": true}
	if first != "" {
		body["first_name"] = first
	}
	if email != "" {
		body["email"] = email
	}
	for _, k := range sortedKeys(a.Attrs) {
		if _, set := body[k]; !set {
			body[k] = a.Attrs[k]
		}
	}
	_, err := t.C.create(ctx, tUser, body)
	return wrap("create user", err)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
		return target.Permanent("update user: %s has no user %s", System, clip(a.Username))
	}
	same, err := t.sameAttrs(ctx, id, a.Attrs)
	if err != nil || same {
		return err
	}
	body := map[string]any{}
	for k, v := range a.Attrs {
		body[k] = v
	}
	return wrap("update user", t.C.update(ctx, tUser, id, body))
}

func clip(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func (t *Target) sameAttrs(ctx context.Context, id string, want map[string]string) (bool, error) {
	if err := checkAttrs(want); err != nil { // the keys go into sysparm_fields
		return false, err
	}
	if len(want) == 0 {
		return false, target.Permanent("no attributes to compare")
	}
	r, err := t.C.one(ctx, tUser, "sys_id="+id, append([]string{"sys_id"}, sortedKeys(want)...))
	if err != nil {
		return false, wrap("read user", err)
	}
	if r == nil {
		return false, nil
	}
	for k, v := range want {
		if r.str(k) != v {
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
	on, err := t.active(ctx, id)
	if err != nil || !on {
		return err
	}
	return wrap("deactivate user", t.C.update(ctx, tUser, id, map[string]any{"active": false}))
}

// entitlement is a group or a role of the instance.
type entitlement struct {
	id    string
	table string // tMember or tHasRole: the table that holds the assignment
	field string // "group" or "role": the column of that table naming it
}

// resolve says whether the sys_id is a group or a role; neither is a permanent error.
func (t *Target) resolve(ctx context.Context, id string) (entitlement, error) {
	if !sysIDRE.MatchString(id) {
		return entitlement{}, target.Permanent("the entitlement needs the sys_id of a group or a role")
	}
	if r, err := t.C.one(ctx, tGroup, "sys_id="+id, []string{"sys_id"}); err != nil {
		return entitlement{}, wrap("read group", err)
	} else if r != nil {
		return entitlement{id, tMember, "group"}, nil
	}
	if r, err := t.C.one(ctx, tRole, "sys_id="+id, []string{"sys_id"}); err != nil {
		return entitlement{}, wrap("read role", err)
	} else if r != nil {
		return entitlement{id, tHasRole, "role"}, nil
	}
	return entitlement{}, target.Permanent("%s has no group or role with that sys_id", System)
}

// held returns the rows that make a user hold the entitlement. A role also counts when inherited through a
// group unless direct is set (what a removal acts on).
func (t *Target) held(ctx context.Context, user string, e entitlement, direct bool) ([]record, error) {
	q := "user=" + user + "^" + e.field + "=" + e.id
	if direct && e.table == tHasRole {
		q += "^inherited=false"
	}
	rs, err := t.C.rows(ctx, e.table, q, []string{"sys_id", "inherited"})
	return rs, wrap("read assignments", err)
}

func (t *Target) entitlement(ctx context.Context, r target.Request) error {
	e, err := t.resolve(ctx, r.Group.ExternalID)
	if err != nil {
		return err
	}
	user, err := t.userID(ctx, r.Account)
	if err != nil {
		return err
	}
	if user == "" {
		if r.Kind == target.AddEntitlement {
			return target.Permanent("add %s: %s has no user %s", e.field, System, clip(r.Account.Username))
		}
		return nil
	}
	rows, err := t.held(ctx, user, e, r.Kind == target.RemoveEntitlement)
	if err != nil {
		return err
	}
	if r.Kind == target.AddEntitlement {
		if len(rows) > 0 {
			return nil
		}
		_, err := t.C.create(ctx, e.table, map[string]any{"user": user, e.field: e.id})
		return wrap("add "+e.field, err)
	}
	for _, row := range rows {
		id := row.str("sys_id")
		if !sysIDRE.MatchString(id) {
			return target.Permanent("the instance returned an invalid sys_id")
		}
		if err := t.C.remove(ctx, e.table, id); err != nil {
			return wrap("remove "+e.field, err)
		}
	}
	return nil
}

func checkKind(r target.Request) error {
	switch r.Kind {
	case target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount, target.AddEntitlement, target.RemoveEntitlement:
	default:
		return target.Permanent("%s is not supported by the ServiceNow target", r.Kind)
	}
	if r.Account.Username == "" && !sysIDRE.MatchString(r.Account.ExternalID) {
		return target.Permanent("the account needs a username or a sys_id")
	}
	return nil
}

// Apply sends the change.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if err := checkKind(r); err != nil {
		return err
	}
	if t.Ticket {
		return t.raise(ctx, r)
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

// Verify re-reads the instance.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	if err := checkKind(r); err != nil {
		return target.Verdict{}, err
	}
	if t.Ticket {
		return t.ticketState(ctx, r)
	}
	return t.verifyDirect(ctx, r)
}

// verifyDirect reads the instance's own tables to see whether the change is there. Ticket mode uses it too: a
// resolved ticket is a person's statement, and this is the proof.
func (t *Target) verifyDirect(ctx context.Context, r target.Request) (target.Verdict, error) {
	verdict := func(ok bool, expected, observed string) (target.Verdict, error) {
		return target.Verdict{OK: ok, Expected: expected, Observed: observed}, nil
	}
	yes := func(b bool, a, c string) string {
		if b {
			return a
		}
		return c
	}
	id, err := t.userID(ctx, r.Account)
	if err != nil {
		return target.Verdict{}, err
	}
	switch r.Kind {
	case target.CreateAccount:
		return verdict(id != "", "the user exists", yes(id != "", "the user exists", "the user does not exist"))
	case target.UpdateAccount:
		if id == "" {
			return verdict(false, "the attributes are set", "the user does not exist")
		}
		same, err := t.sameAttrs(ctx, id, r.Account.Attrs)
		if err != nil {
			return target.Verdict{}, err
		}
		return verdict(same, "the attributes are set", yes(same, "the attributes are set", "the attributes differ"))
	case target.DisableAccount, target.DeleteAccount:
		if id == "" {
			return verdict(true, "the user is inactive", "the user does not exist")
		}
		on, err := t.active(ctx, id)
		if err != nil {
			return target.Verdict{}, err
		}
		return verdict(!on, "the user is inactive", yes(on, "the user is active", "the user is inactive"))
	}
	e, err := t.resolve(ctx, r.Group.ExternalID)
	if err != nil {
		return target.Verdict{}, err
	}
	have := false
	if id != "" {
		rows, err := t.held(ctx, id, e, false) // a role still held through a group is still held
		if err != nil {
			return target.Verdict{}, err
		}
		have = len(rows) > 0
		if have && r.Kind == target.RemoveEntitlement && e.table == tHasRole {
			direct := false
			for _, row := range rows {
				direct = direct || !row.flag("inherited")
			}
			obs := "still holds the role directly"
			if !direct {
				obs = "still holds the role " + t.via(ctx, id, e.id)
			}
			return verdict(false, "does not hold the role", obs)
		}
	}
	obs := yes(have, "holds the "+e.field, "does not hold the "+e.field)
	if r.Kind == target.AddEntitlement {
		return verdict(have, "holds the "+e.field, obs)
	}
	return verdict(!have, "does not hold the "+e.field, obs)
}

// via names the group through which a user holds a role, best effort: the user's groups that carry the role.
func (t *Target) via(ctx context.Context, user, role string) string {
	groups, err := t.C.rows(ctx, tMember, "user="+user, []string{"group"})
	if err != nil {
		return "through a group"
	}
	carried, err := t.C.rows(ctx, tGroupRole, "role="+role, []string{"group"})
	if err != nil {
		return "through a group"
	}
	has := map[string]bool{}
	for _, g := range carried {
		has[g.str("group")] = true
	}
	for _, g := range groups {
		id := g.str("group")
		if !has[id] || !sysIDRE.MatchString(id) {
			continue
		}
		if r, err := t.C.one(ctx, tGroup, "sys_id="+id, []string{"name"}); err == nil && r != nil && r.str("name") != "" {
			return "through the group " + clip(r.str("name"))
		}
		return "through a group"
	}
	return "through a group"
}

// correlation is the incident's correlation id for an operation: an HMAC of its key under the integration's own
// secret, so it is [a-z0-9-] whatever the key holds, the key is not copied into the instance, and nobody else
// can compute it: an incident someone else made cannot stand in for the one Tessera raised.
func (t *Target) correlation(key string) (string, error) {
	if key == "" {
		return "", target.Permanent("a ticket needs the operation's key")
	}
	m := hmac.New(sha256.New, []byte("tessera-ticket|"+t.C.cfg.Secret.Reveal()))
	m.Write([]byte(key))
	return "tessera-" + hex.EncodeToString(m.Sum(nil))[:40], nil
}

// raise creates the incident of an operation unless one with its correlation id exists.
func (t *Target) raise(ctx context.Context, r target.Request) error {
	corr, err := t.correlation(r.Key)
	if err != nil {
		return err
	}
	have, err := t.C.one(ctx, tIncident, "correlation_id="+corr, []string{"sys_id"})
	if err != nil {
		return wrap("read ticket", err)
	}
	if have != nil {
		return nil
	}
	what := strings.NewReplacer("_", " ").Replace(r.Kind)
	desc := fmt.Sprintf("Tessera asks for this access change to be made by hand.\nOperation: %s\nAccount: %s\n", what, clip(r.Account.Username))
	if r.Kind == target.AddEntitlement || r.Kind == target.RemoveEntitlement {
		g := r.Group.Name
		if g == "" {
			g = r.Group.ExternalID
		}
		desc += "Group or role: " + clip(g) + "\n"
	}
	if r.Kind == target.UpdateAccount {
		desc += "Attributes: " + strings.Join(sortedKeys(r.Account.Attrs), ", ") + "\n"
	}
	desc += "Resolve or close this ticket once it is done; Tessera then reads the system again to confirm."
	body := map[string]any{"short_description": "Tessera: " + what + " for " + clip(r.Account.Username), "description": desc,
		"correlation_id": corr, "correlation_display": "Tessera"}
	if t.AssignmentGroup != "" {
		body["assignment_group"] = t.AssignmentGroup
	}
	_, err = t.C.create(ctx, tIncident, body)
	return wrap("raise ticket", err)
}

// ticketState settles an operation from its incident. An open one keeps the operation waiting (the engine does
// not count it against its verification limit); a canceled one fails it; a resolved (6) or closed (7) one counts
// only when the instance's own tables show the change, since a person may resolve a ticket without doing it.
func (t *Target) ticketState(ctx context.Context, r target.Request) (target.Verdict, error) {
	corr, err := t.correlation(r.Key)
	if err != nil {
		return target.Verdict{}, err
	}
	row, err := t.C.one(ctx, tIncident, "correlation_id="+corr, []string{"sys_id", "number", "state"})
	if err != nil {
		return target.Verdict{}, wrap("read ticket", err)
	}
	const want = "the ticket is resolved or closed and the change is in place"
	if row == nil {
		return target.Verdict{OK: false, Expected: want, Observed: "there is no ticket"}, nil
	}
	label := "the ticket"
	if n := row.str("number"); numberRE.MatchString(n) {
		label = "ticket " + n
	}
	switch row.str("state") {
	case "8":
		return target.Verdict{}, target.Permanent("%s was canceled", label)
	case "6", "7":
		v, err := t.verifyDirect(ctx, r)
		if err != nil {
			return target.Verdict{}, err
		}
		if !v.OK {
			return target.Verdict{OK: false, Expected: want, Observed: label + " resolved but change not observed (" + v.Observed + ")"}, nil
		}
		return target.Verdict{OK: true, Expected: want, Observed: label + " resolved and the change is observed"}, nil
	}
	return target.Verdict{OK: false, Waiting: true, Expected: want, Observed: label + " is open"}, nil
}
