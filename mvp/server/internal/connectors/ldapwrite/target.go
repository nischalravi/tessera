package ldapwrite

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// Virtual attributes of update_account (the target contract has no enable or password operation).
const (
	AttrEnabled  = "tessera.enabled"  // "true" enables, "false" disables
	AttrPassword = "tessera.password" // "reset" sets a new random password (AllowPasswordReset)
)

const uacDisabled = 2 // ACCOUNTDISABLE

// Target is the provisioning target of an LDAP directory or Active Directory (target.Connector).
//
//	create_account      a free candidate name, then add; AD: add disabled, set the password, then enable
//	update_account      allow-listed attributes, tessera.enabled, tessera.password
//	disable_account     per DisableMode, then optionally move to the disabled OU
//	delete_account      delete the entry (the engine's deletion guard holds it for approval first)
//	add/remove_entitlement  group membership
//
// Every change reads first and sends nothing that is already so, and each call opens its own
// connection and closes it.
type Target struct {
	cfg    Config
	pw     connsync.Secret
	dialer *safedial.Dialer
	rand   io.Reader
}

// NewTarget validates cfg and returns the target. It does not connect. d is the safedial dialer
// built from the running configuration and the connection's CA.
func NewTarget(cfg Config, pw connsync.Secret, d *safedial.Dialer) (*Target, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if pw.Empty() {
		return nil, target.Permanent("the directory bind credential is missing")
	}
	return &Target{cfg: cfg, pw: pw, dialer: d, rand: rand.Reader}, nil
}

// SetRand replaces the random source of generated passwords (tests).
func (t *Target) SetRand(r io.Reader) { t.rand = r }

var accountAttrs = []string{"*", "userAccountControl", "pwdLastSet", "nsAccountLock", "pwdAccountLockedTime", "adminCount", "objectSid"}

func (t *Target) attrsToRead() []string {
	out := append([]string(nil), accountAttrs...)
	if t.cfg.DisableMode == DisableAttribute {
		out = append(out, t.cfg.DisableAttr)
	}
	return out
}

func (t *Target) vars(a target.Account) Vars { return Vars{User: UserVars(a)} }

func (t *Target) parsed(tpl string) *Template {
	p, _ := ParseTemplate(tpl) // validated by Config.Validate
	return p
}

// find locates the account by its match attribute. nil when there is none.
func (t *Target) find(c *conn, a target.Account) (*goldap.Entry, error) {
	val, err := t.parsed(t.cfg.UserAttrs[t.cfg.attrKey(t.cfg.MatchAttr)]).RenderValue(t.vars(a))
	if err != nil {
		return nil, err
	}
	f, err := EqFilter(t.cfg.MatchAttr, val)
	if err != nil {
		return nil, err
	}
	es, err := c.search(t.cfg.UserBase, goldap.ScopeWholeSubtree, f, t.attrsToRead(), 3)
	if err != nil {
		return nil, err
	}
	var in []*goldap.Entry
	for _, e := range es {
		if t.cfg.InScope(e.DN) {
			in = append(in, e)
		}
	}
	if len(in) > 1 {
		return nil, target.Permanent("more than one account matches this person")
	}
	if len(in) == 0 {
		return nil, nil
	}
	return in[0], nil
}

func (t *Target) disabled(e *goldap.Entry) bool {
	switch t.cfg.DisableMode {
	case DisableUAC:
		n, err := strconv.ParseInt(val(e, "userAccountControl"), 10, 64)
		return err == nil && n&uacDisabled != 0
	case DisablePPolicy:
		return val(e, "pwdAccountLockedTime") != ""
	case DisableAttribute:
		return strings.EqualFold(val(e, t.cfg.DisableAttr), t.cfg.DisableValue)
	}
	return strings.EqualFold(val(e, "nsAccountLock"), "true")
}

// stateChanges are the modifications that set the account's disabled state.
func (t *Target) stateChanges(e *goldap.Entry, disable bool) []change {
	switch t.cfg.DisableMode {
	case DisableUAC:
		n, err := strconv.ParseInt(val(e, "userAccountControl"), 10, 64)
		if err != nil {
			n = 512
		}
		if disable {
			n |= uacDisabled
		} else {
			n &^= uacDisabled
		}
		return []change{{"replace", "userAccountControl", []string{strconv.FormatInt(n, 10)}}}
	case DisablePPolicy:
		if disable {
			return []change{{"replace", "pwdAccountLockedTime", []string{ppolicyPermanentLock}}}
		}
		return []change{{"delete", "pwdAccountLockedTime", nil}}
	case DisableAttribute:
		if disable {
			return []change{{"replace", t.cfg.DisableAttr, []string{t.cfg.DisableValue}}}
		}
		return []change{{"delete", t.cfg.DisableAttr, nil}}
	}
	if disable {
		return []change{{"replace", "nsAccountLock", []string{"true"}}}
	}
	return []change{{"delete", "nsAccountLock", nil}}
}

// setState disables or enables the entry and moves it to the disabled or enabled OU when one is set.
func (t *Target) setState(c *conn, e *goldap.Entry, disable bool) error {
	if err := t.guardTier0(e); err != nil {
		return err
	}
	if t.disabled(e) != disable {
		if !t.cfg.InScope(e.DN) {
			return target.Permanent("the account is outside the write scope")
		}
		if err := c.modify(e.DN, t.stateChanges(e, disable)); err != nil {
			return err
		}
	}
	ou := t.cfg.EnabledOU
	if disable {
		ou = t.cfg.DisabledOU
	}
	if ou == "" || sameDN(parentDN(e.DN), ou) {
		return nil
	}
	rdn, ok := firstRDN(e.DN)
	if !ok || !t.cfg.InScope(e.DN) || !(t.cfg.InScope(ou) || t.cfg.writeRoot(ou)) {
		return target.Permanent("the account cannot be moved outside the write scope")
	}
	return c.move(e.DN, rdn, ou)
}

func (t *Target) renderAttrs(v Vars) (map[string][]string, []string, error) {
	out := map[string][]string{}
	order := []string{"objectClass"}
	out["objectClass"] = append([]string(nil), t.cfg.UserObjectClasses...)
	for _, k := range t.cfg.sortedAttrs() {
		val, err := t.parsed(t.cfg.UserAttrs[k]).RenderValue(v)
		if err != nil {
			return nil, nil, err
		}
		out[k] = []string{val}
		order = append(order, k)
	}
	return out, order, nil
}

// candidates are the names tried for ${account}, in order.
func (t *Target) candidates(a target.Account) []string {
	var out []string
	for _, tpl := range t.cfg.AccountNames {
		if n, err := t.parsed(tpl).RenderValue(t.vars(a)); err == nil && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func (t *Target) password() (connsync.Secret, error) {
	pw, err := GeneratePassword(t.cfg.Password, t.rand)
	if err != nil {
		return connsync.Secret{}, target.Permanent("a password could not be generated")
	}
	return pw, nil
}

// passwordChanges sets pw on AD: unicodePwd (UTF-16, over the encrypted connection), and the
// account must change it at next sign-in.
func (t *Target) passwordChanges(pw connsync.Secret) []change {
	return []change{{"replace", "unicodePwd", []string{string(UnicodePwd(pw.Reveal()))}}, {"replace", "pwdLastSet", []string{"0"}}}
}

// setPassword sets pw on the entry. AD takes unicodePwd. An LDAP directory gets the Password Modify
// operation (RFC 3062) when it advertises it, so the server hashes the value; otherwise the password
// is written to userPassword, which a server stores as sent unless it hashes cleartext on write
// (OpenLDAP ppolicy_hash_cleartext, 389-DS passwordStorageScheme): see the README.
func (t *Target) setPassword(c *conn, dn string, pw connsync.Secret) error {
	switch {
	case t.cfg.Flavor == FlavorAD:
		return c.modify(dn, t.passwordChanges(pw))
	case c.supportsPasswordModify():
		return c.passwordModify(dn, pw.Reveal())
	}
	return c.modify(dn, []change{{"replace", "userPassword", []string{pw.Reveal()}}})
}

func (t *Target) create(c *conn, a target.Account) error {
	var last error = target.Permanent("no candidate account name is unique in the directory")
	for _, cand := range t.candidates(a) {
		v := t.vars(a)
		v.Account = cand
		dn, err := t.parsed(t.cfg.UserDNTemplate).RenderDN(v)
		if err != nil {
			last = err
			continue
		}
		if !t.cfg.InScope(dn) {
			return target.Permanent("the account name falls outside the write scope")
		}
		attrs, order, err := t.renderAttrs(v)
		if err != nil {
			last = err
			continue
		}
		free, mine, err := t.unique(c, dn, attrs)
		if err != nil {
			return err
		}
		if mine {
			return nil // already created: a repeat converges
		}
		if !free {
			continue
		}
		return t.createEntry(c, dn, attrs, order)
	}
	return last
}

// unique checks the candidate against the directory: it is free, already this person's, or taken.
func (t *Target) unique(c *conn, dn string, attrs map[string][]string) (free, mine bool, err error) {
	var terms []string
	for _, a := range t.cfg.UniqueAttrs {
		f, err := EqFilter(a, attrs[t.cfg.attrKey(a)][0])
		if err != nil {
			return false, false, err
		}
		terms = append(terms, f)
	}
	var found []*goldap.Entry
	if len(terms) > 0 {
		f := terms[0]
		if len(terms) > 1 {
			f = "(|" + strings.Join(terms, "") + ")"
		}
		es, err := c.search(t.cfg.UserBase, goldap.ScopeWholeSubtree, f, t.attrsToRead(), 10)
		if err != nil {
			return false, false, err
		}
		found = es
	}
	at, err := c.search(dn, goldap.ScopeBaseObject, "(objectClass=*)", t.attrsToRead(), 1)
	if err != nil {
		return false, false, err
	}
	found = append(found, at...)
	key := t.cfg.attrKey(t.cfg.MatchAttr)
	for _, e := range found {
		if strings.EqualFold(val(e, t.cfg.MatchAttr), attrs[key][0]) {
			return false, true, nil
		}
	}
	return len(found) == 0, false, nil
}

func (t *Target) createEntry(c *conn, dn string, attrs map[string][]string, order []string) error {
	ad := t.cfg.Flavor == FlavorAD
	var pw connsync.Secret
	if t.cfg.InitialPassword {
		var err error
		if pw, err = t.password(); err != nil {
			return err
		}
	}
	switch {
	case ad:
		// AD refuses an enabled account without a password that meets its policy, so the account
		// is added disabled (NORMAL_ACCOUNT | ACCOUNTDISABLE) and enabled last.
		attrs["userAccountControl"] = []string{"514"}
		order = append(order, "userAccountControl")
	}
	if err := c.add(dn, attrs, order); err != nil {
		return err
	}
	if !pw.Empty() {
		if err := t.setPassword(c, dn, pw); err != nil {
			return err
		}
	}
	e, err := t.readDN(c, dn)
	if err != nil || e == nil {
		return err
	}
	if ad && !t.cfg.CreateDisabled && !pw.Empty() {
		return t.setState(c, e, false)
	}
	if !ad && t.cfg.CreateDisabled {
		return t.setState(c, e, true)
	}
	return nil
}

func (t *Target) readDN(c *conn, dn string) (*goldap.Entry, error) {
	es, err := c.search(dn, goldap.ScopeBaseObject, "(objectClass=*)", t.attrsToRead(), 1)
	if err != nil || len(es) == 0 {
		return nil, err
	}
	return es[0], nil
}

func (t *Target) update(c *conn, a target.Account) error {
	e, err := t.find(c, a)
	if err != nil {
		return err
	}
	if e == nil {
		return target.Permanent("the account does not exist in the directory")
	}
	if !t.cfg.InScope(e.DN) {
		return target.Permanent("the account is outside the write scope")
	}
	if err := t.guardTier0(e); err != nil {
		return err
	}
	keys := make([]string, 0, len(a.Attrs))
	for k := range a.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var changes []change
	enable, setEnable := false, false
	reset := false
	for _, k := range keys {
		v := a.Attrs[k]
		switch strings.ToLower(k) {
		case AttrEnabled:
			if v != "true" && v != "false" {
				return target.Permanent("tessera.enabled is true or false")
			}
			enable, setEnable = v == "true", true
		case AttrPassword:
			if v != "reset" || !t.cfg.AllowPasswordReset {
				return target.Permanent("a password reset is not enabled for this target")
			}
			reset = true
		default:
			if !slices.ContainsFunc(t.cfg.UpdateAttrs, func(x string) bool { return strings.EqualFold(x, k) }) || isProtected(t.cfg.Flavor, k, false) {
				return target.Permanent("an attribute is not in the target's update allow-list")
			}
			if !cleanValue(v) {
				return errBadChar
			}
			cur := vals(e, k)
			switch {
			case v == "" && len(cur) > 0:
				changes = append(changes, change{"delete", k, nil})
			case v != "" && !(len(cur) == 1 && cur[0] == v):
				changes = append(changes, change{"replace", k, []string{v}})
			}
		}
	}
	if len(changes) > 0 {
		if err := c.modify(e.DN, changes); err != nil {
			return err
		}
	}
	if reset {
		pw, err := t.password()
		if err != nil {
			return err
		}
		if err := t.setPassword(c, e.DN, pw); err != nil {
			return err
		}
	}
	if setEnable {
		if len(changes) > 0 || reset { // the state may have moved with the entry's attributes
			if e, err = t.readDN(c, e.DN); err != nil || e == nil {
				return err
			}
		}
		return t.setState(c, e, !enable)
	}
	return nil
}

func (t *Target) setDisabled(c *conn, a target.Account, disable bool) error {
	e, err := t.find(c, a)
	if err != nil {
		return err
	}
	if e == nil {
		return target.Permanent("the account does not exist in the directory")
	}
	return t.setState(c, e, disable)
}

func (t *Target) remove(c *conn, a target.Account) error {
	e, err := t.find(c, a)
	if err != nil || e == nil {
		return err // already gone
	}
	if !t.cfg.InScope(e.DN) {
		return target.Permanent("the account is outside the write scope")
	}
	if err := t.guardTier0(e); err != nil {
		return err
	}
	return c.del(e.DN)
}

// group resolves the group an entitlement names: a DN from the external id, the DN template, or a
// search of the group base by cn. The DN must be inside the write scope.
func (t *Target) group(c *conn, g target.Group) (*goldap.Entry, error) {
	var dn string
	switch {
	case g.ExternalID != "" && strings.Contains(g.ExternalID, "=") && validDN(g.ExternalID):
		dn = g.ExternalID
	case g.Name != "" && t.cfg.GroupDNTemplate != "":
		var err error
		if dn, err = t.parsed(t.cfg.GroupDNTemplate).RenderDN(Vars{Group: map[string]string{"name": g.Name}}); err != nil {
			return nil, err
		}
	case g.Name != "" && t.cfg.GroupBase != "":
		if !cleanValue(g.Name) {
			return nil, errBadChar
		}
		f, err := EqFilter("cn", g.Name)
		if err != nil {
			return nil, err
		}
		es, err := c.search(t.cfg.GroupBase, goldap.ScopeWholeSubtree, f, []string{t.cfg.GroupMemberAttr, "adminCount", "objectSid"}, 2)
		if err != nil {
			return nil, err
		}
		if len(es) != 1 {
			return nil, target.Permanent("the group does not exist or its name is not unique")
		}
		dn = es[0].DN
	default:
		return nil, target.Permanent("the group cannot be located: the target has no group base or group template")
	}
	if !t.cfg.InScope(dn) {
		return nil, target.Permanent("the group is outside the write scope")
	}
	e, err := t.readGroup(c, dn)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, target.Permanent("the group does not exist")
	}
	return e, nil
}

func (t *Target) readGroup(c *conn, dn string) (*goldap.Entry, error) {
	es, err := c.search(dn, goldap.ScopeBaseObject, "(objectClass=*)", []string{t.cfg.GroupMemberAttr, "adminCount", "objectSid"}, 1)
	if err != nil || len(es) == 0 {
		return nil, err
	}
	return es[0], nil
}

// memberValue is what the group's member attribute holds for the account.
func (t *Target) memberValue(e *goldap.Entry) string {
	if t.cfg.GroupMemberAttr == "memberUid" {
		return val(e, t.cfg.MemberUIDAttr)
	}
	return e.DN
}

func (t *Target) isMember(g *goldap.Entry, val string) bool {
	for _, m := range vals(g, t.cfg.GroupMemberAttr) {
		if t.cfg.GroupMemberAttr == "memberUid" && strings.EqualFold(m, val) || t.cfg.GroupMemberAttr != "memberUid" && sameDN(m, val) {
			return true
		}
	}
	return false
}

func (t *Target) membership(c *conn, a target.Account, g target.Group, add bool) error {
	e, err := t.find(c, a)
	if err != nil {
		return err
	}
	if e == nil {
		if !add {
			return nil // nothing to remove from
		}
		return target.Permanent("the account does not exist in the directory")
	}
	grp, err := t.group(c, g)
	if err != nil {
		return err
	}
	if err := t.guardTier0(e); err != nil {
		return err
	}
	if err := t.guardTier0(grp); err != nil {
		return err
	}
	val := t.memberValue(e)
	if val == "" {
		return target.Permanent("the account has no value for the group's member attribute")
	}
	if t.isMember(grp, val) == add {
		return nil
	}
	op := "delete"
	if add {
		op = "add"
	}
	return c.modify(grp.DN, []change{{op, t.cfg.GroupMemberAttr, []string{val}}})
}

// Apply sends the change.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if r.Account.Username == "" {
		return target.Permanent("the request names no account")
	}
	c, err := open(ctx, t.dialer, &t.cfg, t.pw)
	if err != nil {
		return err
	}
	defer c.close()
	switch r.Kind {
	case target.CreateAccount:
		return t.create(c, r.Account)
	case target.UpdateAccount:
		return t.update(c, r.Account)
	case target.DisableAccount:
		return t.setDisabled(c, r.Account, true)
	case target.DeleteAccount:
		return t.remove(c, r.Account)
	case target.AddEntitlement:
		return t.membership(c, r.Account, r.Group, true)
	case target.RemoveEntitlement:
		return t.membership(c, r.Account, r.Group, false)
	}
	return target.Permanent("this target does not support the operation")
}

func verdict(ok bool, want, got string) (target.Verdict, error) {
	return target.Verdict{OK: ok, Expected: want, Observed: got}, nil
}

// Verify re-reads the directory. A password cannot be read back: after a reset the evidence is the
// account still existing (AD: pwdLastSet 0, the force-change marker) and the directory having
// accepted the change, which Apply already knows.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	c, err := open(ctx, t.dialer, &t.cfg, t.pw)
	if err != nil {
		return target.Verdict{}, err
	}
	defer c.close()
	e, err := t.find(c, r.Account)
	if err != nil {
		return target.Verdict{}, err
	}
	switch r.Kind {
	case target.DeleteAccount:
		return verdict(e == nil, "the account is gone", observed(e != nil, "the account still exists", "the account is gone"))
	case target.AddEntitlement, target.RemoveEntitlement:
		add := r.Kind == target.AddEntitlement
		if e == nil {
			return verdict(!add, "the account is a "+map[bool]string{true: "member", false: "non-member"}[add], "the account does not exist")
		}
		grp, err := t.group(c, r.Group)
		if err != nil {
			if te, ok := err.(*target.Error); ok && !te.Retryable && !add {
				return verdict(true, "the account is not a member", "the group does not exist")
			}
			return target.Verdict{}, err
		}
		in := t.isMember(grp, t.memberValue(e))
		return verdict(in == add, "membership "+map[bool]string{true: "present", false: "absent"}[add], "membership "+map[bool]string{true: "present", false: "absent"}[in])
	}
	if e == nil {
		return verdict(false, "the account exists", "the account does not exist")
	}
	switch r.Kind {
	case target.CreateAccount:
		return t.verifyCreate(e)
	case target.DisableAccount:
		return t.verifyState(e, true)
	case target.UpdateAccount:
		return t.verifyUpdate(e, r.Account)
	}
	return target.Verdict{}, target.Permanent("this target does not support the operation")
}

func observed(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func (t *Target) verifyCreate(e *goldap.Entry) (target.Verdict, error) {
	want := t.cfg.CreateDisabled
	if t.cfg.Flavor == FlavorAD && !t.cfg.InitialPassword {
		want = true // an AD account without a password stays disabled
	}
	return t.verifyState(e, want)
}

func (t *Target) verifyState(e *goldap.Entry, disabled bool) (target.Verdict, error) {
	name := map[bool]string{true: "the account is disabled", false: "the account is enabled"}
	ok := t.disabled(e) == disabled
	ou := t.cfg.EnabledOU
	if disabled {
		ou = t.cfg.DisabledOU
	}
	if ok && ou != "" && !sameDN(parentDN(e.DN), ou) {
		return verdict(false, name[disabled]+" in the configured OU", "the account is in another OU")
	}
	return verdict(ok, name[disabled], name[t.disabled(e)])
}

func (t *Target) verifyUpdate(e *goldap.Entry, a target.Account) (target.Verdict, error) {
	keys := make([]string, 0, len(a.Attrs))
	for k := range a.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := a.Attrs[k]
		switch strings.ToLower(k) {
		case AttrEnabled:
			if vd, err := t.verifyState(e, v == "false"); err != nil || !vd.OK {
				return vd, err
			}
		case AttrPassword:
			if t.cfg.Flavor == FlavorAD && val(e, "pwdLastSet") != "0" {
				return verdict(false, "the password is set and must be changed at next sign-in", "the password was not changed")
			}
		default:
			cur := vals(e, k)
			if v == "" && len(cur) > 0 || v != "" && !(len(cur) == 1 && strings.EqualFold(cur[0], v)) {
				return verdict(false, "attribute "+k+" is as requested", "attribute "+k+" differs")
			}
		}
	}
	return verdict(true, "the account is as requested", "the account is as requested")
}

// vals and val read an attribute by name, ignoring case: directories answer in their own spelling.
func vals(e *goldap.Entry, name string) []string { return e.GetEqualFoldAttributeValues(name) }

func val(e *goldap.Entry, name string) string {
	if v := vals(e, name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// privilegedRIDs are the well-known relative ids of privileged AD objects: Administrator, Domain
// Admins, Domain Controllers, Schema Admins, Enterprise Admins, Administrators, Account Operators,
// Server Operators and Print Operators.
var privilegedRIDs = map[uint32]bool{500: true, 512: true, 516: true, 518: true, 519: true, 544: true, 548: true, 549: true, 551: true}

// tier0 reports whether the entry is privileged: adminCount=1, or an objectSid that ends in a
// privileged RID (the last four bytes, little endian).
func tier0(e *goldap.Entry) bool {
	if val(e, "adminCount") == "1" {
		return true
	}
	sid := e.GetEqualFoldRawAttributeValue("objectSid")
	return len(sid) >= 8 && privilegedRIDs[binary.LittleEndian.Uint32(sid[len(sid)-4:])]
}

// guardTier0 refuses to change a privileged entry unless the target opted in (allow_tier0).
func (t *Target) guardTier0(e *goldap.Entry) error {
	if e != nil && !t.cfg.AllowTier0 && tier0(e) {
		return target.Permanent("the entry is privileged (adminCount or a well-known privileged group or account); this target is not allowed to change it")
	}
	return nil
}
