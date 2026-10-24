package sqldb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Target is the provisioning target of a database (target.Connector).
//
// Native mode creates, locks, unlocks and drops logins and grants and revokes
// roles with the fixed statements of statements(). A created login gets a
// random credential nobody learns (it authenticates through the database's
// external authentication, or an administrator sets a password); update_account
// with attrs {"status": "active"|"locked"} unlocks or locks it, and
// disable_account locks it. Entitlements are roles (SQL Server ids are
// "server:<role>" or "db:<role>", as Discover emits them).
//
// App mode runs the admin's INSERT, UPDATE and DELETE templates with bound
// placeholders. Both modes read first and change nothing that is already as
// asked, so a repeated request converges; each call opens its own connection
// and closes it.
type Target struct {
	cfg  Config
	pw   connsync.Secret
	rt   connsync.Runtime
	open func(readOnly bool) (*sql.DB, error) // replaced in tests
}

// NewTarget validates cfg and returns the target. It does not connect.
func NewTarget(cfg Config, pw connsync.Secret, rt connsync.Runtime) (*Target, error) {
	if err := cfg.Validate(rt); err != nil {
		return nil, fmt.Errorf("sqldb: %w", err)
	}
	if pw.Empty() {
		return nil, errors.New("sqldb: a password is required")
	}
	return &Target{cfg: cfg, pw: pw, rt: rt, open: func(ro bool) (*sql.DB, error) { return Open(cfg, pw, rt, ro) }}, nil
}

func (t *Target) eq(a, b string) bool {
	if t.cfg.Engine == SQLServer || t.cfg.Engine == Oracle {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func (t *Target) fail(op string, err error) error {
	if err == nil {
		return nil
	}
	var te *target.Error
	if errors.As(err, &te) {
		return err
	}
	return target.Transport(op, scrub(err, t.pw))
}

type state struct {
	accounts map[string]string // external id -> status
	names    map[string]string // external id -> username
	edges    map[[2]string]bool
}

// read takes a snapshot of accounts and memberships through the connector's own readers.
func (t *Target) read(ctx context.Context, db *sql.DB) (*state, error) {
	c := &Connector{cfg: t.cfg, pw: t.pw, rt: t.rt}
	var res *connectors.DiscoveryResult
	var err error
	if t.cfg.Mode == ModeApp {
		res, err = c.discoverApp(ctx, db)
	} else {
		res, err = c.discoverNative(ctx, db)
	}
	if err != nil {
		return nil, err
	}
	if res.Partial != "" {
		return nil, target.Permanent("the database has more rows than the read cap allows, so the account cannot be checked: %s", res.Partial)
	}
	st := &state{accounts: map[string]string{}, names: map[string]string{}, edges: map[[2]string]bool{}}
	for _, a := range res.Accounts {
		st.accounts[a.ExternalID], st.names[a.ExternalID] = a.Status, a.Username
	}
	for _, e := range res.Edges {
		if e.Src.Kind == "account" && e.Dst.Kind == "group" {
			st.edges[[2]string{e.Src.ExternalID, e.Dst.ExternalID}] = true
		}
	}
	return st, nil
}

func (s *state) find(t *Target, a target.Account) (id, status string, ok bool) {
	for k, v := range s.accounts {
		if (a.ExternalID != "" && t.eq(k, a.ExternalID)) || (a.Username != "" && (t.eq(k, a.Username) || t.eq(s.names[k], a.Username))) {
			return k, v, true
		}
	}
	return "", "", false
}

func (s *state) member(t *Target, acct, ent string) bool {
	for k := range s.edges {
		if t.eq(k[0], acct) && t.eq(k[1], ent) {
			return true
		}
	}
	return false
}

func entitlement(g target.Group) string {
	if g.ExternalID != "" {
		return g.ExternalID
	}
	return g.Name
}

func accountName(a target.Account) string { return orDefault(a.Username, a.ExternalID) }

func checkRequest(r target.Request) error {
	if r.Account.Username == "" && r.Account.ExternalID == "" {
		return target.Permanent("the account needs a username")
	}
	switch r.Kind {
	case target.CreateAccount, target.UpdateAccount, target.DisableAccount, target.DeleteAccount:
	case target.AddEntitlement, target.RemoveEntitlement:
		if entitlement(r.Group) == "" {
			return target.Permanent("the entitlement needs a role name")
		}
	default:
		return target.Permanent("%s is not supported by a database target", r.Kind)
	}
	return nil
}

// wantStatus is the status update_account asks for: "", "active" or "locked".
func (t *Target) wantStatus(r target.Request) (string, error) {
	if r.Kind != target.UpdateAccount || t.cfg.Mode == ModeApp {
		return "", nil
	}
	switch v := r.Account.Attrs["status"]; v {
	case "active", "locked":
		return v, nil
	case "":
		return "", target.Permanent("update_account on a database account supports attrs.status active or locked only")
	default:
		return "", target.Permanent("attrs.status must be active or locked")
	}
}

// Apply sends the change.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if err := checkRequest(r); err != nil {
		return err
	}
	want, err := t.wantStatus(r)
	if err != nil {
		return err
	}
	db, err := t.open(false)
	if err != nil {
		return t.fail("connect", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, t.cfg.timeout())
	defer cancel()
	st, err := t.read(ctx, db)
	if err != nil {
		return t.fail("read", err)
	}
	id, status, exists := st.find(t, r.Account)
	if t.cfg.Mode == ModeApp {
		return t.fail("write", t.applyApp(ctx, db, r, st, id, exists, want))
	}
	name := id
	if !exists {
		name = accountName(r.Account)
	}
	// Defense in depth before any DDL is built: names must match a strict allow-list, in addition
	// to the engine's quoting (DDL cannot bind identifiers).
	if !safeName.MatchString(name) {
		return target.Permanent("the account name %q is not allowed: use letters, digits and _ . @ $ # %% : -, at most 128 characters, starting with a letter, digit or _", shorten(name))
	}
	if ent := entitlement(r.Group); (r.Kind == target.AddEntitlement || r.Kind == target.RemoveEntitlement) && !safeName.MatchString(ent) {
		return target.Permanent("the role name %q is not allowed: use letters, digits and _ . @ $ # %% : -, at most 128 characters, starting with a letter, digit or _", shorten(ent))
	}
	var stmts []string
	switch r.Kind {
	case target.CreateAccount:
		if !exists {
			stmts, err = statements(t.cfg.Engine, opCreate, name, "")
		}
	case target.UpdateAccount, target.DisableAccount:
		to := "locked"
		if r.Kind == target.UpdateAccount {
			to = want
		}
		switch {
		case !exists:
			return target.Permanent("%s: the database has no account %s", r.Kind, name)
		case to == "locked" && status != "disabled":
			stmts, err = statements(t.cfg.Engine, opLock, name, "")
		case to == "active" && status == "disabled":
			stmts, err = statements(t.cfg.Engine, opUnlock, name, "")
		}
	case target.DeleteAccount:
		if exists {
			stmts, err = statements(t.cfg.Engine, opDrop, name, "")
		}
	case target.AddEntitlement, target.RemoveEntitlement:
		ent := entitlement(r.Group)
		has := exists && st.member(t, id, ent)
		switch {
		case r.Kind == target.AddEntitlement && !exists:
			return target.Permanent("add entitlement: the database has no account %s", name)
		case r.Kind == target.AddEntitlement && !has:
			stmts, err = statements(t.cfg.Engine, opGrant, name, ent)
		case r.Kind == target.RemoveEntitlement && has:
			stmts, err = statements(t.cfg.Engine, opRevoke, name, ent)
		}
	}
	if err != nil { // a name that cannot be quoted: no retry fixes it
		return target.Permanent("%v", err)
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil { // #nosec G202 -- fixed statements with quoted identifiers, see statements()
			return t.fail(r.Kind, err)
		}
	}
	return nil
}

// safeName is the allow-list for an account or role name that reaches DDL: ASCII letters, digits and
// _ . @ $ # % : - (MySQL user@host, SQL Server server:/db: ids). Quotes, semicolons, backslashes,
// whitespace, control and non-ASCII characters are refused, so a Windows DOMAIN\user login or a
// name with spaces cannot be provisioned here.
var safeName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@$#%:-]{0,127}$`)

func shorten(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

var attrKeyRE = regexp.MustCompile(`[^a-z0-9_]`)

func appValues(r target.Request, id string) map[string]string {
	v := map[string]string{
		"username": r.Account.Username, "external_id": orDefault(r.Account.ExternalID, id), "email": r.Account.Email,
		"display_name": r.Account.DisplayName, "entitlement": entitlement(r.Group), "entitlement_name": r.Group.Name,
	}
	if v["username"] == "" {
		v["username"] = r.Account.ExternalID
	}
	for k, val := range r.Account.Attrs {
		v["attr_"+attrKeyRE.ReplaceAllString(strings.ToLower(k), "_")] = val
	}
	return v
}

func (a *App) templateFor(kind string) string {
	switch kind {
	case target.CreateAccount:
		return a.CreateAccount
	case target.UpdateAccount:
		return a.UpdateAccount
	case target.DisableAccount:
		return a.DisableAccount
	case target.DeleteAccount:
		return a.DeleteAccount
	case target.AddEntitlement:
		return a.AddEntitlement
	case target.RemoveEntitlement:
		return a.RemoveEntitlement
	}
	return ""
}

func (t *Target) applyApp(ctx context.Context, db *sql.DB, r target.Request, st *state, id string, exists bool, _ string) error {
	text := t.cfg.App.templateFor(r.Kind)
	if text == "" {
		return target.Permanent("%s is not configured for this database connection", r.Kind)
	}
	switch {
	case r.Kind == target.CreateAccount && exists, r.Kind == target.DeleteAccount && !exists:
		return nil
	case r.Kind != target.CreateAccount && !exists:
		return target.Permanent("%s: the application has no account %s", r.Kind, orDefault(r.Account.Username, r.Account.ExternalID))
	}
	if t.cfg.App.EntitlementsQuery != "" {
		has := st.member(t, id, entitlement(r.Group))
		if (r.Kind == target.AddEntitlement && has) || (r.Kind == target.RemoveEntitlement && !has) {
			return nil
		}
	}
	tpl, err := ParseTemplate(text, classWrite, t.cfg.Engine)
	if err != nil {
		return target.Permanent("%s: %v", r.Kind, err)
	}
	q, args := tpl.Bind(t.cfg.Engine, appValues(r, id))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// Verify re-reads the database and reports whether the change is visible.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	if err := checkRequest(r); err != nil {
		return target.Verdict{}, err
	}
	want, err := t.wantStatus(r)
	if err != nil {
		return target.Verdict{}, err
	}
	db, err := t.open(true)
	if err != nil {
		return target.Verdict{}, t.fail("connect", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, t.cfg.timeout())
	defer cancel()
	st, err := t.read(ctx, db)
	if err != nil {
		return target.Verdict{}, t.fail("read", err)
	}
	id, status, exists := st.find(t, r.Account)
	v := func(ok bool, exp, obs string) (target.Verdict, error) {
		return target.Verdict{OK: ok, Expected: exp, Observed: obs}, nil
	}
	obsAcct := "no such account"
	if exists {
		obsAcct = "account is " + map[bool]string{true: "locked", false: "active"}[status == "disabled"]
	}
	switch r.Kind {
	case target.CreateAccount:
		return v(exists, "account exists", obsAcct)
	case target.DeleteAccount:
		return v(!exists, "no such account", obsAcct)
	case target.DisableAccount:
		return v(exists && status == "disabled", "account is locked", obsAcct)
	case target.UpdateAccount:
		if t.cfg.Mode == ModeApp {
			return v(exists, "account exists", obsAcct)
		}
		return v(exists && (status == "disabled") == (want == "locked"), "account is "+want, obsAcct)
	}
	has := exists && st.member(t, id, entitlement(r.Group))
	obs := map[bool]string{true: "holds the role", false: "does not hold the role"}[has]
	if r.Kind == target.AddEntitlement {
		return v(has, "holds the role", obs)
	}
	return v(!has, "does not hold the role", obs)
}
