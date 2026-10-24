package sqldb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Connector is the read connector (connectors.Connector) of one database.
type Connector struct {
	cfg  Config
	pw   connsync.Secret
	rt   connsync.Runtime
	open func(readOnly bool) (*sql.DB, error) // replaced in tests
}

// NewConnector validates cfg and returns the connector. Nothing connects until
// Discover.
func NewConnector(cfg Config, pw connsync.Secret, rt connsync.Runtime) (*Connector, error) {
	if err := cfg.Validate(rt); err != nil {
		return nil, fmt.Errorf("sqldb: %w", err)
	}
	if pw.Empty() {
		return nil, errors.New("sqldb: a password is required")
	}
	return &Connector{cfg: cfg, pw: pw, rt: rt, open: func(ro bool) (*sql.DB, error) { return Open(cfg, pw, rt, ro) }}, nil
}

func (c *Connector) System() string      { return c.cfg.SystemName() }
func (c *Connector) DisplayName() string { return c.cfg.DisplayName() }
func (c *Connector) TypeName() string    { return "SQLConnector" }

// StreamEvents: a database reports no usage here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// scrub removes the password from an error before it leaves the package.
func scrub(err error, pw connsync.Secret) error {
	if err == nil || pw.Empty() {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), pw.Reveal(), "REDACTED"))
}

// Discover reads accounts and entitlements: from the catalogue in native
// mode, from the configured SELECTs in app mode. A read that stopped at the row
// cap is returned with Partial set, so the deletion guard holds removals.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	db, err := c.open(true)
	if err != nil {
		return nil, scrub(err, c.pw)
	}
	defer db.Close()
	var res *connectors.DiscoveryResult
	if c.cfg.Mode == ModeApp {
		res, err = c.discoverApp(ctx, db)
	} else {
		res, err = c.discoverNative(ctx, db)
	}
	return res, scrub(err, c.pw)
}

func (c *Connector) instance() connectors.ResourceRecord {
	name := c.cfg.DisplayName() + " " + c.cfg.Host
	if c.cfg.Database != "" {
		name += "/" + c.cfg.Database
	}
	return connectors.ResourceRecord{System: c.System(), ExternalID: "instance", Name: name, Kind: "database",
		Tags: []string{"database", c.cfg.Engine}}
}

func status(s string) string {
	switch strings.ToLower(s) {
	case "locked", "disabled", "inactive", "suspended", "terminated", "0", "false", "n":
		return "disabled"
	}
	return "active"
}

func rolePrefix(id string) string {
	for _, p := range []string{"server:", "db:"} {
		if strings.HasPrefix(id, p) {
			return p
		}
	}
	return ""
}

func (c *Connector) discoverNative(ctx context.Context, db *sql.DB) (*connectors.DiscoveryResult, error) {
	cat, err := readCatalog(ctx, db, c.cfg)
	if err != nil {
		return nil, err
	}
	sys := c.System()
	res := &connectors.DiscoveryResult{Partial: cat.Partial}
	inst := c.instance()
	res.Resources = []connectors.ResourceRecord{inst}
	acct := map[string]bool{}
	for _, a := range cat.Accounts {
		acct[a.Name] = true
	}
	role := map[string]bool{}
	for _, r := range cat.Roles {
		role[r] = true
	}
	// resolve names the account or role a grantee is: SQL Server grants a
	// server permission to a login or to a server role ("server:" id)
	resolve := func(name string) (key string, isAcct, ok bool) {
		switch {
		case acct[name]:
			return name, true, true
		case role[name]:
			return name, false, true
		case role["server:"+name]:
			return "server:" + name, false, true
		}
		return "", false, false
	}
	// privileged: a privileged privilege, or a privileged role, directly or through role nesting
	priv := map[string]bool{}
	for _, p := range cat.Privs {
		if k, _, ok := resolve(p[0]); ok && privilegedPriv(p[1]) {
			priv[k] = true
		}
	}
	for id := range role {
		if privilegedRoles[strings.ToUpper(id)] {
			priv[id] = true
		}
	}
	// member -> roles it is in (member key: account name, or role id)
	memberOf := map[string][]string{}
	for _, m := range cat.Members {
		key := m[0]
		if !acct[key] {
			key = rolePrefix(m[1]) + m[0]
		}
		memberOf[key] = append(memberOf[key], m[1])
	}
	var reach func(key string, seen map[string]bool) bool
	reach = func(key string, seen map[string]bool) bool {
		if priv[key] {
			return true
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		for _, r := range memberOf[key] {
			if reach(r, seen) {
				return true
			}
		}
		return false
	}
	for _, r := range cat.Roles {
		name := strings.TrimPrefix(strings.TrimPrefix(r, "server:"), "db:")
		desc := c.cfg.DisplayName() + " role"
		res.Groups = append(res.Groups, connectors.GroupRecord{System: sys, ExternalID: r, Name: name, Kind: "db_role",
			Privileged: reach(r, map[string]bool{}), Requestable: true, Description: &desc})
	}
	for _, a := range cat.Accounts {
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: sys, ExternalID: a.Name, Username: a.Name, Kind: "user",
			Status: status(a.Status)})
	}
	for _, m := range cat.Members {
		if !role[m[1]] {
			continue
		}
		dst := connectors.Ref{Kind: "group", System: sys, ExternalID: m[1]}
		switch rid := rolePrefix(m[1]) + m[0]; {
		case acct[m[0]]:
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: sys, ExternalID: m[0]}, Dst: dst, Relation: "member_of"})
		case role[rid]:
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "group", System: sys, ExternalID: rid}, Dst: dst, Relation: "member_of"})
		}
	}
	known := map[string]bool{}
	for _, p := range cat.Privs {
		k, isAcct, ok := resolve(p[0])
		if !ok {
			continue
		}
		src, rel := connectors.Ref{Kind: "group", System: sys, ExternalID: k}, "grants"
		if isAcct {
			src, rel = connectors.Ref{Kind: "account", System: sys, ExternalID: k}, "direct_grant"
		}
		pid := strings.ToUpper(p[1])
		if !known[pid] {
			known[pid] = true
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: sys, ExternalID: pid, Action: pid,
				ResourceExternalID: inst.ExternalID, Privileged: privilegedPriv(pid)})
		}
		res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: connectors.Ref{Kind: "perm", System: sys, ExternalID: pid}, Relation: rel})
	}
	return res, nil
}

// discoverApp runs the admin's two SELECTs. Columns are found by name, so the
// SELECT may list them in any order and add others (ignored).
func (c *Connector) discoverApp(ctx context.Context, db *sql.DB) (*connectors.DiscoveryResult, error) {
	app := c.cfg.App
	sys := c.System()
	aq, err := ParseTemplate(app.AccountsQuery, classSelect, c.cfg.Engine)
	if err != nil {
		return nil, fmt.Errorf("accounts_query: %w", err)
	}
	text, _ := aq.Bind(c.cfg.Engine, nil)
	rs, err := query(ctx, db, c.cfg.Engine, c.cfg.timeout(), c.cfg.maxRows(), text)
	if err != nil {
		return nil, fmt.Errorf("accounts_query: %w", err)
	}
	res := &connectors.DiscoveryResult{}
	if rs.Truncated {
		res.Partial = fmt.Sprintf("accounts_query: more than %d rows, the read stopped at the cap", c.cfg.maxRows())
	}
	idc, unc, emc, stc := rs.col("id"), rs.col("username"), rs.col("email"), rs.col("status")
	if idc < 0 {
		return nil, errors.New("accounts_query must return a column named id")
	}
	get := func(row []string, i int) string {
		if i < 0 {
			return ""
		}
		return row[i]
	}
	byKey := map[string]string{} // id and username -> account external id
	for _, row := range rs.Rows {
		id := row[idc]
		if id == "" {
			continue
		}
		user := get(row, unc)
		if user == "" {
			user = id
		}
		a := connectors.AccountRecord{System: sys, ExternalID: id, Username: user, Kind: "user", Status: "active"}
		if stc >= 0 {
			a.Status = status(row[stc])
		}
		if em := get(row, emc); em != "" {
			a.Identity = &connectors.IdentityRef{Email: strings.ToLower(em)}
		}
		res.Accounts = append(res.Accounts, a)
		byKey[id], byKey[user] = id, id
	}
	if app.EntitlementsQuery == "" {
		res.Resources = []connectors.ResourceRecord{c.instance()}
		return res, nil
	}
	eq, err := ParseTemplate(app.EntitlementsQuery, classSelect, c.cfg.Engine)
	if err != nil {
		return nil, fmt.Errorf("entitlements_query: %w", err)
	}
	text, _ = eq.Bind(c.cfg.Engine, nil)
	es, err := query(ctx, db, c.cfg.Engine, c.cfg.timeout(), c.cfg.maxRows(), text)
	if err != nil {
		return nil, fmt.Errorf("entitlements_query: %w", err)
	}
	if es.Truncated && res.Partial == "" {
		res.Partial = fmt.Sprintf("entitlements_query: more than %d rows, the read stopped at the cap", c.cfg.maxRows())
	}
	ac, ec, dc := es.col("account"), es.col("entitlement"), es.col("description")
	if ac < 0 || ec < 0 {
		return nil, errors.New("entitlements_query must return columns named account and entitlement")
	}
	seen := map[string]bool{}
	edge := map[[2]string]bool{}
	for _, row := range es.Rows {
		ent := row[ec]
		id, ok := byKey[row[ac]]
		if ent == "" || !ok {
			continue
		}
		if !seen[ent] {
			seen[ent] = true
			g := connectors.GroupRecord{System: sys, ExternalID: ent, Name: ent, Kind: "app_entitlement", Requestable: true}
			if d := get(row, dc); d != "" {
				g.Description = &d
			}
			res.Groups = append(res.Groups, g)
		}
		if k := [2]string{id, ent}; !edge[k] {
			edge[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: sys, ExternalID: id},
				Dst: connectors.Ref{Kind: "group", System: sys, ExternalID: ent}, Relation: "member_of"})
		}
	}
	res.Resources = []connectors.ResourceRecord{c.instance()}
	return res, nil
}

// FromEnv builds the connector from TESSERA_SQL_*:
//
//	TESSERA_SQL_ENGINE    postgres | mysql | sqlserver | oracle
//	TESSERA_SQL_HOST      database host name or IP
//	TESSERA_SQL_PORT      optional, the engine's default otherwise
//	TESSERA_SQL_DATABASE  database (Oracle: service name)
//	TESSERA_SQL_USERNAME  a read-only database user
//	TESSERA_SQL_PASSWORD  reference to its password: file:/abs/path or env:NAME
//	TESSERA_SQL_MODE      native (default) or app
//	TESSERA_SQL_TLS       verify-full (default) or disable (dev only)
//	TESSERA_SQL_CA_FILE   optional path of a PEM CA bundle
//	TESSERA_SQL_APP       path of the JSON file with the app statements (mode app)
//	TESSERA_SQL_SYSTEM    system name, default sql
func FromEnv(getenv func(string) string, readFile func(string) ([]byte, error), rt connsync.Runtime) (connectors.Connector, error) {
	cfg := Config{System: getenv("TESSERA_SQL_SYSTEM"), Engine: getenv("TESSERA_SQL_ENGINE"), Host: getenv("TESSERA_SQL_HOST"),
		Database: getenv("TESSERA_SQL_DATABASE"), Username: getenv("TESSERA_SQL_USERNAME"), TLS: getenv("TESSERA_SQL_TLS"),
		Mode: orDefault(getenv("TESSERA_SQL_MODE"), ModeNative)}
	if p := getenv("TESSERA_SQL_PORT"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &cfg.Port); err != nil {
			return nil, errors.New("TESSERA_SQL_PORT: not a number")
		}
	}
	if f := getenv("TESSERA_SQL_CA_FILE"); f != "" {
		b, err := readFile(f)
		if err != nil {
			return nil, errors.New("TESSERA_SQL_CA_FILE: cannot read the file")
		}
		cfg.CABundle = string(b)
	}
	if f := getenv("TESSERA_SQL_APP"); f != "" {
		b, err := readFile(f)
		if err != nil {
			return nil, errors.New("TESSERA_SQL_APP: cannot read the file")
		}
		app, err := DecodeApp(b)
		if err != nil {
			return nil, fmt.Errorf("TESSERA_SQL_APP: %w", err)
		}
		cfg.App = app
	}
	pw, err := connsync.ResolveSecret(getenv("TESSERA_SQL_PASSWORD"), getenv)
	if err != nil {
		return nil, errors.New("TESSERA_SQL_PASSWORD: " + err.Error())
	}
	return NewConnector(cfg, pw, rt)
}
