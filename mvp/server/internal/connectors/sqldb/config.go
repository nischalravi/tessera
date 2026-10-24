// Package sqldb is the generic database connector: PostgreSQL, MySQL, SQL
// Server and Oracle Database as an identity source (Discover) and as a
// provisioning target (Target). Issue #553.
//
// ARCHITECTURE EXCEPTION. Tessera's own data goes only through internal/store,
// and internal/archtest bans database/sql, drivers and Query/Exec calls
// everywhere else. This package talks to a customer's database, never to
// Tessera's store, so archtest exempts this one directory (and only for the
// database/sql, driver and Query/Exec rules; see sqlDBDir there). The package
// must not import internal/store (archtest enforces it), so customer-database
// code can never reach tenant data, and nothing else may import a SQL driver.
//
// Two modes:
//
//   - native: accounts, roles and grants are read from the engine's own
//     catalogue (pg_roles and pg_auth_members; mysql.user and role_edges;
//     sys.server_principals and the role-member views; DBA_USERS,
//     DBA_ROLE_PRIVS and DBA_SYS_PRIVS) and changed with fixed per-engine
//     statements. Identifiers are quoted by the engine's quoting function
//     (quote.go) and values are never string-built.
//   - app: an application's own tables, through admin-configured SELECTs and
//     INSERT/UPDATE/DELETE templates that take named placeholders only
//     (template.go).
//
// Safety: every read runs in a transaction that is read-only where the driver
// can say so (PostgreSQL, MySQL; Oracle by SET TRANSACTION READ ONLY; SQL
// Server has no such option, so its reads are fixed catalogue statements or
// validated SELECTs on an ApplicationIntent=ReadOnly connection) with a query
// timeout and a row cap; a capped read is reported as partial so the deletion
// guard holds removals. The connection is dialled through safehttp's address
// policy (no loopback, private, link-local or metadata address in prod),
// TLS is verified (verify-full equivalent per driver) unless the dev runtime
// turns it off, and the password is a connsync.Secret that never prints.
package sqldb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Engines.
const (
	Postgres  = "postgres"
	MySQL     = "mysql"
	SQLServer = "sqlserver"
	Oracle    = "oracle"
)

// Engines lists every supported engine.
var Engines = []string{Postgres, MySQL, SQLServer, Oracle}

// Modes.
const (
	ModeNative = "native"
	ModeApp    = "app"
)

// TLS modes. verify-full (the default) verifies the chain and the host name.
const (
	TLSVerifyFull = "verify-full"
	TLSDisable    = "disable" // dev runtime only
)

// Limits.
const (
	DefaultQueryTimeout = 30 * time.Second
	MaxQueryTimeout     = 5 * time.Minute
	DefaultMaxRows      = 100_000
	MaxRowsLimit        = 1_000_000
	ConnectTimeout      = 10 * time.Second
	maxCABundle         = 64 << 10
)

// Config describes one database. It holds no secret: the password is passed
// separately (a connsync.Secret, or sealed with SealPassword).
type Config struct {
	// System is the system name in Tessera (default "sql").
	System string `json:"system,omitempty"`
	Engine string `json:"engine"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"` // default per engine
	// Database is the database name (PostgreSQL, MySQL, SQL Server) or the
	// service name (Oracle).
	Database string `json:"database,omitempty"`
	Username string `json:"username"`
	// TLS is verify-full (default) or disable (dev runtime only).
	TLS string `json:"tls,omitempty"`
	// CABundle is the PEM of the CA that signed the server certificate
	// (public); empty means the system roots.
	CABundle string `json:"ca_bundle,omitempty"`
	Mode     string `json:"mode"`
	// QueryTimeoutSeconds and MaxRows bound every statement and every read.
	QueryTimeoutSeconds int  `json:"query_timeout_seconds,omitempty"`
	MaxRows             int  `json:"max_rows,omitempty"`
	App                 *App `json:"app,omitempty"`
}

// App is the application-table mode: admin-written statements. Reads are
// SELECTs without placeholders; writes are INSERT, UPDATE or DELETE templates
// with named placeholders (:username, :external_id, :email, :display_name,
// :entitlement, :entitlement_name, :attr_<name>).
//
// AccountsQuery returns the columns id, username, email, display_name and
// status (only id is required). EntitlementsQuery returns account (an id or
// username of AccountsQuery), entitlement and, optionally, description.
type App struct {
	AccountsQuery     string `json:"accounts_query,omitempty"`
	EntitlementsQuery string `json:"entitlements_query,omitempty"`
	CreateAccount     string `json:"create_account,omitempty"`
	UpdateAccount     string `json:"update_account,omitempty"`
	DisableAccount    string `json:"disable_account,omitempty"`
	DeleteAccount     string `json:"delete_account,omitempty"`
	AddEntitlement    string `json:"add_entitlement,omitempty"`
	RemoveEntitlement string `json:"remove_entitlement,omitempty"`
}

var (
	hostRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.$#@-]{0,127}$`)
	systemRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// DefaultPort is the engine's well-known port.
func DefaultPort(engine string) int {
	switch engine {
	case Postgres:
		return 5432
	case MySQL:
		return 3306
	case SQLServer:
		return 1433
	case Oracle:
		return 1521
	}
	return 0
}

// SystemName is the system name the connector reports.
func (c Config) SystemName() string {
	if c.System != "" {
		return c.System
	}
	return "sql"
}

// DisplayName is the UI name.
func (c Config) DisplayName() string {
	return map[string]string{Postgres: "PostgreSQL", MySQL: "MySQL", SQLServer: "SQL Server", Oracle: "Oracle Database"}[c.Engine]
}

func (c Config) EffectivePort() int {
	if c.Port != 0 {
		return c.Port
	}
	return DefaultPort(c.Engine)
}

func (c Config) timeout() time.Duration {
	if c.QueryTimeoutSeconds > 0 {
		return time.Duration(c.QueryTimeoutSeconds) * time.Second
	}
	return DefaultQueryTimeout
}

func (c Config) maxRows() int {
	if c.MaxRows > 0 {
		return c.MaxRows
	}
	return DefaultMaxRows
}

// Validate checks a config against the runtime and returns every problem.
// TLS may be turned off only in dev.
func (c Config) Validate(rt connsync.Runtime) error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !validEngine(c.Engine) {
		bad("engine must be one of %s", strings.Join(Engines, ", "))
	}
	if c.System != "" && !systemRE.MatchString(c.System) {
		bad("system must be a short lower-case name")
	}
	if _, err := netip.ParseAddr(c.Host); err != nil && !hostRE.MatchString(c.Host) {
		bad("host must be a host name or IP address without scheme, port or path")
	}
	if c.Port < 0 || c.Port > 65535 {
		bad("port must be between 1 and 65535")
	}
	if c.Database != "" && !nameRE.MatchString(c.Database) {
		bad("database is not a valid name")
	}
	if c.Username == "" || len(c.Username) > 128 || !cleanText(c.Username) {
		bad("username is required (at most 128 characters, no control characters)")
	}
	switch c.TLS {
	case "", TLSVerifyFull:
	case TLSDisable:
		if rt.Env != config.Dev {
			bad("tls %q is allowed in dev only: production requires verify-full", TLSDisable)
		}
	default:
		bad("tls must be %s or %s", TLSVerifyFull, TLSDisable)
	}
	if len(c.CABundle) > maxCABundle || strings.Contains(c.CABundle, "PRIVATE KEY") {
		bad("ca_bundle must hold certificates only, at most 64 KiB")
	} else if c.CABundle != "" {
		if _, err := caPool(c.CABundle); err != nil {
			bad("ca_bundle: %v", err)
		}
	}
	if c.QueryTimeoutSeconds < 0 || time.Duration(c.QueryTimeoutSeconds)*time.Second > MaxQueryTimeout {
		bad("query_timeout_seconds must be between 1 and %d", int(MaxQueryTimeout/time.Second))
	}
	if c.MaxRows < 0 || c.MaxRows > MaxRowsLimit {
		bad("max_rows must be between 1 and %d", MaxRowsLimit)
	}
	switch c.Mode {
	case ModeNative:
		if c.App != nil {
			bad("app applies to mode %s only", ModeApp)
		}
	case ModeApp:
		if c.App == nil {
			bad("mode %s needs app statements", ModeApp)
		} else if err := c.App.validate(); err != nil {
			errs = append(errs, err)
		}
	default:
		bad("mode must be %s or %s", ModeNative, ModeApp)
	}
	return errors.Join(errs...)
}

func validEngine(e string) bool {
	for _, k := range Engines {
		if k == e {
			return true
		}
	}
	return false
}

// cleanText: valid UTF-8 without control characters.
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// DecodeApp strictly decodes the JSON of an App (unknown fields refused).
func DecodeApp(raw []byte) (*App, error) {
	var a App
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return nil, fmt.Errorf("app statements: %w", err)
	}
	if d.More() {
		return nil, errors.New("app statements: trailing data")
	}
	return &a, nil
}
