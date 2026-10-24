package sqldb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	go_ora "github.com/sijms/go-ora/v2"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// caPool parses a PEM CA bundle.
func caPool(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, errors.New("holds no PEM certificate")
	}
	return pool, nil
}

// guardedDialer connects only through safehttp's address policy: the host is
// resolved once, refused when any address is loopback, private, link-local,
// cloud metadata or another blocked range (the dev runtime may allow
// loopback), and only a checked address is dialled. Only the configured port
// is allowed. It satisfies the dialer interfaces of all four drivers.
type guardedDialer struct{ dial safehttp.DialFunc }

func newDialer(c Config, rt connsync.Runtime, base safehttp.DialFunc) (*guardedDialer, error) {
	if base != nil { // tests
		return &guardedDialer{base}, nil
	}
	d, err := safehttp.NewDialer(safehttp.Options{Env: rt.Env, AllowLoopback: rt.AllowLoopback,
		AllowedPorts: []int{c.EffectivePort()}, Timeout: ConnectTimeout})
	if err != nil {
		return nil, err
	}
	return &guardedDialer{d}, nil
}

func (g *guardedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return g.dial(ctx, network, addr)
}

// tlsConfig is the client TLS config: TLS 1.2 or later, the chain and host
// name verified (verify-full), against the CA bundle or the system roots. It
// is nil when TLS is off (dev only; Validate refuses it otherwise).
func tlsConfig(c Config) (*tls.Config, error) {
	if c.TLS == TLSDisable {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host}
	if c.CABundle != "" {
		pool, err := caPool(c.CABundle)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Open returns a handle to the database with one connection at most, the
// driver's own timeouts applied, TLS verified and the dial guarded. It does
// not connect yet. readOnly asks for the engine's read-only connection intent
// where it has one; the transaction-level guard is in beginRead.
func Open(c Config, pw connsync.Secret, rt connsync.Runtime, readOnly bool) (*sql.DB, error) {
	return open(c, pw, rt, nil, readOnly)
}

func open(c Config, pw connsync.Secret, rt connsync.Runtime, base safehttp.DialFunc, readOnly bool) (*sql.DB, error) {
	if err := c.Validate(rt); err != nil {
		return nil, err
	}
	if pw.Empty() {
		return nil, errors.New("sqldb: a password is required")
	}
	gd, err := newDialer(c, rt, base)
	if err != nil {
		return nil, err
	}
	tc, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	var db *sql.DB
	switch c.Engine {
	case Postgres:
		db, err = openPostgres(c, pw, gd, tc)
	case MySQL:
		db, err = openMySQL(c, pw, gd, tc)
	case SQLServer:
		db, err = openSQLServer(c, pw, gd, tc, readOnly)
	case Oracle:
		db, err = openOracle(c, pw, gd, tc)
	}
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

func openPostgres(c Config, pw connsync.Secret, gd *guardedDialer, tc *tls.Config) (*sql.DB, error) {
	// the conn string holds no password: it is set on the config below
	cs := "host=" + c.Host + " port=" + strconv.Itoa(c.EffectivePort()) + " dbname=" + orDefault(c.Database, "postgres") +
		" user=" + pgEscape(c.Username) + " sslmode=verify-full"
	if tc == nil {
		cs = "host=" + c.Host + " port=" + strconv.Itoa(c.EffectivePort()) + " dbname=" + orDefault(c.Database, "postgres") +
			" user=" + pgEscape(c.Username) + " sslmode=disable"
	}
	cfg, err := pgx.ParseConfig(cs)
	if err != nil {
		return nil, errors.New("sqldb: the PostgreSQL settings are not valid")
	}
	cfg.Password = pw.Reveal()
	cfg.ConnectTimeout = ConnectTimeout
	cfg.DialFunc = gd.DialContext
	// the guarded dialer resolves and checks the name, once
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	if tc != nil {
		cfg.TLSConfig = tc
		cfg.Fallbacks = nil
	} else {
		cfg.TLSConfig = nil
	}
	cfg.RuntimeParams["statement_timeout"] = strconv.Itoa(int(c.timeout() / time.Millisecond))
	cfg.RuntimeParams["application_name"] = "tessera"
	return stdlib.OpenDB(*cfg), nil
}

// pgEscape quotes a value of a libpq key/value connection string.
func pgEscape(v string) string {
	out := []byte{'\''}
	for i := 0; i < len(v); i++ {
		if v[i] == '\'' || v[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, v[i])
	}
	return string(append(out, '\''))
}

func openMySQL(c Config, pw connsync.Secret, gd *guardedDialer, tc *tls.Config) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net = c.Username, pw.Reveal(), "tcp"
	cfg.Addr = net.JoinHostPort(c.Host, strconv.Itoa(c.EffectivePort()))
	cfg.DBName = c.Database
	cfg.DialFunc = gd.DialContext
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = ConnectTimeout, c.timeout(), c.timeout()
	cfg.AllowCleartextPasswords, cfg.AllowAllFiles, cfg.MultiStatements, cfg.InterpolateParams = false, false, false, false
	if tc != nil {
		cfg.TLS = tc
	} else {
		cfg.TLSConfig = "false"
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, errors.New("sqldb: the MySQL settings are not valid")
	}
	return sql.OpenDB(conn), nil
}

func openSQLServer(c Config, pw connsync.Secret, gd *guardedDialer, tc *tls.Config, readOnly bool) (*sql.DB, error) {
	q := url.Values{}
	if c.Database != "" {
		q.Set("database", c.Database)
	}
	q.Set("connection timeout", strconv.Itoa(int(ConnectTimeout/time.Second)))
	if tc != nil {
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "false")
	} else {
		q.Set("encrypt", "disable")
	}
	if readOnly {
		q.Set("ApplicationIntent", "ReadOnly")
	}
	u := url.URL{Scheme: "sqlserver", User: url.UserPassword(c.Username, pw.Reveal()),
		Host: net.JoinHostPort(c.Host, strconv.Itoa(c.EffectivePort())), RawQuery: q.Encode()}
	cfg, err := msdsn.Parse(u.String())
	if err != nil {
		return nil, errors.New("sqldb: the SQL Server settings are not valid")
	}
	if tc != nil {
		cfg.TLSConfig = tc
	}
	conn := mssql.NewConnectorConfig(cfg)
	conn.Dialer = gd
	return sql.OpenDB(conn), nil
}

func openOracle(c Config, pw connsync.Secret, gd *guardedDialer, tc *tls.Config) (*sql.DB, error) {
	opts := map[string]string{"TIMEOUT": strconv.Itoa(int(ConnectTimeout / time.Second))}
	if tc != nil {
		opts["SSL"], opts["SSL VERIFY"] = "TRUE", "TRUE"
	}
	dsn := go_ora.BuildUrl(c.Host, c.EffectivePort(), c.Database, c.Username, pw.Reveal(), opts)
	conn, ok := go_ora.NewConnector(dsn).(*go_ora.OracleConnector)
	if !ok {
		return nil, errors.New("sqldb: the Oracle driver changed")
	}
	conn.Dialer(gd)
	if tc != nil {
		conn.WithTLSConfig(tc)
	}
	return sql.OpenDB(conn), nil
}

func orDefault(v, d string) string {
	if v != "" {
		return v
	}
	return d
}
