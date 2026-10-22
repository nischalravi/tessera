package store

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

// The read-only query of a SQL loader that runs on a Postgres database that is
// NOT Tessera's (issue GR-10; design docs/design/groups-grouper-parity.md
// §9.1). Like RunExtQuery it lives here because only this package may use
// database/sql. Four lines of defence stand between a loader's query and the
// remote database: the statement must pass CheckReadOnlySQL, the session is
// read-only (default_transaction_read_only and a READ ONLY transaction), a
// statement timeout bounds it on the server, and the rows are capped. The
// connection goes through the caller's address-checked dialer (the SSRF guard),
// and the DSN is restricted to what a loader needs: a postgres:// URL whose
// only options are sslmode and connect_timeout (so no sslrootcert or
// passfile can make the server read its own files); a private CA comes as PEM.

// ExtPGQuery is one query of a loader's Postgres source.
type ExtPGQuery struct {
	// DSN is a postgres:// URL (opened from the loader's sealed secret).
	DSN string
	// RootCAPEM replaces the system roots for verifying the server's certificate.
	RootCAPEM string
	// RequireVerifyFull refuses any sslmode but verify-full (production).
	RequireVerifyFull bool
	// Dial is the address-checked dialer; required (nil is refused: a loader
	// must never dial through the process's default network access).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// SQL is the statement; Args are its named parameters (@name).
	SQL  string
	Args map[string]string
	// MaxRows and Timeout as in ExtQuery.
	MaxRows int
	Timeout time.Duration
}

// Errors of RunExtQueryPG.
var (
	ErrExtDSN = errors.New("store: invalid source database DSN")
	ErrExtTLS = errors.New("store: the source database DSN must use sslmode=verify-full")
)

// CheckPGDSN checks a loader's Postgres DSN without connecting: a postgres://
// URL with a host and a user, whose only options are sslmode and
// connect_timeout, and (requireVerifyFull) sslmode=verify-full. The errors
// never contain the DSN.
func CheckPGDSN(dsn string, requireVerifyFull bool) error {
	_, err := parseExtPGDSN(dsn, requireVerifyFull)
	return err
}

type extPGDSN struct {
	u       *url.URL
	sslmode string
	timeout time.Duration
}

func parseExtPGDSN(dsn string, requireVerifyFull bool) (*extPGDSN, error) {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: it is a postgres:// URL with a host", ErrExtDSN)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("%w: it names a user", ErrExtDSN)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: the port is not valid", ErrExtDSN)
		}
	}
	if strings.Trim(u.Path, "/") == "" || strings.Contains(strings.Trim(u.Path, "/"), "/") {
		return nil, fmt.Errorf("%w: it names one database", ErrExtDSN)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: the options are malformed", ErrExtDSN)
	}
	out := &extPGDSN{u: u, sslmode: "verify-full", timeout: 10 * time.Second}
	for k, v := range q {
		switch {
		case len(v) != 1:
			return nil, fmt.Errorf("%w: option %s is given twice", ErrExtDSN, k)
		case k == "sslmode":
			out.sslmode = v[0]
		case k == "connect_timeout":
			n, err := strconv.Atoi(v[0])
			if err != nil || n < 1 || n > 60 {
				return nil, fmt.Errorf("%w: connect_timeout is 1 to 60 seconds", ErrExtDSN)
			}
			out.timeout = time.Duration(n) * time.Second
		default:
			return nil, fmt.Errorf("%w: only the options sslmode and connect_timeout are allowed", ErrExtDSN)
		}
	}
	switch out.sslmode {
	case "verify-full":
	case "disable", "allow", "prefer", "require", "verify-ca":
		if requireVerifyFull {
			return nil, ErrExtTLS
		}
	default:
		return nil, fmt.Errorf("%w: sslmode is not valid", ErrExtDSN)
	}
	return out, nil
}

// pgNamedArgs rewrites @name parameters to $1, $2... and returns the values in
// order. Quoted text is left alone; an @name with no value is an error. A value
// that is a whole number is sent as one, so "seq > @cursor" compares numbers.
func pgNamedArgs(q string, args map[string]string) (string, []any, error) {
	var out strings.Builder
	var vals []any
	index := map[string]int{}
	var quote byte
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			out.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			out.WriteByte(c)
		case c == '@' && i+1 < len(q) && (q[i+1] == '_' || (q[i+1] >= 'a' && q[i+1] <= 'z') || (q[i+1] >= 'A' && q[i+1] <= 'Z')):
			j := i + 1
			for j < len(q) && (q[j] == '_' || (q[j] >= 'a' && q[j] <= 'z') || (q[j] >= 'A' && q[j] <= 'Z') || (q[j] >= '0' && q[j] <= '9')) {
				j++
			}
			name := q[i+1 : j]
			n, ok := index[name]
			if !ok {
				v, has := args[name]
				if !has {
					return "", nil, fmt.Errorf("the query uses @%s, which is not a parameter", name)
				}
				if num, err := strconv.ParseInt(v, 10, 64); err == nil {
					vals = append(vals, num)
				} else {
					vals = append(vals, v)
				}
				n = len(vals)
				index[name] = n
			}
			out.WriteString("$" + strconv.Itoa(n))
			i = j - 1
		default:
			out.WriteByte(c)
		}
	}
	return out.String(), vals, nil
}

// RunExtQueryPG runs q on a read-only session of the Postgres database named
// by q.DSN and returns its rows.
func RunExtQueryPG(ctx context.Context, q ExtPGQuery) (*ExtResult, error) {
	if q.Dial == nil {
		return nil, errors.New("store: no address-checked dialer for the source database")
	}
	d, err := parseExtPGDSN(q.DSN, q.RequireVerifyFull)
	if err != nil {
		return nil, err
	}
	if err := CheckReadOnlySQL(q.SQL); err != nil {
		return nil, err
	}
	if q.MaxRows <= 0 {
		q.MaxRows = DefaultExtMaxRows
	}
	if q.Timeout <= 0 {
		q.Timeout = DefaultExtTimeout
	}
	stmt, args, err := pgNamedArgs(q.SQL, q.Args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, q.Timeout)
	defer cancel()
	cfg, err := parsePGDSN(d.u.String())
	if err != nil {
		return nil, ErrExtDSN
	}
	cfg.DialFunc = q.Dial
	cfg.ConnectTimeout = d.timeout
	// the session is read-only and bounded on the server too
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = strconv.FormatInt(q.Timeout.Milliseconds(), 10)
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = strconv.FormatInt(q.Timeout.Milliseconds(), 10)
	cfg.RuntimeParams["application_name"] = "tessera-loader"
	if q.RootCAPEM != "" && cfg.TLSConfig != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(q.RootCAPEM)) {
			return nil, errors.New("store: the CA bundle holds no PEM certificate")
		}
		cfg.TLSConfig.RootCAs = pool
		for _, f := range cfg.Fallbacks {
			if f.TLSConfig != nil {
				f.TLSConfig.RootCAs = pool
			}
		}
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, scrubPG(err, q.DSN)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, scrubPG(err, q.DSN)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, scrubPG(err, q.DSN)
	}
	out := &ExtResult{Columns: cols}
	for rows.Next() {
		if len(out.Rows) >= q.MaxRows {
			return nil, ErrExtRowLimit
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, scrubPG(err, q.DSN)
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = extText(v)
		}
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, scrubPG(err, q.DSN)
	}
	return out, nil
}

// scrubPG keeps a driver error from carrying the DSN (and so the password)
// into a run's error text.
func scrubPG(err error, dsn string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	msg := err.Error()
	if u, perr := url.Parse(dsn); perr == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			msg = strings.ReplaceAll(msg, pw, "***")
		}
	}
	return errors.New(msg)
}
