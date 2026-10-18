package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TenantTx is the only handle on tenant-owned tables. It exists only inside
// DB.InTenant, DB.ReadTenant and DB.ForEachActiveTenant, is bound to one
// tenant for its whole life (there is no setter), and binds @tenant into
// every statement itself. Repository methods are methods on *TenantTx and
// take no tenant argument.
//
// The context passed to InTenant is bound into the transaction, so methods do
// not take one.
type TenantTx struct {
	ctx      context.Context
	db       *DB
	tx       *sql.Tx
	tenant   tenancy.ID
	readOnly bool
	appended int64 // audit events appended (counted into AuditContext.Committed on commit)
}

// Tenant returns the tenant this transaction is scoped to.
func (tx *TenantTx) Tenant() tenancy.ID { return tx.tenant }

// Context returns the context the transaction was opened with.
func (tx *TenantTx) Context() context.Context { return tx.ctx }

// own checks that a row passed in for insert belongs to this transaction's
// tenant (or does not say). A different non-zero tenant is ErrCrossTenant,
// never silently overwritten.
func (tx *TenantTx) own(t tenancy.ID) error {
	if !t.IsZero() && t != tx.tenant {
		return ErrCrossTenant
	}
	return nil
}

// bind appends @tenant to args, refusing a caller-supplied "tenant".
func (tx *TenantTx) bind(args []sql.NamedArg) ([]any, error) {
	out := make([]any, 0, len(args)) // append grows it by one for @tenant
	for _, a := range args {
		if strings.EqualFold(a.Name, "tenant") {
			return nil, ErrCrossTenant // a caller tried to supply the tenant
		}
		out = append(out, a)
	}
	return append(out, sql.Named("tenant", tx.tenant.String())), nil
}

func (tx *TenantTx) exec(s tstmt, args ...sql.NamedArg) (sql.Result, error) {
	if tx.readOnly {
		return nil, ErrReadOnly
	}
	a, err := tx.bind(args)
	if err != nil {
		return nil, err
	}
	res, err := tx.db.execIn(tx.ctx, tx.tx, s.sql, a)
	return res, crossTenant(err)
}

// crossTenant maps a cross-tenant reference refused by the schema's guard
// triggers (schema/0001_tenancy.sql) to ErrCrossTenant.
func crossTenant(err error) error {
	if err != nil && strings.Contains(err.Error(), "cross-tenant reference") {
		return fmt.Errorf("%w: %v", ErrCrossTenant, err)
	}
	return err
}

// insert runs an INSERT and returns the new row id.
func (tx *TenantTx) insert(s tstmt, args ...sql.NamedArg) (int64, error) {
	res, err := tx.exec(s, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (tx *TenantTx) query(s tstmt, args ...sql.NamedArg) (*sql.Rows, error) {
	a, err := tx.bind(args)
	if err != nil {
		return nil, err
	}
	return tx.db.queryIn(tx.ctx, tx.tx, s.sql, a)
}

func (tx *TenantTx) queryRow(s tstmt, args ...sql.NamedArg) scanner {
	a, err := tx.bind(args)
	if err != nil {
		return errScanner{err}
	}
	return tx.db.queryRowIn(tx.ctx, tx.tx, s.sql, a)
}

// count runs a COUNT-style statement returning one integer.
func (tx *TenantTx) count(s tstmt, args ...sql.NamedArg) (int, error) {
	var n sql.NullInt64
	err := tx.queryRow(s, args...).Scan(&n)
	return int(n.Int64), err
}

type scanner interface{ Scan(dest ...any) error }

type errScanner struct{ err error }

func (e errScanner) Scan(...any) error { return e.err }

func collect[T any](tx *TenantTx, scan func(scanner) (*T, error), s tstmt, args ...sql.NamedArg) (out []*T, err error) {
	rows, err := tx.query(s, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func one[T any](tx *TenantTx, scan func(scanner) (*T, error), s tstmt, args ...sql.NamedArg) (*T, error) {
	v, err := scan(tx.queryRow(s, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// ---------------------------------------------------------------- request context

type txKey struct{}

// WithTx returns ctx carrying tx; the API's tenant middleware uses it.
func WithTx(ctx context.Context, tx *TenantTx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// MissingTenantContext is the panic value of TxFrom when no tenant
// transaction is in the context. The API's recovery middleware turns it into a
// 500 and a tenancy.context_missing event.
type MissingTenantContext struct{}

func (MissingTenantContext) Error() string { return ErrNoTenant.Error() }

// TxFrom returns the request's tenant transaction. It panics with
// MissingTenantContext if the tenant middleware did not run: that is a
// programming error, and failing loudly is safer than running unscoped.
func TxFrom(ctx context.Context) *TenantTx {
	tx, ok := ctx.Value(txKey{}).(*TenantTx)
	if !ok || tx == nil {
		panic(MissingTenantContext{})
	}
	return tx
}

// ReadOnly reports whether this is a ReadTenant transaction.
func (tx *TenantTx) ReadOnly() bool { return tx.readOnly }
