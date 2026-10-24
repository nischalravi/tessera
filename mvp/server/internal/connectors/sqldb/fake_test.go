package sqldb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
)

// fakeDB is a database/sql driver with scripted answers, so statement
// generation and the readers are tested without a server and without sqlmock:
// every statement, its arguments and the transaction options are recorded, and
// a query is answered from a table keyed by the exact statement text.
type fakeDB struct {
	mu sync.Mutex
	// answers maps an exact query text to its rows (first row = columns).
	answers map[string][][]string
	// failQuery makes a query fail when it contains the text.
	failQuery string
	// Log of what ran.
	Queries []string
	Execs   []string
	Args    [][]any
	Txs     []driver.TxOptions
	Closed  bool
}

func newFake() *fakeDB { return &fakeDB{answers: map[string][][]string{}} }

// answer registers rows for a query: cols then data rows.
func (f *fakeDB) answer(query string, cols []string, rows ...[]string) {
	f.answers[query] = append([][]string{cols}, rows...)
}

func (f *fakeDB) db() *sql.DB { return sql.OpenDB(fakeConnector{f}) }

func (f *fakeDB) execs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Execs...)
}

type fakeConnector struct{ f *fakeDB }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return &fakeConn{c.f}, nil }
func (c fakeConnector) Driver() driver.Driver                        { return nil }

type fakeConn struct{ f *fakeDB }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("fake: use the context methods")
}
func (c *fakeConn) Close() error { c.f.mu.Lock(); c.f.Closed = true; c.f.mu.Unlock(); return nil }
func (c *fakeConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *fakeConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.f.mu.Lock()
	c.f.Txs = append(c.f.Txs, o)
	c.f.mu.Unlock()
	return fakeTx{}, nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

func named(args []driver.NamedValue) []any {
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = a.Value
	}
	return out
}

func (c *fakeConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.failQuery != "" && strings.Contains(q, c.f.failQuery) {
		return nil, fmt.Errorf("fake: refused %q", q)
	}
	c.f.Execs = append(c.f.Execs, q)
	c.f.Args = append(c.f.Args, named(args))
	return driver.RowsAffected(1), nil
}

func (c *fakeConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.failQuery != "" && strings.Contains(q, c.f.failQuery) {
		return nil, fmt.Errorf("fake: refused %q", q)
	}
	c.f.Queries = append(c.f.Queries, q)
	c.f.Args = append(c.f.Args, named(args))
	data, ok := c.f.answers[q]
	if !ok {
		return nil, fmt.Errorf("fake: no answer for query %q", q)
	}
	return &fakeRows{data: data}, nil
}

type fakeRows struct {
	data [][]string
	i    int
}

func (r *fakeRows) Columns() []string { return r.data[0] }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	r.i++
	if r.i >= len(r.data) {
		return io.EOF
	}
	for i, v := range r.data[r.i] {
		if v == "<null>" {
			dest[i] = nil
		} else {
			dest[i] = v
		}
	}
	return nil
}
