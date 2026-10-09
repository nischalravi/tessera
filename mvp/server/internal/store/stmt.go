package store

import (
	"fmt"
	"strings"
)

// tstmt is a statement on tenant-owned tables. Its SQL uses only named
// parameters, and every tenant table it names is filtered (or, for INSERT,
// stamped) with the parameter @tenant, which only TenantTx binds.
type tstmt struct{ name, sql string }

// sstmt is a system statement: it may touch only the GlobalTables.
type sstmt struct{ name, sql string }

type registered struct {
	name, sql string
	system    bool
}

// statements is every SQL statement the store runs (besides schema DDL and
// the PRAGMAs in db.go), keyed by name. isolation_test.go lints each one.
var statements = map[string]registered{}

func register(name, sql string, system bool) {
	if _, dup := statements[name]; dup {
		panic(fmt.Sprintf("store: duplicate statement name %q", name))
	}
	statements[name] = registered{name, strings.TrimSpace(sql), system}
}

// tq declares a tenant statement. Call it only from package-level var blocks.
func tq(name, sql string) tstmt {
	register(name, sql, false)
	return tstmt{name, strings.TrimSpace(sql)}
}

// sq declares a system statement. Call it only from package-level var blocks.
func sq(name, sql string) sstmt {
	register(name, sql, true)
	return sstmt{name, strings.TrimSpace(sql)}
}
