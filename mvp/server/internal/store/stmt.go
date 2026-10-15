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

// lstmt is one of the two hash lookups of design §14.2, the only reads of a
// tenant table outside a TenantTx: SELECT tenant_id, id FROM <table> WHERE
// <unique hash column> = @hash (GlobalHashLookups). They run on a SystemTx
// and return just enough to open the right tenant transaction.
type lstmt struct{ name, sql string }

type registered struct {
	name, sql string
	system    bool
	lookup    bool
}

// statements is every SQL statement the store runs (besides schema DDL and
// the PRAGMAs in db.go), keyed by name. isolation_test.go lints each one.
var statements = map[string]registered{}

func register(name, sql string, system, lookup bool) {
	if _, dup := statements[name]; dup {
		panic(fmt.Sprintf("store: duplicate statement name %q", name))
	}
	statements[name] = registered{name, strings.TrimSpace(sql), system, lookup}
}

// tq declares a tenant statement. Call it only from package-level var blocks.
func tq(name, sql string) tstmt {
	register(name, sql, false, false)
	return tstmt{name, strings.TrimSpace(sql)}
}

// sq declares a system statement. Call it only from package-level var blocks.
func sq(name, sql string) sstmt {
	register(name, sql, true, false)
	return sstmt{name, strings.TrimSpace(sql)}
}

// lq declares a hash lookup (see lstmt). Call it only from package-level var blocks.
func lq(name, sql string) lstmt {
	register(name, sql, true, true)
	return lstmt{name, strings.TrimSpace(sql)}
}

// GlobalHashLookups are the tenant-table columns that are unique across
// tenants and may be looked up before the tenant is known (design §14.2):
// bearer-secret hashes. The schema meta-test allows a unique index on exactly
// these columns not to start with tenant_id.
var GlobalHashLookups = map[string]string{"sessions": "secret_hash", "login_transactions": "cookie_hash"}
