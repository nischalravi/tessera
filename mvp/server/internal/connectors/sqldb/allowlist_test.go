package sqldb

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Hostile names are refused before any SQL is built or sent, for every engine,
// as account names and as role names; the refusal is permanent.
func TestTarget_NamesAreAllowListed(t *testing.T) {
	bad := []string{
		`x"`, `x'`, "x;", "x; DROP ROLE y", `x\y`, "a\x00b", "a b", "a\nb", "a\tb", "x`y", "x]y", "x/*y",
		"é", "аdmin", // Cyrillic a
		"a‮b", "a​b", "ａdmin", // bidi override, zero width space, full-width
		"", "-lead", ".lead", strings.Repeat("a", 129), "x(y)", "x,y", "x=y", "x\"y", "$(id)",
	}
	for _, e := range Engines {
		for _, name := range bad {
			f := newFake()
			loadCatalog(f, e, nativeData{}, nil, nil)
			tg := targetFor(f, goodConfig(e))
			for _, r := range []target.Request{
				req(target.CreateAccount, name),
				req(target.DeleteAccount, name),
				withGroup(req(target.AddEntitlement, "alice"), name),
			} {
				if r.Kind == target.AddEntitlement { // the account must exist for the role check to be reached
					loadCatalog(f, e, nativeData{accounts: [][]string{{"alice", "active"}}}, nil, nil)
				}
				err := tg.Apply(context.Background(), r)
				if name == "" && r.Kind != target.AddEntitlement {
					continue // an empty account is refused earlier ("needs a username")
				}
				if err == nil || target.Retryable(err) {
					t.Errorf("%s %s %q: err = %v, want a permanent refusal", e, r.Kind, name, err)
				}
				if ddl := nonTx(f.execs()); len(ddl) != 0 {
					t.Errorf("%s %s %q: SQL was sent: %q", e, r.Kind, name, ddl)
				}
			}
		}
	}
}

func TestSafeName_Accepts(t *testing.T) {
	for _, n := range []string{"alice", "A", "_x", "svc.app-1", "alice@db.example", "alice@%", "o_neil$1", "tsr#1", "server:sysadmin", "db:db_owner", strings.Repeat("a", 128)} {
		if !safeName.MatchString(n) {
			t.Errorf("%q refused", n)
		}
	}
}

// nonTx drops the read-transaction statement Oracle reads send.
func nonTx(execs []string) []string {
	var out []string
	for _, e := range execs {
		if e != "SET TRANSACTION READ ONLY" {
			out = append(out, e)
		}
	}
	return out
}

// Valid names still produce the golden statements through Apply.
func TestTarget_ValidNamesGolden(t *testing.T) {
	f := newFake()
	loadCatalog(f, MySQL, nativeData{accounts: [][]string{{"alice@%", "active"}}}, [][][]string{{{"readers@%"}}}, nil)
	tg := targetFor(f, goodConfig(MySQL))
	if err := tg.Apply(context.Background(), withGroup(req(target.AddEntitlement, "alice@%"), "readers@%")); err != nil {
		t.Fatal(err)
	}
	if got := f.execs(); len(got) != 1 || got[0] != "GRANT 'readers'@'%' TO 'alice'@'%'" {
		t.Fatalf("ran %q", got)
	}
}
