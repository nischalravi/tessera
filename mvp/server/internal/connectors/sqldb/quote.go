package sqldb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// maxIdent is the longest name accepted (SQL Server and Oracle cap identifiers
// at 128 bytes; MySQL account parts are shorter still and the server decides).
const maxIdent = 128

var errIdent = errors.New("not a usable name")

// Quote returns name as a quoted identifier of the engine, the only way a name
// reaches a DDL statement (DDL cannot bind identifiers). It refuses an empty
// name, a name over 128 bytes, invalid UTF-8, NUL and other control
// characters. The quoting itself is the engine's own rule:
//
//   - postgres: pgx.Identifier.Sanitize (the driver's function): "name", with
//     embedded double quotes doubled.
//   - mysql: `name`, backticks doubled; an account is 'user'@'host' (QuoteMySQLAccount).
//   - sqlserver: [name], closing brackets doubled (what QUOTENAME does).
//   - oracle: "name"; a name holding a double quote is refused, as Oracle has
//     no way to write one.
func Quote(engine, name string) (string, error) {
	if err := checkIdent(name); err != nil {
		return "", err
	}
	switch engine {
	case Postgres:
		return pgx.Identifier{name}.Sanitize(), nil
	case MySQL:
		return "`" + strings.ReplaceAll(name, "`", "``") + "`", nil
	case SQLServer:
		return "[" + strings.ReplaceAll(name, "]", "]]") + "]", nil
	case Oracle:
		if strings.Contains(name, `"`) {
			return "", fmt.Errorf("%w: holds a double quote", errIdent)
		}
		return `"` + name + `"`, nil
	}
	return "", fmt.Errorf("unknown engine %q", engine)
}

func checkIdent(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty", errIdent)
	case len(name) > maxIdent:
		return fmt.Errorf("%w: longer than %d bytes", errIdent, maxIdent)
	case !cleanText(name):
		return fmt.Errorf("%w: control characters or invalid UTF-8", errIdent)
	}
	return nil
}

// QuoteMySQLAccount quotes "user@host" (host "%" when there is no "@") as the
// account literal 'user'@'host'. The split is at the last "@", so a user name
// that is an e-mail address works. Backslash is refused (its meaning changes
// with NO_BACKSLASH_ESCAPES) and a single quote is doubled.
func QuoteMySQLAccount(account string) (string, error) {
	if err := checkIdent(account); err != nil {
		return "", err
	}
	user, host := account, "%"
	if i := strings.LastIndexByte(account, '@'); i >= 0 {
		user, host = account[:i], account[i+1:]
	}
	if user == "" || host == "" {
		return "", fmt.Errorf("%w: account must be user@host", errIdent)
	}
	if strings.Contains(account, `\`) {
		return "", fmt.Errorf("%w: backslash", errIdent)
	}
	lit := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	return lit(user) + "@" + lit(host), nil
}
