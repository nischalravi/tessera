package sqldb

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// prefixed is a catalogue query whose entitlement ids carry a prefix (SQL
// Server tells server roles from database roles by "server:" and "db:").
type prefixed struct{ Prefix, SQL string }

// catalogue is the fixed set of read statements of one engine. Column order
// is the contract:
//
//	Accounts: name, status ("active" or "locked")
//	Roles:    name
//	Members:  member, role  (member is an account or a role)
//	Privs:    grantee, privilege
//
// Nothing here takes a parameter and nothing is built from input.
type catalogue struct {
	Accounts string
	Roles    []prefixed
	Members  []prefixed
	Privs    string
}

// Names a PostgreSQL role carries when Tessera locked it (NOLOGIN), so the
// role still reads as an account (a NOLOGIN role is otherwise a group).
const pgLockedMark = "tessera:locked"

var catalogues = map[string]catalogue{
	Postgres: {
		Accounts: `SELECT r.rolname,
  CASE WHEN r.rolcanlogin AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > now()) THEN 'active' ELSE 'locked' END
FROM pg_catalog.pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%' AND (r.rolcanlogin OR pg_catalog.shobj_description(r.oid, 'pg_authid') = '` + pgLockedMark + `')
ORDER BY r.rolname`,
		Roles: []prefixed{{"", `SELECT r.rolname
FROM pg_catalog.pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%'
  AND ((NOT r.rolcanlogin AND COALESCE(pg_catalog.shobj_description(r.oid, 'pg_authid'), '') <> '` + pgLockedMark + `')
       OR r.oid IN (SELECT roleid FROM pg_catalog.pg_auth_members))
ORDER BY r.rolname`}},
		Members: []prefixed{{"", `SELECT m.rolname, r.rolname
FROM pg_catalog.pg_auth_members am
JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
JOIN pg_catalog.pg_roles m ON m.oid = am.member
WHERE r.rolname NOT LIKE 'pg\_%'
ORDER BY m.rolname, r.rolname`}},
		Privs: `SELECT rolname, 'SUPERUSER' FROM pg_catalog.pg_roles WHERE rolsuper AND rolname NOT LIKE 'pg\_%'
UNION ALL SELECT rolname, 'CREATEROLE' FROM pg_catalog.pg_roles WHERE rolcreaterole AND rolname NOT LIKE 'pg\_%'
UNION ALL SELECT rolname, 'CREATEDB' FROM pg_catalog.pg_roles WHERE rolcreatedb AND rolname NOT LIKE 'pg\_%'
UNION ALL SELECT rolname, 'REPLICATION' FROM pg_catalog.pg_roles WHERE rolreplication AND rolname NOT LIKE 'pg\_%'
UNION ALL SELECT rolname, 'BYPASSRLS' FROM pg_catalog.pg_roles WHERE rolbypassrls AND rolname NOT LIKE 'pg\_%'`,
	},
	// MySQL 8.0 and later (roles). A role is a locked, expired row of mysql.user.
	MySQL: {
		Accounts: `SELECT CONCAT(u.User, '@', u.Host),
  CASE WHEN u.account_locked = 'Y' THEN 'locked' ELSE 'active' END
FROM mysql.user u
WHERE u.User <> '' AND u.User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
  AND NOT (u.account_locked = 'Y' AND u.password_expired = 'Y')
  AND NOT EXISTS (SELECT 1 FROM mysql.role_edges e WHERE e.FROM_USER = u.User AND e.FROM_HOST = u.Host)
ORDER BY 1`,
		Roles: []prefixed{{"", `SELECT CONCAT(u.User, '@', u.Host)
FROM mysql.user u
WHERE u.User <> '' AND ((u.account_locked = 'Y' AND u.password_expired = 'Y')
  OR EXISTS (SELECT 1 FROM mysql.role_edges e WHERE e.FROM_USER = u.User AND e.FROM_HOST = u.Host))
ORDER BY 1`}},
		Members: []prefixed{{"", `SELECT CONCAT(e.TO_USER, '@', e.TO_HOST), CONCAT(e.FROM_USER, '@', e.FROM_HOST)
FROM mysql.role_edges e
ORDER BY 1, 2`}},
		Privs: `SELECT CONCAT(User, '@', Host), 'SUPER' FROM mysql.user WHERE Super_priv = 'Y' AND User <> ''
UNION ALL SELECT CONCAT(User, '@', Host), 'GRANT OPTION' FROM mysql.user WHERE Grant_priv = 'Y' AND User <> ''
UNION ALL SELECT CONCAT(User, '@', Host), 'FILE' FROM mysql.user WHERE File_priv = 'Y' AND User <> ''
UNION ALL SELECT CONCAT(User, '@', Host), 'CREATE USER' FROM mysql.user WHERE Create_user_priv = 'Y' AND User <> ''
UNION ALL SELECT CONCAT(User, '@', Host), 'SHUTDOWN' FROM mysql.user WHERE Shutdown_priv = 'Y' AND User <> ''
UNION ALL SELECT CONCAT(User, '@', Host), 'PROCESS' FROM mysql.user WHERE Process_priv = 'Y' AND User <> ''`,
	},
	// SQL Server logins, server roles and, in the connected database, database roles.
	SQLServer: {
		Accounts: `SELECT p.name, CASE WHEN p.is_disabled = 1 THEN 'locked' ELSE 'active' END
FROM sys.server_principals p
WHERE p.type IN ('S', 'U', 'E', 'X') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT SERVICE\%' AND p.name NOT LIKE 'NT AUTHORITY\%'
ORDER BY p.name`,
		Roles: []prefixed{
			{"server:", `SELECT name FROM sys.server_principals WHERE type = 'R' AND name <> 'public' ORDER BY name`},
			{"db:", `SELECT name FROM sys.database_principals WHERE type = 'R' AND name <> 'public' ORDER BY name`},
		},
		Members: []prefixed{
			{"server:", `SELECT m.name, r.name
FROM sys.server_role_members rm
JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id
ORDER BY m.name, r.name`},
			{"db:", `SELECT m.name, r.name
FROM sys.database_role_members rm
JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
WHERE m.type IN ('S', 'U', 'E', 'X', 'R')
ORDER BY m.name, r.name`},
		},
		Privs: `SELECT p.name, sp.permission_name
FROM sys.server_permissions sp
JOIN sys.server_principals p ON p.principal_id = sp.grantee_principal_id
WHERE sp.state IN ('G', 'W') AND sp.permission_name <> 'CONNECT SQL'`,
	},
	// Oracle Database 12c and later (ORACLE_MAINTAINED). Needs SELECT on the DBA_ views.
	Oracle: {
		Accounts: `SELECT USERNAME, CASE WHEN ACCOUNT_STATUS LIKE '%LOCKED%' THEN 'locked' ELSE 'active' END
FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'N' ORDER BY USERNAME`,
		Roles: []prefixed{{"", `SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'N' OR ROLE = 'DBA' ORDER BY ROLE`}},
		Members: []prefixed{{"", `SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS
WHERE GRANTEE IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'N')
   OR GRANTEE IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'N')
ORDER BY GRANTEE, GRANTED_ROLE`}},
		Privs: `SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS
WHERE GRANTEE IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'N')
   OR GRANTEE IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'N')`,
	},
}

// privilegedPrivs are privileges (upper case) that make a holder privileged.
// Oracle's "... ANY ..." system privileges are privileged as a family.
var privilegedPrivs = map[string]bool{
	"SUPERUSER": true, "CREATEROLE": true, "REPLICATION": true, "BYPASSRLS": true,
	"SUPER": true, "GRANT OPTION": true, "FILE": true, "CREATE USER": true, "SHUTDOWN": true,
	"CONTROL SERVER": true, "ALTER ANY LOGIN": true, "ALTER ANY SERVER ROLE": true, "IMPERSONATE ANY LOGIN": true,
	"ALTER USER": true, "DROP USER": true, "GRANT ANY ROLE": true, "GRANT ANY PRIVILEGE": true,
	"ALTER SYSTEM": true, "ALTER DATABASE": true, "BECOME USER": true, "SYSDBA": true, "SYSOPER": true,
	"EXEMPT ACCESS POLICY": true,
}

// privilegedRoles are roles (upper case) that are privileged by name.
var privilegedRoles = map[string]bool{
	"SERVER:SYSADMIN": true, "SERVER:SECURITYADMIN": true, "SERVER:SERVERADMIN": true,
	"DB:DB_OWNER": true, "DB:DB_SECURITYADMIN": true, "DBA": true,
}

func privilegedPriv(p string) bool {
	p = strings.ToUpper(p)
	return privilegedPrivs[p] || strings.Contains(" "+p+" ", " ANY ")
}

// Operations of the native-mode writer.
const (
	opCreate = iota
	opLock
	opUnlock
	opDrop
	opGrant
	opRevoke
)

// randomSecret is a throw-away credential for a login Tessera creates: the
// engine insists on one, nobody ever learns it (it is never returned, stored
// or logged), and the suffix satisfies a password-complexity policy. The
// alphabet (letters, digits, "-" and "_") needs no escaping in a literal.
func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b) + "aA1_", nil
}

// statements returns the fixed statements of one native-mode operation. name
// is the login (or "user@host" on MySQL) and role the entitlement id as
// Discover emits it ("server:" or "db:" prefixed on SQL Server). Every
// identifier goes through Quote (or QuoteMySQLAccount); the only literals are
// constants and the random secret.
func statements(engine string, op int, name, role string) ([]string, error) {
	q := func(s string) (string, error) {
		if engine == MySQL {
			return QuoteMySQLAccount(s)
		}
		return Quote(engine, s)
	}
	who, err := q(name)
	if err != nil {
		return nil, fmt.Errorf("account name: %w", err)
	}
	switch op {
	case opCreate, opLock, opUnlock, opDrop:
		return accountStatements(engine, op, who)
	}
	scope, r := "", role
	if engine == SQLServer {
		switch {
		case strings.HasPrefix(role, "server:"):
			scope, r = "server", strings.TrimPrefix(role, "server:")
		case strings.HasPrefix(role, "db:"):
			scope, r = "db", strings.TrimPrefix(role, "db:")
		default:
			return nil, fmt.Errorf("entitlement %q must start with server: or db:", role)
		}
	}
	rq, err := q(r)
	if err != nil {
		return nil, fmt.Errorf("entitlement: %w", err)
	}
	if engine == SQLServer {
		verb, kw := "ADD", "ALTER ROLE"
		if op == opRevoke {
			verb = "DROP"
		}
		if scope == "server" {
			kw = "ALTER SERVER ROLE"
		}
		return []string{fmt.Sprintf("%s %s %s MEMBER %s", kw, rq, verb, who)}, nil
	}
	if op == opGrant {
		return []string{fmt.Sprintf("GRANT %s TO %s", rq, who)}, nil
	}
	return []string{fmt.Sprintf("REVOKE %s FROM %s", rq, who)}, nil
}

func accountStatements(engine string, op int, who string) ([]string, error) {
	switch engine {
	case Postgres:
		switch op {
		case opCreate:
			return []string{"CREATE ROLE " + who + " LOGIN"}, nil
		case opLock:
			return []string{"ALTER ROLE " + who + " NOLOGIN", "COMMENT ON ROLE " + who + " IS '" + pgLockedMark + "'"}, nil
		case opUnlock:
			return []string{"ALTER ROLE " + who + " LOGIN", "COMMENT ON ROLE " + who + " IS NULL"}, nil
		}
		return []string{"DROP ROLE " + who}, nil
	case MySQL:
		switch op {
		case opCreate:
			return []string{"CREATE USER " + who + " IDENTIFIED BY RANDOM PASSWORD"}, nil
		case opLock:
			return []string{"ALTER USER " + who + " ACCOUNT LOCK"}, nil
		case opUnlock:
			return []string{"ALTER USER " + who + " ACCOUNT UNLOCK"}, nil
		}
		return []string{"DROP USER " + who}, nil
	case SQLServer:
		switch op {
		case opCreate:
			pw, err := randomSecret()
			if err != nil {
				return nil, err
			}
			return []string{"CREATE LOGIN " + who + " WITH PASSWORD = N'" + pw + "', CHECK_POLICY = ON"}, nil
		case opLock:
			return []string{"ALTER LOGIN " + who + " DISABLE"}, nil
		case opUnlock:
			return []string{"ALTER LOGIN " + who + " ENABLE"}, nil
		}
		return []string{"DROP LOGIN " + who}, nil
	case Oracle:
		switch op {
		case opCreate:
			pw, err := randomSecret()
			if err != nil {
				return nil, err
			}
			return []string{`CREATE USER ` + who + ` IDENTIFIED BY "` + pw + `"`}, nil
		case opLock:
			return []string{"ALTER USER " + who + " ACCOUNT LOCK"}, nil
		case opUnlock:
			return []string{"ALTER USER " + who + " ACCOUNT UNLOCK"}, nil
		}
		return []string{"DROP USER " + who}, nil
	}
	return nil, fmt.Errorf("unknown engine %q", engine)
}
