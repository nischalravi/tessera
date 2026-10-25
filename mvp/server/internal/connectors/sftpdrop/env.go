package sftpdrop

import (
	"errors"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
)

// FromEnv builds the connector from TESSERA_SFTPDROP_*:
//
//	TESSERA_SFTPDROP_HOST, _PORT, _USER, _HOST_KEY, _KEY   as TESSERA_UNIXSSH_* (host, port, login, pinned host key, key reference)
//	TESSERA_SFTPDROP_DIR                  the absolute directory the files are read from
//	TESSERA_SFTPDROP_ACCOUNTS_FILE        the accounts file name
//	TESSERA_SFTPDROP_ENTITLEMENTS_FILE    optional: the account-entitlement file name
//	TESSERA_SFTPDROP_COL_ACCOUNT_ID, _COL_USERNAME   required column names of the accounts file
//	TESSERA_SFTPDROP_COL_EMAIL, _COL_IDENTITY_ID, _COL_STATUS   optional
//	TESSERA_SFTPDROP_COL_ENT_ACCOUNT_ID, _COL_ENT_ENTITLEMENT   required with an entitlements file
//	TESSERA_SFTPDROP_COL_ENT_NAME, _COL_ENT_PRIVILEGED          optional
func FromEnv(getenv func(string) string, rt connsync.Runtime) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, nil)
}

// ConfigFromEnv is the environment mapping of FromEnv on its own, so a governed connection
// (internal/connectors/governed) reads its settings the same way.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_SFTPDROP_"
	// the SSH part is the Unix connector's mapping under this connector's names; sudo is not a setting here
	ssh, err := unixssh.ConfigFromEnv(func(k string) string {
		name, ok := strings.CutPrefix(k, "TESSERA_UNIXSSH_")
		switch {
		case !ok: // the target of a key reference (env:NAME) is not renamed
			return getenv(k)
		case name == "SUDO":
			return ""
		}
		return getenv(p + name)
	})
	if err != nil {
		return Config{}, errors.New(strings.Replace(err.Error(), "TESSERA_UNIXSSH_", p, 1))
	}
	v := func(k string) string { return strings.TrimSpace(getenv(p + k)) }
	cfg := Config{SSH: ssh, Directory: v("DIR"), AccountsFile: v("ACCOUNTS_FILE"), EntitlementsFile: v("ENTITLEMENTS_FILE")}
	cfg.Mapping.Accounts = flatfile.AccountCols{AccountID: v("COL_ACCOUNT_ID"), Username: v("COL_USERNAME"), Email: v("COL_EMAIL"),
		IdentityID: v("COL_IDENTITY_ID"), Status: v("COL_STATUS")}
	if cfg.EntitlementsFile != "" {
		cfg.Mapping.Entitlements = &flatfile.EntitlementCols{AccountID: v("COL_ENT_ACCOUNT_ID"), Entitlement: v("COL_ENT_ENTITLEMENT"),
			Name: v("COL_ENT_NAME"), Privileged: v("COL_ENT_PRIVILEGED")}
	}
	return cfg, nil
}
