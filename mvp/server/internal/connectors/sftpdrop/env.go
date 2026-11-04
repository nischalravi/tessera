package sftpdrop

import (
	"errors"
	"strconv"
	"strings"
	"time"

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
//	TESSERA_SFTPDROP_MAX_AGE_HOURS        optional, 1 to 8760: a file older than this is flagged stale by the probe
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
	if h := v("MAX_AGE_HOURS"); h != "" {
		n, err := strconv.Atoi(h)
		if err != nil || n < 1 || n > MaxAgeHours {
			return Config{}, errors.New(p + "MAX_AGE_HOURS: must be a whole number of hours between 1 and " + strconv.Itoa(MaxAgeHours))
		}
		cfg.MaxAge = time.Duration(n) * time.Hour
	}
	return cfg, nil
}

// Stored is an SFTP drop connection as the readiness service holds it: its settings (the keys of
// governed.SettingSpecs: host, port, username, host_key, directory, the file names, the column names and
// max_age_hours) and its opened credential, the unencrypted SSH private key.
type Stored struct {
	Settings   map[string]string
	Credential string
}

// settingNames maps each setting key to the suffix of the TESSERA_SFTPDROP_* variable that holds the
// same value, so the stored and the environment mappings parse one way.
var settingNames = map[string]string{"host": "HOST", "port": "PORT", "username": "USER", "host_key": "HOST_KEY",
	"directory": "DIR", "accounts_file": "ACCOUNTS_FILE", "entitlements_file": "ENTITLEMENTS_FILE",
	"accounts_account_id": "COL_ACCOUNT_ID", "accounts_username": "COL_USERNAME", "accounts_email": "COL_EMAIL",
	"accounts_identity_id": "COL_IDENTITY_ID", "accounts_status": "COL_STATUS",
	"entitlements_account_id": "COL_ENT_ACCOUNT_ID", "entitlements_entitlement": "COL_ENT_ENTITLEMENT",
	"entitlements_name": "COL_ENT_NAME", "entitlements_privileged": "COL_ENT_PRIVILEGED", "max_age_hours": "MAX_AGE_HOURS"}

// FromStored builds the connector from a connection's stored config instead of TESSERA_SFTPDROP_*
// variables. Nothing is read from the environment and there is no override. The host is never a cloud
// metadata host, and the host key is mandatory (a connection without one does not open).
func FromStored(s Stored, rt connsync.Runtime) (connectors.Connector, error) {
	key := strings.TrimSpace(s.Credential)
	if key == "" {
		return nil, errors.New("sftpdrop: the connection has no stored credential")
	}
	const keyVar = "TESSERA_SFTPDROP_KEY"
	m := map[string]string{keyVar: "env:TESSERA_GOVERNED_SECRET", "TESSERA_GOVERNED_SECRET": key}
	for k, name := range settingNames {
		m["TESSERA_SFTPDROP_"+name] = s.Settings[k]
	}
	cfg, err := ConfigFromEnv(func(k string) string { return m[k] })
	if err != nil {
		return nil, err
	}
	if err := unixssh.CheckHost(cfg.SSH.Host); err != nil {
		return nil, err
	}
	return New(cfg, rt, nil)
}
