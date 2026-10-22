package pam

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromEnv builds the read connector of a vendor from TESSERA_<VENDOR>_*:
//
//	TESSERA_CYBERARK_BASE_URL   https://pvwa.example.com   (likewise TESSERA_DELINEA_*, TESSERA_BEYONDTRUST_*)
//	TESSERA_CYBERARK_USER       the service user (BeyondTrust: the run-as user)
//	TESSERA_CYBERARK_SECRET     reference to its password (BeyondTrust: the API key): file:/abs/path or env:NAME
//	TESSERA_CYBERARK_API_ROOT   optional API root path
//
// The user needs read access to safes, members and accounts (CyberArk: Audit
// Users and List Accounts on each safe; Delinea: a role with view on folders
// and folder permissions; BeyondTrust: a key with read on smart rules and user groups).
func FromEnv(vendor string, getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	p := "TESSERA_" + strings.ToUpper(vendor) + "_"
	secret, err := connsync.ResolveSecret(getenv(p+"SECRET"), getenv)
	if err != nil {
		return nil, errors.New(p + "SECRET: " + err.Error())
	}
	v, err := Open(Config{Vendor: vendor, BaseURL: getenv(p + "BASE_URL"), Username: getenv(p + "USER"), Secret: secret,
		APIRoot: getenv(p + "API_ROOT")}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(v), nil
}
