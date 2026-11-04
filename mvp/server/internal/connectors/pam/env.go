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
	cfg, err := ConfigFromEnv(vendor, getenv)
	if err != nil {
		return nil, err
	}
	v, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(v), nil
}

// ConfigFromEnv is the environment mapping of FromEnv on its own, so a governed
// connection (internal/connectors/governed) reads its settings the same way.
func ConfigFromEnv(vendor string, getenv func(string) string) (Config, error) {
	p := "TESSERA_" + strings.ToUpper(vendor) + "_"
	secret, err := connsync.ResolveSecret(getenv(p+"SECRET"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "SECRET: " + err.Error())
	}
	return Config{Vendor: vendor, BaseURL: getenv(p + "BASE_URL"), Username: getenv(p + "USER"), Secret: secret,
		APIRoot: getenv(p + "API_ROOT")}, nil
}

// Stored is a vault connection as the readiness service holds it: the vendor, server, service user and
// API root of its stored config and its opened credential.
type Stored struct {
	Vendor   string // cyberark, delinea or beyondtrust
	BaseURL  string // https://pvwa.example.com
	Username string // the service user (BeyondTrust: the run-as user)
	APIRoot  string // optional API root path
	// Credential is the sealed credential, opened: the user's password (BeyondTrust: the API key).
	Credential string
}

// FromStored builds the read connector from a connection's stored config instead of TESSERA_<VENDOR>_*
// variables. Nothing is read from the environment: getenv only supplies the dev override
// TESSERA_<VENDOR>_BASE_URL (the caller passes the layer that refuses it outside dev).
func FromStored(s Stored, getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	secret := strings.TrimSpace(s.Credential)
	if secret == "" {
		return nil, errors.New("pam: the connection has no stored credential")
	}
	base := strings.TrimSpace(getenv("TESSERA_" + strings.ToUpper(s.Vendor) + "_BASE_URL"))
	if base == "" {
		base = strings.TrimSpace(s.BaseURL)
	}
	if base == "" {
		return nil, errors.New("pam: the connection's base_url is required")
	}
	v, err := Open(Config{Vendor: s.Vendor, BaseURL: base, Username: strings.TrimSpace(s.Username), Secret: connsync.NewSecret(secret),
		APIRoot: strings.TrimSpace(s.APIRoot)}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(v), nil
}
