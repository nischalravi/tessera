package erp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromEnv builds the read connector of an ERP from TESSERA_<SYSTEM>_*:
//
//	TESSERA_SAP_BASE_URL       https://s4.example.com        (likewise TESSERA_ORACLE_*)
//	TESSERA_SAP_CLIENT_ID      the integration's OAuth client
//	TESSERA_SAP_CLIENT_SECRET  reference to its secret: file:/abs/path or env:NAME
//	TESSERA_SAP_API_ROOT       optional path of the authorization service
//	TESSERA_SAP_TOKEN_PATH     optional OAuth token path
func FromEnv(system string, getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(system, getenv)
	if err != nil {
		return nil, err
	}
	s, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(s, now), nil
}

// ConfigFromEnv is the environment mapping of FromEnv on its own, so a governed
// connection (internal/connectors/governed) reads its settings the same way.
func ConfigFromEnv(system string, getenv func(string) string) (Config, error) {
	p := "TESSERA_" + strings.ToUpper(system) + "_"
	secret, err := connsync.ResolveSecret(getenv(p+"CLIENT_SECRET"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "CLIENT_SECRET: " + err.Error())
	}
	return Config{System: system, BaseURL: getenv(p + "BASE_URL"), ClientID: getenv(p + "CLIENT_ID"), ClientSecret: secret,
		APIRoot: getenv(p + "API_ROOT"), TokenPath: getenv(p + "TOKEN_PATH")}, nil
}

// Stored is an ERP connection as the readiness service holds it: the system, server, OAuth client and
// paths of its stored config and its opened credential.
type Stored struct {
	System    string // sap or oracle
	BaseURL   string // https://s4.example.com
	ClientID  string // the integration's OAuth client
	APIRoot   string // optional path of the authorization service
	TokenPath string // optional OAuth token path
	// Credential is the sealed credential, opened: the client secret.
	Credential string
}

// FromStored builds the read connector from a connection's stored config instead of TESSERA_<SYSTEM>_*
// variables. Nothing is read from the environment: getenv only supplies the dev override
// TESSERA_<SYSTEM>_BASE_URL (the caller passes the layer that refuses it outside dev).
func FromStored(s Stored, getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	secret := strings.TrimSpace(s.Credential)
	if secret == "" {
		return nil, errors.New("erp: the connection has no stored credential")
	}
	base := strings.TrimSpace(getenv("TESSERA_" + strings.ToUpper(s.System) + "_BASE_URL"))
	if base == "" {
		base = strings.TrimSpace(s.BaseURL)
	}
	if base == "" {
		return nil, errors.New("erp: the connection's base_url is required")
	}
	sys, err := Open(Config{System: s.System, BaseURL: base, ClientID: strings.TrimSpace(s.ClientID), ClientSecret: connsync.NewSecret(secret),
		APIRoot: strings.TrimSpace(s.APIRoot), TokenPath: strings.TrimSpace(s.TokenPath)}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(sys, now), nil
}
