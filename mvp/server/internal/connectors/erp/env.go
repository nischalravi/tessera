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
