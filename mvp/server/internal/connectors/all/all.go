// Package all registers the production connectors with connectors.Factories,
// so TESSERA_CONNECTORS=okta,entra (or any mix with the demo-* names) works.
//
// It is a separate package because the connectors import package connectors
// for the record types, so package connectors cannot import them back. The
// server binary calls Register once it has built its outbound client:
//
//	all.Register(outbound, connsync.RuntimeFromConfig(cfg))
//
// The default stays the demo company: nothing here runs unless the spec names
// okta or entra. Credentials and URLs are read from TESSERA_OKTA_* and
// TESSERA_ENTRA_* when the connector is built, never earlier. The connectors
// use the shared client they are given (safehttp.ForConfig) and never build
// their own.
package all

import (
	"net/http"
	"os"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/entra"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/okta"
)

// Register adds the okta and entra factories. hc is the server's shared
// outbound client and rt comes from the validated configuration.
func Register(hc *http.Client, rt connsync.Runtime) {
	connectors.Factories["okta"] = func(now time.Time) (connectors.Connector, error) {
		return okta.FromEnv(os.Getenv, now, rt, hc)
	}
	connectors.Factories["entra"] = func(now time.Time) (connectors.Connector, error) {
		return entra.FromEnv(os.Getenv, now, rt, hc)
	}
}
