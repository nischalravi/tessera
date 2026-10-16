// Package all registers the production connectors with connectors.Factories,
// so TESSERA_CONNECTORS=okta,entra,google,workday (or any mix with the demo-*
// names) works.
//
// It is a separate package because the connectors import package connectors
// for the record types, so package connectors cannot import them back. The
// server binary imports it for its side effect:
//
//	import _ "github.com/nischalravi/tessera/mvp/server/internal/connectors/all"
//
// The default stays the demo company: nothing here runs unless the spec names
// a production name. Credentials and URLs are read from TESSERA_OKTA_*,
// TESSERA_ENTRA_*, TESSERA_GOOGLE_* and TESSERA_WORKDAY_* when the connector is
// built, never earlier.
package all

import (
	"os"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/entra"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/google"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/workday"
)

func init() {
	connectors.Factories["okta"] = func(now time.Time) (connectors.Connector, error) { return okta.FromEnv(os.Getenv, now) }
	connectors.Factories["entra"] = func(now time.Time) (connectors.Connector, error) { return entra.FromEnv(os.Getenv, now) }
	connectors.Factories["google"] = func(now time.Time) (connectors.Connector, error) { return google.FromEnv(os.Getenv, now) }
	connectors.Factories["workday"] = func(now time.Time) (connectors.Connector, error) { return workday.FromEnv(os.Getenv, now) }
}
