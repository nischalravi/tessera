package wire

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
)

// Options is the readiness wiring of the governed connector types: the
// server's guarded outbound client, the validated runtime, the tenant data
// directory (AgentCore snapshots) and the openers of the real probers and
// connectors. Set it as readiness.Service.Runner.Gov in every process that
// validates, dry-runs or syncs a governed connection (the API, the worker).
func Options(hc *http.Client, rt connsync.Runtime, dataDir string, prod bool) readiness.GovOptions {
	return readiness.GovOptions{Client: hc, Runtime: rt, DataDir: dataDir, Prod: prod, Prober: Prober, Connector: Connector,
		AWS: func(p governed.Params, hc *http.Client, now func() time.Time) (connectors.Prober, error) {
			if prod {
				// a governed AWS connection holds an access key; prod reads AWS
				// with federated credentials only (/api/aws/connectors, EP-2)
				return nil, awsorg.ErrStaticKeysDisabled
			}
			return awsorg.GovernedProber(p, hc, now)
		}}
}
