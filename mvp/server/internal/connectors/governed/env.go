package governed

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Net is what a prober or a connector needs of the server: the validated
// runtime, the safehttp client (already allowed the connection's configured
// port) and, for AWS, the factory of its prober (package awsorg implements it;
// it cannot be imported by the readiness packages without a cycle). Now is the
// run's clock.
type Net struct {
	RT  connsync.Runtime
	HC  *http.Client
	AWS func(p Params) (connectors.Prober, error)
	Now func() time.Time
}

// Clock returns the run's clock (the wall clock when none is set).
func (n Net) Clock() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now().UTC()
}

// secretVar is the name under which the opened credential is handed to the
// connectors' FromEnv mapping. The mapping reads it through the closure below,
// never from the process environment.
const secretVar = "TESSERA_GOVERNED_SECRET"

// Env returns the environment a connector's FromEnv reads, built from the
// connection: the same variables an operator would export for the legacy,
// env-configured connector, with the credential behind an env: reference that
// only this closure can resolve. The second result is the connector's own
// error when the connection cannot be mapped (a snapshot outside the tenant's
// directory, a prod refusal).
func (p Params) Env() (func(string) string, error) {
	t, ok := Lookup(p.Type)
	if !ok {
		return nil, fmt.Errorf("governed: no connector for type %q", p.Type)
	}
	m := map[string]string{secretVar: p.Secret}
	set := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
	pre := "TESSERA_" + strings.ToUpper(t.Vendor) + "_"
	switch p.Type {
	case CyberArk, Delinea, BeyondTrust:
		m[pre+"BASE_URL"], m[pre+"USER"], m[pre+"API_ROOT"] = p.BaseURL, set("username"), set("api_root")
		m[pre+"SECRET"] = "env:" + secretVar
	case SAP, Oracle:
		m[pre+"BASE_URL"], m[pre+"CLIENT_ID"] = p.BaseURL, set("client_id")
		m[pre+"API_ROOT"], m[pre+"TOKEN_PATH"] = set("api_root"), set("token_path")
		m[pre+"CLIENT_SECRET"] = "env:" + secretVar
	case GitHubScan:
		m["TESSERA_GITHUB_SCAN_ORG"], m["TESSERA_GITHUB_SCAN_API_URL"] = set("org"), p.BaseURL
		m["TESSERA_GITHUB_SCAN_TOKEN"] = "env:" + secretVar
	case AgentCore:
		path, err := confine(p.DataDir, p.Tenant, set("snapshot"))
		if err != nil {
			return nil, err
		}
		m["TESSERA_AGENTCORE_SNAPSHOT"] = path
		if p.Prod {
			m["TESSERA_ENV"] = config.Prod
		}
	default:
		return nil, fmt.Errorf("governed: %s is read by its own feature, not by the connector sync", p.Type)
	}
	return func(k string) string { return m[k] }, nil
}

// confine resolves a snapshot file name under <data dir>/<tenant id>/, the
// directory the tenant's own loader files live in. A name with a directory,
// a symbolic link that leads out and a missing file are refused, so one
// tenant's connection never reads another tenant's file or anything else on
// the server.
func confine(dataDir, tenant, name string) (string, error) {
	switch {
	case dataDir == "":
		return "", errors.New("agentcore: no data directory is configured (TESSERA_LOADER_DATA_DIR)")
	case tenant == "" || strings.ContainsAny(tenant, `/\.`):
		return "", errors.New("agentcore: the snapshot is outside the tenant's directory")
	case !fileRE.MatchString(name) || strings.Contains(name, ".."):
		return "", errors.New("agentcore: the snapshot must be a file name in the tenant's directory")
	}
	base, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return "", errors.New("agentcore: the data directory cannot be opened")
	}
	if base, err = filepath.Abs(base); err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(filepath.Join(base, tenant))
	if err != nil || filepath.Dir(root) != base {
		return "", errors.New("agentcore: the tenant has no data directory")
	}
	full, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return "", errors.New("agentcore: the snapshot file cannot be opened")
	}
	if !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", errors.New("agentcore: the snapshot is outside the tenant's directory")
	}
	return full, nil
}
