package restgen

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromEnv builds the source connector named "rest" (TESSERA_CONNECTORS=rest),
// like the other production connectors. TESSERA_REST_SPEC is the absolute path
// of the Spec file (JSON or YAML); TESSERA_REST_CREDENTIAL is a reference to
// the secret, env:NAME or file:/path (connsync.ResolveSecret), holding the
// bare secret or the JSON object ParseSecrets reads. A literal secret in the
// environment variable is refused.
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client) (connectors.Connector, error) {
	path := getenv("TESSERA_REST_SPEC")
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("rest: TESSERA_REST_SPEC must be the absolute path of the connector config")
	}
	f, err := os.Open(filepath.Clean(path)) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, errors.New("rest: cannot read TESSERA_REST_SPEC")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 256<<10+1))
	if err != nil {
		return nil, errors.New("rest: cannot read TESSERA_REST_SPEC")
	}
	spec, err := ParseSpec(raw)
	if err != nil {
		return nil, err
	}
	ref, err := connsync.ResolveSecret(getenv("TESSERA_REST_CREDENTIAL"), getenv)
	if err != nil {
		return nil, errors.New("rest: TESSERA_REST_CREDENTIAL: " + err.Error())
	}
	sec, err := ParseSecrets(spec.Auth.Type, ref.Reveal())
	if err != nil {
		return nil, errors.New("rest: " + err.Error())
	}
	return New(spec, sec, rt, hc)
}
