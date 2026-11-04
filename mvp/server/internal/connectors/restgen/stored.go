package restgen

import (
	"errors"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromStored builds the source connector from a connection's stored spec and its opened credential
// (the bare secret or the JSON object ParseSecrets reads) instead of TESSERA_REST_SPEC and
// TESSERA_REST_CREDENTIAL. Nothing is read from the environment. The spec is validated as New
// does, under the runtime's URL policy; the spec is not modified.
func FromStored(spec *Spec, credential string, rt connsync.Runtime, hc *http.Client) (connectors.Connector, error) {
	if spec == nil {
		return nil, errors.New("rest: the connection has no spec")
	}
	if credential == "" {
		return nil, errors.New("rest: the connection has no stored credential")
	}
	sec, err := ParseSecrets(spec.Auth.Type, credential)
	if err != nil {
		return nil, errors.New("rest: " + err.Error())
	}
	cp := *spec
	return New(&cp, sec, rt, hc)
}
