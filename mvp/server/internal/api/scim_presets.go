package api

import (
	"net/http"

	scimpreset "github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
)

// listSCIMPresets is the vendor library behind the SCIM tiles of the New
// connection picker: a typed table in code, the same for every tenant. A
// connection created from a preset carries its id in config.preset.
func (s *Server) listSCIMPresets(_ *http.Request, _ *params) (int, any, error) {
	return http.StatusOK, scimpreset.Presets, nil
}
