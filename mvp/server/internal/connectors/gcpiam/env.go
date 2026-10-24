package gcpiam

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromEnv builds the connector from TESSERA_GCP_*:
//
//	TESSERA_GCP_KEY           reference to the service account key (JSON): file:/abs/path or env:NAME
//	TESSERA_GCP_ORG_ID        optional, the numeric organization id (its folders and projects are walked)
//	TESSERA_GCP_FOLDER_IDS    optional, comma separated folder ids (walked)
//	TESSERA_GCP_PROJECT_IDS   optional, comma separated project ids
//	TESSERA_GCP_CRM_URL, TESSERA_GCP_IAM_URL, TESSERA_GCP_TOKEN_URL   dev and test overrides; refused in prod
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, hc, now)
}

// ConfigFromEnv is the environment mapping of FromEnv on its own, so a governed connection
// (internal/connectors/governed) reads its settings the same way.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_GCP_"
	key, err := connsync.ResolveSecret(getenv(p+"KEY"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "KEY: " + err.Error())
	}
	return Config{Key: key, OrganizationID: strings.TrimSpace(getenv(p + "ORG_ID")), FolderIDs: split(getenv(p + "FOLDER_IDS")),
		ProjectIDs: split(getenv(p + "PROJECT_IDS")), CRMURL: getenv(p + "CRM_URL"), IAMURL: getenv(p + "IAM_URL"),
		TokenURL: getenv(p + "TOKEN_URL")}, nil
}

func split(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
