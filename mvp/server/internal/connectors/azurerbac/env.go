package azurerbac

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromEnv builds the connector from TESSERA_AZURE_*:
//
//	TESSERA_AZURE_TENANT_ID          the directory GUID
//	TESSERA_AZURE_CLIENT_ID          the application (client) GUID
//	TESSERA_AZURE_CREDENTIAL         reference to the client secret, or to a PEM with the certificate and its RSA key: file:/abs/path or env:NAME
//	TESSERA_AZURE_SUBSCRIPTIONS      optional, comma separated subscription GUIDs
//	TESSERA_AZURE_MANAGEMENT_GROUPS  optional, comma separated management group ids (both empty: everything listable)
//	TESSERA_AZURE_ELIGIBLE           true to read PIM eligible assignments
//	TESSERA_AZURE_MANAGEMENT_URL, TESSERA_AZURE_AUTHORITY_URL   dev and test overrides; refused in prod
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
	const p = "TESSERA_AZURE_"
	secret, err := connsync.ResolveSecret(getenv(p+"CREDENTIAL"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "CREDENTIAL: " + err.Error())
	}
	return Config{TenantID: getenv(p + "TENANT_ID"), ClientID: getenv(p + "CLIENT_ID"), Credential: secret,
		SubscriptionIDs: split(getenv(p + "SUBSCRIPTIONS")), ManagementGroupIDs: split(getenv(p + "MANAGEMENT_GROUPS")),
		IncludeEligible: strings.EqualFold(strings.TrimSpace(getenv(p+"ELIGIBLE")), "true"),
		ManagementURL:   getenv(p + "MANAGEMENT_URL"), AuthorityURL: getenv(p + "AUTHORITY_URL")}, nil
}

// Stored is an Azure RBAC connection as the readiness service holds it: the app registration and scope
// of its stored config and its opened credential.
type Stored struct {
	// TenantID and ClientID are the directory and application GUIDs.
	TenantID, ClientID string
	// SubscriptionIDs and ManagementGroupIDs are the comma separated scopes (both empty: everything listable).
	SubscriptionIDs, ManagementGroupIDs string
	// IncludeEligible is "true" to read PIM eligible assignments.
	IncludeEligible string
	// Credential is the sealed credential, opened: the client secret, or a PEM with the certificate and its RSA key.
	Credential string
}

// FromStored builds the connector from a connection's stored config instead of TESSERA_AZURE_* variables.
// Nothing is read from the environment: getenv only supplies the dev overrides TESSERA_AZURE_MANAGEMENT_URL
// and TESSERA_AZURE_AUTHORITY_URL (the caller passes the layer that refuses them outside dev).
func FromStored(s Stored, getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cred := strings.TrimSpace(s.Credential)
	if cred == "" {
		return nil, errors.New("azurerbac: the connection has no stored credential")
	}
	return New(Config{TenantID: strings.TrimSpace(s.TenantID), ClientID: strings.TrimSpace(s.ClientID), Credential: connsync.NewSecret(cred),
		SubscriptionIDs: split(s.SubscriptionIDs), ManagementGroupIDs: split(s.ManagementGroupIDs),
		IncludeEligible: strings.EqualFold(strings.TrimSpace(s.IncludeEligible), "true"),
		ManagementURL:   getenv("TESSERA_AZURE_MANAGEMENT_URL"), AuthorityURL: getenv("TESSERA_AZURE_AUTHORITY_URL")}, rt, hc, now)
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
