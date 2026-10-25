package foundryagents

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentmap"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Connector is the read connector (connectors.Connector).
type Connector struct{ c *Client }

// NewConnector wraps a client.
func NewConnector(c *Client) *Connector { return &Connector{c} }

// Format prints the connector without its client's credentials (every verb): fmt cannot call the
// redacting methods of unexported fields.
func (c *Connector) Format(f fmt.State, _ rune) { c.c.Format(f, 'v') }

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Azure AI Foundry agents" }
func (*Connector) TypeName() string    { return "FoundryAgentsConnector" }

// StreamEvents: no usage is read.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// ConfigFromEnv reads TESSERA_FOUNDRY_*:
//
//	TESSERA_FOUNDRY_ENDPOINT    the project endpoint, https://<account>.services.ai.azure.com/api/projects/<project>
//	TESSERA_FOUNDRY_TENANT_ID   the directory GUID
//	TESSERA_FOUNDRY_CLIENT_ID   the application (client) GUID
//	TESSERA_FOUNDRY_CREDENTIAL  reference to the client secret, or to a PEM with the certificate and its RSA key: file:/abs/path or env:NAME
//	TESSERA_FOUNDRY_OWNER       optional, the e-mail address of the person accountable for agents that name no sponsor
//	TESSERA_FOUNDRY_AUTHORITY_URL   dev and test override; refused outside dev
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_FOUNDRY_"
	secret, err := connsync.ResolveSecret(getenv(p+"CREDENTIAL"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "CREDENTIAL: " + err.Error())
	}
	return Config{BaseURL: strings.TrimSpace(getenv(p + "ENDPOINT")), TenantID: getenv(p + "TENANT_ID"), ClientID: getenv(p + "CLIENT_ID"),
		Credential: secret, Owner: strings.TrimSpace(getenv(p + "OWNER")), AuthorityURL: getenv(p + "AUTHORITY_URL")}, nil
}

// FromEnv builds the read connector from TESSERA_FOUNDRY_* (ConfigFromEnv).
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	c, err := Open(cfg, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(c), nil
}

// Discover reads every agent of the project and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	agents, err := c.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return agentmap.Build(System, "foundry:", "Azure AI Foundry agent", agents), nil
}
