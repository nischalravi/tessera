package agentforce

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
func (*Connector) DisplayName() string { return "Salesforce Agentforce" }
func (*Connector) TypeName() string    { return "AgentforceConnector" }

// StreamEvents: no usage is read.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// ConfigFromEnv reads TESSERA_AGENTFORCE_*:
//
//	TESSERA_AGENTFORCE_BASE_URL     the org's My Domain URL, https://acme.my.salesforce.com
//	TESSERA_AGENTFORCE_CREDENTIAL   reference to the credential JSON (client_id, username, private_key): file:/abs/path or env:NAME
//	TESSERA_AGENTFORCE_API_VERSION  optional, v61.0 and the like
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_AGENTFORCE_"
	secret, err := connsync.ResolveSecret(getenv(p+"CREDENTIAL"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "CREDENTIAL: " + err.Error())
	}
	return Config{BaseURL: strings.TrimSpace(getenv(p + "BASE_URL")), Credential: secret, APIVersion: strings.TrimSpace(getenv(p + "API_VERSION"))}, nil
}

// FromEnv builds the read connector from TESSERA_AGENTFORCE_* (ConfigFromEnv).
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

// Discover reads every agent of the org and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	agents, err := c.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return agentmap.Build(System, "agentforce:", "Salesforce Agentforce agent", agents), nil
}
