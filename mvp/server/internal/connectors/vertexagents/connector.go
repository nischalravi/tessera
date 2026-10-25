package vertexagents

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
func (*Connector) DisplayName() string { return "Google Vertex AI Agent Engine" }
func (*Connector) TypeName() string    { return "VertexAgentsConnector" }

// StreamEvents: no usage is read.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// ConfigFromEnv reads TESSERA_VERTEX_*:
//
//	TESSERA_VERTEX_KEY         reference to the service account key (JSON): file:/abs/path or env:NAME
//	TESSERA_VERTEX_PROJECT     the project id or number
//	TESSERA_VERTEX_LOCATION    the region whose agents are read, for example us-central1
//	TESSERA_VERTEX_OWNER       optional, the e-mail address of the person accountable for the agents
//	TESSERA_VERTEX_API_URL, TESSERA_VERTEX_TOKEN_URL   dev and test overrides; refused outside dev
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_VERTEX_"
	key, err := connsync.ResolveSecret(getenv(p+"KEY"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "KEY: " + err.Error())
	}
	return Config{Key: key, ProjectID: strings.TrimSpace(getenv(p + "PROJECT")), Location: strings.TrimSpace(getenv(p + "LOCATION")),
		Owner: strings.TrimSpace(getenv(p + "OWNER")), APIURL: getenv(p + "API_URL"), TokenURL: getenv(p + "TOKEN_URL")}, nil
}

// FromEnv builds the read connector from TESSERA_VERTEX_* (ConfigFromEnv).
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

// Discover reads every reasoning engine of the location and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	agents, err := c.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return agentmap.Build(System, "vertex:", "Google Vertex AI Agent Engine agent", agents), nil
}
