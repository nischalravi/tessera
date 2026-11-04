package sqldb

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromStored builds the connector from a connection's stored settings (engine, host, database,
// user, CA bundle, mode and app statements) and its opened credential, the database password,
// instead of TESSERA_SQL_*. Nothing is read from the environment or from files. The settings are
// validated as NewConnector does, under the runtime's policy (the host check included).
func FromStored(cfg *Config, password string, rt connsync.Runtime) (connectors.Connector, error) {
	if cfg == nil {
		return nil, errors.New("sqldb: the connection has no database settings")
	}
	if password == "" {
		return nil, errors.New("sqldb: the connection has no stored credential")
	}
	c := *cfg
	if c.Mode == "" {
		c.Mode = ModeNative
	}
	return NewConnector(c, connsync.NewSecret(password), rt)
}
