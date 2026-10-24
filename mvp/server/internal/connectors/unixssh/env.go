package unixssh

import (
	"errors"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// FromEnv builds the connector from TESSERA_UNIXSSH_*:
//
//	TESSERA_UNIXSSH_HOST       the host name or IP address
//	TESSERA_UNIXSSH_PORT       optional, default 22
//	TESSERA_UNIXSSH_USER       the SSH login
//	TESSERA_UNIXSSH_HOST_KEY   the pinned host key: SHA256:<fingerprint> or a public key line
//	TESSERA_UNIXSSH_KEY        reference to the private key: file:/abs/path or env:NAME
//	TESSERA_UNIXSSH_SUDO       true: read the sudoers files through sudo -n (default false)
func FromEnv(getenv func(string) string, rt connsync.Runtime) (connectors.Connector, error) {
	cfg, err := ConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, nil)
}

// ConfigFromEnv is the environment mapping of FromEnv on its own, so a governed connection
// (internal/connectors/governed) reads its settings the same way.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	const p = "TESSERA_UNIXSSH_"
	key, err := connsync.ResolveSecret(getenv(p+"KEY"), getenv)
	if err != nil {
		return Config{}, errors.New(p + "KEY: " + err.Error())
	}
	cfg := Config{Host: strings.TrimSpace(getenv(p + "HOST")), Username: strings.TrimSpace(getenv(p + "USER")),
		HostKey: strings.TrimSpace(getenv(p + "HOST_KEY")), Key: key}
	if v := strings.TrimSpace(getenv(p + "PORT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, errors.New(p + "PORT: must be between 1 and 65535")
		}
		cfg.Port = n
	}
	switch v := strings.TrimSpace(getenv(p + "SUDO")); v {
	case "", "false":
	case "true":
		cfg.UseSudo = true
	default:
		return Config{}, errors.New(p + "SUDO: must be true or false")
	}
	return cfg, nil
}
