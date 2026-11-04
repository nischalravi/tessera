package unixssh

import (
	"errors"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
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

// Stored is a Unix SSH connection as the readiness service holds it: the host, port, login, pinned
// host key and sudo choice of its settings and its opened credential.
type Stored struct {
	Host     string // the host name or IP address
	Port     string // optional, default 22
	Username string // the SSH login
	// HostKey is the pinned host key (SHA256:<fingerprint> or a public key line). It is never optional: a
	// connection without one does not open, in any environment (there is no trust on first use).
	HostKey string
	// UseSudo is "true" to read the sudoers files through sudo -n ("" or "false" otherwise).
	UseSudo string
	// Credential is the sealed credential, opened: the unencrypted SSH private key (PEM or OpenSSH).
	Credential string
}

// FromStored builds the connector from a connection's stored config instead of TESSERA_UNIXSSH_*
// variables. Nothing is read from the environment, and there is no override: a dev host is a loopback
// address that the dev runtime allows.
func FromStored(s Stored, rt connsync.Runtime) (connectors.Connector, error) {
	cfg, err := StoredConfig(s)
	if err != nil {
		return nil, err
	}
	return New(cfg, rt, nil)
}

// StoredConfig maps a stored connection onto a Config. The host is checked as New checks it, and a
// cloud metadata host is refused; sftpdrop maps its SSH part through it too.
func StoredConfig(s Stored) (Config, error) {
	key := strings.TrimSpace(s.Credential)
	if key == "" {
		return Config{}, errors.New("unixssh: the connection has no stored credential")
	}
	cfg := Config{Host: strings.TrimSpace(s.Host), Username: strings.TrimSpace(s.Username),
		HostKey: strings.TrimSpace(s.HostKey), Key: connsync.NewSecret(key)}
	if err := CheckHost(cfg.Host); err != nil {
		return Config{}, err
	}
	if v := strings.TrimSpace(s.Port); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, errors.New("unixssh: the port must be between 1 and 65535")
		}
		cfg.Port = n
	}
	switch v := strings.TrimSpace(s.UseSudo); v {
	case "", "false":
	case "true":
		cfg.UseSudo = true
	default:
		return Config{}, errors.New("unixssh: use_sudo must be true or false")
	}
	return cfg, nil
}

// CheckHost is ValidateHost plus the refusal of a cloud metadata host. The readiness service calls it on
// save, so a host New would refuse is refused before it is stored.
func CheckHost(h string) error {
	if err := ValidateHost(h); err != nil {
		return err
	}
	if safehttp.IsMetadataHost(h) {
		return errors.New("unixssh: the host must not be a cloud metadata service")
	}
	return nil
}
