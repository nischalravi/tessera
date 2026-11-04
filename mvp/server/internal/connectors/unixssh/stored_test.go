package unixssh_test

import (
	"context"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
)

// FromStored reads host, port, login and pinned host key from the stored config and the private key from
// the credential; the host key is mandatory and a metadata host is refused.
func TestFromStored(t *testing.T) {
	f := fake(t)
	good := unixssh.Stored{Host: "127.0.0.1", Port: f.Port, Username: "tessera", HostKey: f.Fingerprint, Credential: f.KeyPEM}
	c, err := unixssh.FromStored(good, devRT)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(context.Background())
	if err != nil || c.System() != "unix" || len(res.Accounts) != 5 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	for name, mut := range map[string]func(*unixssh.Stored){
		"no key":        func(s *unixssh.Stored) { s.Credential = "" },
		"not a key":     func(s *unixssh.Stored) { s.Credential = "hunter2" },
		"no host key":   func(s *unixssh.Stored) { s.HostKey = "" },
		"bad host key":  func(s *unixssh.Stored) { s.HostKey = "SHA256:short" },
		"no host":       func(s *unixssh.Stored) { s.Host = "" },
		"url as host":   func(s *unixssh.Stored) { s.Host = "https://h" },
		"metadata ip":   func(s *unixssh.Stored) { s.Host = "169.254.169.254" },
		"metadata name": func(s *unixssh.Stored) { s.Host = "metadata.google.internal" },
		"bad port":      func(s *unixssh.Stored) { s.Port = "70000" },
		"port text":     func(s *unixssh.Stored) { s.Port = "ssh" },
		"bad sudo":      func(s *unixssh.Stored) { s.UseSudo = "1" },
		"bad user":      func(s *unixssh.Stored) { s.Username = "-root" },
	} {
		t.Run(name, func(t *testing.T) {
			s := good
			mut(&s)
			for _, rt := range []connsync.Runtime{devRT, {Env: config.Prod}} {
				_, err := unixssh.FromStored(s, rt)
				if err == nil {
					t.Fatalf("accepted in %s", rt.Env)
				}
				if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "PRIVATE KEY") {
					t.Errorf("the error quotes the credential: %v", err)
				}
			}
		})
	}
	// sudo and a default port are accepted
	s := good
	s.Port, s.UseSudo = "", "true"
	if _, err := unixssh.FromStored(s, devRT); err != nil {
		t.Errorf("default port with sudo: %v", err)
	}
}

// The governed build of the connection is stored-backed: it replaces the env-configured connector of the
// system, reads the same data, and fails closed without the pinned host key or the credential.
func TestStoredConnectorIsConnectionBacked(t *testing.T) {
	f := fake(t)
	n := governed.Net{RT: devRT}
	cn, err := wire.Connector(params(f, nil), n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "unix" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	if res, err := cn.Discover(context.Background()); err != nil || res.Stats == nil {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	for name, mut := range map[string]func(*governed.Params){
		"no credential": func(p *governed.Params) { p.Secret = "" },
		"no host key":   func(p *governed.Params) { delete(p.Settings, "host_key") },
		"metadata host": func(p *governed.Params) { p.Settings["host"] = "169.254.169.254" },
	} {
		if _, err := wire.Connector(params(f, mut), n); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}
