package sftpdrop_test

import (
	"context"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"maps"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sftpdrop"
)

// FromStored reads the server, directory, files and columns from the stored settings and the private key
// from the credential; the host key is mandatory and a metadata host is refused.
func TestFromStored(t *testing.T) {
	f := fake(t)
	base := params(f, nil).Settings
	build := func(mut func(map[string]string)) (map[string]string, error) {
		set := maps.Clone(base)
		if mut != nil {
			mut(set)
		}
		_, err := sftpdrop.FromStored(sftpdrop.Stored{Settings: set, Credential: f.KeyPEM}, devRT)
		return set, err
	}
	c, err := sftpdrop.FromStored(sftpdrop.Stored{Settings: base, Credential: f.KeyPEM}, devRT)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(context.Background())
	if err != nil || c.System() != "sftp" || len(res.Accounts) != 2 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	for name, mut := range map[string]func(map[string]string){
		"no host key":   func(m map[string]string) { delete(m, "host_key") },
		"bad host key":  func(m map[string]string) { m["host_key"] = "SHA256:short" },
		"no host":       func(m map[string]string) { delete(m, "host") },
		"metadata ip":   func(m map[string]string) { m["host"] = "169.254.169.254" },
		"metadata name": func(m map[string]string) { m["host"] = "metadata.google.internal" },
		"bad port":      func(m map[string]string) { m["port"] = "0" },
		"no accounts":   func(m map[string]string) { delete(m, "accounts_file") },
		"no column":     func(m map[string]string) { delete(m, "accounts_username") },
		"bad age":       func(m map[string]string) { m["max_age_hours"] = "99999" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(mut); err == nil {
				t.Error("accepted")
			}
		})
	}
	for name, s := range map[string]sftpdrop.Stored{
		"no credential": {Settings: base},
		"not a key":     {Settings: base, Credential: "hunter2"},
	} {
		for _, rt := range []connsync.Runtime{devRT, {Env: config.Prod}} {
			_, err := sftpdrop.FromStored(s, rt)
			if err == nil {
				t.Errorf("%s: accepted in %s", name, rt.Env)
			} else if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("%s: the error quotes the credential: %v", name, err)
			}
		}
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
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "sftp" {
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
