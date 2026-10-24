package unixssh_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
)

var devRT = connsync.Runtime{Env: config.Dev, AllowLoopback: true}

func params(f unixssh.Fake, mut func(*governed.Params)) governed.Params {
	p := governed.Params{Type: governed.UnixSSH, Secret: f.KeyPEM, Settings: map[string]string{
		"host": "127.0.0.1", "port": f.Port, "username": "tessera", "host_key": f.Fingerprint}}
	if mut != nil {
		mut(&p)
	}
	return p
}

func fake(t *testing.T) unixssh.Fake {
	return unixssh.StartFake(t, map[string]string{unixssh.CmdPasswd: unixssh.PasswdOut, unixssh.CmdGroup: unixssh.GroupOut,
		unixssh.CmdSudoers: unixssh.SudoersOut, unixssh.CmdLastlog: unixssh.LastlogOut})
}

func check(t *testing.T, p connectors.Prober, id string) checks.Result {
	t.Helper()
	c, ok := checks.Get(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return checks.Run(ctx, c, checks.Env{TemplateID: "unixssh", Probe: p, Now: time.Now()}, nil)
}

func TestGovernedProberAndConnector(t *testing.T) {
	f := fake(t)
	n := governed.Net{RT: devRT}
	p, err := wire.Prober(params(f, nil), n)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"auth_ok", "read_probe"} {
		if r := check(t, p, id); r.Status != checks.Pass {
			t.Errorf("%s: %s %s %v", id, r.Status, r.Message, r.Observed)
		}
	}
	auth, err := p.Authenticate(context.Background())
	if err != nil || !auth.OK || auth.Identity != "tessera" || auth.Mode != "ssh_key" {
		t.Errorf("auth = %+v, err = %v", auth, err)
	}
	st, err := p.Sample(context.Background(), connectors.SampleQuery{})
	if err != nil || !st.Available || st.PerClass["account"] != 5 || st.PerClass["group"] != 6 || st.PerClass["sudo_rule"] != 4 {
		t.Errorf("sample = %+v, err = %v", st, err)
	}
	cn, err := wire.Connector(params(f, nil), n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "unix" || len(res.Accounts) != 5 || len(res.Permissions) != 5 {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

func TestGovernedHostKeyMismatchFailsTheAuthCheck(t *testing.T) {
	f := fake(t)
	other := fake(t)
	p, err := wire.Prober(params(f, func(p *governed.Params) { p.Settings["host_key"] = other.Fingerprint }), governed.Net{RT: devRT})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := p.Authenticate(context.Background())
	if err != nil || auth.OK {
		t.Errorf("a host with another key authenticated: %+v, %v", auth, err)
	}
	if r := check(t, p, "auth_ok"); r.Status == checks.Pass {
		t.Error("auth_ok passed against an unpinned host")
	}
}

func TestGovernedRefusesBadInput(t *testing.T) {
	f := fake(t)
	for name, mut := range map[string]func(*governed.Params){
		"no key":        func(p *governed.Params) { p.Secret = "" },
		"not a key":     func(p *governed.Params) { p.Secret = "hunter2" },
		"no host key":   func(p *governed.Params) { delete(p.Settings, "host_key") },
		"url as host":   func(p *governed.Params) { p.Settings["host"] = "https://h" },
		"bad sudo":      func(p *governed.Params) { p.Settings["use_sudo"] = "1" },
		"prod loopback": nil,
	} {
		t.Run(name, func(t *testing.T) {
			n := governed.Net{RT: devRT}
			if mut == nil {
				n.RT = connsync.Runtime{Env: config.Prod}
			}
			p, err := wire.Prober(params(f, mut), n)
			if err == nil {
				// the prod runtime refuses the loopback address when the socket is opened
				_, err = p.Authenticate(context.Background())
				if err == nil {
					t.Fatal("accepted")
				}
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the error quotes the credential: %v", err)
			}
		})
	}
}

func TestGovernedParamsNeverPrintTheKey(t *testing.T) {
	f := fake(t)
	p := params(f, nil)
	for _, s := range []string{p.String(), p.GoString()} {
		if strings.Contains(s, "PRIVATE KEY") {
			t.Errorf("params print the key: %s", s)
		}
	}
}
