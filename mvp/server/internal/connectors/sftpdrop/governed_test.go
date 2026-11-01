package sftpdrop_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sftpdrop"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
)

var devRT = connsync.Runtime{Env: config.Dev, AllowLoopback: true}

func fake(t *testing.T) sftpdrop.Fake {
	f := sftpdrop.StartFake(t)
	f.Write("accounts.csv", "ID,Login,Mail\nu1,alice,alice@example.com\nu2,bob,bob@example.com\n")
	f.Write("ents.csv", "ID,Role\nu1,admin\nu2,viewer\n")
	return f
}

func params(f sftpdrop.Fake, mut func(*governed.Params)) governed.Params {
	p := governed.Params{Type: governed.SFTPDrop, Secret: f.KeyPEM, Settings: map[string]string{
		"host": "127.0.0.1", "port": f.Port, "username": "tessera", "host_key": f.Fingerprint, "directory": f.Dir,
		"accounts_file": "accounts.csv", "entitlements_file": "ents.csv", "accounts_account_id": "ID", "accounts_username": "Login", "accounts_email": "Mail",
		"entitlements_account_id": "ID", "entitlements_entitlement": "Role"}}
	if mut != nil {
		mut(&p)
	}
	return p
}

func check(t *testing.T, p connectors.Prober, id string) checks.Result {
	t.Helper()
	c, ok := checks.Get(id)
	if !ok {
		t.Fatalf("no check %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return checks.Run(ctx, c, checks.Env{TemplateID: "sftpdrop", Probe: p, Now: time.Now()}, nil)
}

func TestGovernedProberAndConnector(t *testing.T) {
	f := fake(t)
	n := governed.Net{RT: devRT}
	if errs := governed.ValidateSettings(governed.SFTPDrop, params(f, nil).Settings); len(errs) > 0 {
		t.Fatalf("settings: %v", errs)
	}
	p, err := wire.Prober(params(f, nil), n)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"auth_ok", "read_probe"} {
		if r := check(t, p, id); r.Status != checks.Pass {
			t.Errorf("%s: %s %s %v", id, r.Status, r.Message, r.Observed)
		}
	}
	st, err := p.Sample(context.Background(), connectors.SampleQuery{})
	if err != nil || !st.Available || st.PerClass["account"] != 2 || st.PerClass["entitlement"] != 2 {
		t.Errorf("sample = %+v, err = %v", st, err)
	}
	cn, err := wire.Connector(params(f, nil), n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "sftp" || len(res.Accounts) != 2 || len(res.Permissions) != 2 || len(res.Edges) != 2 {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

func TestGovernedHostKeyMismatchFailsTheAuthCheck(t *testing.T) {
	f, other := fake(t), fake(t)
	p, err := wire.Prober(params(f, func(p *governed.Params) { p.Settings["host_key"] = other.Fingerprint }), governed.Net{RT: devRT})
	if err != nil {
		t.Fatal(err)
	}
	if auth, err := p.Authenticate(context.Background()); err != nil || auth.OK {
		t.Errorf("a server with another key authenticated: %+v, %v", auth, err)
	}
	if r := check(t, p, "auth_ok"); r.Status == checks.Pass {
		t.Error("auth_ok passed against an unpinned server")
	}
}

func TestGovernedRefusesBadInput(t *testing.T) {
	f := fake(t)
	for name, mut := range map[string]func(*governed.Params){
		"no key":         func(p *governed.Params) { p.Secret = "" },
		"not a key":      func(p *governed.Params) { p.Secret = "hunter2" },
		"no host key":    func(p *governed.Params) { delete(p.Settings, "host_key") },
		"traversal":      func(p *governed.Params) { p.Settings["accounts_file"] = "../accounts.csv" },
		"relative dir":   func(p *governed.Params) { p.Settings["directory"] = "drop" },
		"ents no column": func(p *governed.Params) { delete(p.Settings, "entitlements_entitlement") },
		"prod loopback":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			n := governed.Net{RT: devRT}
			if mut == nil {
				n.RT = connsync.Runtime{Env: config.Prod}
			}
			p, err := wire.Prober(params(f, mut), n)
			if err == nil {
				if _, err = p.Authenticate(context.Background()); err == nil {
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
	p := params(fake(t), nil)
	for _, s := range []string{p.String(), p.GoString()} {
		if strings.Contains(s, "PRIVATE KEY") {
			t.Errorf("params print the key: %s", s)
		}
	}
}

// filesObserved is the read_probe's per-file observation (size, modified time, stale).
func filesObserved(t *testing.T, r checks.Result) map[string]map[string]any {
	t.Helper()
	files, ok := r.Observed["files"].([]map[string]any)
	if !ok {
		t.Fatalf("observed has no files: %v", r.Observed)
	}
	out := map[string]map[string]any{}
	for _, f := range files {
		out[f["role"].(string)] = f
	}
	return out
}

func TestProbeSurfacesFileSizeAndModifiedTime(t *testing.T) {
	f := fake(t)
	mt := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(f.Dir, "accounts.csv"), mt, mt); err != nil {
		t.Fatal(err)
	}
	p, err := wire.Prober(params(f, nil), governed.Net{RT: devRT})
	if err != nil {
		t.Fatal(err)
	}
	r := check(t, p, "read_probe")
	if r.Status != checks.Pass { // no maximum age: the file is reported, never flagged
		t.Fatalf("read_probe: %s %s %v", r.Status, r.Message, r.Observed)
	}
	files := filesObserved(t, r)
	acc, ent := files["accounts"], files["entitlements"]
	if acc == nil || ent == nil {
		t.Fatalf("files = %v", files)
	}
	st, _ := os.Stat(filepath.Join(f.Dir, "accounts.csv"))
	if acc["size"] != st.Size() || acc["modified"] != mt.UTC().Format(time.RFC3339) || acc["stale"] != false {
		t.Errorf("accounts = %v, want size %d modified %s", acc, st.Size(), mt.UTC().Format(time.RFC3339))
	}
}

func TestProbeFlagsAStaleFile(t *testing.T) {
	f := fake(t)
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join(f.Dir, "ents.csv"), old, old); err != nil { // a stuck export left the entitlements file
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		age  string
		want string
	}{
		{"older than the maximum", "24", checks.Fail},
		{"within the maximum", "96", checks.Pass},
		{"no maximum", "", checks.Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := wire.Prober(params(f, func(p *governed.Params) {
				if tc.age != "" {
					p.Settings["max_age_hours"] = tc.age
				}
			}), governed.Net{RT: devRT})
			if err != nil {
				t.Fatal(err)
			}
			r := check(t, p, "read_probe")
			if r.Status != tc.want {
				t.Fatalf("read_probe = %s %q, want %s", r.Status, r.Message, tc.want)
			}
			files := filesObserved(t, r)
			if files["accounts"]["stale"] != false || files["entitlements"]["stale"] != (tc.want == checks.Fail) {
				t.Errorf("stale flags = %v", files)
			}
			if tc.want == checks.Fail && !strings.Contains(r.Message, "entitlements") {
				t.Errorf("message does not name the stale file: %q", r.Message)
			}
		})
	}
}
