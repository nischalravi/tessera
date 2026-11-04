package restgen

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen/fakerest"
)

// FromStored reads through the stored spec and the opened credential, leaves the spec untouched
// and refuses what Validate refuses without echoing the credential.
func TestFromStored(t *testing.T) {
	f := newFake(t, 3)
	spec := baseSpec(f, "page")
	cn, err := FromStored(spec, fakerest.Bearer, devRT, httpClient(t))
	if err != nil {
		t.Fatal(err)
	}
	if cn.System() != DefaultSystem {
		t.Errorf("system %q", cn.System())
	}
	res, err := cn.Discover(context.Background())
	if err != nil || len(res.Accounts) != 3 {
		t.Fatalf("discover: %d accounts, %v", len(res.Accounts), err)
	}
	if spec.System != "" {
		t.Errorf("the stored spec was modified: %+v", spec)
	}

	for _, tc := range []struct {
		name string
		spec func() *Spec
		cred string
		want string
	}{
		{"no spec", func() *Spec { return nil }, "x", "no spec"},
		{"no credential", func() *Spec { return baseSpec(f, "page") }, "", "no stored credential"},
		{"metadata host", func() *Spec { s := baseSpec(f, "page"); s.BaseURL = "http://169.254.169.254"; return s }, "SECRET-VALUE", "metadata"},
		{"http in prod", func() *Spec { return baseSpec(f, "page") }, "SECRET-VALUE", "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromStored(tc.spec(), tc.cred, connsync.Runtime{Env: config.Prod}, httpClient(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SECRET-VALUE") {
				t.Errorf("error %v, want one containing %q and no secret", err, tc.want)
			}
		})
	}
}
