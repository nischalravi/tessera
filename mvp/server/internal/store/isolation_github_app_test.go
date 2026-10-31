package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// githubAppCovered lists the GitHub App repository methods the test below exercises
// (TestIsolation_EveryTenantTxMethodCovered).
func githubAppCovered() map[string]bool {
	return map[string]bool{"GitHubAppSettings": true, "PutGitHubAppSettings": true, "GitHubPRCheck": true, "PutGitHubPRCheck": true}
}

// The GitHub App settings and the posted checks (schema/0957, issue #656) are a tenant's own: the same repository and
// pull request number in two tenants are two records, and one tenant's write never changes the other's.
func TestIsolation_GitHubApp(t *testing.T) {
	f := storetest.TwoTenants(t)
	later := storetest.Now.Add(time.Hour)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.PutGitHubAppSettings(&store.GitHubAppSettings{Enabled: true, AppID: "123", InstallationID: 7, Repo: "o/policy",
				KeyEnc: []byte("sealed-" + tn.Slug), KeyFingerprint: "SHA256:" + tn.Slug, KeySetAt: "t", UpdatedBy: "test"}, later); err != nil {
				return err
			}
			return c.PutGitHubPRCheck(&store.GitHubPRCheck{Repo: "o/policy", PullNumber: 5, HeadSHA: "a", CheckRunID: 11, CommentID: 22,
				Conclusion: "success", DiffSHA256: tn.Slug}, later)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(label string, tn storetest.Tenant, wantKey, wantConclusion string) {
		t.Helper()
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			s, err := c.GitHubAppSettings()
			if err != nil || !s.Enabled || string(s.KeyEnc) != wantKey || s.InstallationID != 7 {
				t.Errorf("%s: GitHubAppSettings = %+v, %v; want its own", label, s, err)
			}
			pc, err := c.GitHubPRCheck("o/policy", 5)
			if err != nil || pc == nil || pc.Conclusion != wantConclusion || pc.DiffSHA256 != tn.Slug {
				t.Errorf("%s: GitHubPRCheck = %+v, %v; want its own", label, pc, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check("A", f.A, "sealed-"+f.A.Slug, "success")
	check("B", f.B, "sealed-"+f.B.Slug, "success")

	// B changing its settings and its check leaves A's untouched
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.PutGitHubAppSettings(&store.GitHubAppSettings{AppID: "9", InstallationID: 7, UpdatedBy: "test", KeyEnc: []byte("rotated")}, later); err != nil {
			return err
		}
		return c.PutGitHubPRCheck(&store.GitHubPRCheck{Repo: "o/policy", PullNumber: 5, HeadSHA: "b", Conclusion: "failure", DiffSHA256: f.B.Slug}, later)
	})
	check("A after B's write", f.A, "sealed-"+f.A.Slug, "success")

	// a pull request nothing was posted on has no record
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if pc, err := c.GitHubPRCheck("o/other", 5); err != nil || pc != nil {
			t.Errorf("GitHubPRCheck of an unknown pull request = %+v, %v; want nil", pc, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
