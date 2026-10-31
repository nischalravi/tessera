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
	return map[string]bool{"GitHubAppSettings": true, "PutGitHubAppSettings": true, "GitHubPRCheck": true, "PutGitHubPRCheck": true, "ClaimGitHubPRCheck": true, "ReleaseGitHubPRCheck": true,
		"GitHubWebhookSecret": true, "PutGitHubWebhookSecret": true, "DeleteGitHubWebhookSecret": true, "RecordGitHubDelivery": true, "ForgetGitHubDelivery": true}
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

// A claim on a pull request (schema/0960, issue #781) is a tenant's own and is held by one request at a time: the same
// repository and pull request in the other tenant is a separate claim, a second claim is refused until the first is
// released or older than its time to live.
func TestIsolation_GitHubPRCheckClaims(t *testing.T) {
	f := storetest.TwoTenants(t)
	at := storetest.Now
	claim := func(tn storetest.Tenant, now time.Time) (ok bool) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			var err error
			ok, err = c.ClaimGitHubPRCheck("o/policy", 5, now, time.Minute)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !claim(f.A, at) || !claim(f.B, at) {
		t.Fatal("each tenant must get its own claim on the same pull request")
	}
	if claim(f.A, at.Add(time.Second)) {
		t.Error("a second claim on the same pull request was granted")
	}
	// B releasing its claim does not free A's
	inB(t, f, func(c *store.TenantTx) error { return c.ReleaseGitHubPRCheck("o/policy", 5) })
	if claim(f.A, at.Add(2*time.Second)) {
		t.Error("B's release freed A's claim")
	}
	if !claim(f.B, at.Add(2*time.Second)) {
		t.Error("B could not claim after its release")
	}
	// a claim older than the time to live is replaced
	if !claim(f.A, at.Add(2*time.Minute)) {
		t.Error("an expired claim was not replaced")
	}
}

// The webhook secret and the handled delivery ids (schema/0963, issue #771) are a tenant's own: B never reads, replaces or
// deletes A's secret, the same delivery id in two tenants is two records, and B forgetting or pruning one leaves A's.
func TestIsolation_GitHubWebhook(t *testing.T) {
	f := storetest.TwoTenants(t)
	at := storetest.Now
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.PutGitHubWebhookSecret([]byte("sealed-"+tn.Slug), "test", at)
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(tn storetest.Tenant) (s *store.GitHubWebhookSecret) {
		t.Helper()
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			var err error
			s, err = c.GitHubWebhookSecret()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := read(f.A); s == nil || string(s.SecretEnc) != "sealed-"+f.A.Slug {
		t.Errorf("A's secret = %+v", s)
	}
	inB(t, f, func(c *store.TenantTx) error { return c.DeleteGitHubWebhookSecret() })
	if read(f.B) != nil {
		t.Error("B's secret was not deleted")
	}
	if s := read(f.A); s == nil || string(s.SecretEnc) != "sealed-"+f.A.Slug {
		t.Errorf("B's delete changed A's secret: %+v", s)
	}

	record := func(tn storetest.Tenant, id string, now time.Time) (fresh bool) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			var err error
			fresh, err = c.RecordGitHubDelivery(id, now.Add(time.Hour), now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return fresh
	}
	if !record(f.A, "d-1", at) || !record(f.B, "d-1", at) {
		t.Fatal("each tenant must record the same delivery id once")
	}
	if record(f.A, "d-1", at.Add(time.Minute)) {
		t.Error("a replayed delivery id was recorded again")
	}
	inB(t, f, func(c *store.TenantTx) error { return c.ForgetGitHubDelivery("d-1") })
	if record(f.A, "d-1", at.Add(time.Minute)) {
		t.Error("B forgetting a delivery freed A's")
	}
	if !record(f.B, "d-1", at.Add(time.Minute)) {
		t.Error("B could not record a forgotten delivery again")
	}
	// expired ids are pruned, so the id is fresh again after its retention
	if !record(f.A, "d-1", at.Add(2*time.Hour)) {
		t.Error("an expired delivery id was not pruned")
	}
}
