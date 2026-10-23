package breach

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/rotation"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestNormalizeVendor(t *testing.T) {
	for _, c := range []struct {
		in, want string
		bad      bool
	}{
		{"GitHub", "github", false},
		{"  Railway ", "railway", false},
		{"Acme Corp.", "acme corp.", false},
		{"", "", true},
		{"  ", "", true},
		{"a/b", "", true},
		{"-lead", "", true},
		{"<script>", "", true},
		{"a'; drop table x;--", "", true},
		{string(make([]byte, 65)), "", true},
	} {
		got, err := NormalizeVendor(c.in)
		var be *Error
		if c.bad && (!errors.As(err, &be) || be.Status != http.StatusUnprocessableEntity || be.Code != "invalid_vendor") {
			t.Errorf("NormalizeVendor(%q) = %q, %v, want invalid_vendor", c.in, got, err)
		}
		if !c.bad && (err != nil || got != c.want) {
			t.Errorf("NormalizeVendor(%q) = %q, %v, want %q", c.in, got, err, c.want)
		}
	}
}

// seed gives tenant A an OAuth app of the vendor with two grants, a GitHub
// token, a service account and an unrelated app.
func seed(t *testing.T, f *storetest.Fixture) (grants []string, tokenID string, acctID int64) {
	t.Helper()
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		app := &store.OAuthApp{Provider: "github", ClientID: "c1", Name: "Acme CI", Publisher: "Acme"}
		other := &store.OAuthApp{Provider: "github", ClientID: "c2", Name: "Other", Publisher: "Other Inc"}
		for _, a := range []*store.OAuthApp{app, other} {
			if err := c.UpsertOAuthApp(a, storetest.Now); err != nil {
				return err
			}
		}
		for _, g := range []*store.OAuthGrant{{AppID: app.ID, Provider: "github", GrantKey: "g1", ProviderRef: "1", Kind: "token", ConsentType: "user", UserRef: "octocat"},
			{AppID: app.ID, Provider: "github", GrantKey: "g2", ProviderRef: "2", Kind: "token", ConsentType: "user", UserRef: "hubot"},
			{AppID: other.ID, Provider: "github", GrantKey: "g3", ProviderRef: "3", Kind: "token", ConsentType: "user", UserRef: "octocat"}} {
			if err := c.UpsertOAuthGrant(g, storetest.Now); err != nil {
				return err
			}
			if g.AppID == app.ID {
				grants = append(grants, g.ID)
			}
		}
		tk := &store.GitHubToken{Key: "pat:1", Kind: store.GHClassicPAT, Name: "deploy", OwnerLogin: "octocat"}
		if err := c.UpsertGitHubToken(tk, storetest.Now); err != nil {
			return err
		}
		ts, err := c.GitHubTokens()
		if err != nil {
			return err
		}
		tokenID = ts[0].ID
		acctID, err = c.InsertAccount(&store.Account{TenantID: f.A.ID, System: "github", ExternalID: "svc-1", Username: "ci-bot", Kind: "service", Status: "active"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return grants, tokenID, acctID
}

// The inventory finds every kind of credential tied to the vendor, and only
// those, in the vendor's own tenant.
func TestInventory(t *testing.T) {
	f := storetest.TwoTenants(t)
	grants, tokenID, acctID := seed(t, f)
	s := &Service{Rotation: &rotation.Service{}}
	read := func(tn storetest.Tenant, vendor string) []Candidate {
		var out []Candidate
		err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			var err error
			out, err = s.Inventory(c, vendor, storetest.Now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	count := func(cs []Candidate) map[string]int {
		m := map[string]int{}
		for _, c := range cs {
			m[c.Kind+"/"+c.Action]++
		}
		return m
	}
	if got := count(read(f.A, "acme")); got["oauth_grant/revoke"] != 2 || len(got) != 1 {
		t.Errorf("acme = %v", got) // two grants of Acme's app, none of the other app; GitHub tokens belong to github
	}
	got := count(read(f.A, "github"))
	if got["github_token/manual"] != 1 || got["service_account/manual"] != 1 {
		t.Errorf("github = %v", got)
	}
	_, _ = grants, tokenID
	_ = acctID
	if got := read(f.B, "acme"); len(got) != 0 {
		t.Errorf("tenant B sees tenant A's credentials: %v", got)
	}
}

// A plan is verified only by a re-read: revoking a grant or removing a token
// is not enough until the record shows it; a person's attestation counts for a
// manual item only; the plan completes only when nothing is open.
func TestPlanLifecycleVerifiesByReRead(t *testing.T) {
	f := storetest.TwoTenants(t)
	_, tokenID, acctID := seed(t, f)
	s := &Service{Rotation: &rotation.Service{}}
	ctx := context.Background()
	now := storetest.Now
	var planID string
	step := func(fn func(c *store.TenantTx) (*View, error)) *View {
		t.Helper()
		var v *View
		err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) { v, err = fn(c); return })
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	state := func(v *View, kind, ref string) ItemView {
		for _, it := range v.Items {
			if it.Kind == kind && it.Ref == ref {
				return it
			}
		}
		t.Fatalf("no %s %s in %v", kind, ref, v.Items)
		return ItemView{}
	}
	v := step(func(c *store.TenantTx) (*View, error) {
		return s.Create(c, "Github", "github breach of 21 Oct", "admin", now)
	})
	planID = v.ID
	if v.Status != "planned" || v.Report.Counts.Total != 2 { // the PAT and the service account (no grant: github is the provider, not the publisher)
		t.Fatalf("created = %+v", v.Report.Counts)
	}
	// an unstarted plan does not complete, even when a re-read finds things gone
	v = step(func(c *store.TenantTx) (*View, error) { return s.Verify(c, planID, "admin", now) })
	if v.Status != "planned" || v.Report.Complete {
		t.Errorf("unstarted plan: %+v", v.Report)
	}
	v = step(func(c *store.TenantTx) (*View, error) { return s.Start(c, planID, "admin", now) })
	if v.Status != "running" || v.RotationRun != nil { // no secret of the vendor: no rotation run
		t.Errorf("started: %v %v", v.Status, v.RotationRun)
	}
	tok := state(v, "github_token", tokenID)
	// attest needs a real note, a manual item and a running plan
	for _, c := range []struct{ note, code string }{{"short", "note_required"}} {
		err := f.DB.InTenant(ctx, f.A.ID, func(tx *store.TenantTx) error {
			_, err := s.Attest(tx, planID, tok.ID, c.note, "admin", now)
			return err
		})
		var be *Error
		if !errors.As(err, &be) || be.Code != c.code {
			t.Errorf("attest(%q) = %v, want %s", c.note, err, c.code)
		}
	}
	v = step(func(c *store.TenantTx) (*View, error) {
		return s.Attest(c, planID, tok.ID, "revoked the PAT in the GitHub console", "admin", now)
	})
	if got := state(v, "github_token", tokenID); got.State != "attested" || got.AttestedBy == nil || v.Status != "running" {
		t.Errorf("after attest: %+v status %s", got, v.Status)
	}
	// the account is disabled in the system of record: a re-read verifies it, with no attestation
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.SetAccountStatus(acctID, "disabled") })
	if err != nil {
		t.Fatal(err)
	}
	v = step(func(c *store.TenantTx) (*View, error) { return s.Verify(c, planID, "admin", now) })
	if got := state(v, "service_account", itoa(acctID)); got.State != "verified" || got.VerifiedAt == nil || got.Verification == nil {
		t.Errorf("disabled account: %+v", got)
	}
	if v.Status != "completed" || !v.Report.Complete || v.Report.Counts.Verified != 1 || v.Report.Counts.Attested != 1 || v.CompletedAt == nil {
		t.Errorf("completed plan: %v %+v", v.Status, v.Report.Counts)
	}
	// a completed plan is final
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { _, err := s.Start(c, planID, "admin", now); return err })
	var be *Error
	if !errors.As(err, &be) || be.Status != http.StatusConflict {
		t.Errorf("start of a completed plan = %v", err)
	}
	// the evidence is hashed and names every item
	var ev *Evidence
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) { ev, err = s.Evidence(c, planID, now); return }); err != nil {
		t.Fatal(err)
	}
	if len(ev.SHA256) != 64 || len(ev.Body.Report.Items) != 2 || ev.Body.Plan.Status != "completed" {
		t.Errorf("evidence = %+v", ev)
	}
}

// OAuth grants: revoked at the provider is "in progress" until the grant's
// record shows revoked; a refused revoke fails the item; both are re-reads.
func TestOAuthGrantItems(t *testing.T) {
	f := storetest.TwoTenants(t)
	grants, _, _ := seed(t, f)
	s := &Service{Rotation: &rotation.Service{}}
	ctx := context.Background()
	now := storetest.Now
	var v *View
	run := func(fn func(c *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(ctx, f.A.ID, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(c *store.TenantTx) (err error) {
		v, err = s.Create(c, "acme", "acme breach of 21 Oct", "admin", now)
		return
	})
	if v.Report.Counts.Total != 2 || v.Items[0].Action != "revoke" {
		t.Fatalf("created = %+v", v.Report.Counts)
	}
	run(func(c *store.TenantTx) (err error) { v, err = s.Start(c, v.ID, "admin", now); return })
	id := v.ID
	run(func(c *store.TenantTx) error {
		return s.RecordRevoke(c, id, map[string]RevokeResult{
			grants[0]: {State: store.BreachInProgress, Detail: "revoked at the provider; awaiting the re-read"},
			grants[1]: {State: store.BreachFailed, Detail: "403"}}, now)
	})
	run(func(c *store.TenantTx) (err error) { v, err = s.View(c, id, now); return })
	if v.Report.Counts.InProgress != 1 || v.Report.Counts.Failed != 1 {
		t.Fatalf("after the revoke: %+v", v.Report.Counts)
	}
	// the provider revoke is recorded on the grant by oauthapps; the re-read sees it
	run(func(c *store.TenantTx) error {
		if err := c.SetOAuthGrantStatus(grants[0], store.OAuthRevoked, nil, &now, ""); err != nil {
			return err
		}
		return c.SetOAuthGrantStatus(grants[1], store.OAuthRevokeFailed, nil, nil, "provider refused")
	})
	run(func(c *store.TenantTx) (err error) { v, err = s.Verify(c, id, "admin", now); return })
	if v.Report.Counts.Verified != 1 || v.Report.Counts.Failed != 1 || v.Report.Complete || v.Status != "running" {
		t.Errorf("after the re-read: %v %+v", v.Status, v.Report.Counts)
	}
	// a failed grant is not attestable (only manual items are)
	var failed ItemView
	for _, it := range v.Items {
		if it.State == "failed" {
			failed = it
		}
	}
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		_, err := s.Attest(c, id, failed.ID, "I promise it is fine really", "admin", now)
		return err
	})
	var be *Error
	if !errors.As(err, &be) || be.Code != "not_manual" {
		t.Errorf("attest of a failed grant = %v", err)
	}
	// the provider finally lets it go: the next re-read completes the plan
	run(func(c *store.TenantTx) error {
		return c.SetOAuthGrantStatus(grants[1], store.OAuthRevoked, nil, &now, "")
	})
	run(func(c *store.TenantTx) (err error) { v, err = s.Verify(c, id, "admin", now); return })
	if v.Status != "completed" || !v.Report.Complete {
		t.Errorf("after the second re-read: %v %+v", v.Status, v.Report.Counts)
	}
}

func TestCreateValidation(t *testing.T) {
	f := storetest.TwoTenants(t)
	seed(t, f)
	s := &Service{Rotation: &rotation.Service{}}
	for _, c := range []struct {
		vendor, reason, code string
		status               int
	}{
		{"acme", "short", "reason_required", 422},
		{"acme", "", "reason_required", 422},
		{"bad/vendor", "a long enough reason", "invalid_vendor", 422},
		{"nobody", "a long enough reason", "no_credentials", 404},
	} {
		err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
			_, err := s.Create(tx, c.vendor, c.reason, "admin", storetest.Now)
			return err
		})
		var be *Error
		if !errors.As(err, &be) || be.Code != c.code || be.Status != c.status {
			t.Errorf("Create(%q, %q) = %v, want %d %s", c.vendor, c.reason, err, c.status, c.code)
		}
	}
	// a plan of tenant A is invisible to tenant B
	var id string
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		v, err := s.Create(tx, "acme", "a long enough reason", "admin", storetest.Now)
		if v != nil {
			id = v.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		_, err := s.View(tx, id, storetest.Now)
		return err
	})
	var be *Error
	if !errors.As(err, &be) || be.Status != 404 {
		t.Errorf("tenant B reads tenant A's plan: %v", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
