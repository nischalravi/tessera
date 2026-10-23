package ghtokens_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ghtokens"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// rig is tenant A with a live GitHub connection and credential, pointing at a
// stateful fake served over loopback through a real safehttp client.
type rig struct {
	f   *storetest.Fixture
	svc *ghtokens.Service
	gh  *oauthfake.GitHub
	now time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{f: storetest.TwoTenants(t), now: storetest.Now, gh: &oauthfake.GitHub{Org: "acme"}}
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	cs := &containment.Service{HTTP: hc, Sealer: sealer, Clock: func() time.Time { return r.now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	r.svc = &ghtokens.Service{Containment: cs, Clock: func() time.Time { return r.now }}
	srv := httptest.NewServer(r.gh)
	t.Cleanup(srv.Close)
	err = r.f.DB.InTenant(context.Background(), r.f.A.ID, func(c *store.TenantTx) error {
		id := store.NewID()
		if err := c.InsertConnection(&store.Connection{ID: id, Name: "github", ConnectorType: "github", System: "github",
			Role: "account_source", CreatedAt: r.now, UpdatedAt: r.now}); err != nil {
			return err
		}
		return cs.PutCredential(c, id, containment.CredentialInput{Token: oauthfake.Token, BaseURL: srv.URL, Org: "acme"}, "admin", r.now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) seed() {
	r.gh.Credentials = []*oauthfake.GitHubCredential{
		{ID: 21, Login: "octocat", Type: "OAuth app token", Title: "GitHub CLI", Authorized: "2026-05-01T00:00:00Z",
			Accessed: "2026-10-05T00:00:00Z", Scopes: []string{"repo", "workflow"}},
		{ID: 22, Login: "hubot", Type: "personal access token", Title: "ci", Authorized: "2026-06-02T00:00:00Z", Scopes: []string{"read:user"}},
		{ID: 23, Login: "mona", Type: "SSH key", Authorized: "2026-06-03T00:00:00Z"},
	}
	r.gh.FineGrained = []*oauthfake.GitHubPAT{
		{ID: 31, Owner: "octocat", Name: "release-bot", Permissions: map[string]string{"contents": "write", "metadata": "read"},
			Granted: "2026-09-20T00:00:00Z", Expires: "2026-12-01T00:00:00Z", LastUsed: "2026-10-07T00:00:00Z"},
	}
	r.gh.Secrets = []*oauthfake.GitHubSecret{
		{Name: "NPM_TOKEN", Created: "2025-11-01T00:00:00Z", Updated: "2025-11-01T00:00:00Z", Visibility: "all"},
		{Name: "DEPLOY_KEY", Created: "2026-03-01T00:00:00Z", Updated: "2026-10-01T00:00:00Z", Visibility: "selected"},
	}
}

func (r *rig) sync(t *testing.T) *ghtokens.Report {
	t.Helper()
	rep, err := r.svc.Sync(context.Background(), r.f.DB, r.f.A.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func (r *rig) list(t *testing.T) (vs []ghtokens.View, sum ghtokens.Summary) {
	t.Helper()
	if err := r.f.DB.ReadTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		var err error
		vs, sum, err = ghtokens.List(tx, r.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return vs, sum
}

func byName(vs []ghtokens.View, name string) *ghtokens.View {
	for i := range vs {
		if vs[i].Name == name {
			return &vs[i]
		}
	}
	return nil
}

func TestSyncInventoriesEveryKind(t *testing.T) {
	r := newRig(t)
	r.seed()
	rep := r.sync(t)
	if rep.Status != ghtokens.SyncOK || rep.Tokens != 5 {
		t.Fatalf("report = %+v, want ok with 5 tokens (the SSH key is not a token)", rep)
	}
	vs, sum := r.list(t)
	if sum.Total != 5 || sum.ByKind[ghtokens.OAuthAppToken] != 1 || sum.ByKind[ghtokens.ClassicPAT] != 1 ||
		sum.ByKind[ghtokens.FineGrainedPAT] != 1 || sum.ByKind[ghtokens.ActionsSecret] != 2 {
		t.Errorf("summary = %+v", sum)
	}
	cli := byName(vs, "GitHub CLI")
	if cli == nil || cli.Kind != ghtokens.OAuthAppToken || cli.OwnerLogin != "octocat" || !slices.Contains(cli.Flags, ghtokens.FlagCLIToken) ||
		!slices.Contains(cli.Flags, ghtokens.FlagHighRiskScope) || !slices.Contains(cli.Flags, ghtokens.FlagOrphaned) {
		t.Errorf("GitHub CLI token = %+v", cli)
	}
	npm := byName(vs, "NPM_TOKEN")
	if npm == nil || npm.Owner != nil || !slices.Contains(npm.Flags, ghtokens.FlagStale) || !slices.Contains(npm.Flags, ghtokens.FlagOrgWideSecret) ||
		slices.Contains(npm.Flags, ghtokens.FlagOrphaned) || npm.AgeDays < 300 {
		t.Errorf("NPM_TOKEN = %+v", npm)
	}
	fresh := byName(vs, "DEPLOY_KEY")
	if fresh == nil || slices.Contains(fresh.Flags, ghtokens.FlagStale) || fresh.AgeDays != 7 {
		t.Errorf("DEPLOY_KEY = %+v (rotation 7 days ago is not stale)", fresh)
	}
	pat := byName(vs, "ci")
	if pat == nil || !slices.Contains(pat.Flags, ghtokens.FlagNoExpiry) || !slices.Contains(pat.Flags, ghtokens.FlagClassic) {
		t.Errorf("classic PAT = %+v", pat)
	}
	fg := byName(vs, "release-bot")
	if fg == nil || slices.Contains(fg.Flags, ghtokens.FlagNoExpiry) || !slices.Contains(fg.Flags, ghtokens.FlagHighRiskScope) ||
		!slices.Equal(fg.Scopes, []string{"contents:write", "metadata:read"}) {
		t.Errorf("fine-grained PAT = %+v", fg)
	}
	if vs[0].Risk < vs[len(vs)-1].Risk {
		t.Error("list is not ordered by risk")
	}
	// only GETs reach GitHub, and no value of a token or secret is kept or shown
	for _, c := range r.gh.Calls() {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("non-read call %s", c)
		}
	}
	raw, _ := json.Marshal(vs)
	if strings.Contains(string(raw), "SECRET00") || strings.Contains(string(raw), "SHA256") {
		t.Errorf("response carries token material: %s", raw)
	}
	if !slices.Contains(auditActions(t, r), "ghtokens.synced") {
		t.Error("no ghtokens.synced event")
	}
}

func auditActions(t *testing.T, r *rig) []string {
	t.Helper()
	var out []string
	if err := r.f.DB.ReadTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		log, err := tx.AuditLog(-1)
		for _, e := range log {
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), oauthfake.Token) {
				t.Errorf("audit event %s carries the provider token", e.Action)
			}
			out = append(out, e.Action)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOwnerCorrelation(t *testing.T) {
	r := newRig(t)
	r.seed()
	alice := r.f.A.IDs["alice"]
	if err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		_, err := tx.InsertAccount(&store.Account{TenantID: r.f.A.ID, System: "github", ExternalID: "1", IdentityID: &alice,
			Username: "OctoCat", Kind: "human", Status: "active"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.sync(t)
	vs, _ := r.list(t)
	cli := byName(vs, "GitHub CLI")
	if cli == nil || cli.Owner == nil || cli.Owner.ID != alice || slices.Contains(cli.Flags, ghtokens.FlagOrphaned) {
		t.Errorf("a token of a known login has its owner: %+v", cli)
	}
	if ci := byName(vs, "ci"); ci == nil || ci.Owner != nil || !slices.Contains(ci.Flags, ghtokens.FlagOrphaned) {
		t.Errorf("a token of an unknown login is orphaned: %+v", ci)
	}
}

// A credential a full read no longer lists leaves the inventory; a failed
// read changes nothing.
func TestRemovalAndFailedRead(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.sync(t)
	r.now = r.now.Add(time.Hour)
	r.gh.FailReads.Store(true)
	rep := r.sync(t)
	if rep.Status != ghtokens.SyncFailed || rep.Error == "" {
		t.Fatalf("report = %+v, want failed", rep)
	}
	if _, sum := r.list(t); sum.Total != 5 {
		t.Errorf("a failed read changed the inventory: %+v", sum)
	}
	if !slices.Contains(auditActions(t, r), "ghtokens.sync_failed") {
		t.Error("no ghtokens.sync_failed event")
	}
	r.gh.FailReads.Store(false)
	r.gh.With(func() { r.gh.Secrets = r.gh.Secrets[:1] })
	r.sync(t)
	if vs, sum := r.list(t); sum.Total != 4 || byName(vs, "DEPLOY_KEY") != nil {
		t.Errorf("after the secret was deleted: %+v", sum)
	}
}

func TestNoSAMLIsANote(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.gh.NoSAML = true
	rep := r.sync(t)
	if rep.Status != ghtokens.SyncOK || rep.Tokens != 3 || !strings.Contains(strings.Join(rep.Notes, " "), "no SAML SSO") {
		t.Errorf("report = %+v", rep)
	}
}

func TestPagedLists(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 230; i++ {
		r.gh.Secrets = append(r.gh.Secrets, &oauthfake.GitHubSecret{Name: "S_" + strings.Repeat("X", 1) + string(rune('A'+i%26)) + string(rune('a'+i/26)),
			Created: "2026-10-01T00:00:00Z", Updated: "2026-10-01T00:00:00Z", Visibility: "private"})
	}
	if rep := r.sync(t); rep.Status != ghtokens.SyncOK || rep.Tokens != 230 {
		t.Errorf("report = %+v, want 230 secrets over 3 pages", rep)
	}
}

func TestSkippedWithoutConnection(t *testing.T) {
	r := newRig(t)
	rep, err := r.svc.Sync(context.Background(), r.f.DB, r.f.B.ID, "tester") // tenant B has no GitHub connection
	if err != nil || rep.Status != ghtokens.SyncSkipped {
		t.Errorf("report = %+v, %v", rep, err)
	}
	if len(r.gh.Calls()) != 0 {
		t.Errorf("a tenant without a credential called GitHub: %v", r.gh.Calls())
	}
}

func TestAssess(t *testing.T) {
	now := storetest.Now
	ago := func(days int) *time.Time { t := now.AddDate(0, 0, -days); return &t }
	ahead := func(days int) *time.Time { t := now.AddDate(0, 0, days); return &t }
	for _, tc := range []struct {
		name  string
		tok   store.GitHubToken
		owner ghtokens.Owner
		want  []string
		not   []string
	}{
		{"fresh fine-grained, active owner", store.GitHubToken{Kind: store.GHFineGrainedPAT, CreatedAt: ago(5), ExpiresAt: ahead(30),
			Scopes: []string{"metadata:read"}}, ghtokens.OwnerActive, nil,
			[]string{ghtokens.FlagStale, ghtokens.FlagNoExpiry, ghtokens.FlagOrphaned, ghtokens.FlagHighRiskScope}},
		{"owner left", store.GitHubToken{Kind: store.GHFineGrainedPAT, CreatedAt: ago(5), ExpiresAt: ahead(30)}, ghtokens.OwnerInactive,
			[]string{ghtokens.FlagOwnerLeft}, []string{ghtokens.FlagOrphaned}},
		{"old classic PAT never expiring", store.GitHubToken{Kind: store.GHClassicPAT, CreatedAt: ago(120)}, ghtokens.OwnerActive,
			[]string{ghtokens.FlagStale, ghtokens.FlagNoExpiry, ghtokens.FlagClassic}, nil},
		{"expired token is not no_expiry", store.GitHubToken{Kind: store.GHClassicPAT, CreatedAt: ago(10), ExpiresAt: ago(1)}, ghtokens.OwnerActive,
			[]string{ghtokens.FlagExpired}, []string{ghtokens.FlagNoExpiry}},
		{"unused for 100 days", store.GitHubToken{Kind: store.GHOAuthAppToken, CreatedAt: ago(10), LastUsedAt: ago(100)}, ghtokens.OwnerActive,
			[]string{ghtokens.FlagUnused}, nil},
		{"unknown last use is not unused", store.GitHubToken{Kind: store.GHOAuthAppToken, CreatedAt: ago(10)}, ghtokens.OwnerActive,
			nil, []string{ghtokens.FlagUnused}},
		{"rotated secret is not stale", store.GitHubToken{Kind: store.GHActionsSecret, CreatedAt: ago(400), RotatedAt: ago(3), Visibility: "private"},
			ghtokens.OwnerNone, nil, []string{ghtokens.FlagStale, ghtokens.FlagOrphaned, ghtokens.FlagOrgWideSecret}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ghtokens.Assess(&tc.tok, tc.owner, now)
			for _, f := range tc.want {
				if !slices.Contains(got.Flags, f) {
					t.Errorf("flags %v lack %s", got.Flags, f)
				}
			}
			for _, f := range tc.not {
				if slices.Contains(got.Flags, f) {
					t.Errorf("flags %v hold %s", got.Flags, f)
				}
			}
			if got.Score < 0 || got.Score > 100 {
				t.Errorf("score %d", got.Score)
			}
		})
	}
}
