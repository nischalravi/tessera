package oauthfake

import "net/http"

// DevOrg is the GitHub organization the dev handler's GitHub fake serves.
const DevOrg = "acme"

// NewDevHandler returns the four fakes, preloaded with a few apps and grants
// (one high-risk app held by several users), each under its own path prefix
// (/google, /entra, /salesforce, /github). base is the URL the handler is
// reached at, which the Entra fake needs for its paging links. It is for the
// local dev stack only: cmd/tessera serves it behind TESSERA_DEV_OAUTH_FAKE_URL,
// which config refuses in prod.
func NewDevHandler(base string) http.Handler {
	g := &Google{Users: []*GoogleUser{
		{ID: "g1", Email: "alice@larkspur.example", Tokens: []GoogleToken{
			{ClientID: "drift.apps.googleusercontent.com", DisplayText: "Salesloft Drift", Scopes: []string{"https://mail.google.com/"}},
			{ClientID: "cal.apps.googleusercontent.com", DisplayText: "Calendar sync", Scopes: []string{"openid"}}}},
		{ID: "g2", Email: "pat@larkspur.example", Tokens: []GoogleToken{
			{ClientID: "drift.apps.googleusercontent.com", DisplayText: "Salesloft Drift", Scopes: []string{"https://mail.google.com/"}}}},
		{ID: "g3", Email: "ivan@larkspur.example", Admin: true},
	}}
	e := &Entra{BaseURL: base + "/entra",
		SPs: []*EntraSP{
			{ID: "sp-graph", AppID: "00000003-0000-0000-c000-000000000000", Name: "Microsoft Graph", Roles: map[string]string{"role-dir": "Directory.ReadWrite.All"}},
			{ID: "sp-gain", AppID: "app-gainsight", Name: "Gainsight", Publisher: "Gainsight Inc"},
			{ID: "sp-klue", AppID: "app-klue", Name: "Klue", Publisher: "Klue Labs", VerifiedPublisher: "v-1"},
		},
		UserNames: map[string]string{"u-alice": "alice@larkspur.example"},
		Delegated: []*EntraDelegated{
			{ID: "d1", ClientSP: "sp-gain", ConsentType: "Principal", Principal: "u-alice", Scope: " Mail.Read offline_access"},
			{ID: "d2", ClientSP: "sp-klue", ConsentType: "AllPrincipals", Scope: "User.Read"},
			{ID: "d3", ClientSP: "sp-gain", ConsentType: "AllPrincipals", Scope: "Files.Read.All"},
		},
		Roles: []*EntraRole{{ID: "ra1", ClientSP: "sp-gain", Resource: "sp-graph", RoleID: "role-dir", Created: "2026-09-01T00:00:00Z"}},
	}
	s := &Salesforce{Tokens: []*SalesforceToken{
		{ID: ID("00Xa", 1), AppName: "Salesloft Drift", AppID: ID("0Aa", 1), UserID: "005A", Username: "alice@larkspur.example",
			Created: "2026-08-01T10:00:00.000+0000", LastUsed: "2026-10-01T10:00:00.000+0000", Scopes: "api refresh_token"},
		{ID: ID("00Xa", 2), AppName: "Salesloft Drift", AppID: ID("0Aa", 1), UserID: "005B", Username: "pat@larkspur.example",
			ModifyAll: true, Created: "2026-08-02T10:00:00.000+0000", Scopes: "full"},
		{ID: ID("00Xa", 3), AppName: "Quiet app", AppID: ID("0Aa", 2), UserID: "005A", Username: "alice@larkspur.example", Scopes: "id"},
	}}
	h := &GitHub{Org: DevOrg,
		Installs: []*GitHubInstall{
			{ID: 11, Slug: "deploy-bot", Owner: "acme-tools", Permissions: map[string]string{"contents": "write", "metadata": "read"}, Created: "2026-07-01T00:00:00Z"}},
		Credentials: []*GitHubCredential{
			{ID: 21, Login: "octocat", Type: "OAuth app token", Authorized: "2026-06-01T00:00:00Z", Accessed: "2026-10-10T00:00:00Z", Scopes: []string{"repo"}},
			{ID: 22, Login: "hubot", Type: "personal access token", Authorized: "2026-06-02T00:00:00Z", Scopes: []string{"read:user"}},
			{ID: 23, Login: "mona", Type: "OAuth app token", Authorized: "2026-06-03T00:00:00Z", Scopes: []string{"read:org"}},
		}}
	mux := http.NewServeMux()
	for name, fake := range map[string]http.Handler{"google": g, "entra": e, "salesforce": s, "github": h} {
		mux.Handle("/"+name+"/", http.StripPrefix("/"+name, fake))
	}
	return mux
}
