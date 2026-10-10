package devidp

import (
	"crypto/rand"
	"crypto/subtle"
	"hash/fnv"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// GitHub-style OAuth 2.0 (issue #151): an authorization server that issues
// no ID token, and a user API, shaped like GitHub's:
//
//	GET  /github/login/oauth/authorize     the sign-in page (state and PKCE S256 required)
//	POST /github/login/oauth/access_token  client_id + client_secret in the form; a form-encoded answer
//	GET  /github/user                      {"id": <number>, "login", "name", "email"}
//	GET  /github/user/emails               [{"email", "primary", "verified"}]
//
// It shares the sign-in page, pending requests and codes with OIDC. The
// numeric id is GitHubID(sub).

const (
	pathGitHubAuthorize = "/github/login/oauth/authorize"
	pathGitHubToken     = "/github/login/oauth/access_token" // #nosec G101 -- an endpoint path, not a credential
	pathGitHubUser      = "/github/user"
	pathGitHubEmails    = "/github/user/emails"
)

// GitHub faults.
const (
	FaultGitHubTokenError Fault = "github_token_error" // the token endpoint answers 200 with error=bad_verification_code (as GitHub does)
	FaultGitHubTokenType  Fault = "github_token_type"  // token_type is not bearer
	FaultGitHubUserError  Fault = "github_user_error"  // the user API answers 500
	FaultGitHubNoID       Fault = "github_no_id"       // the user object has login and email but no id
	FaultGitHubStringID   Fault = "github_string_id"   // id is the login string instead of the numeric id
)

// GitHubFaults lists the GitHub faults.
func GitHubFaults() []Fault {
	return []Fault{FaultGitHubTokenError, FaultGitHubTokenType, FaultGitHubUserError, FaultGitHubNoID, FaultGitHubStringID}
}

// GitHubID is the dev user's numeric GitHub-style id, derived from sub.
func GitHubID(sub string) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sub))
	return 1_000_000 + int64(h.Sum32()%9_000_000)
}

// GitHubAuthorizeURL, GitHubTokenURL, GitHubUserURL are the emulated endpoints.
func (s *Server) GitHubAuthorizeURL() string { return s.issuer + pathGitHubAuthorize }
func (s *Server) GitHubTokenURL() string     { return s.issuer + pathGitHubToken }
func (s *Server) GitHubUserURL() string      { return s.issuer + pathGitHubUser }

// githubGrant backs a GitHub-style access token.
type githubGrant struct {
	user  User
	fault Fault
}

func (s *Server) handleGitHubAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	c := s.clients[q.Get("client_id")]
	if c == nil || len(q["client_id"]) != 1 {
		s.errorPage(w, http.StatusBadRequest, "Unknown or repeated client_id.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if len(q["redirect_uri"]) != 1 || !absoluteHTTP(redirectURI) || !c.redirectAllowed(redirectURI) {
		s.errorPage(w, http.StatusBadRequest, "redirect_uri is missing, repeated or not registered for this client.")
		return
	}
	p := pendingAuthz{clientID: c.ID, redirectURI: redirectURI, state: q.Get("state"), github: true,
		scope: strings.Fields(q.Get("scope")), codeChallenge: q.Get("code_challenge")}
	for k, v := range q {
		if len(v) > 1 {
			s.redirectError(w, r, redirectURI, p.state, "invalid_request", "parameter "+k+" is repeated")
			return
		}
	}
	switch {
	case p.state == "":
		s.redirectError(w, r, redirectURI, "", "invalid_request", "state is required")
		return
	case q.Get("code_challenge_method") != "S256" || !challengeRE.MatchString(p.codeChallenge):
		s.redirectError(w, r, redirectURI, p.state, "invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256")
		return
	}
	p.fault = s.currentFault()
	if q.Has("fault") {
		f := Fault(q.Get("fault"))
		if !s.faults || !slices.Contains(GitHubFaults(), f) {
			s.redirectError(w, r, redirectURI, p.state, "invalid_request", "unknown or disabled GitHub fault")
			return
		}
		p.fault = f
	}
	if !slices.Contains(GitHubFaults(), p.fault) {
		p.fault = FaultNone // an OIDC or SAML fault set globally does not apply here
	}
	id := rand.Text()
	if err := s.pending.put(id, p, now.Add(pendingTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sign-ins in progress.")
		return
	}
	d := pageData{Title: "Sign in (GitHub-style OAuth 2.0)", Req: id, Action: s.issuer + pathAuthorize, ClientID: p.clientID,
		Fault: string(p.fault)}
	s.renderUsers(w, &d, "")
}

// handleGitHubToken redeems a code. Like GitHub, the client authenticates
// with client_id and client_secret in the form, errors come back as 200
// with an error parameter, and the answer is form-encoded unless the client
// asks for JSON.
func (s *Server) handleGitHubToken(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	id, secret := f.Get("client_id"), f.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok { // also accepted
		id, secret = u, p
	}
	c := s.clients[id]
	answer := func(v url.Values) {
		w.Header().Set("Cache-Control", "no-store")
		if strings.Contains(r.Header.Get("Accept"), "json") {
			m := map[string]string{}
			for k := range v {
				m[k] = v.Get(k)
			}
			writeJSON(w, http.StatusOK, m)
			return
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		_, _ = w.Write([]byte(v.Encode()))
	}
	githubError := func(code string) { answer(url.Values{"error": {code}, "error_description": {code}}) }
	if c == nil || c.Secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		githubError("incorrect_client_credentials")
		return
	}
	ac, ok := s.codes.take(f.Get("code"), now)
	switch {
	case !ok || !ac.authz.github || ac.authz.clientID != c.ID:
		githubError("bad_verification_code")
		return
	case f.Get("redirect_uri") != ac.authz.redirectURI:
		githubError("redirect_uri_mismatch")
		return
	case !pkceOK(f.Get("code_verifier"), ac.authz.codeChallenge):
		githubError("bad_verification_code")
		return
	case ac.authz.fault == FaultGitHubTokenError:
		githubError("bad_verification_code")
		return
	}
	at := "gho_" + rand.Text()
	if err := s.github.put(at, githubGrant{user: ac.user, fault: ac.authz.fault}, now.Add(accessTokenTTL), now); err != nil {
		http.Error(w, "too many tokens", http.StatusServiceUnavailable)
		return
	}
	tt := "bearer"
	if ac.authz.fault == FaultGitHubTokenType {
		tt = "mac"
	}
	answer(url.Values{"access_token": {at}, "token_type": {tt}, "scope": {strings.Join(ac.authz.scope, ",")}})
}

func (s *Server) githubGrantOf(w http.ResponseWriter, r *http.Request) (githubGrant, bool) {
	scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	g, ok := s.github.get(tok, s.now())
	if (!strings.EqualFold(scheme, "Bearer") && !strings.EqualFold(scheme, "token")) || tok == "" || !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		return g, false
	}
	return g, true
}

func (s *Server) handleGitHubUser(w http.ResponseWriter, r *http.Request) {
	g, ok := s.githubGrantOf(w, r)
	if !ok {
		return
	}
	u := g.user
	login := strings.TrimPrefix(u.Sub, "00u-")
	v := map[string]any{"login": login, "id": GitHubID(u.Sub), "name": u.Name, "email": u.Email, "type": "User",
		"html_url": s.issuer + "/github/" + login, "created_at": time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339)}
	switch g.fault {
	case FaultGitHubUserError:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server Error"})
		return
	case FaultGitHubNoID:
		delete(v, "id")
	case FaultGitHubStringID:
		v["id"] = login
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleGitHubEmails(w http.ResponseWriter, r *http.Request) {
	g, ok := s.githubGrantOf(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, []map[string]any{
		{"email": "unverified-" + g.user.Email, "primary": false, "verified": false},
		{"email": g.user.Email, "primary": true, "verified": true},
	})
}
