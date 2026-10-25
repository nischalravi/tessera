// Package vertexfake is an in-process Vertex AI reasoning engines API (issue #562) and the Google token
// endpoint, for tests: the service account JWT exchange (the assertion's issuer is checked), a bearer-checked,
// paged reasoningEngines list, and the faults a service shows. Every answer is a fixed body or a stored value.
package vertexfake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Token is the access token the fake issues.
const Token = "ya29.vertex-access-token" // #nosec G101 -- a fixed test token of an in-process fake, not a credential

// Key returns a service account key file (JSON) for email, with a fresh RSA key.
func Key(email string) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	b, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": email, "private_key_id": "k1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	return string(b)
}

// Engine is one reasoning engine.
type Engine struct {
	ID, DisplayName, CreateTime string
	ServiceAccount              string
	IdentityType, Effective     string
	Labels                      map[string]string
	Secrets                     []string
	// Description and Env are served so a test can prove the connector does not keep them.
	Description string
	Env         map[string]string
}

// Fake is one project and location.
type Fake struct {
	// PageSize is the engines per page (0: all in one).
	PageSize int
	// Deny makes the API answer 403; RefuseToken makes the token endpoint answer 400; NotJSON a body that is no JSON;
	// Endless gives every page a next token.
	Deny, RefuseToken, NotJSON, Endless bool

	email, project, location string
	mu                       sync.Mutex
	engines                  []Engine
	writes, tokens           int
}

// New returns a fake whose service account is email.
func New(email, project, location string, engines ...Engine) *Fake {
	return &Fake{email: email, project: project, location: location, engines: engines}
}

// Writes counts requests that were neither a GET of the API nor a token exchange.
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

// Tokens counts token exchanges.
func (f *Fake) Tokens() int { f.mu.Lock(); defer f.mu.Unlock(); return f.tokens }

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" && r.Method == http.MethodPost {
		f.token(w, r)
		return
	}
	if r.Method != http.MethodGet {
		f.mu.Lock()
		f.writes++
		f.mu.Unlock()
		http.Error(w, `{"error":{"code":405}}`, http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Token {
		http.Error(w, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized)
		return
	}
	if f.Deny {
		http.Error(w, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`, http.StatusForbidden)
		return
	}
	if r.URL.Path != "/v1/projects/"+f.project+"/locations/"+f.location+"/reasoningEngines" {
		http.NotFound(w, r)
		return
	}
	if f.NotJSON {
		_, _ = w.Write([]byte("<html>not json</html>"))
		return
	}
	// the page token and size are matched against the values the fake can issue, so the answer is built
	// from the fake's own numbers and nothing the request carried reaches it
	start := matchIndex(r.URL.Query().Get("pageToken"), len(f.engines))
	size := f.PageSize
	if size <= 0 || size > len(f.engines) {
		size = len(f.engines)
	}
	if q := matchIndex(r.URL.Query().Get("pageSize"), size); q > 0 && f.PageSize == 0 {
		size = q
	}
	end := min(start+size, len(f.engines))
	out := []map[string]any{}
	for _, e := range f.engines[start:end] {
		var sec []map[string]any
		for _, s := range e.Secrets {
			sec = append(sec, map[string]any{"env": "X", "secretRef": map[string]any{"secret": s, "version": "latest"}})
		}
		env := []map[string]string{}
		for k, v := range e.Env {
			env = append(env, map[string]string{"name": k, "value": v})
		}
		out = append(out, map[string]any{"name": "projects/123456/locations/" + f.location + "/reasoningEngines/" + e.ID, "displayName": e.DisplayName,
			"description": e.Description, "createTime": e.CreateTime, "labels": e.Labels,
			"spec": map[string]any{"serviceAccount": e.ServiceAccount, "identityType": e.IdentityType, "effectiveIdentity": e.Effective,
				"deploymentSpec": map[string]any{"secretEnv": sec, "env": env}}})
	}
	body := map[string]any{"reasoningEngines": out}
	if end < len(f.engines) || f.Endless {
		body["nextPageToken"] = strconv.Itoa(end)
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokens++
	f.mu.Unlock()
	if r.ParseForm() != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || f.RefuseToken {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	var claims struct {
		Iss, Scope string
	}
	if len(parts) != 3 {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(b, &claims)
	if claims.Iss != f.email || !strings.Contains(claims.Scope, "cloud-platform") {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": Token, "token_type": "Bearer", "expires_in": 3600})
}

// matchIndex returns the i in [0, n) whose decimal form is s, or 0.
func matchIndex(s string, n int) int {
	for i := range n {
		if strconv.Itoa(i) == s {
			return i
		}
	}
	return 0
}
