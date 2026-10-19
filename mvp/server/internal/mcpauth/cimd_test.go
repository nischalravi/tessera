package mcpauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestValidateClientID(t *testing.T) {
	cases := []struct {
		id  string
		bad bool
	}{
		{"https://client.example/meta.json", false},
		{"https://client.example:8443/a/b", false},
		{"http://client.example/meta.json", true},
		{"https://client.example", true},
		{"https://client.example/", true},
		{"https://client.example/meta.json#frag", true},
		{"https://client.example/meta.json?x=1", true},
		{"https://user:pw@client.example/meta.json", true},
		{"https://client.example/a/../b", true},
		{"https://client.example/a/./b", true},
		{"https://CLIENT.example/meta.json", false},
		{"ftp://client.example/meta.json", true},
		{"/meta.json", true},
		{"", true},
		{"https://client.example/" + strings.Repeat("a", 600), true},
	}
	for _, c := range cases {
		if err := ValidateClientID(c.id); (err != nil) != c.bad {
			t.Errorf("ValidateClientID(%.60q) = %v", c.id, err)
		}
	}
}

func TestValidateRedirectURI(t *testing.T) {
	for uri, bad := range map[string]bool{
		"https://app.example/cb":              false,
		"http://localhost:8080/cb":            false,
		"http://127.0.0.1:9/cb":               false,
		"http://[::1]:9/cb":                   false,
		"http://app.example/cb":               true,
		"http://localhost.evil.com/cb":        true,
		"https://app.example/cb#x":            true,
		"https://u:p@app.example/cb":          true,
		"custom-scheme://cb":                  true,
		"javascript:alert(1)":                 true,
		"/relative":                           true,
		"https://app.example/cb?x=1":          false,
		"https://" + strings.Repeat("a", 600): true,
	} {
		if err := ValidateRedirectURI(uri); (err != nil) != bad {
			t.Errorf("ValidateRedirectURI(%.60q) = %v", uri, err)
		}
	}
}

func TestParseDocument(t *testing.T) {
	const id = "https://client.example/meta.json"
	good := `{"client_id":"` + id + `","client_name":"Agent Host","redirect_uris":["https://client.example/cb","https://client.example/cb"],
		"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"]}`
	cases := []struct {
		name, id, body string
		bad            bool
	}{
		{"valid", id, good, false},
		{"id mismatch", id, strings.Replace(good, id, "https://evil.example/meta.json", 1), true},
		{"other url", "https://other.example/meta.json", good, true},
		{"not json", id, `<html>`, true},
		{"no name", id, `{"client_id":"` + id + `","redirect_uris":["https://client.example/cb"]}`, true},
		{"control in name", id, `{"client_id":"` + id + `","client_name":"a\u0007b","redirect_uris":["https://client.example/cb"]}`, true},
		{"long name", id, `{"client_id":"` + id + `","client_name":"` + strings.Repeat("n", 101) + `","redirect_uris":["https://client.example/cb"]}`, true},
		{"no redirects", id, `{"client_id":"` + id + `","client_name":"x","redirect_uris":[]}`, true},
		{"http redirect", id, `{"client_id":"` + id + `","client_name":"x","redirect_uris":["http://client.example/cb"]}`, true},
		{"client secret auth", id, `{"client_id":"` + id + `","client_name":"x","redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, true},
		{"implicit", id, `{"client_id":"` + id + `","client_name":"x","redirect_uris":["https://client.example/cb"],"response_types":["token"]}`, true},
		{"refresh grant", id, `{"client_id":"` + id + `","client_name":"x","redirect_uris":["https://client.example/cb"],"grant_types":["refresh_token"]}`, true},
		{"private jwk", id, `{"client_id":"` + id + `","client_name":"x","redirect_uris":["https://client.example/cb"],"jwks":{"keys":[{"kty":"oct","k":"AAAA","kid":"k"}]}}`, true},
		{"too large", id, good + strings.Repeat(" ", MaxDocumentBytes), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := ParseDocument(c.id, []byte(c.body))
			if (err != nil) != c.bad {
				t.Fatalf("err = %v", err)
			}
			if err == nil {
				var ce *ErrClient
				if len(d.RedirectURIs) != 1 || d.Name != "Agent Host" || d.SHA256 == "" || errors.As(err, &ce) {
					t.Errorf("doc = %+v", d)
				}
			}
		})
	}
}

// cimdServer serves one metadata document over TLS and counts the hits. The
// client is a safehttp client in dev mode that may reach loopback (the only
// way to reach httptest).
func cimdServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *http.Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool, MaxBodyBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	return srv, hc, &hits
}

func docFor(id string) string {
	return fmt.Sprintf(`{"client_id":%q,"client_name":"Agent Host","redirect_uris":["https://client.example/cb"]}`, id)
}

func TestFetchDocument(t *testing.T) {
	ctx := context.Background()
	t.Run("valid", func(t *testing.T) {
		srv, hc, _ := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprint(w, docFor("https://"+r.Host+"/meta.json"))
		})
		url := srv.URL + "/meta.json"
		s := &Service{HTTP: hc}
		d, err := s.fetchDocument(ctx, url)
		if err != nil || d.Name != "Agent Host" {
			t.Fatalf("fetch = %+v, %v", d, err)
		}
	})
	t.Run("document names another url", func(t *testing.T) {
		srv, hc, _ := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, docFor("https://victim.example/meta.json"))
		})
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, srv.URL+"/meta.json"); err == nil {
			t.Fatal("a document naming a different client_id was accepted")
		}
	})
	t.Run("redirect is not followed", func(t *testing.T) {
		srv, hc, hits := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/other.json" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, docFor("https://"+r.Host+"/meta.json"))
				return
			}
			http.Redirect(w, r, "/other.json", http.StatusFound)
		})
		url := srv.URL + "/meta.json"
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, url); err == nil || hits.Load() != 1 {
			t.Fatalf("err = %v after %d requests", err, hits.Load())
		}
	})
	t.Run("not json", func(t *testing.T) {
		srv, hc, _ := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, docFor("x"))
		})
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, srv.URL+"/meta.json"); err == nil {
			t.Fatal("a text/html document was accepted")
		}
	})
	t.Run("not found", func(t *testing.T) {
		srv, hc, _ := cimdServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, srv.URL+"/meta.json"); err == nil {
			t.Fatal("a 404 was accepted")
		}
	})
	t.Run("oversized body is cut", func(t *testing.T) {
		srv, hc, _ := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"client_id":"x","padding":"`+strings.Repeat("a", 100<<10)+`"}`)
		})
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, srv.URL+"/meta.json"); err == nil {
			t.Fatal("an oversized document was accepted")
		}
	})
	t.Run("http is refused before any request", func(t *testing.T) {
		srv, hc, hits := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {})
		plain := strings.Replace(srv.URL, "https://", "http://", 1) + "/meta.json"
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, plain); err == nil || hits.Load() != 0 {
			t.Fatalf("err = %v after %d requests", err, hits.Load())
		}
	})
	t.Run("a production client cannot reach loopback", func(t *testing.T) {
		srv, _, hits := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {})
		hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&Service{HTTP: hc}).fetchDocument(ctx, srv.URL+"/meta.json"); err == nil || hits.Load() != 0 {
			t.Fatalf("err = %v after %d requests", err, hits.Load())
		}
	})
	t.Run("no outbound client", func(t *testing.T) {
		if _, err := (&Service{}).fetchDocument(ctx, "https://client.example/meta.json"); err == nil {
			t.Fatal("fetched without a client")
		}
	})
}

// TestClientCache: the validated document is cached (one fetch inside the
// TTL), refetched after it, and a changed redirect URI set re-pends an active
// client and revokes its tokens.
func TestClientCache(t *testing.T) {
	ctx := context.Background()
	db, _ := testkit.Tiny(t)
	var urlV, redirV atomic.Value
	redirV.Store("https://client.example/cb")
	srv, hc, hits := cimdServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Agent Host","redirect_uris":[%q]}`, urlV.Load(), redirV.Load())
	})
	url := srv.URL + "/meta.json"
	urlV.Store(url)
	now := testkit.Now
	s := &Service{HTTP: hc, Clock: func() time.Time { return now }}

	c, err := s.Client(ctx, db.DB, db.Tenant, url)
	if err != nil || c.Status != "pending" || c.AgentIdentityID != nil {
		t.Fatalf("first fetch = %+v, %v", c, err)
	}
	if _, err := s.Client(ctx, db.DB, db.Tenant, url); err != nil || hits.Load() != 1 {
		t.Fatalf("second call: %d fetches, %v; want the cache", hits.Load(), err)
	}
	// activate it, then let the cache expire with a changed document
	if err := db.InTenant(ctx, db.Tenant, func(tx *store.TenantTx) error {
		return tx.SetMCPClient(url, nil, "active", now)
	}); err != nil {
		t.Fatal(err)
	}
	redirect := "https://client.example/other"
	redirV.Store(redirect)
	now = now.Add(ClientDocTTL + time.Second)
	c, err = s.Client(ctx, db.DB, db.Tenant, url)
	if err != nil || hits.Load() != 2 {
		t.Fatalf("after the TTL: %d fetches, %v", hits.Load(), err)
	}
	if c.Status != "pending" || RedirectURIsOf(c)[0] != redirect {
		t.Errorf("changed document left the client %q with %v", c.Status, RedirectURIsOf(c))
	}
	// a failing fetch with an expired cache fails closed
	now = now.Add(ClientDocTTL + time.Second)
	redirV.Store("not a uri")
	if _, err := s.Client(ctx, db.DB, db.Tenant, url); err == nil {
		t.Error("an invalid refetch was served from the expired cache")
	}
}
