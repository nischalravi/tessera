package prcomment_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/prcomment"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const token = "ghp_ExampleTokenValue0123456789abcdef"

type seen struct {
	method, path, auth, accept, ctype string
	body                              string
}

// server is a local TLS stand-in for api.github.com and a safehttp client
// that trusts it (the loopback exception exists in dev only).
func server(t *testing.T, h http.HandlerFunc) (*prcomment.Poster, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*s = seen{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Accept"), r.Header.Get("Content-Type"), string(b)}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	return &prcomment.Poster{HTTP: c, APIBase: srv.URL}, s
}

func TestPostSendsTheComment(t *testing.T) {
	p, s := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":42,"html_url":"https://github.com/o/r/pull/7#issuecomment-42"}`))
	})
	res, err := p.Post(context.Background(), token, "o/r", 7, "hello `world`")
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != 42 || res.URL != "https://github.com/o/r/pull/7#issuecomment-42" {
		t.Errorf("result = %+v", res)
	}
	if s.method != http.MethodPost || s.path != "/repos/o/r/issues/7/comments" {
		t.Errorf("request = %s %s", s.method, s.path)
	}
	if s.auth != "Bearer "+token || s.accept != "application/vnd.github+json" || s.ctype != "application/json" {
		t.Errorf("headers: auth=%q accept=%q type=%q", s.auth, s.accept, s.ctype)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(s.body), &body); err != nil || body["body"] != "hello `world`" || len(body) != 1 {
		t.Errorf("body = %q (%v)", s.body, err)
	}
}

func TestPostValidatesBeforeSending(t *testing.T) {
	p, s := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) })
	for name, tc := range map[string]struct {
		token, repo string
		n           int
		body        string
		want        error
	}{
		"no owner":            {token, "repo", 1, "x", prcomment.ErrRepo},
		"path traversal":      {token, "o/../../admin", 1, "x", prcomment.ErrRepo},
		"dot repo":            {token, "o/..", 1, "x", prcomment.ErrRepo},
		"query in repo":       {token, "o/r?x=1", 1, "x", prcomment.ErrRepo},
		"extra segment":       {token, "o/r/issues", 1, "x", prcomment.ErrRepo},
		"zero number":         {token, "o/r", 0, "x", prcomment.ErrNumber},
		"huge number":         {token, "o/r", 1 << 40, "x", prcomment.ErrNumber},
		"no token":            {"", "o/r", 1, "x", prcomment.ErrToken},
		"header injection":    {"abc\r\nX-Evil: 1", "o/r", 1, "x", prcomment.ErrToken},
		"token with a space":  {"abc def", "o/r", 1, "x", prcomment.ErrToken},
		"empty body":          {token, "o/r", 1, "", prcomment.ErrBody},
		"oversized body":      {token, "o/r", 1, strings.Repeat("a", prcomment.MaxBodyBytes+1), prcomment.ErrBody},
		"token over the cap":  {strings.Repeat("a", prcomment.MaxTokenBytes+1), "o/r", 1, "x", prcomment.ErrToken},
		"owner with a colon":  {token, "o:x/r", 1, "x", prcomment.ErrRepo},
		"name with a newline": {token, "o/r\n", 1, "x", prcomment.ErrRepo},
	} {
		if _, err := p.Post(context.Background(), tc.token, tc.repo, tc.n, tc.body); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if s.method != "" {
		t.Errorf("a refused post still reached the server: %+v", s)
	}
	var nilPoster *prcomment.Poster
	if _, err := nilPoster.Post(context.Background(), token, "o/r", 1, "x"); err == nil {
		t.Error("a poster with no client posted")
	}
}

// An error carries neither the token, nor the response body, nor the URL.
func TestErrorsLeakNothing(t *testing.T) {
	p, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"echo ` + r.Header.Get("Authorization") + `"}`))
	})
	_, err := p.Post(context.Background(), token, "secret-owner/secret-repo", 1, "x")
	var se *prcomment.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusForbidden {
		t.Fatalf("err = %v, want a 403 StatusError", err)
	}
	for _, leak := range []string{token, "secret-owner", "echo"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q contains %q", err, leak)
		}
	}

	// a transport failure (nothing listens) names neither the token nor the repository
	dead := &prcomment.Poster{HTTP: p.HTTP, APIBase: "https://127.0.0.1:1"}
	_, err = dead.Post(context.Background(), token, "secret-owner/secret-repo", 1, "x")
	if err == nil {
		t.Fatal("a post to a closed port succeeded")
	}
	for _, leak := range []string{token, "secret-owner"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("transport error %q contains %q", err, leak)
		}
	}
}

// A redirect to another host is refused by safehttp, so the token is never
// sent to it.
func TestRedirectOffHostIsRefused(t *testing.T) {
	var elsewhere bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere = true }))
	defer other.Close()
	p, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	})
	if _, err := p.Post(context.Background(), token, "o/r", 1, "x"); err == nil {
		t.Error("a redirect to another origin was followed")
	}
	if elsewhere {
		t.Error("the token reached the redirect target")
	}
}

func TestOnlyCreatedIsSuccess(t *testing.T) {
	p, _ := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if _, err := p.Post(context.Background(), token, "o/r", 1, "x"); err == nil {
		t.Error("a 200 was taken for a created comment")
	}
	p, _ = server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not json`))
	})
	if res, err := p.Post(context.Background(), token, "o/r", 1, "x"); err != nil || res.ID != 0 || res.URL != "" {
		t.Errorf("created with an unreadable answer = %+v, %v", res, err)
	}
	p, _ = server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1,"html_url":"javascript:alert(1)"}`))
	})
	if res, err := p.Post(context.Background(), token, "o/r", 1, "x"); err != nil || res.URL != "" {
		t.Errorf("a non-https html_url was returned: %+v, %v", res, err)
	}
}

func TestValidRepo(t *testing.T) {
	for _, ok := range []string{"o/r", "Org-1/repo.name_2", "a/.github", "a/b-c"} {
		if !prcomment.ValidRepo(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "/", "o/", "/r", "o/r/", "-o/r", ".hidden/r", "o/.", "o/..", "o r/x", "o/r r", strings.Repeat("a", 101) + "/r"} {
		if prcomment.ValidRepo(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
