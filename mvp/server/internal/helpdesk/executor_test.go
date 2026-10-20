package helpdesk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recorder is a fake IdP: it records "METHOD path?query" and answers by route.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) serve(t *testing.T, answer func(w http.ResponseWriter, req *http.Request)) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.calls = append(r.calls, req.Method+" "+req.URL.RequestURI())
		r.mu.Unlock()
		answer(w, req)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (r *recorder) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func TestOktaExecutor(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "SSWS tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	})
	ex, err := NewOkta(srv.Client(), srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Reset(context.Background(), Target{System: SystemOkta, UserID: "00u1", Username: "a", Kind: KindMFA})
	if err != nil || len(res.Steps) != 1 || res.TemporaryAccessPass != "" {
		t.Fatalf("mfa reset = %+v, %v", res, err)
	}
	if _, err := ex.Reset(context.Background(), Target{System: SystemOkta, UserID: "00u1", Kind: KindPassword}); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /api/v1/users/00u1/lifecycle/reset_factors", "POST /api/v1/users/00u1/lifecycle/reset_password?sendEmail=true"}
	if got := rec.get(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", got, want)
	}
	// a bad id never reaches the provider
	if _, err := ex.Reset(context.Background(), Target{UserID: "../x", Kind: KindMFA}); !errors.Is(err, ErrBadTarget) {
		t.Errorf("bad id = %v", err)
	}
	if len(rec.get()) != 2 {
		t.Errorf("a bad id made a call: %v", rec.get())
	}
	// a wrong token is a failed reset whose error carries no secret
	bad, _ := NewOkta(srv.Client(), srv.URL, "wrong-token-value")
	_, err = bad.Reset(context.Background(), Target{UserID: "00u1", Kind: KindMFA})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 401 || strings.Contains(err.Error(), "wrong-token-value") {
		t.Errorf("wrong token = %v", err)
	}
}

func TestEntraExecutor(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/authentication/methods"):
			_, _ = io.WriteString(w, `{"value":[
				{"@odata.type":"#microsoft.graph.passwordAuthenticationMethod","id":"pw1"},
				{"@odata.type":"#microsoft.graph.phoneAuthenticationMethod","id":"ph1"},
				{"@odata.type":"#microsoft.graph.fido2AuthenticationMethod","id":"fk1"}]}`)
		case req.Method == "DELETE":
			w.WriteHeader(http.StatusNoContent)
		case req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/temporaryAccessPassMethods"):
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"temporaryAccessPass":"Tap-123-secret"}`)
		default:
			http.NotFound(w, req)
		}
	})
	ex, err := NewEntra(srv.Client(), srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Reset(context.Background(), Target{System: SystemEntra, UserID: "u-1", Kind: KindMFA})
	if err != nil || res.TemporaryAccessPass != "Tap-123-secret" {
		t.Fatalf("mfa reset = %+v, %v", res, err)
	}
	for _, s := range res.Steps {
		if strings.Contains(s, "Tap-123") {
			t.Errorf("a step carries the pass: %q", s)
		}
	}
	want := []string{"GET /v1.0/users/u-1/authentication/methods",
		"DELETE /v1.0/users/u-1/authentication/phoneMethods/ph1", "DELETE /v1.0/users/u-1/authentication/fido2Methods/fk1",
		"POST /v1.0/users/u-1/authentication/temporaryAccessPassMethods"}
	if got := rec.get(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", got, want)
	}

	// a password reset only issues the pass
	rec.calls = nil
	if _, err := ex.Reset(context.Background(), Target{UserID: "u-1", Kind: KindPassword}); err != nil {
		t.Fatal(err)
	}
	if got := rec.get(); len(got) != 1 || !strings.HasPrefix(got[0], "POST ") {
		t.Errorf("password calls = %v", got)
	}
}

// An Entra method Tessera cannot delete fails the reset before a pass is issued.
func TestEntraExecutorFailsClosed(t *testing.T) {
	var rec recorder
	srv := rec.serve(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" {
			_, _ = io.WriteString(w, `{"value":[{"@odata.type":"#microsoft.graph.somethingNewAuthenticationMethod","id":"x1"}]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ex, _ := NewEntra(srv.Client(), srv.URL, "tok")
	if _, err := ex.Reset(context.Background(), Target{UserID: "u-1", Kind: KindMFA}); err == nil {
		t.Fatal("an undeletable method must fail the reset")
	}
	for _, c := range rec.get() {
		if strings.HasPrefix(c, "POST ") {
			t.Errorf("a pass was issued after a failed delete: %v", rec.get())
		}
	}
}

func TestNewClientValidation(t *testing.T) {
	hc := &http.Client{} // nothing is sent: every case fails validation first
	for name, fn := range map[string]func() error{
		"no http":   func() error { _, err := NewOkta(nil, "https://x.okta.com", "t"); return err },
		"no token":  func() error { _, err := NewOkta(hc, "https://x.okta.com", ""); return err },
		"no url":    func() error { _, err := NewOkta(hc, "", "t"); return err },
		"url creds": func() error { _, err := NewOkta(hc, "https://u:p@x.okta.com", "t"); return err },
		"scheme":    func() error { _, err := NewEntra(hc, "ftp://x", "t"); return err },
	} {
		if fn() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
