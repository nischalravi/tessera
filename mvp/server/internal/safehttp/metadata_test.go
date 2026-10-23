package safehttp_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func metaServer(t *testing.T) (*http.Client, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/other", http.StatusFound)
			return
		}
		if r.URL.Path == "/big" {
			_, _ = w.Write([]byte(strings.Repeat("x", 100<<10)))
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return safehttp.NewMetadataClientForTest(t, srv.Listener.Addr().String()), &hits
}

// The metadata client reaches only the fixed addresses on port 80 over http.
func TestMetadataClient_OnlyTheFixedAddresses(t *testing.T) {
	c, hits := metaServer(t)
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "http://169.254.170.2/v2/credentials", "http://[fd00:ec2::254]/latest/api/token"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		resp.Body.Close()
	}
	if *hits != 3 {
		t.Fatalf("hits = %d", *hits)
	}
	for _, u := range []string{
		"https://169.254.169.254/",         // not http
		"http://169.254.169.254:8080/",     // not port 80
		"http://169.254.169.253/",          // another link-local address
		"http://metadata.google.internal/", // a name, never resolved
		"http://127.0.0.1/",                // loopback
		"http://10.0.0.1/",                 // private
		"http://example.com/",              // public
		"http://user@169.254.169.254/",     // user info
		"http://[::ffff:169.254.169.254]/", // mapped form
		"http://2852039166/",               // numeric form of 169.254.169.254
	} {
		before := *hits
		resp, err := c.Get(u)
		if err == nil {
			resp.Body.Close()
			t.Errorf("%s was allowed", u)
		} else if !errors.Is(err, safehttp.ErrMetadataTarget) {
			t.Errorf("%s: %v", u, err)
		}
		if *hits != before {
			t.Errorf("%s reached the server", u)
		}
	}
}

func TestMetadataClient_NoRedirectsAndBodyLimit(t *testing.T) {
	c, _ := metaServer(t)
	resp, err := c.Get("http://169.254.169.254/redirect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("a redirect must be returned, not followed: %d", resp.StatusCode)
	}
	resp, err = c.Get("http://169.254.169.254/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, safehttp.ErrTooLarge) {
		t.Fatalf("oversized body: %v", err)
	}
}

// The ordinary client still refuses the metadata address: the exception is
// only the dedicated client.
func TestOrdinaryClientStillRefusesMetadata(t *testing.T) {
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := c.Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		resp.Body.Close()
		t.Fatal("the guarded client reached the metadata address")
	}
}
