package kubernetes_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/kubernetes"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func prodClient(t testing.TB) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

// ParseCredential keeps the old format (the bare token) and reads the token and CA bundle of the JSON one.
func TestParseCredential(t *testing.T) {
	for _, tc := range []struct {
		name, in, token, ca string
		bad                 bool
	}{
		{"bare token", " abc.def ", "abc.def", "", false},
		{"json", `{"token":"abc","ca_bundle":"PEM"}`, "abc", "PEM", false},
		{"json without bundle", `{"token":"abc"}`, "abc", "", false},
		{"broken json", `{"token":`, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, ca, err := kubernetes.ParseCredential(tc.in)
			if (err != nil) != tc.bad || tok != tc.token || ca != tc.ca {
				t.Errorf("= %q, %q, %v", tok, ca, err)
			}
		})
	}
}

// FromStored reads the API server and scope from the stored config and the token (and the optional CA
// bundle) from the credential, refuses what does not open without echoing the credential, and lets only
// the dev override replace the base URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	prod := connsync.Runtime{Env: "prod"}
	const tok = "SA-SECRET-TOKEN"
	const api = "https://api.cluster.example.com:6443"
	for _, tc := range []struct {
		name string
		s    kubernetes.Stored
		good bool
	}{
		{"token", kubernetes.Stored{BaseURL: api, Credential: tok}, true},
		{"namespaces", kubernetes.Stored{BaseURL: api, Namespaces: "payments, ops", OpenShift: "true", Credential: tok}, true},
		{"default port", kubernetes.Stored{BaseURL: "https://api.cluster.example.com", Credential: tok}, true},
		{"no credential", kubernetes.Stored{BaseURL: api}, false},
		{"bad credential", kubernetes.Stored{BaseURL: api, Credential: "two words"}, false},
		{"bad json credential", kubernetes.Stored{BaseURL: api, Credential: `{"token":"` + tok}, false},
		{"bundle without a certificate", kubernetes.Stored{BaseURL: api, Credential: `{"token":"` + tok + `","ca_bundle":"not pem"}`}, false},
		{"no base url", kubernetes.Stored{Credential: tok}, false},
		{"bad namespace", kubernetes.Stored{BaseURL: api, Namespaces: "Bad_Name", Credential: tok}, false},
		{"http", kubernetes.Stored{BaseURL: "http://api.cluster.example.com", Credential: tok}, false},
		{"metadata host", kubernetes.Stored{BaseURL: "https://169.254.169.254", Credential: tok}, false},
		{"other port", kubernetes.Stored{BaseURL: "https://api.cluster.example.com:9999", Credential: tok}, false},
		{"path", kubernetes.Stored{BaseURL: api + "/api", Credential: tok}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := kubernetes.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), tok) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "kubernetes" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	env := func(k string) string {
		if k == "TESSERA_KUBERNETES_BASE_URL" {
			return "https://other.cluster.example.com"
		}
		return ""
	}
	if _, err := kubernetes.FromStored(kubernetes.Stored{Credential: tok}, env, prod, hc, nil); err != nil {
		t.Errorf("base override: %v", err)
	}
}

// With a CA bundle in the credential the API server's certificate is verified against it; without one
// the system roots apply and a private CA is refused.
func TestFromStoredCABundle(t *testing.T) {
	srv := connsynctest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(obj{"metadata": obj{}, "items": []any{}})
	}))
	o := srv.Options(0)
	o.RootCAs = nil // the client trusts the system roots only: the test server's CA is private
	hc, err := safehttp.NewForTest(t, o)
	if err != nil {
		t.Fatal(err)
	}
	noEnv := func(string) string { return "" }
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	withCA, _ := json.Marshal(obj{"token": token, "ca_bundle": ca})

	cn, err := kubernetes.FromStored(kubernetes.Stored{BaseURL: srv.URL, Credential: token}, noEnv, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cn.Discover(context.Background()); err == nil {
		t.Error("a private CA was trusted without a bundle")
	}
	cn, err = kubernetes.FromStored(kubernetes.Stored{BaseURL: srv.URL, Credential: string(withCA)}, noEnv, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cn.Discover(context.Background()); err != nil {
		t.Errorf("with the bundle: %v", err)
	}
}

func TestCheckURL(t *testing.T) {
	for _, tc := range []struct {
		raw string
		bad bool
	}{
		{"https://api.cluster.example.com:6443", false},
		{"https://api.cluster.example.com", false},
		{"http://api.cluster.example.com", true},
		{"https://169.254.169.254", true},
		{"https://api.cluster.example.com:22", true},
		{"https://api.cluster.example.com/x", true},
	} {
		if _, err := kubernetes.CheckURL(tc.raw, connsync.Runtime{Env: "prod"}); (err != nil) != tc.bad {
			t.Errorf("CheckURL(%q) = %v", tc.raw, err)
		}
	}
}
