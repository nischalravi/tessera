package wire_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

const (
	k8sToken   = "k8s-sa-token-value"
	vaultToken = "hvs.vault-token-value"
)

func k8sFake() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+k8sToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		out := func(items ...any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": items})
		}
		meta := func(ns, name string) map[string]any { return map[string]any{"namespace": ns, "name": name} }
		switch {
		case strings.HasSuffix(r.URL.Path, "/clusterroles"):
			out(map[string]any{"metadata": meta("", "cluster-admin"), "rules": []any{map[string]any{"verbs": []string{"*"}, "resources": []string{"*"}}}})
		case strings.HasSuffix(r.URL.Path, "/clusterrolebindings"):
			out(map[string]any{"metadata": meta("", "admins"), "roleRef": map[string]any{"kind": "ClusterRole", "name": "cluster-admin"},
				"subjects": []any{map[string]any{"kind": "User", "name": "alice@example.com"}}})
		case strings.HasSuffix(r.URL.Path, "/roles"), strings.HasSuffix(r.URL.Path, "/rolebindings"):
			out()
		case strings.HasSuffix(r.URL.Path, "/serviceaccounts"):
			out(map[string]any{"metadata": meta("payments", "ci")})
		case strings.HasSuffix(r.URL.Path, "/groups"):
			out(map[string]any{"metadata": meta("", "ops"), "users": []string{"alice@example.com"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func vaultFake() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Vault-Token") != vaultToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		data := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
		keys := func(k ...string) { data(map[string]any{"keys": k}) }
		list := r.URL.Query().Get("list") == "true"
		switch p := strings.TrimPrefix(r.URL.Path, "/v1/"); {
		case p == "auth/token/lookup-self":
			data(map[string]any{"display_name": "token-tessera"})
		case p == "sys/policies/acl" && list:
			keys("admin")
		case p == "sys/policies/acl/admin":
			data(map[string]any{"policy": `path "sys/*" { capabilities = ["sudo"] }`})
		case p == "sys/auth":
			data(map[string]any{"approle/": map[string]any{"type": "approle"}})
		case p == "auth/approle/role" && list:
			keys("ci")
		case p == "auth/approle/role/ci":
			data(map[string]any{"token_policies": []string{"admin"}})
		case p == "identity/entity/id" && list:
			keys("e1")
		case p == "identity/entity/id/e1":
			data(map[string]any{"id": "e1", "name": "alice", "policies": []string{"admin"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestKubernetesProberAndConnector(t *testing.T) {
	srv, n := serve(t, k8sFake())
	p := governed.Params{Type: governed.Kubernetes, BaseURL: srv.URL, Secret: k8sToken, Settings: map[string]string{"openshift": "true"}}
	pr := prober(t, p, n)
	wantPass(t, pr, "kubernetes", "endpoint_reachable", "auth_ok", "read_probe")
	auth, err := pr.Authenticate(context.Background())
	if err != nil || !auth.OK || auth.Mode != "bearer_token" {
		t.Errorf("auth = %+v, err = %v", auth, err)
	}
	st, err := pr.Sample(context.Background(), connectors.SampleQuery{})
	if err != nil || !st.Available || st.PerClass["cluster_role"] != 1 || st.PerClass["service_account"] != 1 || st.PerClass["group"] != 1 {
		t.Errorf("sample = %+v, err = %v", st, err)
	}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "kubernetes" || len(res.Permissions) != 1 || !res.Permissions[0].Privileged || res.Stats == nil {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	// the wrong token is an answer to the authentication check, not a failure of the probe
	bad := p
	bad.Secret = "wrong"
	auth, err = prober(t, bad, n).Authenticate(context.Background())
	if err != nil || auth.OK {
		t.Errorf("wrong token: %+v, %v", auth, err)
	}
	// the base URL is required and checked: plain http to a public name is refused
	if _, err := wire.Prober(governed.Params{Type: governed.Kubernetes, BaseURL: "http://api.example.com", Secret: k8sToken}, n); err == nil {
		t.Error("an http base URL was accepted")
	}
}

func TestVaultProberAndConnector(t *testing.T) {
	srv, n := serve(t, vaultFake())
	p := governed.Params{Type: governed.Vault, BaseURL: srv.URL, Secret: vaultToken}
	pr := prober(t, p, n)
	wantPass(t, pr, "vault", "endpoint_reachable", "auth_ok", "read_probe")
	st, err := pr.Sample(context.Background(), connectors.SampleQuery{})
	if err != nil || !st.Available || st.PerClass["policy"] != 1 || st.PerClass["auth_method"] != 1 || st.PerClass["entity"] != 1 {
		t.Errorf("sample = %+v, err = %v", st, err)
	}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "vault" || len(res.Permissions) != 1 || !res.Permissions[0].Privileged || len(res.Accounts) != 2 {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	bad := p
	bad.Secret = "hvs.wrong"
	auth, err := prober(t, bad, n).Authenticate(context.Background())
	if err != nil || auth.OK {
		t.Errorf("wrong token: %+v, %v", auth, err)
	}
}

func TestK8sVaultParamsNeverPrintTheSecret(t *testing.T) {
	for typ, secret := range map[string]string{governed.Kubernetes: k8sToken, governed.Vault: vaultToken} {
		if s := (governed.Params{Type: typ, Secret: secret}).String(); strings.Contains(s, secret) {
			t.Errorf("%s params print the secret: %s", typ, s)
		}
		if ty, _ := governed.Lookup(typ); ty.Feature {
			t.Errorf("%s hands over to a feature; it is read by the connector sync", typ)
		}
	}
}
