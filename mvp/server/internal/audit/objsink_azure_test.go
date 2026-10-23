package audit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// An Azure worm=container anchor into a container without an immutability policy is refused before any blob
// is written.
func TestObjectSink_AzureContainerWithoutPolicyRefused(t *testing.T) {
	policy, puts := "", 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("restype") == "container":
			if policy != "" {
				w.Header().Set("x-ms-has-immutability-policy", policy)
			}
		case r.Method == http.MethodPut:
			puts++
			w.Header().Set("x-ms-version-id", "v1")
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "dev", AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	az := &cloudcred.Azure{Env: cloudcred.Env{Getenv: func(k string) string {
		if k == "AZURE_STORAGE_SAS_TOKEN" {
			return "sv=2023-11-03&sig=abc"
		}
		return ""
	}}}
	st, err := objstore.Open("azure://acct123/cont?worm=container&endpoint="+url.QueryEscape(srv.URL), objstore.Deps{HTTP: hc, Azure: az})
	if err != nil {
		t.Fatal(err)
	}
	sink := &audit.ObjectSink{Store: st}
	a := audit.Anchor{TID: sinkTID, Seq: 5, HeadHash: "h", JWS: "jws"}
	if _, err := sink.Anchor(context.Background(), a); err == nil || !strings.Contains(err.Error(), "immutability policy") || puts != 0 {
		t.Fatalf("anchor into an unprotected container: err=%v puts=%d", err, puts)
	}
	policy = "true"
	if _, err := sink.Anchor(context.Background(), a); err != nil || puts != 1 {
		t.Fatalf("anchor into a protected container: err=%v puts=%d", err, puts)
	}
}
