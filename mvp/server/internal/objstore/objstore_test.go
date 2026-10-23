package objstore_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const segKey = "00000000-0000-4000-8000-000000000001/audit/00000000-0000-4000-8000-0000000000aa.seg"

func devClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: "dev", AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeBucket is a create-only object store behind an http handler.
type fakeBucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	last    *http.Request
}

func (f *fakeBucket) put(key string, b []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	if _, ok := f.objects[key]; ok {
		return false
	}
	f.objects[key] = b
	return true
}

func (f *fakeBucket) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	return b, ok
}

func staticAWS() *cloudcred.AWS {
	m := map[string]string{"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "sess"}
	return &cloudcred.AWS{Env: cloudcred.Env{Getenv: func(k string) string { return m[k] }}}
}

func TestS3_PutGetCreateOnly(t *testing.T) {
	fb := &fakeBucket{}
	var lastPut *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/us-east-1/s3/aws4_request") ||
			r.Header.Get("X-Amz-Security-Token") != "sess" || r.Header.Get("X-Amz-Content-Sha256") == "" {
			http.Error(w, "unsigned", 403)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/bkt/")
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			lastPut = r.Clone(context.Background())
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "must be create-only", 400)
				return
			}
			if !fb.put(key, b) {
				http.Error(w, "exists", http.StatusPreconditionFailed)
				return
			}
			w.Header().Set("x-amz-version-id", "v1")
		case http.MethodGet:
			b, ok := fb.get(key)
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		}
	}))
	defer srv.Close()
	st, err := objstore.Open("s3://bkt/pre/fix?endpoint="+url.QueryEscape(srv.URL), objstore.Deps{HTTP: devClient(t), AWS: staticAWS()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	until := time.Date(2033, 1, 2, 3, 4, 5, 0, time.UTC)
	ref, err := st.Put(ctx, segKey, []byte("hello"), objstore.PutOptions{RetainUntil: until, Metadata: map[string]string{"Tid": "t1"}})
	if err != nil || ref != "v1" {
		t.Fatalf("put: %q %v", ref, err)
	}
	if lastPut.Header.Get("x-amz-object-lock-mode") != "COMPLIANCE" || lastPut.Header.Get("x-amz-object-lock-retain-until-date") != "2033-01-02T03:04:05Z" ||
		lastPut.Header.Get("x-amz-checksum-sha256") == "" || lastPut.Header.Get("x-amz-meta-tid") != "t1" {
		t.Errorf("headers: %v", lastPut.Header)
	}
	if _, err := st.Put(ctx, segKey, []byte("other"), objstore.PutOptions{}); !errors.Is(err, objstore.ErrExists) {
		t.Fatalf("second put: %v", err)
	}
	got, err := st.Get(ctx, segKey)
	if err != nil || string(got) != "hello" {
		t.Fatalf("get: %q %v", got, err)
	}
	if _, err := st.Get(ctx, "00000000-0000-4000-8000-000000000001/audit/missing.seg"); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, ok := fb.get("pre/fix/" + segKey); !ok {
		t.Errorf("object not under the prefix: %v", fb.objects)
	}
}

func TestS3_URLStyles(t *testing.T) {
	// no endpoint: virtual-hosted style on the region; the request fails here (no network),
	// so only check what the client would build through an erroring transport
	var seen string
	hc := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return nil, errors.New("stop")
	})}
	st, err := objstore.Open("s3://my-bucket/p?region=eu-west-1", objstore.Deps{HTTP: hc, AWS: staticAWS()})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.Get(context.Background(), "a/b.seg")
	if seen != "https://my-bucket.s3.eu-west-1.amazonaws.com/p/a/b.seg" {
		t.Errorf("virtual-hosted: %s", seen)
	}
	st, _ = objstore.Open("s3://my.dotted.bucket?region=eu-west-1", objstore.Deps{HTTP: hc, AWS: staticAWS()})
	_, _ = st.Get(context.Background(), "a.seg")
	if seen != "https://s3.eu-west-1.amazonaws.com/my.dotted.bucket/a.seg" {
		t.Errorf("path style for dotted bucket: %s", seen)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAzure_BearerAndSAS(t *testing.T) {
	fb := &fakeBucket{}
	var puts []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-ms-version") == "" {
			http.Error(w, "no version", 400)
			return
		}
		sas := r.URL.Query().Get("sig") != ""
		if !sas && r.Header.Get("Authorization") != "Bearer az-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/cont/")
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			puts = append(puts, r.Clone(context.Background()))
			if r.Header.Get("x-ms-blob-type") != "BlockBlob" || r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "bad put", 400)
				return
			}
			if !fb.put(key, b) {
				http.Error(w, "BlobAlreadyExists", http.StatusConflict)
				return
			}
			w.Header().Set("x-ms-version-id", "2026-10-01T00:00:00Z")
		case http.MethodGet:
			b, ok := fb.get(key)
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		}
	}))
	defer srv.Close()
	raw := "azure://acct123/cont/anchors?endpoint=" + url.QueryEscape(srv.URL)
	meta := map[string]string{}
	az := &cloudcred.Azure{Env: cloudcred.Env{Getenv: func(k string) string { return meta[k] }},
		Meta: nil}
	_ = az
	// SAS path: no token fetch at all
	meta["AZURE_STORAGE_SAS_TOKEN"] = "?sv=2023-11-03&sig=abc"
	st, err := objstore.Open(raw, objstore.Deps{HTTP: devClient(t), Azure: az})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	until := time.Date(2033, 1, 2, 3, 4, 5, 0, time.UTC)
	ref, err := st.Put(ctx, "tid/1.jws", []byte("jws"), objstore.PutOptions{RetainUntil: until, Metadata: map[string]string{"head-hash": "h"}})
	if err != nil || ref == "" {
		t.Fatalf("put: %q %v", ref, err)
	}
	h := puts[0].Header
	if h.Get("x-ms-immutability-policy-mode") != "Locked" || h.Get("x-ms-immutability-policy-until-date") != "Sun, 02 Jan 2033 03:04:05 UTC" || h.Get("x-ms-meta-head_hash") != "h" {
		t.Errorf("headers: %v", h)
	}
	if _, err := st.Put(ctx, "tid/1.jws", []byte("x"), objstore.PutOptions{}); !errors.Is(err, objstore.ErrExists) {
		t.Fatalf("second put: %v", err)
	}
	if b, err := st.Get(ctx, "tid/1.jws"); err != nil || string(b) != "jws" {
		t.Fatalf("get: %q %v", b, err)
	}
	// worm=container: no immutability headers (the container's policy applies)
	st2, _ := objstore.Open(raw+"&worm=container", objstore.Deps{HTTP: devClient(t), Azure: az})
	if _, err := st2.Put(ctx, "tid/2.jws", []byte("j2"), objstore.PutOptions{RetainUntil: until}); err != nil {
		t.Fatal(err)
	}
	if puts[len(puts)-1].Header.Get("x-ms-immutability-policy-mode") != "" {
		t.Error("container mode must not set per-blob immutability")
	}
}

func TestAzure_ManagedIdentityBearer(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "data")
	}))
	defer srv.Close()
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"az-token","expires_in":"3600"}`)
	}))
	defer imds.Close()
	az := &cloudcred.Azure{Meta: safehttp.NewMetadataClientForTest(t, imds.Listener.Addr().String())}
	st, err := objstore.Open("azure://acct123/cont?endpoint="+url.QueryEscape(srv.URL), objstore.Deps{HTTP: devClient(t), Azure: az})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := st.Get(context.Background(), "k.seg"); err != nil || string(b) != "data" || auth != "Bearer az-token" {
		t.Fatalf("%q %v auth=%q", b, err, auth)
	}
}

func TestGCS_PutGetAndRetentionCheck(t *testing.T) {
	fb := &fakeBucket{}
	locked := false
	var putURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/bkt/o":
			putURL = r.URL.String()
			b, _ := io.ReadAll(r.Body)
			if r.URL.Query().Get("ifGenerationMatch") != "0" {
				http.Error(w, "must be create-only", 400)
				return
			}
			if !fb.put(r.URL.Query().Get("name"), b) {
				http.Error(w, "exists", http.StatusPreconditionFailed)
				return
			}
			fmt.Fprint(w, `{"generation":"1730000000000000"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/bkt":
			fmt.Fprintf(w, `{"retentionPolicy":{"isLocked":%v}}`, locked)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/storage/v1/b/bkt/o/"):
			name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/storage/v1/b/bkt/o/"))
			b, ok := fb.get(name)
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"gcp-token","expires_in":3600}`)
	}))
	defer tok.Close()
	gcp := &cloudcred.GCP{Meta: safehttp.NewMetadataClientForTest(t, tok.Listener.Addr().String())}
	st, err := objstore.Open("gs://bkt/anch?endpoint="+url.QueryEscape(srv.URL), objstore.Deps{HTTP: devClient(t), GCP: gcp})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ref, err := st.Put(ctx, "tid/7.jws", []byte("jws7"), objstore.PutOptions{})
	if err != nil || ref != "anch/tid/7.jws#1730000000000000" {
		t.Fatalf("put: %q %v (%s)", ref, err, putURL)
	}
	if _, err := st.Put(ctx, "tid/7.jws", []byte("x"), objstore.PutOptions{}); !errors.Is(err, objstore.ErrExists) {
		t.Fatalf("second put: %v", err)
	}
	if b, err := st.Get(ctx, "tid/7.jws"); err != nil || string(b) != "jws7" {
		t.Fatalf("get: %q %v", b, err)
	}
	if _, err := st.Get(ctx, "tid/8.jws"); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	v := st.(objstore.Verifier)
	if err := v.VerifyRetention(ctx); err == nil {
		t.Fatal("an unlocked bucket passed")
	}
	locked = true
	if err := v.VerifyRetention(ctx); err != nil {
		t.Fatalf("a locked bucket failed: %v", err)
	}
}

func TestParseURL(t *testing.T) {
	good := map[string]objstore.Target{
		"s3://bkt":                            {Scheme: "s3", Bucket: "bkt", Immutable: "version"},
		"s3://bkt/a/b/?region=eu-west-1":      {Scheme: "s3", Bucket: "bkt", Prefix: "a/b", Region: "eu-west-1", Immutable: "version"},
		"azure://acct123/cont/p":              {Scheme: "azure", Account: "acct123", Bucket: "cont", Prefix: "p", Immutable: "version"},
		"azure://acct123/cont?worm=container": {Scheme: "azure", Account: "acct123", Bucket: "cont", Immutable: "container"},
		"gs://bkt/x":                          {Scheme: "gs", Bucket: "bkt", Prefix: "x", Immutable: "version"},
	}
	for raw, want := range good {
		got, err := objstore.ParseURL(raw)
		if err != nil || *got != want {
			t.Errorf("%s: %+v %v, want %+v", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"s3://", "s3://BAD_Bucket", "s3://bkt/../x", "s3://bkt/a//b", "s3://user:pw@bkt/x", "s3://bkt?foo=1", "s3://bkt?region=EU WEST",
		"s3://bkt?endpoint=ftp://x", "s3://bkt?endpoint=https://u:p@x", "azure://acct123", "azure://AB/cont", "azure://acct123/c",
		"azure://acct123/cont?worm=maybe", "gs://bkt?region=x", "gs://bkt#frag", "http://example.com/x", "s3://bkt/a b",
	} {
		if _, err := objstore.ParseURL(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
	// credentials in an error message are redacted
	_, err := objstore.ParseURL("s3://user:hunter2@bkt/x")
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestKeysCannotEscape(t *testing.T) {
	st, _ := objstore.Open("gs://bkt/p?endpoint=http://127.0.0.1:1", objstore.Deps{HTTP: devClient(t), GCP: &cloudcred.GCP{}})
	for _, k := range []string{"", "/abs", "../x", "a/../b", "a//b", "a b", "a?b"} {
		if _, err := st.Get(context.Background(), k); err == nil || !strings.Contains(err.Error(), "invalid object key") {
			t.Errorf("key %q: %v", k, err)
		}
	}
}
