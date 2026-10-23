package kekwrap_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
	"github.com/nischalravi/tessera/mvp/server/internal/kekwrap"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var theKEK = []byte("0123456789abcdef0123456789abcdef")

// xor is the fake providers' "encryption".
func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0x5a
	}
	return out
}

func devClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: "dev", AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustRef(t *testing.T, s string) kekwrap.Ref {
	t.Helper()
	r, err := kekwrap.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const awsARN = "aws:arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func TestAWSKMS_WrapAndUnwrap(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/eu-west-1/kms/aws4_request") ||
			r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
			http.Error(w, `{"__type":"IncompleteSignature"}`, 403)
			return
		}
		var in struct {
			KeyID             string `json:"KeyId"`
			CiphertextBlob    string
			Plaintext         string
			EncryptionContext map[string]string
		}
		_ = json.Unmarshal(b, &in)
		if in.KeyID != strings.TrimPrefix(awsARN, "aws:") || in.EncryptionContext["purpose"] != "tessera-kek" {
			http.Error(w, `{"__type":"InvalidCiphertextException"}`, 400)
			return
		}
		seen = append(seen, r.Header.Get("X-Amz-Target"))
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			p, _ := base64.StdEncoding.DecodeString(in.Plaintext)
			fmt.Fprintf(w, `{"CiphertextBlob":%q}`, base64.StdEncoding.EncodeToString(xor(p)))
		case "TrentService.Decrypt":
			c, _ := base64.StdEncoding.DecodeString(in.CiphertextBlob)
			fmt.Fprintf(w, `{"Plaintext":%q}`, base64.StdEncoding.EncodeToString(xor(c)))
		}
	}))
	defer srv.Close()
	creds := map[string]string{"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "s"}
	d := kekwrap.Deps{HTTP: devClient(t), Endpoint: srv.URL, AWS: &cloudcred.AWS{Env: cloudcred.Env{Getenv: func(k string) string { return creds[k] }}}}
	ctx := context.Background()
	ref := mustRef(t, awsARN)
	wrapped, err := kekwrap.Wrap(ctx, ref, theKEK, d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped, theKEK) {
		t.Fatal("not wrapped")
	}
	got, err := kekwrap.Unwrap(ctx, ref, wrapped, d)
	if err != nil || !bytes.Equal(got, theKEK) {
		t.Fatalf("%q %v", got, err)
	}
	if strings.Join(seen, ",") != "TrentService.Encrypt,TrentService.Decrypt" {
		t.Errorf("calls: %v", seen)
	}
}

func TestAzureKeyVault_UnwrapKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer vault-token" || r.URL.Query().Get("api-version") == "" {
			http.Error(w, `{"error":{"code":"Unauthorized"}}`, 401)
			return
		}
		var in struct{ Alg, Value string }
		_ = json.Unmarshal(b, &in)
		v, _ := base64.RawURLEncoding.DecodeString(in.Value)
		if in.Alg != "RSA-OAEP-256" {
			http.Error(w, `{"error":{"code":"BadParameter"}}`, 400)
			return
		}
		switch r.URL.Path {
		case "/keys/tessera-kek/v1/wrapkey", "/keys/tessera-kek/v1/unwrapkey":
			fmt.Fprintf(w, `{"kid":"x","value":%q}`, base64.RawURLEncoding.EncodeToString(xor(v)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "https://vault.azure.net" {
			http.Error(w, "wrong resource", 400)
			return
		}
		fmt.Fprint(w, `{"access_token":"vault-token","expires_in":"3600"}`)
	}))
	defer imds.Close()
	d := kekwrap.Deps{HTTP: devClient(t), Endpoint: srv.URL,
		Azure: &cloudcred.Azure{Meta: safehttp.NewMetadataClientForTest(t, imds.Listener.Addr().String())}}
	ref := mustRef(t, "azure:https://myvault.vault.azure.net/keys/tessera-kek/v1")
	wrapped, err := kekwrap.Wrap(context.Background(), ref, theKEK, d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kekwrap.Unwrap(context.Background(), ref, wrapped, d)
	if err != nil || !bytes.Equal(got, theKEK) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestGCPKMS_DecryptBindsThePurpose(t *testing.T) {
	const name = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			http.Error(w, "{}", 401)
			return
		}
		var in struct{ Plaintext, Ciphertext, AdditionalAuthenticatedData string }
		_ = json.Unmarshal(b, &in)
		aad, _ := base64.StdEncoding.DecodeString(in.AdditionalAuthenticatedData)
		if string(aad) != "tessera-kek" {
			http.Error(w, `{"error":{"status":"INVALID_ARGUMENT"}}`, 400)
			return
		}
		switch r.URL.Path {
		case "/v1/" + name + ":encrypt":
			p, _ := base64.StdEncoding.DecodeString(in.Plaintext)
			fmt.Fprintf(w, `{"ciphertext":%q}`, base64.StdEncoding.EncodeToString(xor(p)))
		case "/v1/" + name + ":decrypt":
			c, _ := base64.StdEncoding.DecodeString(in.Ciphertext)
			fmt.Fprintf(w, `{"plaintext":%q}`, base64.StdEncoding.EncodeToString(xor(c)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"gcp-token","expires_in":3600}`)
	}))
	defer meta.Close()
	d := kekwrap.Deps{HTTP: devClient(t), Endpoint: srv.URL,
		GCP: &cloudcred.GCP{Meta: safehttp.NewMetadataClientForTest(t, meta.Listener.Addr().String())}}
	ref := mustRef(t, "gcp:"+name)
	wrapped, err := kekwrap.Wrap(context.Background(), ref, theKEK, d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kekwrap.Unwrap(context.Background(), ref, wrapped, d)
	if err != nil || !bytes.Equal(got, theKEK) {
		t.Fatalf("%q %v", got, err)
	}
}

// Failures name the provider and the status, never the response body.
func TestUnwrapErrorsAreQuietAndSizeChecked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "short") {
			fmt.Fprintf(w, `{"plaintext":%q}`, base64.StdEncoding.EncodeToString([]byte("too short")))
			return
		}
		http.Error(w, `{"error":{"status":"PERMISSION_DENIED","message":"secret-detail-xyz"}}`, 403)
	}))
	defer srv.Close()
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"t","expires_in":3600}`)
	}))
	defer meta.Close()
	d := kekwrap.Deps{HTTP: devClient(t), Endpoint: srv.URL, GCP: &cloudcred.GCP{Meta: safehttp.NewMetadataClientForTest(t, meta.Listener.Addr().String())}}
	_, err := kekwrap.Unwrap(context.Background(), mustRef(t, "gcp:projects/p/locations/g/keyRings/r/cryptoKeys/k"), []byte("c"), d)
	if err == nil || strings.Contains(err.Error(), "secret-detail") || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("%v", err)
	}
	_, err = kekwrap.Unwrap(context.Background(), mustRef(t, "gcp:projects/p/locations/g/keyRings/short/cryptoKeys/k"), []byte("c"), d)
	if err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("a short unwrapped key must be refused: %v", err)
	}
	if _, err := kekwrap.Unwrap(context.Background(), mustRef(t, "gcp:projects/p/locations/g/keyRings/r/cryptoKeys/k"), nil, d); err == nil {
		t.Fatal("an empty wrapped key was accepted")
	}
}

func TestParseRef(t *testing.T) {
	for _, s := range []string{
		awsARN, "aws:arn:aws:kms:us-gov-west-1:111122223333:alias/tessera", "aws:arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abc-1",
		"azure:https://v1.vault.azure.net/keys/k", "azure:https://v1.managedhsm.azure.net/keys/k/abc123",
		"gcp:projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
	} {
		if _, err := kekwrap.ParseRef(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{
		"", "aws", "aws:", "aws:arn:aws:s3:::b", "aws:arn:aws:kms:eu-west-1:1:key/x", "aws:key/1234",
		"azure:http://v.vault.azure.net/keys/k", "azure:https://v.vault.azure.net:8443/keys/k", "azure:https://vault.azure.net/keys/k",
		"azure:https://u@v.vault.azure.net/keys/k", "azure:https://v.vault.azure.net/keys/k?x=1", "azure:https://v.vault.azure.net/secrets/k",
		"azure:https://evil.example.com/keys/k", "azure:https://v.vault.azure.net.evil.com/keys/k", "azure:https://v.vault.azure.net/keys/../k",
		"gcp:projects/p/locations/l/keyRings/r", "gcp:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "gcp:../x",
		"vault:x", "AWS:arn:aws:kms:eu-west-1:111122223333:key/a",
	} {
		if _, err := kekwrap.ParseRef(s); err == nil {
			t.Errorf("%q was accepted", s)
		}
	}
}
