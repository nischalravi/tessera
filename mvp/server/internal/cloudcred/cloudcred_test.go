package cloudcred_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func env(m map[string]string, files map[string]string) cloudcred.Env {
	return cloudcred.Env{
		Getenv: func(k string) string { return m[k] },
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, fmt.Errorf("no file %s", p)
		},
		Now: func() time.Time { return t0 },
	}
}

// metaClient serves h as the cloud metadata service.
func metaClient(t *testing.T, h http.Handler) *http.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return safehttp.NewMetadataClientForTest(t, srv.Listener.Addr().String())
}

// devClient is the guarded client with the dev loopback exception, for fake
// token endpoints on 127.0.0.1.
func devClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: "dev", AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAWS_StaticEnvKeys(t *testing.T) {
	a := &cloudcred.AWS{Env: env(map[string]string{"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "s3cr3t", "AWS_SESSION_TOKEN": "tok"}, nil)}
	c, err := a.Credentials(context.Background())
	if err != nil || c.AccessKeyID != "AKIDEXAMPLE" || c.SessionToken != "tok" {
		t.Fatalf("%v %v", c, err)
	}
	if strings.Contains(fmt.Sprint(c), "s3cr3t") || strings.Contains(fmt.Sprintf("%#v", c), "s3cr3t") {
		t.Fatal("credentials leaked through fmt")
	}
}

func TestAWS_IMDSv2(t *testing.T) {
	var tokenReqs, credReqs atomic.Int32
	meta := metaClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				http.Error(w, "no ttl", 400)
				return
			}
			tokenReqs.Add(1)
			fmt.Fprint(w, "imds-session")
		case r.Header.Get("X-aws-ec2-metadata-token") != "imds-session":
			http.Error(w, "IMDSv1 is not served", 401)
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			fmt.Fprint(w, "tessera-role\n")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/tessera-role":
			credReqs.Add(1)
			fmt.Fprintf(w, `{"AccessKeyId":"ASIAROLE","SecretAccessKey":"sek","Token":"sess","Expiration":%q}`, t0.Add(time.Hour).Format(time.RFC3339))
		case r.URL.Path == "/latest/meta-data/placement/region":
			fmt.Fprint(w, "eu-west-1")
		default:
			http.NotFound(w, r)
		}
	}))
	a := &cloudcred.AWS{Env: env(nil, nil), Meta: meta}
	for i := 0; i < 3; i++ { // cached after the first fetch
		c, err := a.Credentials(context.Background())
		if err != nil || c.AccessKeyID != "ASIAROLE" || c.SessionToken != "sess" {
			t.Fatalf("%v %v", c, err)
		}
	}
	if credReqs.Load() != 1 {
		t.Fatalf("credentials fetched %d times", credReqs.Load())
	}
	if r, err := a.Region(context.Background()); err != nil || r != "eu-west-1" {
		t.Fatalf("region %q %v", r, err)
	}
}

func TestAWS_NoIMDSMeansNoCredentials(t *testing.T) {
	meta := metaClient(t, http.NotFoundHandler())
	_, err := (&cloudcred.AWS{Env: env(nil, nil), Meta: meta}).Credentials(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestAWS_WebIdentity(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("WebIdentityToken") != "jwt-from-k8s" ||
			r.Form.Get("RoleArn") != "arn:aws:iam::1:role/tessera" {
			http.Error(w, "bad", 400)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>
			<AccessKeyId>ASIAWEB</AccessKeyId><SecretAccessKey>websek</SecretAccessKey><SessionToken>webtok</SessionToken>
			<Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, t0.Add(time.Hour).Format(time.RFC3339))
	}))
	defer sts.Close()
	a := &cloudcred.AWS{HTTP: devClient(t), STSURL: sts.URL + "/", Env: env(map[string]string{
		"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/token", "AWS_ROLE_ARN": "arn:aws:iam::1:role/tessera", "AWS_REGION": "us-east-1"},
		map[string]string{"/var/run/secrets/token": "jwt-from-k8s\n"})}
	c, err := a.Credentials(context.Background())
	if err != nil || c.AccessKeyID != "ASIAWEB" || c.SessionToken != "webtok" {
		t.Fatalf("%v %v", c, err)
	}
}

func TestAWS_ECSContainerCredentials(t *testing.T) {
	meta := metaClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/credentials/abc" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"AccessKeyId":"ASIAECS","SecretAccessKey":"x","Token":"y","Expiration":%q}`, t0.Add(time.Hour).Format(time.RFC3339))
	}))
	a := &cloudcred.AWS{Meta: meta, Env: env(map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/abc"}, nil)}
	if c, err := a.Credentials(context.Background()); err != nil || c.AccessKeyID != "ASIAECS" {
		t.Fatalf("%v %v", c, err)
	}
	bad := &cloudcred.AWS{Meta: meta, Env: env(map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/../x"}, nil)}
	if _, err := bad.Credentials(context.Background()); err == nil {
		t.Fatal("a path with .. was accepted")
	}
}

func TestAzure_ManagedIdentity(t *testing.T) {
	var n atomic.Int32
	meta := metaClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" || r.URL.Path != "/metadata/identity/oauth2/token" ||
			r.URL.Query().Get("resource") != "https://storage.azure.com" || r.URL.Query().Get("client_id") != "uami" {
			http.Error(w, "bad request", 400)
			return
		}
		n.Add(1)
		fmt.Fprint(w, `{"access_token":"az-token","expires_in":"3599"}`)
	}))
	z := &cloudcred.Azure{Meta: meta, Env: env(map[string]string{"AZURE_CLIENT_ID": "uami"}, nil)}
	for i := 0; i < 2; i++ {
		tok, err := z.Token(context.Background(), "https://storage.azure.com/")
		if err != nil || tok != "az-token" {
			t.Fatalf("%q %v", tok, err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("fetched %d times", n.Load())
	}
}

func TestAzure_WorkloadIdentityFederation(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" || r.Form.Get("client_assertion") != "k8s-jwt" ||
			r.Form.Get("client_id") != "client-1" || r.Form.Get("scope") != "https://vault.azure.net/.default" ||
			r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "bad", 400)
			return
		}
		fmt.Fprint(w, `{"access_token":"fed-token","expires_in":3600}`)
	}))
	defer login.Close()
	z := &cloudcred.Azure{HTTP: devClient(t), LoginURL: login.URL, Env: env(map[string]string{
		"AZURE_FEDERATED_TOKEN_FILE": "/tok", "AZURE_TENANT_ID": "tenant-1", "AZURE_CLIENT_ID": "client-1"},
		map[string]string{"/tok": "k8s-jwt"})}
	if tok, err := z.Token(context.Background(), "https://vault.azure.net"); err != nil || tok != "fed-token" {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestGCP_MetadataServer(t *testing.T) {
	meta := metaClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" || r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/token" {
			http.Error(w, "bad", 403)
			return
		}
		fmt.Fprint(w, `{"access_token":"gcp-meta","expires_in":3000,"token_type":"Bearer"}`)
	}))
	g := &cloudcred.GCP{Meta: meta, Env: env(nil, nil)}
	if tok, err := g.Token(context.Background(), "scope"); err != nil || tok != "gcp-meta" {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestGCP_ServiceAccountKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	keyFile, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com",
		"private_key": pemKey, "private_key_id": "kid1", "token_uri": "https://evil.example/token"})
	var endpoint string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			http.Error(w, "bad jwt", 400)
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
			http.Error(w, "bad signature", 400)
			return
		}
		cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(cb, &claims)
		if claims["iss"] != "sa@p.iam.gserviceaccount.com" || claims["scope"] != "the-scope" || claims["aud"] != endpoint {
			http.Error(w, fmt.Sprint("bad claims ", claims), 400)
			return
		}
		fmt.Fprint(w, `{"access_token":"gcp-sa","expires_in":3600}`)
	}))
	defer tokenSrv.Close()
	endpoint = tokenSrv.URL
	g := &cloudcred.GCP{HTTP: devClient(t), TokenURL: tokenSrv.URL, Env: env(map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/key.json"},
		map[string]string{"/key.json": string(keyFile)})}
	if tok, err := g.Token(context.Background(), "the-scope"); err != nil || tok != "gcp-sa" {
		t.Fatalf("%q %v", tok, err)
	}
	// a federation file (not a service_account key) is refused with a clear message
	g2 := &cloudcred.GCP{Env: env(map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/k"}, map[string]string{"/k": `{"type":"external_account"}`})}
	if _, err := g2.Token(context.Background(), "s"); err == nil || !strings.Contains(err.Error(), "service_account") {
		t.Fatalf("external_account: %v", err)
	}
}

// Error messages carry the status, never a response body or a token.
func TestErrorsDoNotLeakBodies(t *testing.T) {
	meta := metaClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-body-AKIA123", http.StatusForbidden)
	}))
	_, err := (&cloudcred.GCP{Meta: meta, Env: env(nil, nil)}).Token(context.Background(), "s")
	if err == nil || strings.Contains(err.Error(), "secret-body") {
		t.Fatalf("%v", err)
	}
}
