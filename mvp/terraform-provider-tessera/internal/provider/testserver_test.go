package provider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A real `tessera serve` for the acceptance tests: SQLite, a free port from 8400 up, a seeded demo tenant (larkspur) and two machine
// clients made with `tessera admin add-client`. The tests are skipped unless TF_ACC is set (the Terraform convention), because
// building and starting the server takes about a minute. TESSERA_BIN uses an existing binary instead of building ../../server.
// The process is stopped by its own PID at the end of the test, nothing else is touched.

type testServer struct {
	URL       string
	Tenant    string
	KeyFile   string
	KeyPEM    string
	BearerID  string // a client registered with -dpop=false
	DPoPID    string // a client that requires DPoP
	KeyID     string
	DataDir   string
	serveProc *exec.Cmd
}

func requireAcc(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC=1 (it builds and starts a real tessera serve)")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	for p := 8400; p < 8500; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			_ = l.Close()
			return p
		}
	}
	t.Fatal("no free port in 8400-8499")
	return 0
}

func run(t *testing.T, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...) // #nosec G204 -- test helper with fixed arguments
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	requireAcc(t)
	dir := t.TempDir()
	bin := os.Getenv("TESSERA_BIN")
	if bin == "" {
		bin = filepath.Join(dir, "tessera")
		serverDir, err := filepath.Abs("../../../server")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/tessera") // #nosec G204
		cmd.Dir = serverDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building the server: %v\n%s", err, out)
		}
	}
	port := freePort(t)
	ts := &testServer{URL: fmt.Sprintf("http://127.0.0.1:%d", port), Tenant: "larkspur", KeyID: "tf-test", DataDir: dir}
	env := []string{"TESSERA_ENV=dev", "TESSERA_PUBLIC_URL=" + ts.URL}
	db := filepath.Join(dir, "tessera.db")

	// the client's key pair: only the public half is registered
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	ts.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	ts.KeyFile = filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(ts.KeyFile, []byte(ts.KeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding
	jwks := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":%q,"x":%q,"y":%q}]}`, ts.KeyID,
		b64.EncodeToString(k.X.FillBytes(make([]byte, 32))), b64.EncodeToString(k.Y.FillBytes(make([]byte, 32))))
	jwksFile := filepath.Join(dir, "pub.jwks")
	if err := os.WriteFile(jwksFile, []byte(jwks), 0o600); err != nil {
		t.Fatal(err)
	}

	run(t, env, bin, "seed", "-db", db)
	idRE := regexp.MustCompile(`added machine client (\S+) `)
	add := func(name string, dpop bool) string {
		out := run(t, env, bin, "admin", "add-client", "-tenant", ts.Tenant, "-name", name, "-owner", "ivan.admin@larkspur.example",
			"-jwks-file", jwksFile, "-scope", "tessera:read tessera:write", "-roles", "viewer,operator,auditor",
			fmt.Sprintf("-dpop=%v", dpop), "-db", db)
		m := idRE.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("add-client printed no client id:\n%s", out)
		}
		return m[1]
	}
	ts.BearerID, ts.DPoPID = add("terraform bearer", false), add("terraform dpop", true)

	logFile, err := os.Create(filepath.Join(dir, "serve.log")) // #nosec G304 -- a temp dir
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "serve", "-addr", fmt.Sprintf("127.0.0.1:%d", port), "-db", db) // #nosec G204
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ts.serveProc = cmd
	t.Cleanup(func() {
		_ = cmd.Process.Kill() // this test's own process, by handle
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := http.Get(ts.URL + "/api/health") // #nosec G107 G704 -- loopback test server
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logFile.Name())
			t.Fatalf("the server did not become healthy:\n%s", log)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ts
}
