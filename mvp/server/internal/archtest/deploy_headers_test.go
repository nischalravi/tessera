package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeploy_UIHeaders keeps the SPA's security headers wired into every static location (issue #531): a
// location with its own add_header drops the inherited ones, so each must include the shared file.
func TestDeploy_UIHeaders(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "..", "..", "deploy", "docker", "nginx")
	inc, err := os.ReadFile(filepath.Join(dir, "tessera-headers.inc"))
	if err != nil {
		t.Skip("deploy/ not present")
	}
	for _, want := range []string{"Content-Security-Policy", "default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'",
		"X-Content-Type-Options nosniff", "Referrer-Policy", "Strict-Transport-Security $tessera_hsts"} {
		if !strings.Contains(string(inc), want) {
			t.Errorf("tessera-headers.inc lacks %q", want)
		}
	}
	if strings.Contains(string(inc), "'unsafe-eval'") || strings.Contains(string(inc), "script-src 'self' 'unsafe") {
		t.Error("the CSP must not allow unsafe script")
	}
	tpl, err := os.ReadFile(filepath.Join(dir, "tessera.conf.template"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(tpl)
	for _, loc := range []string{"location /assets/ {", "location / {"} {
		i := strings.Index(s, loc)
		if i < 0 {
			t.Fatalf("template lacks %q", loc)
		}
		end := strings.Index(s[i:], "\n  }")
		if end < 0 || !strings.Contains(s[i:i+end], "include /etc/nginx/tessera-headers.inc;") {
			t.Errorf("%s does not include tessera-headers.inc", loc)
		}
	}
	if !strings.Contains(s, `https   "${TESSERA_HSTS}"`) {
		t.Error("HSTS must be sent only for https requests")
	}
}
