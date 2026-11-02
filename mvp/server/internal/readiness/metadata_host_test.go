package readiness

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
)

// metadataHostError refuses a metadata service in every field that takes a host or URL and in every
// form it can be written (#820): settings.host of the SSH and SFTP types, and host values with a port,
// user info or path.
func TestMetadataHostError(t *testing.T) {
	t.Parallel()
	forms := []string{"169.254.169.254", "169.254.169.254:80", "x@169.254.169.254", "x:y@169.254.169.254:80", "169.254.169.254/latest",
		"[fd00:ec2::254]:80", "fd00:ec2::254", "[fd00:ec2::254]", "metadata.google.internal", "METADATA.GOOGLE.INTERNAL.",
		"metadata.google.internal:80", "https://metadata.google.internal/x", "::ffff:169.254.169.254", "168.63.129.16:443", " 169.254.169.254 ",
		"[169.254.169.254]:80", "[metadata.google.internal]:22", "[METADATA.GOOGLE.INTERNAL.]:80", "METADATA.GOOGLE.INTERNAL..", "x@[169.254.169.254]:80",
		"http://[169.254.169.254]:80/latest", "169.254.169.254..:80", "[100.100.100.200]:80/x"}
	fields := map[string]func(h string) ConnConfig{
		"host":          func(h string) ConnConfig { return ConnConfig{Host: h} },
		"org_url":       func(h string) ConnConfig { return ConnConfig{OrgURL: h} },
		"domain":        func(h string) ConnConfig { return ConnConfig{Domain: h} },
		"base_url":      func(h string) ConnConfig { return ConnConfig{BaseURL: h} },
		"tenant_host":   func(h string) ConnConfig { return ConnConfig{TenantHost: h} },
		"sql.host":      func(h string) ConnConfig { return ConnConfig{SQL: &sqldb.Config{Host: h}} },
		"settings.host": func(h string) ConnConfig { return ConnConfig{Settings: map[string]string{"host": h}} },
	}
	for field, mk := range fields {
		for _, h := range forms {
			e, ok := metadataHostError(mk(h)).(*Error)
			if !ok || e.Status != 422 || len(e.Fields) != 1 || e.Fields[0].Field != field {
				t.Errorf("%s=%q: got %v, want 422 naming the field", field, h, e)
			}
		}
	}
	// ordinary hosts are fine, in the same forms
	for field, mk := range fields {
		for _, h := range []string{"ldap.example.com", "ldap.example.com:636", "10.0.0.5", "sftp.example.com", "https://acme.okta.com", "2001:db8::1", "[2001:db8::1]:22", "user@example.com", "ldap.example.com.", "[example.com]:22"} {
			if err := metadataHostError(mk(h)); err != nil {
				t.Errorf("%s=%q was refused: %v", field, h, err)
			}
		}
	}
	if err := metadataHostError(ConnConfig{}); err != nil {
		t.Errorf("empty config: %v", err)
	}
}
