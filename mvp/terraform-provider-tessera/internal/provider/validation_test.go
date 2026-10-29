package provider

import (
	"strings"
	"testing"
)

// Plan-time validation and provider configuration: no server needed.

func TestReviewSchedule_ValidateConfig(t *testing.T) {
	p := newProtocol(t)
	base := func(over map[string]any) map[string]any {
		m := map[string]any{"name": "Quarterly privileged review", "recurrence": "quarterly", "first_run_at": "2027-01-01T00:00:00Z"}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name string
		cfg  map[string]any
		want string // "" = accepted; otherwise a substring of the error
	}{
		{"minimal", base(nil), ""},
		{"all settings", base(map[string]any{"system": "aws", "privileged_only": true, "unused_days": 90, "duration_days": 30,
			"reminder_days": 5, "close_out": "escalate", "escalation_identity_id": 16, "escalation_days": 10, "enabled": true,
			"role_ids": []string{"r1"}, "review_type": "manager"}), ""},
		{"empty name", base(map[string]any{"name": ""}), "string length"},
		{"padded name", base(map[string]any{"name": " x"}), "whitespace"},
		{"long name", base(map[string]any{"name": strings.Repeat("a", 201)}), "string length"},
		{"bad recurrence", base(map[string]any{"recurrence": "weekly"}), "recurrence"},
		{"bad close out", base(map[string]any{"close_out": "ignore"}), "close_out"},
		{"unused days zero", base(map[string]any{"unused_days": 0}), "unused_days"},
		{"unused days high", base(map[string]any{"unused_days": 366}), "unused_days"},
		{"duration high", base(map[string]any{"duration_days": 91}), "duration_days"},
		{"escalation days high", base(map[string]any{"escalation_days": 31}), "escalation_days"},
		{"reminder not before due", base(map[string]any{"duration_days": 5, "reminder_days": 5}), "less than duration_days"},
		{"default reminder vs short duration", base(map[string]any{"duration_days": 3}), "less than duration_days"},
		{"escalate needs a reviewer", base(map[string]any{"close_out": "escalate"}), "escalation_identity_id"},
		{"bad timestamp", base(map[string]any{"first_run_at": "next tuesday"}), "RFC 3339"},
		{"bad identity id", base(map[string]any{"escalation_identity_id": 0}), "escalation_identity_id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := diagText(p.validate("tessera_review_schedule", c.cfg))
			switch {
			case c.want == "" && got != "":
				t.Fatalf("rejected: %s", got)
			case c.want != "" && !strings.Contains(got, c.want):
				t.Fatalf("want an error containing %q, got %q", c.want, got)
			}
		})
	}
}

func TestProvider_Configure(t *testing.T) {
	_, pemKey := testKeyPEM(t)
	for _, k := range []string{"TESSERA_ENDPOINT", "TESSERA_TENANT", "TESSERA_CLIENT_ID", "TESSERA_PRIVATE_KEY", "TESSERA_PRIVATE_KEY_FILE", "TESSERA_KEY_ID", "TESSERA_DPOP", "TESSERA_CA_FILE"} {
		t.Setenv(k, "")
	}
	good := func(over map[string]any) map[string]any {
		m := map[string]any{"endpoint": "https://tessera.example.com", "tenant": "larkspur", "client_id": "tsc_abc", "private_key": pemKey}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name string
		cfg  map[string]any
		env  map[string]string
		want string
	}{
		{"ok", good(nil), nil, ""},
		{"ok from the environment", map[string]any{}, map[string]string{"TESSERA_ENDPOINT": "https://tessera.example.com", "TESSERA_TENANT": "larkspur",
			"TESSERA_CLIENT_ID": "tsc_abc", "TESSERA_PRIVATE_KEY": pemKey}, ""},
		{"loopback http", good(map[string]any{"endpoint": "http://127.0.0.1:8400"}), nil, ""},
		{"remote http", good(map[string]any{"endpoint": "http://tessera.example.com"}), nil, "https"},
		{"endpoint with credentials", good(map[string]any{"endpoint": "https://u:p@tessera.example.com"}), nil, "endpoint"},
		{"missing endpoint", good(map[string]any{"endpoint": nil}), nil, "endpoint"},
		{"missing tenant", good(map[string]any{"tenant": nil}), nil, "tenant"},
		{"bad tenant", good(map[string]any{"tenant": "Not A Slug"}), nil, "tenant"},
		{"missing client id", good(map[string]any{"client_id": nil}), nil, "client_id"},
		{"missing key", good(map[string]any{"private_key": nil}), nil, "private key"},
		{"both key settings", good(map[string]any{"private_key_file": "/nonexistent"}), nil, "not both"},
		{"unreadable key file", good(map[string]any{"private_key": nil, "private_key_file": "/nonexistent/key.pem"}), nil, "Cannot read"},
		{"garbage key", good(map[string]any{"private_key": "not a key"}), nil, "PEM"},
		{"missing CA file", good(map[string]any{"ca_file": "/nonexistent/ca.pem"}), nil, "ca_file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			got := diagText(newProtocol(t).configure(c.cfg))
			switch {
			case c.want == "" && got != "":
				t.Fatalf("rejected: %s", got)
			case c.want != "" && !strings.Contains(got, c.want):
				t.Fatalf("want an error containing %q, got %q", c.want, got)
			case strings.Contains(got, "PRIVATE KEY") || strings.Contains(got, pemKey):
				t.Fatalf("a diagnostic leaks the key: %s", got)
			}
		})
	}
}

func TestProvider_PrivateKeyIsSensitive(t *testing.T) {
	p := newProtocol(t)
	for _, a := range p.schema.Provider.Block.Attributes {
		if a.Name == "private_key" && !a.Sensitive {
			t.Fatal("private_key must be sensitive")
		}
	}
}

func TestImport_RejectsANonUUID(t *testing.T) {
	_, d := newProtocol(t).importState("tessera_review_schedule", "not-a-uuid")
	if got := diagText(d); !strings.Contains(got, "Invalid import id") {
		t.Fatalf("got %q", got)
	}
}
