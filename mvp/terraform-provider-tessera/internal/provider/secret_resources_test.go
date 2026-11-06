package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// The secret arguments of tessera_connection, tessera_alert_channel and tessera_siem_sink are Sensitive and write-only, so they
// never enter a plan or the state; the schema says so, and a Terraform that cannot honour that is refused.

func TestSecretArgumentsAreWriteOnly(t *testing.T) {
	for res, attr := range map[string]string{"tessera_connection": "secret", "tessera_alert_channel": "signing_secret", "tessera_siem_sink": "token"} {
		var resp resource.SchemaResponse
		switch res {
		case "tessera_connection":
			NewConnectionResource().Schema(context.Background(), resource.SchemaRequest{}, &resp)
		case "tessera_alert_channel":
			NewAlertChannelResource().Schema(context.Background(), resource.SchemaRequest{}, &resp)
		default:
			NewSiemSinkResource().Schema(context.Background(), resource.SchemaRequest{}, &resp)
		}
		a, ok := resp.Schema.Attributes[attr].(schema.StringAttribute)
		if !ok || !a.WriteOnly || !a.Sensitive || a.Computed || a.Required {
			t.Errorf("%s.%s must be an optional, sensitive, write-only string: %+v", res, attr, a)
		}
		if !strings.Contains(resp.Schema.Description, "write-only") {
			t.Errorf("%s does not document the write-only secret", res)
		}
	}
}

func TestSecretArgumentsRefuseOldTerraform(t *testing.T) {
	p := newProtocol(t)
	cases := map[string]map[string]any{
		"tessera_connection":    {"name": "x", "connector_type": "okta", "secret": "s", "secret_version": "1"},
		"tessera_alert_channel": {"name": "x", "kind": "webhook", "target_url": "https://h.example.com/x", "target_url_version": "1", "signing_secret": strings.Repeat("ab", 8), "signing_secret_version": "1"},
		"tessera_siem_sink":     {"name": "x", "kind": "webhook", "target_url": "https://h.example.com/x", "target_url_version": "1", "token": "t", "token_version": "1"},
	}
	for res, cfg := range cases {
		if d := p.validate(res, cfg); diagText(d) != "" {
			t.Errorf("%s with write-only support: %q", res, diagText(d))
		}
		if d := p.validateOld(res, cfg); !strings.Contains(strings.ToLower(diagText(d)), "write-only") {
			t.Errorf("%s on a Terraform without write-only support: %q", res, diagText(d))
		}
		// a secret needs its version, so a rotation is never silent
		noVersion := map[string]any{}
		for k, v := range cfg {
			if !strings.HasSuffix(k, "_version") {
				noVersion[k] = v
			}
		}
		if d := p.validate(res, noVersion); !strings.Contains(diagText(d), "_version") {
			t.Errorf("%s without a version: %q", res, diagText(d))
		}
	}
}

// A webhook URL is write-only too: it takes target_url (never target), the other kinds take target, and the URL needs its version.
func TestTargetURLIsWriteOnlyAndKindChecked(t *testing.T) {
	p := newProtocol(t)
	for _, tc := range []struct {
		res  string
		cfg  map[string]any
		want string
	}{
		{"tessera_alert_channel", map[string]any{"name": "x", "kind": "webhook", "target": "https://h.example.com/x", "signing_secret": strings.Repeat("ab", 8), "signing_secret_version": "1"}, "target_url is required"},
		{"tessera_alert_channel", map[string]any{"name": "x", "kind": "email", "target": "a@example.com", "target_url": "https://h.example.com/x", "target_url_version": "1"}, "target_url is not used"},
		{"tessera_alert_channel", map[string]any{"name": "x", "kind": "email"}, "target is required"},
		{"tessera_alert_channel", map[string]any{"name": "x", "kind": "email", "target": "a@example.com", "target_url": "https://h.example.com/x"}, "target_url_version"},
		{"tessera_siem_sink", map[string]any{"name": "x", "kind": "syslog", "target": "c.example.com:6514"}, ""},
		{"tessera_siem_sink", map[string]any{"name": "x", "kind": "s3", "target": "https://b.example.com", "token": "t", "token_version": "1"}, "target_url is required"},
		{"tessera_siem_sink", map[string]any{"name": "x", "kind": "s3", "target_url": "https://b.example.com", "target_url_version": "1", "token": "t", "token_version": "1"}, ""},
	} {
		d := diagText(p.validate(tc.res, tc.cfg))
		if (tc.want == "") != (d == "") || (tc.want != "" && !strings.Contains(d, tc.want)) {
			t.Errorf("%s %v: %q, want %q", tc.res, tc.cfg, d, tc.want)
		}
	}
	for _, res := range []string{"tessera_alert_channel", "tessera_siem_sink"} {
		i := indexOf(p.schema.ResourceSchemas[res], "target_url")
		if i < 0 {
			t.Fatalf("%s has no target_url", res)
		}
		if a := p.schema.ResourceSchemas[res].Block.Attributes[i]; !a.WriteOnly || !a.Sensitive {
			t.Errorf("%s.target_url must be sensitive and write-only", res)
		}
	}
}

func indexOf(s *tfprotov6.Schema, name string) int {
	for i, a := range s.Block.Attributes {
		if a.Name == name {
			return i
		}
	}
	return -1
}
