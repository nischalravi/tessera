package provider

import (
	"context"
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
		"tessera_alert_channel": {"name": "x", "kind": "webhook", "target": "https://h.example.com/x", "signing_secret": "0123456789abcdef", "signing_secret_version": "1"},
		"tessera_siem_sink":     {"name": "x", "kind": "webhook", "target": "https://h.example.com/x", "token": "t", "token_version": "1"},
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
