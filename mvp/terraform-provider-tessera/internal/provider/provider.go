// Package provider is the Terraform provider for Tessera configuration.
package provider

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/client"
)

var _ provider.Provider = (*tesseraProvider)(nil)

// New returns the provider factory. version is set at build time.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &tesseraProvider{version: version} }
}

type tesseraProvider struct{ version string }

type providerModel struct {
	Endpoint       types.String `tfsdk:"endpoint"`
	Tenant         types.String `tfsdk:"tenant"`
	ClientID       types.String `tfsdk:"client_id"`
	PrivateKey     types.String `tfsdk:"private_key"`
	PrivateKeyFile types.String `tfsdk:"private_key_file"`
	KeyID          types.String `tfsdk:"key_id"`
	Scope          types.String `tfsdk:"scope"`
	DPoP           types.Bool   `tfsdk:"dpop"`
	CAFile         types.String `tfsdk:"ca_file"`
	InsecureTLS    types.Bool   `tfsdk:"insecure_skip_verify"`
	WaitTimeout    types.String `tfsdk:"wait_timeout"`
	PollInterval   types.String `tfsdk:"poll_interval"`
}

func (p *tesseraProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName, resp.Version = "tessera", p.version
}

func (p *tesseraProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Tessera configuration as code. The provider signs in as a machine client (OAuth client credentials with a " +
			"private-key JWT, RFC 7523, optionally DPoP-bound) and talks only to the public `/api/v1` API. It never uses a browser session " +
			"or the dev IdP. A machine client holds the viewer, operator and auditor roles at most, so the provider can only manage what those " +
			"roles may change without a step-up sign-in; see the README for what that covers.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{Optional: true,
				Description: "The server's public URL, for example `https://tessera.example.com`. Plain http is accepted for localhost only. " +
					"Env: `TESSERA_ENDPOINT`. It must be the URL the server advertises as its token endpoint's origin (`TESSERA_PUBLIC_URL`)."},
			"tenant": schema.StringAttribute{Optional: true, Description: "The tenant slug. Env: `TESSERA_TENANT`."},
			"client_id": schema.StringAttribute{Optional: true,
				Description: "The machine client's id (`tsc_...`), from Admin > API clients or `tessera admin add-client`. Env: `TESSERA_CLIENT_ID`."},
			"private_key": schema.StringAttribute{Optional: true, Sensitive: true,
				Description: "The client's PEM private key (ES256 P-256 or EdDSA Ed25519); the matching public key is registered with the client. " +
					"Env: `TESSERA_PRIVATE_KEY`. Prefer `private_key_file` or the env var over a literal in configuration."},
			"private_key_file": schema.StringAttribute{Optional: true,
				Description: "Path to the PEM private key. Env: `TESSERA_PRIVATE_KEY_FILE`. Exactly one of `private_key` and `private_key_file`."},
			"key_id": schema.StringAttribute{Optional: true,
				Description: "The `kid` the public key is registered under. Env: `TESSERA_KEY_ID`. Optional when the client has one key."},
			"scope": schema.StringAttribute{Optional: true,
				Description: "Space-separated scopes to request (`tessera:read`, `tessera:write`, `tessera:audit`). Default: every scope the client holds."},
			"dpop": schema.BoolAttribute{Optional: true,
				Description: "Bind the access token to a per-run DPoP key (RFC 9449). Set it when the client is registered with `dpop_required` " +
					"(the default for clients made in the UI). Env: `TESSERA_DPOP`."},
			"ca_file": schema.StringAttribute{Optional: true, Description: "A PEM file of extra trusted CA certificates, for a private PKI. Env: `TESSERA_CA_FILE`."},
			"insecure_skip_verify": schema.BoolAttribute{Optional: true,
				Description: "Skip TLS certificate verification. For throwaway test servers only; verification is on by default."},
			"wait_timeout": schema.StringAttribute{Optional: true,
				Description: "How long a resource that proposes a change (`tessera_alert_rule`, `tessera_catalog_item`, `tessera_business_role`, " +
					"`tessera_sod_ruleset`) waits for a person to approve it, as a duration such as `30m`. Default `30m`. On a timeout the apply fails " +
					"with the change's URL; the proposal stays open for 72 hours. Env: `TESSERA_WAIT_TIMEOUT`.",
				Validators: []validator.String{durationValidator{min: time.Second}}},
			"poll_interval": schema.StringAttribute{Optional: true,
				Description: "How often a waiting resource asks whether the change was approved, as a duration such as `5s` (at least `100ms`). Default `5s`. " +
					"Env: `TESSERA_POLL_INTERVAL`.",
				Validators: []validator.String{durationValidator{min: 100 * time.Millisecond}}},
		},
	}
}

func envOr(v types.String, name string) string {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueString()
	}
	return os.Getenv(name)
}

func (p *tesseraProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// an unknown value (built from another resource) cannot be used to sign in: wait for the apply
	for name, v := range map[string]attrValue{"endpoint": m.Endpoint, "tenant": m.Tenant, "client_id": m.ClientID,
		"private_key": m.PrivateKey, "private_key_file": m.PrivateKeyFile} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider value",
				"The provider cannot be configured with a value that is not known until apply.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := client.Config{
		Endpoint: envOr(m.Endpoint, "TESSERA_ENDPOINT"), Tenant: envOr(m.Tenant, "TESSERA_TENANT"),
		ClientID: envOr(m.ClientID, "TESSERA_CLIENT_ID"), KeyID: envOr(m.KeyID, "TESSERA_KEY_ID"),
		Scope: m.Scope.ValueString(), CAFile: envOr(m.CAFile, "TESSERA_CA_FILE"),
		SkipTLSVerify: m.InsecureTLS.ValueBool(), UserAgent: "terraform-provider-tessera/" + p.version,
		DPoP: m.DPoP.ValueBool() || (m.DPoP.IsNull() && isTrue(os.Getenv("TESSERA_DPOP"))),
	}
	for name, d := range map[string]*time.Duration{"wait_timeout": &cfg.WaitTimeout, "poll_interval": &cfg.PollInterval} {
		raw := envOr(map[string]types.String{"wait_timeout": m.WaitTimeout, "poll_interval": m.PollInterval}[name], "TESSERA_"+strings.ToUpper(name))
		if raw == "" {
			continue
		}
		v, err := time.ParseDuration(raw)
		if err != nil || v <= 0 {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Invalid "+name, "Use a duration such as 30m or 5s.")
			continue
		}
		*d = v
	}
	for name, v := range map[string]string{"endpoint": cfg.Endpoint, "tenant": cfg.Tenant, "client_id": cfg.ClientID} {
		if strings.TrimSpace(v) == "" {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Missing "+name,
				"Set "+name+" in the provider block or the TESSERA_"+strings.ToUpper(name)+" environment variable.")
		}
	}
	key, file := envOr(m.PrivateKey, "TESSERA_PRIVATE_KEY"), envOr(m.PrivateKeyFile, "TESSERA_PRIVATE_KEY_FILE")
	switch {
	case key != "" && file != "":
		resp.Diagnostics.AddError("Conflicting key settings", "Set one of private_key and private_key_file, not both.")
	case key == "" && file == "":
		resp.Diagnostics.AddError("Missing private key", "Set private_key_file (or TESSERA_PRIVATE_KEY_FILE, or TESSERA_PRIVATE_KEY).")
	case file != "":
		b, err := os.ReadFile(file) // #nosec G304 -- the operator's own configuration
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("private_key_file"), "Cannot read the private key file", err.Error())
		}
		key = string(b)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	cfg.PrivateKeyPEM = key
	c, err := client.New(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	resp.ResourceData, resp.DataSourceData = c, c
}

type attrValue interface{ IsUnknown() bool }

func isTrue(s string) bool { return s == "1" || strings.EqualFold(s, "true") }

func (p *tesseraProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewReviewScheduleResource, NewAlertRuleResource, NewCatalogItemResource, NewBusinessRoleResource,
		NewSoDRulesetResource}
}

func (p *tesseraProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewIdentitiesDataSource, NewEntitlementsDataSource, NewConnectorsDataSource}
}

// oneOf is stringvalidator.OneOf.
func oneOf(v ...string) validator.String { return stringvalidator.OneOf(v...) }

func nonEmptyString() []validator.String { return []validator.String{stringvalidator.LengthAtLeast(1)} }

// durationValidator accepts a Go duration of at least min.
type durationValidator struct{ min time.Duration }

func (v durationValidator) Description(context.Context) string {
	return "a duration such as 30m or 5s, at least " + v.min.String()
}
func (v durationValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v durationValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if d, err := time.ParseDuration(req.ConfigValue.ValueString()); err != nil || d < v.min {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", "Use a duration such as 30m or 5s, at least "+v.min.String()+".")
	}
}
