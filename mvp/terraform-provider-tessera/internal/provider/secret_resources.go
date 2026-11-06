package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/client"
)

// Resources whose configuration carries a secret (server issue #719): a connection (its credential), an alert channel (a
// webhook's signing secret) and a SIEM sink (an HEC token or an S3 secret access key). They are proposed like the others
// (proposal_resources.go), and the server seals the secret at submit, apart from the proposal, and opens it only to apply.
//
// A secret argument is Sensitive and WRITE-ONLY: Terraform hands it to the provider while planning and applying and never
// writes it to the plan or the state (Terraform 1.11 or later; an older one is refused). Because the state holds no secret,
// Terraform cannot see that it changed. The companion `*_version` argument is how a change is signalled: the secret is sent
// on create, and on an update only when the version differs from the one in the state; otherwise the server keeps the
// secret it holds. Rotate by changing the secret and its version together.

// secretNote is appended to the description of each of these resources.
const secretNote = "The secret argument is write-only: it never enters the plan or the state (needs Terraform 1.11 or later). Because the " +
	"state does not hold it, change the matching `*_version` argument along with the secret to send the new value; without a new " +
	"version the server keeps the secret it has. "

// writeOnlySecret is the schema of a write-only secret argument that needs its version argument.
func writeOnlySecret(desc, versionAttr string, conflicts ...path.Expression) schema.StringAttribute {
	vs := []validator.String{stringvalidator.LengthBetween(1, 8192), stringvalidator.AlsoRequires(path.MatchRoot(versionAttr))}
	for _, c := range conflicts {
		vs = append(vs, stringvalidator.ConflictsWith(c))
	}
	return schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: desc, Validators: vs}
}

func versionAttr(desc string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Description: desc, Validators: []validator.String{stringvalidator.LengthBetween(1, 64)}}
}

// secretToSend returns the write-only secret from the configuration when this apply must send it: on create, or when its
// version changed. It refuses a changed version with no secret.
func secretToSend(ctx context.Context, d *diag.Diagnostics, cfg interface {
	GetAttribute(context.Context, path.Path, any) diag.Diagnostics
}, secretAttr, versionAttr string, plan, state types.String, creating bool) (string, bool) {
	var s types.String
	d.Append(cfg.GetAttribute(ctx, path.Root(secretAttr), &s)...)
	if d.HasError() {
		return "", false
	}
	changed := creating || plan.ValueString() != state.ValueString()
	switch {
	case !known(s):
		if !creating && changed && known(plan) {
			d.AddAttributeError(path.Root(versionAttr), "Version changed without a secret",
				fmt.Sprintf("%s changed, so a new value for %s is expected, but none is set in the configuration.", versionAttr, secretAttr))
		}
		return "", false
	case !changed:
		return "", false // the same version: the server keeps the secret it holds
	}
	return s.ValueString(), true
}

// ---------------------------------------------------------------- tessera_connection

var (
	_ resource.Resource                = (*connectionResource)(nil)
	_ resource.ResourceWithConfigure   = (*connectionResource)(nil)
	_ resource.ResourceWithImportState = (*connectionResource)(nil)
)

// NewConnectionResource is tessera_connection: a connection to a source or target system, created in draft.
func NewConnectionResource() resource.Resource { return &connectionResource{} }

type connectionResource struct{ proposer }

type connectionModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	ConnectorType       types.String `tfsdk:"connector_type"`
	System              types.String `tfsdk:"system"`
	Role                types.String `tfsdk:"role"`
	ConfigJSON          types.String `tfsdk:"config_json"`
	CredentialReference types.String `tfsdk:"credential_reference"`
	Secret              types.String `tfsdk:"secret"`
	SecretVersion       types.String `tfsdk:"secret_version"`
	State               types.String `tfsdk:"state"`
	ChangeID            types.String `tfsdk:"change_id"`
	ChangeURL           types.String `tfsdk:"change_url"`
}

func (r *connectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connection"
}

func (r *connectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A connection to a connected system, with its configuration and credential. The server creates it in `draft`: it " +
			"still needs its validation and dry run, and a person activates it as a separate step, which Terraform cannot do. " +
			proposalNote + secretNote +
			"A connection is retired in the admin center, not by Terraform: destroy leaves it on the server. Its name, connector type, " +
			"system and role cannot change, so changing one replaces the resource (and the server refuses a second connection of the same name).",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The connection id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "A unique name, at most 100 characters.",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 100), noEdgeSpace},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"connector_type": schema.StringAttribute{Required: true, Description: "The connector type, for example `okta`; see `tessera_connectors`.",
				Validators:    nonEmptyString(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"system": schema.StringAttribute{Optional: true, Computed: true, Description: "The system name in the graph; the server derives it when omitted.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplaceIfConfigured()}},
			"role": schema.StringAttribute{Optional: true, Computed: true, Description: "`authoritative` or `account_source`; the connector type's own when omitted.",
				Validators:    []validator.String{oneOf("authoritative", "account_source")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplaceIfConfigured()}},
			"config_json": schema.StringAttribute{Optional: true, Description: "The connection's settings as a JSON object (for example `jsonencode({org_url = \"https://acme.okta.com\"})`), " +
				"merged over the connector type's defaults. Put no secret here: the server refuses a config key that names one. Not read back (the server " +
				"fills in defaults), so a change made elsewhere is not seen.", Validators: []validator.String{jsonValidator{}}},
			"credential_reference": schema.StringAttribute{Optional: true, Description: "A reference to a credential held elsewhere, `vault:<path>` or `agent:<id>/<name>`. " +
				"Use this or `secret`.", Validators: []validator.String{stringvalidator.ConflictsWith(path.MatchRoot("secret"))}},
			"secret": writeOnlySecret("The connector's secret (a password, client secret or API key). Write-only: never in the plan or the state, and never returned.",
				"secret_version"),
			"secret_version": versionAttr("Any text; change it along with `secret` to send the new secret. Without a change the server keeps the credential it has."),
			"state":          schema.StringAttribute{Computed: true, Description: "The connection's readiness state on the server (`draft` until a person activates it)."},
		}),
	}
}

func (r *connectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type connectionCredentialBody struct {
	Secret    string `json:"secret,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type connectionBody struct {
	Name          string                    `json:"name,omitempty"`
	ConnectorType string                    `json:"connector_type,omitempty"`
	System        string                    `json:"system,omitempty"`
	Role          string                    `json:"role,omitempty"`
	Config        json.RawMessage           `json:"config,omitempty"`
	Credential    *connectionCredentialBody `json:"credential,omitempty"`
}

type connectionRead struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	ConnectorType string  `json:"connector_type"`
	System        string  `json:"system"`
	Role          string  `json:"role"`
	State         string  `json:"state"`
	RetiredAt     *string `json:"retired_at"`
}

func (r *connectionResource) read(ctx context.Context, id string) (*connectionRead, error) {
	var v connectionRead
	if err := r.c.Do(ctx, "GET", "/connections/"+url.PathEscape(id), nil, &v); err != nil {
		if client.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if v.RetiredAt != nil {
		return nil, nil
	}
	return &v, nil
}

func (m *connectionModel) fromServer(v *connectionRead) {
	m.ID, m.Name, m.ConnectorType = types.StringValue(v.ID), types.StringValue(v.Name), types.StringValue(v.ConnectorType)
	m.System, m.Role, m.State = types.StringValue(v.System), types.StringValue(v.Role), types.StringValue(v.State)
}

// put files the proposal. id is "" to create.
func (r *connectionResource) put(ctx context.Context, plan, state *connectionModel, id string, d *diag.Diagnostics, secretFrom func() (string, bool)) {
	b := connectionBody{}
	if id == "" {
		b.Name, b.ConnectorType = plan.Name.ValueString(), plan.ConnectorType.ValueString()
		b.System, b.Role = plan.System.ValueString(), plan.Role.ValueString()
	}
	if known(plan.ConfigJSON) && (id == "" || plan.ConfigJSON.ValueString() != state.ConfigJSON.ValueString()) {
		b.Config = json.RawMessage(plan.ConfigJSON.ValueString())
	}
	if secret, send := secretFrom(); send {
		b.Credential = &connectionCredentialBody{Secret: secret}
	} else if known(plan.CredentialReference) && (id == "" || plan.CredentialReference.ValueString() != state.CredentialReference.ValueString()) {
		b.Credential = &connectionCredentialBody{Reference: plan.CredentialReference.ValueString()}
	}
	pth, what := "/proposals/connections", "create the connection"
	if id != "" {
		if b.Config == nil && b.Credential == nil {
			return // nothing to change on the server (only bookkeeping differs)
		}
		pth, what = "/proposals/connections/"+url.PathEscape(id), "update the connection"
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new connection", "The change "+ch.ChangeID+" was applied but the server did not say which connection it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	v, err := r.read(ctx, id)
	if err != nil || v == nil {
		d.AddError("Cannot read the connection back", fmt.Sprintf("change %s was applied; reading connection %s failed: %v", ch.ChangeID, id, err))
		return
	}
	plan.fromServer(v)
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *connectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan connectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, &plan, nil, "", &resp.Diagnostics, func() (string, bool) {
		return secretToSend(ctx, &resp.Diagnostics, req.Config, "secret", "secret_version", plan.SecretVersion, types.StringNull(), true)
	})
	if !resp.Diagnostics.HasError() {
		plan.Secret = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *connectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state connectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, &plan, &state, state.ID.ValueString(), &resp.Diagnostics, func() (string, bool) {
		return secretToSend(ctx, &resp.Diagnostics, req.Config, "secret", "secret_version", plan.SecretVersion, state.SecretVersion, false)
	})
	if !resp.Diagnostics.HasError() {
		plan.Secret = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *connectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state connectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsForbidden(err) {
			return // this client cannot read connections: the state stays as last applied
		}
		resp.Diagnostics.AddError("Cannot read the connection", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromServer(v)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *connectionResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The connection")
}

func (r *connectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// ---------------------------------------------------------------- tessera_alert_channel

var (
	_ resource.Resource                   = (*alertChannelResource)(nil)
	_ resource.ResourceWithConfigure      = (*alertChannelResource)(nil)
	_ resource.ResourceWithImportState    = (*alertChannelResource)(nil)
	_ resource.ResourceWithValidateConfig = (*alertChannelResource)(nil)
)

// NewAlertChannelResource is tessera_alert_channel: where alerts are delivered, an email list or a signed webhook.
func NewAlertChannelResource() resource.Resource { return &alertChannelResource{} }

type alertChannelResource struct{ proposer }

type alertChannelModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Kind                 types.String `tfsdk:"kind"`
	Target               types.String `tfsdk:"target"`
	TargetURL            types.String `tfsdk:"target_url"`
	TargetURLVersion     types.String `tfsdk:"target_url_version"`
	TargetOrigin         types.String `tfsdk:"target_origin"`
	TargetFingerprint    types.String `tfsdk:"target_fingerprint"`
	MinSeverity          types.String `tfsdk:"min_severity"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	SigningSecret        types.String `tfsdk:"signing_secret"`
	SigningSecretVersion types.String `tfsdk:"signing_secret_version"`
	ChangeID             types.String `tfsdk:"change_id"`
	ChangeURL            types.String `tfsdk:"change_url"`
}

func (r *alertChannelResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alert_channel"
}

func (r *alertChannelResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A channel that alerts are delivered to: a list of email addresses, or an HTTPS webhook whose payloads are signed with an " +
			"HMAC secret you choose and give the receiver. " + proposalNote + secretNote +
			"A webhook URL usually carries a token, so it goes in the write-only `target_url` (with `target_url_version`), never in the state: " +
			"the server seals it, shows the approver its origin and a keyed fingerprint, and the state keeps those two (`target_origin`, `target_fingerprint`). " +
			"Channels are switched off with `enabled = false`, not deleted: destroy leaves the channel on the server. " +
			"The server's read of channels needs the admin scope, so refresh keeps the state unless the client can read them.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The channel id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "A name, at most 100 characters.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 100), noEdgeSpace}},
			"kind": schema.StringAttribute{Required: true, Description: "`email` or `webhook`. It cannot change.",
				Validators:    []validator.String{oneOf("email", "webhook")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"target": schema.StringAttribute{Optional: true, Validators: nonEmptyString(),
				Description: "Email channel: up to 20 addresses separated by commas. A webhook uses `target_url` instead."},
			"min_severity": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("high"),
				Validators: []validator.String{oneOf("low", "medium", "high", "critical")}, Description: "The lowest severity that is sent. Default `high`."},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "Whether alerts are sent. Default true."},
			"signing_secret": writeOnlySecret("A webhook's HMAC signing secret, 16 to 256 characters, which you also give the receiver. Required for a webhook "+
				"(the server cannot show you one it generated). Write-only: never in the plan or the state.", "signing_secret_version"),
			"signing_secret_version": versionAttr("Any text; change it along with `signing_secret` to send the new secret."),
		}),
	}
	for k, v := range targetURLAttrs("webhook") {
		resp.Schema.Attributes[k] = v
	}
}

func (r *alertChannelResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m alertChannelModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if !resp.Diagnostics.HasError() {
		urlKindRule(&resp.Diagnostics, m.Kind, m.Target, m.TargetURL, "webhook")
	}
}

func (r *alertChannelResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type alertChannelBody struct {
	Name          string  `json:"name,omitempty"`
	Kind          string  `json:"kind,omitempty"`
	Target        *string `json:"target,omitempty"`
	MinSeverity   string  `json:"min_severity,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	SigningSecret *string `json:"signing_secret,omitempty"`
}

type alertChannelRead struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	MinSeverity string `json:"min_severity"`
	Enabled     bool   `json:"enabled"`
}

func (r *alertChannelResource) put(ctx context.Context, plan, state *alertChannelModel, secret string, send bool, rawURL string, sendURL bool, id string, d *diag.Diagnostics) {
	enabled := plan.Enabled.ValueBool()
	b := alertChannelBody{Name: plan.Name.ValueString(), Kind: plan.Kind.ValueString(), Target: optString(plan.Target),
		MinSeverity: plan.MinSeverity.ValueString(), Enabled: &enabled}
	if sendURL {
		b.Target = &rawURL
	}
	if send {
		b.SigningSecret = &secret
	}
	pth, what := "/proposals/alert-channels", "create the alert channel"
	if id != "" {
		b.Kind = "" // fixed after creation
		pth, what = "/proposals/alert-channels/"+url.PathEscape(id), "update the alert channel"
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new alert channel", "The change "+ch.ChangeID+" was applied but the server did not say which channel it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	plan.ID = types.StringValue(id)
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
	setTarget(&plan.TargetOrigin, &plan.TargetFingerprint, state, ch, func(m *alertChannelModel) (types.String, types.String) {
		return m.TargetOrigin, m.TargetFingerprint
	})
}

func (r *alertChannelResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan alertChannelModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, send := secretToSend(ctx, &resp.Diagnostics, req.Config, "signing_secret", "signing_secret_version", plan.SigningSecretVersion, types.StringNull(), true)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Kind.ValueString() == "webhook" && !send {
		resp.Diagnostics.AddAttributeError(path.Root("signing_secret"), "A webhook needs its signing secret",
			"Set signing_secret (and signing_secret_version): the receiver must know it, and the server cannot show a secret it generated for a proposal.")
		return
	}
	rawURL, sendURL := secretToSend(ctx, &resp.Diagnostics, req.Config, "target_url", "target_url_version", plan.TargetURLVersion, types.StringNull(), true)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, nil, secret, send, rawURL, sendURL, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		plan.TargetURL = types.StringNull()
		plan.SigningSecret = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *alertChannelResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state alertChannelModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, send := secretToSend(ctx, &resp.Diagnostics, req.Config, "signing_secret", "signing_secret_version", plan.SigningSecretVersion, state.SigningSecretVersion, false)
	if resp.Diagnostics.HasError() {
		return
	}
	rawURL, sendURL := secretToSend(ctx, &resp.Diagnostics, req.Config, "target_url", "target_url_version", plan.TargetURLVersion, state.TargetURLVersion, false)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, &state, secret, send, rawURL, sendURL, state.ID.ValueString(), &resp.Diagnostics); !resp.Diagnostics.HasError() {
		plan.TargetURL = types.StringNull()
		plan.SigningSecret = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

// Read refreshes name, severity and enabled when the client may read the channels (alerts.configure) and keeps the state otherwise.
// The target and the secret are never read back.
func (r *alertChannelResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state alertChannelModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := r.c.List(ctx, "/alerts/channels", url.Values{})
	if err != nil {
		if client.IsForbidden(err) {
			return
		}
		resp.Diagnostics.AddError("Cannot read the alert channels", err.Error())
		return
	}
	for _, raw := range items {
		var v alertChannelRead
		if err := json.Unmarshal(raw, &v); err != nil {
			resp.Diagnostics.AddError("Cannot read the alert channels", err.Error())
			return
		}
		if v.ID == state.ID.ValueString() {
			state.Name, state.Kind, state.MinSeverity, state.Enabled = types.StringValue(v.Name), types.StringValue(v.Kind),
				types.StringValue(v.MinSeverity), types.BoolValue(v.Enabled)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *alertChannelResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The alert channel")
}

func (r *alertChannelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// ---------------------------------------------------------------- tessera_siem_sink

var (
	_ resource.Resource                   = (*siemSinkResource)(nil)
	_ resource.ResourceWithConfigure      = (*siemSinkResource)(nil)
	_ resource.ResourceWithImportState    = (*siemSinkResource)(nil)
	_ resource.ResourceWithValidateConfig = (*siemSinkResource)(nil)
)

// NewSiemSinkResource is tessera_siem_sink: a destination the audit ledger is streamed to.
func NewSiemSinkResource() resource.Resource { return &siemSinkResource{} }

type siemSinkResource struct{ proposer }

type siemSinkModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Kind              types.String `tfsdk:"kind"`
	Format            types.String `tfsdk:"format"`
	Target            types.String `tfsdk:"target"`
	TargetURL         types.String `tfsdk:"target_url"`
	TargetURLVersion  types.String `tfsdk:"target_url_version"`
	TargetOrigin      types.String `tfsdk:"target_origin"`
	TargetFingerprint types.String `tfsdk:"target_fingerprint"`
	Flavor            types.String `tfsdk:"flavor"`
	CAPEM             types.String `tfsdk:"ca_pem"`
	IncludeHTTP       types.Bool   `tfsdk:"include_http"`
	EventFilter       types.Set    `tfsdk:"event_filter"`
	Region            types.String `tfsdk:"region"`
	AccessKeyID       types.String `tfsdk:"access_key_id"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	Start             types.String `tfsdk:"start"`
	Token             types.String `tfsdk:"token"`
	TokenVersion      types.String `tfsdk:"token_version"`
	ChangeID          types.String `tfsdk:"change_id"`
	ChangeURL         types.String `tfsdk:"change_url"`
}

func (r *siemSinkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_siem_sink"
}

func (r *siemSinkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A SIEM sink: the audit ledger streamed to Splunk HEC (`webhook` with flavor `hec`), a JSON webhook, a syslog-over-TLS " +
			"collector or an S3 bucket. " + proposalNote + secretNote +
			"As on the admin routes, a sink that moves to another origin needs a new `token` (the stored one never follows it). " +
			"A webhook or S3 URL may carry a token, so it goes in the write-only `target_url` (with `target_url_version`), never in the state; the state " +
			"keeps `target_origin` and `target_fingerprint`, which the approver sees too. " +
			"Sinks are switched off with `enabled = false`, not deleted: destroy leaves the sink on the server. Refresh reads the sink " +
			"when the client also holds the audit scope (siem.read) and keeps the state otherwise.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The sink id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 100), noEdgeSpace}},
			"kind": schema.StringAttribute{Required: true, Description: "`webhook`, `syslog` or `s3`. It cannot change.",
				Validators:    []validator.String{oneOf("webhook", "syslog", "s3")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"format": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("json"),
				Validators: []validator.String{oneOf("json", "ocsf")}, Description: "`json` (default) or `ocsf`."},
			"target": schema.StringAttribute{Optional: true, Validators: nonEmptyString(),
				Description: "Syslog collector: `host:port` (6514 by default), not a private address. A webhook or S3 sink uses `target_url` instead."},
			"flavor": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""),
				Validators: []validator.String{oneOf("", "hec", "json")}, Description: "A webhook's flavor, `hec` (Splunk) or `json`."},
			"ca_pem": schema.StringAttribute{Optional: true, Description: "A syslog collector's CA bundle (PEM certificates, public, at most 64 KiB)."},
			"include_http": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Whether `http.request` events are sent too. Default false."},
			"event_filter": schema.SetAttribute{Optional: true, ElementType: types.StringType,
				Description: "Audit actions or prefixes (`auth.*`) the sink receives; unset or empty means every event."},
			"region":        schema.StringAttribute{Optional: true, Description: "S3: the signing region, for example `eu-west-1`."},
			"access_key_id": schema.StringAttribute{Optional: true, Description: "S3: the access key id (the secret access key is `token`)."},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Whether events are sent. Default true."},
			"start": schema.StringAttribute{Optional: true, Description: "On creation: `now` (the default) or `beginning` (replay the whole ledger). Ignored afterwards."},
			"token": writeOnlySecret("An HEC token, or an S3 secret access key. Required for HEC and S3. Write-only: never in the plan or the state.",
				"token_version"),
			"token_version": versionAttr("Any text; change it along with `token` to send the new token."),
		}),
	}
	for k, v := range targetURLAttrs("webhook or S3") {
		resp.Schema.Attributes[k] = v
	}
}

func (r *siemSinkResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m siemSinkModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if !resp.Diagnostics.HasError() {
		urlKindRule(&resp.Diagnostics, m.Kind, m.Target, m.TargetURL, "webhook", "s3")
	}
}

func (r *siemSinkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type siemSinkBody struct {
	Name        string    `json:"name,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Format      string    `json:"format,omitempty"`
	Target      *string   `json:"target,omitempty"`
	Flavor      string    `json:"flavor,omitempty"`
	CAPEM       *string   `json:"ca_pem,omitempty"`
	Token       *string   `json:"token,omitempty"`
	IncludeHTTP *bool     `json:"include_http,omitempty"`
	EventFilter *[]string `json:"event_filter,omitempty"`
	Region      *string   `json:"region,omitempty"`
	AccessKeyID *string   `json:"access_key_id,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
	Start       string    `json:"start,omitempty"`
}

type siemSinkRead struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Format      string   `json:"format"`
	Flavor      string   `json:"flavor"`
	IncludeHTTP bool     `json:"include_http"`
	EventFilter []string `json:"event_filter"`
	Region      string   `json:"region"`
	AccessKeyID string   `json:"access_key_id"`
	Enabled     bool     `json:"enabled"`
}

func optString(v types.String) *string {
	if !known(v) {
		return nil
	}
	s := v.ValueString()
	return &s
}

func (r *siemSinkResource) body(ctx context.Context, plan *siemSinkModel, secret string, send bool, rawURL string, sendURL bool, update bool, d *diag.Diagnostics) siemSinkBody {
	inc, en := plan.IncludeHTTP.ValueBool(), plan.Enabled.ValueBool()
	filter := stringSetOf(ctx, d, plan.EventFilter)
	b := siemSinkBody{Name: plan.Name.ValueString(), Kind: plan.Kind.ValueString(), Format: plan.Format.ValueString(), Target: optString(plan.Target),
		Flavor: plan.Flavor.ValueString(), CAPEM: optString(plan.CAPEM), IncludeHTTP: &inc, EventFilter: &filter,
		Region: optString(plan.Region), AccessKeyID: optString(plan.AccessKeyID), Enabled: &en}
	if send {
		b.Token = &secret
	}
	if sendURL {
		b.Target = &rawURL
	}
	if update {
		b.Kind = "" // fixed after creation
	} else {
		b.Start = plan.Start.ValueString()
	}
	return b
}

func (r *siemSinkResource) file(ctx context.Context, plan, state *siemSinkModel, b siemSinkBody, id string, d *diag.Diagnostics) {
	pth, what := "/proposals/siem-sinks", "create the SIEM sink"
	if id != "" {
		pth, what = "/proposals/siem-sinks/"+url.PathEscape(id), "update the SIEM sink"
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new SIEM sink", "The change "+ch.ChangeID+" was applied but the server did not say which sink it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	plan.ID = types.StringValue(id)
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
	setTarget(&plan.TargetOrigin, &plan.TargetFingerprint, state, ch, func(m *siemSinkModel) (types.String, types.String) {
		return m.TargetOrigin, m.TargetFingerprint
	})
}

func (r *siemSinkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan siemSinkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, send := secretToSend(ctx, &resp.Diagnostics, req.Config, "token", "token_version", plan.TokenVersion, types.StringNull(), true)
	if resp.Diagnostics.HasError() {
		return
	}
	rawURL, sendURL := secretToSend(ctx, &resp.Diagnostics, req.Config, "target_url", "target_url_version", plan.TargetURLVersion, types.StringNull(), true)
	b := r.body(ctx, &plan, secret, send, rawURL, sendURL, false, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.file(ctx, &plan, nil, b, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		plan.TargetURL = types.StringNull()
		plan.Token = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *siemSinkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state siemSinkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, send := secretToSend(ctx, &resp.Diagnostics, req.Config, "token", "token_version", plan.TokenVersion, state.TokenVersion, false)
	if resp.Diagnostics.HasError() {
		return
	}
	rawURL, sendURL := secretToSend(ctx, &resp.Diagnostics, req.Config, "target_url", "target_url_version", plan.TargetURLVersion, state.TargetURLVersion, false)
	b := r.body(ctx, &plan, secret, send, rawURL, sendURL, true, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.file(ctx, &plan, &state, b, state.ID.ValueString(), &resp.Diagnostics); !resp.Diagnostics.HasError() {
		plan.TargetURL = types.StringNull()
		plan.Token = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *siemSinkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state siemSinkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := r.c.List(ctx, "/siem/sinks", url.Values{})
	if err != nil {
		if client.IsForbidden(err) {
			return
		}
		resp.Diagnostics.AddError("Cannot read the SIEM sinks", err.Error())
		return
	}
	for _, raw := range items {
		var v siemSinkRead
		if err := json.Unmarshal(raw, &v); err != nil {
			resp.Diagnostics.AddError("Cannot read the SIEM sinks", err.Error())
			return
		}
		if v.ID != state.ID.ValueString() {
			continue
		}
		state.Name, state.Kind, state.Format, state.Flavor = types.StringValue(v.Name), types.StringValue(v.Kind), types.StringValue(v.Format), types.StringValue(v.Flavor)
		state.IncludeHTTP, state.Enabled = types.BoolValue(v.IncludeHTTP), types.BoolValue(v.Enabled)
		if known(state.EventFilter) || len(v.EventFilter) > 0 {
			set, diags := types.SetValueFrom(ctx, types.StringType, v.EventFilter)
			resp.Diagnostics.Append(diags...)
			state.EventFilter = set
		}
		if v.Kind == "s3" {
			state.Region, state.AccessKeyID = types.StringValue(v.Region), types.StringValue(v.AccessKeyID)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	resp.State.RemoveResource(ctx)
}

func (r *siemSinkResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The SIEM sink")
}

func (r *siemSinkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// targetURLAttrs is the schema of a write-only URL argument and what the server reports about it. A webhook URL usually carries a
// token (Slack, Teams and Sumo Logic put it in the path), so it is write-only like a secret and never in the state; the state keeps
// its origin and a keyed fingerprint of the whole URL, which the approver is shown too, so a person can match the two.
func targetURLAttrs(what string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"target_url": schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true,
			Description: "The " + what + " URL: absolute, `https`, no credentials, not a cloud metadata service (the server checks again when the proposal " +
				"is approved). Write-only: never in the plan or the state. The server seals it; the approver sees its origin and a fingerprint.",
			Validators: []validator.String{stringvalidator.LengthBetween(1, 2000), stringvalidator.AlsoRequires(path.MatchRoot("target_url_version"))}},
		"target_url_version": versionAttr("Any text; change it along with `target_url` to send the new URL. Without a change the server keeps the URL it has."),
		"target_origin":      schema.StringAttribute{Computed: true, Description: "The scheme, host and port of the URL the server sealed (never its path)."},
		"target_fingerprint": schema.StringAttribute{Computed: true, Description: "A keyed fingerprint of the whole sealed URL (16 hex characters), which the approver sees too. " +
			"Compare it to the one shown for the change request to confirm the receiver, including its path; it cannot be computed from a list of candidate URLs."},
	}
}

// urlKindRule is the config check shared by the alert channel and the SIEM sink: a webhook (or S3) sink takes `target_url`, the others
// `target`, and a write-only URL is needed in the configuration on every run.
func urlKindRule(d *diag.Diagnostics, kind, target, targetURL types.String, urlKinds ...string) {
	if !known(kind) {
		return
	}
	isURL := false
	for _, k := range urlKinds {
		isURL = isURL || kind.ValueString() == k
	}
	switch {
	case isURL && !targetURL.IsUnknown() && targetURL.IsNull():
		d.AddAttributeError(path.Root("target_url"), "target_url is required", "A "+kind.ValueString()+" takes its URL in target_url (write-only), with target_url_version.")
	case isURL && known(target):
		d.AddAttributeError(path.Root("target"), "target is not used", "A "+kind.ValueString()+" takes its URL in target_url, not target.")
	case !isURL && !target.IsUnknown() && target.IsNull():
		d.AddAttributeError(path.Root("target"), "target is required", "A "+kind.ValueString()+" takes target.")
	case !isURL && known(targetURL):
		d.AddAttributeError(path.Root("target_url"), "target_url is not used", "A "+kind.ValueString()+" takes target, not target_url.")
	}
}

// setTarget records what the server says about the URL it sealed. When this apply sent no URL (the version did not change) the
// state keeps the origin and fingerprint it had; a computed attribute must never stay unknown.
func setTarget[M any](origin, fp *types.String, state *M, ch *client.Change, get func(*M) (types.String, types.String)) {
	switch {
	case ch.TargetOrigin != nil && ch.TargetFingerprint != nil:
		*origin, *fp = types.StringValue(*ch.TargetOrigin), types.StringValue(*ch.TargetFingerprint)
	case state != nil:
		*origin, *fp = get(state)
	default:
		*origin, *fp = types.StringNull(), types.StringNull()
	}
}
