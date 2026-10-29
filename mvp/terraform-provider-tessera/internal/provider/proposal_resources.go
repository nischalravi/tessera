package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/client"
)

// Resources that PROPOSE configuration (server issue #721). A machine client may not write configuration, so each of
// these files a change request (POST /api/v1/proposals/...), waits until a person approves it with a step-up sign-in
// and the server applies it, and fails with the change's URL when it is refused, expires or the wait runs out
// (provider settings wait_timeout and poll_interval). Plan is read-only; an apply that needs approval takes as long as
// the approval does. The client needs the config.propose scope, which only two admins can give it.
//
// What the server lets a client read decides what refresh can see: a role and a SoD ruleset are read back (viewer
// routes), an alert rule is read when the client also holds the audit scope, and a catalog item cannot be read at all
// (its routes need requests.create, which no token scope grants), so its state is what was last applied. None of
// them is destroyed by `terraform destroy`: the proposal routes only create and change, so destroy removes the
// resource from state, leaves the configuration on the server, and says so in a warning.

const proposalNote = "Needs the `config.propose` scope, which an admin grants with a change request that a second admin approves. " +
	"The resource is applied only after a person approves the proposal with a step-up sign-in; until then apply waits (provider " +
	"settings `wait_timeout` and `poll_interval`) and fails with the change's URL on a refusal or a timeout. "

// proposer is what the four resources share.
type proposer struct{ c *client.Client }

func (p *proposer) configure(req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	p.c = c
}

// propose files body at path and waits for the change to be applied.
func (p *proposer) propose(ctx context.Context, d *diag.Diagnostics, what, path string, body any) *client.Change {
	timeout, interval := p.c.Waits()
	ch, err := p.c.ProposeAndWait(ctx, path, body, timeout, interval)
	if err != nil {
		msg := err.Error()
		if client.IsForbidden(err) {
			msg += "\nThe machine client needs the config.propose scope. Two admins grant it: one files a change request of type " +
				"api_client.propose.grant for this client, a different one approves it with a step-up sign-in. Then get a new token (run again)."
		}
		d.AddError("Cannot "+what, msg)
		return nil
	}
	return ch
}

func (p *proposer) leftOnServer(d *diag.Diagnostics, what string) {
	d.AddWarning(what+" stays on the server",
		"Tessera has no proposal that removes it, so destroying the resource only removes it from the Terraform state.")
}

// commonAttrs are the computed attributes every proposing resource has.
func commonAttrs(m map[string]schema.Attribute) map[string]schema.Attribute {
	m["change_id"] = schema.StringAttribute{Computed: true, Description: "The id of the change request that applied the last create or update."}
	m["change_url"] = schema.StringAttribute{Computed: true, Description: "Where a person reviews that change request."}
	return m
}

func setChange(id, url *types.String, ch *client.Change) {
	*id, *url = types.StringValue(ch.ChangeID), types.StringValue(ch.URL)
}

func int64Set(ctx context.Context, d *diag.Diagnostics, s types.Set) []int64 {
	out := []int64{}
	if known(s) {
		d.Append(s.ElementsAs(ctx, &out, false)...)
	}
	return out
}

func stringSetOf(ctx context.Context, d *diag.Diagnostics, s types.Set) []string {
	out := []string{}
	if known(s) {
		d.Append(s.ElementsAs(ctx, &out, false)...)
	}
	return out
}

func stringListOf(ctx context.Context, d *diag.Diagnostics, s types.List) []string {
	out := []string{}
	if known(s) {
		d.Append(s.ElementsAs(ctx, &out, false)...)
	}
	return out
}

// ---------------------------------------------------------------- tessera_alert_rule

var (
	_ resource.Resource                = (*alertRuleResource)(nil)
	_ resource.ResourceWithConfigure   = (*alertRuleResource)(nil)
	_ resource.ResourceWithImportState = (*alertRuleResource)(nil)
)

// NewAlertRuleResource is tessera_alert_rule: the settings of one of Tessera's built-in alert rules.
func NewAlertRuleResource() resource.Resource { return &alertRuleResource{} }

type alertRuleResource struct{ proposer }

type alertRuleModel struct {
	ID            types.String `tfsdk:"id"`
	RuleID        types.String `tfsdk:"rule_id"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	Severity      types.String `tfsdk:"severity"`
	Threshold     types.Int64  `tfsdk:"threshold"`
	WindowMinutes types.Int64  `tfsdk:"window_minutes"`
	ChangeID      types.String `tfsdk:"change_id"`
	ChangeURL     types.String `tfsdk:"change_url"`
}

func (r *alertRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alert_rule"
}

func (r *alertRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The settings of a built-in alert rule (whether it fires, its severity, threshold and window). " + proposalNote +
			"Alert rules are built in, so destroy leaves the settings as they are.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The rule id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"rule_id": schema.StringAttribute{Required: true, Description: "The built-in rule id, for example `signin_failures`.",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 64)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"enabled": schema.BoolAttribute{Required: true, Description: "Whether the rule raises alerts."},
			"severity": schema.StringAttribute{Required: true, Description: "`low`, `medium`, `high` or `critical`.",
				Validators: []validator.String{oneOf("low", "medium", "high", "critical")}},
			"threshold": schema.Int64Attribute{Required: true, Description: "Events in the window that raise an alert (1 to 10000).",
				Validators: []validator.Int64{int64validator.Between(1, 10000)}},
			"window_minutes": schema.Int64Attribute{Required: true, Description: "The window in minutes (1 to 10080).",
				Validators: []validator.Int64{int64validator.Between(1, 10080)}},
		}),
	}
}

func (r *alertRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type alertRuleBody struct {
	Enabled       bool   `json:"enabled"`
	Severity      string `json:"severity"`
	Threshold     int64  `json:"threshold"`
	WindowMinutes int64  `json:"window_minutes"`
}

func (r *alertRuleResource) put(ctx context.Context, plan *alertRuleModel, d *diag.Diagnostics) {
	ch := r.propose(ctx, d, "apply the alert rule", "/proposals/alert-rules/"+url.PathEscape(plan.RuleID.ValueString()),
		alertRuleBody{Enabled: plan.Enabled.ValueBool(), Severity: plan.Severity.ValueString(),
			Threshold: plan.Threshold.ValueInt64(), WindowMinutes: plan.WindowMinutes.ValueInt64()})
	if ch == nil {
		return
	}
	plan.ID = plan.RuleID
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *alertRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan alertRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *alertRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan alertRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

// Read refreshes the settings when the client may read the rules (alerts.read: the auditor role and the audit scope) and
// keeps the state otherwise.
func (r *alertRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state alertRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := r.c.List(ctx, "/alerts/rules", url.Values{})
	if err != nil {
		if client.IsForbidden(err) {
			return // this client cannot read alert rules: the state stays as last applied
		}
		resp.Diagnostics.AddError("Cannot read the alert rules", err.Error())
		return
	}
	for _, raw := range items {
		var v struct {
			ID            string `json:"id"`
			Enabled       bool   `json:"enabled"`
			Severity      string `json:"severity"`
			Threshold     int64  `json:"threshold"`
			WindowMinutes int64  `json:"window_minutes"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			resp.Diagnostics.AddError("Cannot read the alert rules", err.Error())
			return
		}
		if v.ID == state.RuleID.ValueString() {
			state.Enabled, state.Severity = types.BoolValue(v.Enabled), types.StringValue(v.Severity)
			state.Threshold, state.WindowMinutes = types.Int64Value(v.Threshold), types.Int64Value(v.WindowMinutes)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *alertRuleResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The alert rule")
}

func (r *alertRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("rule_id"), req.ID)...)
}

// ---------------------------------------------------------------- tessera_catalog_item

var (
	_ resource.Resource              = (*catalogItemResource)(nil)
	_ resource.ResourceWithConfigure = (*catalogItemResource)(nil)
)

// NewCatalogItemResource is tessera_catalog_item: the access-request catalog entry of one entitlement group.
func NewCatalogItemResource() resource.Resource { return &catalogItemResource{} }

type catalogItemResource struct{ proposer }

type catalogItemModel struct {
	ID                  types.String  `tfsdk:"id"`
	GroupID             types.Int64   `tfsdk:"group_id"`
	Requestable         types.Bool    `tfsdk:"requestable"`
	Description         types.String  `tfsdk:"description"`
	Risk                types.String  `tfsdk:"risk"`
	OwnerIdentityID     types.Int64   `tfsdk:"owner_identity_id"`
	EligibleTypes       types.Set     `tfsdk:"eligible_types"`
	EligibleDepartments types.Set     `tfsdk:"eligible_departments"`
	DefaultHours        types.Float64 `tfsdk:"default_hours"`
	MaxHours            types.Float64 `tfsdk:"max_hours"`
	ApprovalStages      types.List    `tfsdk:"approval_stages"`
	EscalateAfterHours  types.Float64 `tfsdk:"escalate_after_hours"`
	ChangeID            types.String  `tfsdk:"change_id"`
	ChangeURL           types.String  `tfsdk:"change_url"`
}

func (r *catalogItemResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_catalog_item"
}

func (r *catalogItemResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The access-request catalog entry of one entitlement group (an id from `tessera_entitlements`): whether people can " +
			"request it, its risk, who may, for how long and who approves. " + proposalNote +
			"The server offers no read for a catalog item to a machine client, so refresh cannot see changes made elsewhere.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The group id, as text.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"group_id": schema.Int64Attribute{Required: true, Description: "The entitlement group's id.",
				Validators:    []validator.Int64{int64validator.AtLeast(1)},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}},
			"requestable": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Whether people can request the entitlement. Default false."},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""),
				Description: "Up to 1000 characters shown to requesters.", Validators: []validator.String{stringvalidator.LengthAtMost(1000)}},
			"risk": schema.StringAttribute{Required: true, Description: "`low`, `medium` or `high`.", Validators: []validator.String{oneOf("low", "medium", "high")}},
			"owner_identity_id": schema.Int64Attribute{Optional: true, Description: "The active person who owns the entitlement (an id from `tessera_identities`).",
				Validators: []validator.Int64{int64validator.AtLeast(1)}},
			"eligible_types":       schema.SetAttribute{Optional: true, ElementType: types.StringType, Description: "Identity types that may request it: `human`, `service`, `ai_agent`. Unset: any."},
			"eligible_departments": schema.SetAttribute{Optional: true, ElementType: types.StringType, Description: "Departments that may request it. Unset: any."},
			"default_hours":        schema.Float64Attribute{Optional: true, Description: "Default duration of a grant, in hours (a privileged item that is requestable needs one)."},
			"max_hours":            schema.Float64Attribute{Optional: true, Description: "Longest grant, in hours."},
			"approval_stages":      schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Approval stages in order: `manager`, `owner`, `decider`. Unset: unchanged."},
			"escalate_after_hours": schema.Float64Attribute{Optional: true, Description: "Hours before a pending approval escalates. Unset: unchanged."},
		}),
	}
}

func (r *catalogItemResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type catalogItemBody struct {
	Requestable         bool     `json:"requestable"`
	Description         string   `json:"description"`
	OwnerIdentityID     *int64   `json:"owner_identity_id"`
	Risk                string   `json:"risk"`
	EligibleTypes       []string `json:"eligible_types"`
	EligibleDepartments []string `json:"eligible_departments"`
	DefaultHours        *float64 `json:"default_hours"`
	MaxHours            *float64 `json:"max_hours"`
	ApprovalStages      []string `json:"approval_stages"`
	EscalateAfterHours  *float64 `json:"escalate_after_hours"`
}

func (r *catalogItemResource) put(ctx context.Context, plan *catalogItemModel, d *diag.Diagnostics) {
	b := catalogItemBody{Requestable: plan.Requestable.ValueBool(), Description: plan.Description.ValueString(), Risk: plan.Risk.ValueString(),
		EligibleTypes: stringSetOf(ctx, d, plan.EligibleTypes), EligibleDepartments: stringSetOf(ctx, d, plan.EligibleDepartments)}
	if known(plan.OwnerIdentityID) {
		v := plan.OwnerIdentityID.ValueInt64()
		b.OwnerIdentityID = &v
	}
	for dst, src := range map[**float64]types.Float64{&b.DefaultHours: plan.DefaultHours, &b.MaxHours: plan.MaxHours, &b.EscalateAfterHours: plan.EscalateAfterHours} {
		if known(src) {
			v := src.ValueFloat64()
			*dst = &v
		}
	}
	if known(plan.ApprovalStages) {
		b.ApprovalStages = stringListOf(ctx, d, plan.ApprovalStages)
	}
	if d.HasError() {
		return
	}
	ch := r.propose(ctx, d, "apply the catalog item", "/proposals/catalog-items/"+strconv.FormatInt(plan.GroupID.ValueInt64(), 10), b)
	if ch == nil {
		return
	}
	plan.ID = types.StringValue(strconv.FormatInt(plan.GroupID.ValueInt64(), 10))
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *catalogItemResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan catalogItemModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *catalogItemResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan catalogItemModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

// Read keeps the state: a machine client cannot read catalog items.
func (r *catalogItemResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {}

func (r *catalogItemResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The catalog item")
}

// ---------------------------------------------------------------- tessera_business_role

var (
	_ resource.Resource              = (*businessRoleResource)(nil)
	_ resource.ResourceWithConfigure = (*businessRoleResource)(nil)
)

// NewBusinessRoleResource is tessera_business_role: a business role, a bundle of entitlements people request as one.
func NewBusinessRoleResource() resource.Resource { return &businessRoleResource{} }

type businessRoleResource struct{ proposer }

type businessRoleModel struct {
	ID                  types.String `tfsdk:"id"`
	Key                 types.String `tfsdk:"key"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	Risk                types.String `tfsdk:"risk"`
	Requestable         types.Bool   `tfsdk:"requestable"`
	EntitlementGroupIDs types.Set    `tfsdk:"entitlement_group_ids"`
	OwnerIdentityID     types.Int64  `tfsdk:"owner_identity_id"`
	Note                types.String `tfsdk:"note"`
	Version             types.Int64  `tfsdk:"version"`
	ChangeID            types.String `tfsdk:"change_id"`
	ChangeURL           types.String `tfsdk:"change_url"`
}

func (r *businessRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_business_role"
}

func (r *businessRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A business role: a named bundle of entitlement groups that people request as one. " + proposalNote +
			"Roles are retired in the admin center, not by Terraform: destroy leaves the role on the server.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The role id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"key": schema.StringAttribute{Required: true, Description: "The role's stable key (letters, digits, `.`, `_`, `:` and `-`). It never changes: a new key is a new role.",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 64)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"name": schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 200), noEdgeSpace}},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""),
				Validators: []validator.String{stringvalidator.LengthAtMost(1000)}},
			"risk":        schema.StringAttribute{Required: true, Description: "`low`, `medium` or `high`.", Validators: []validator.String{oneOf("low", "medium", "high")}},
			"requestable": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Whether people can request the role."},
			"entitlement_group_ids": schema.SetAttribute{Required: true, ElementType: types.Int64Type,
				Description: "The entitlement groups the role grants (ids from `tessera_entitlements`); at least one."},
			"owner_identity_id": schema.Int64Attribute{Optional: true, Description: "The active person who owns the role. Not read back."},
			"note":              schema.StringAttribute{Optional: true, Description: "Why the change was made; kept in the role's version history. Not read back."},
			"version":           schema.Int64Attribute{Computed: true, Description: "The role's version on the server; an update proposes a change to this version, and is refused if the role moved on."},
		}),
	}
}

func (r *businessRoleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type businessRoleBody struct {
	Version      int64   `json:"version"`
	Key          string  `json:"key"`
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Owner        *int64  `json:"owner_identity_id"`
	Risk         string  `json:"risk"`
	Requestable  bool    `json:"requestable"`
	Entitlements []int64 `json:"entitlement_group_ids"`
	Note         string  `json:"note"`
}

type roleRead struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Risk         string `json:"risk"`
	Requestable  bool   `json:"requestable"`
	Status       string `json:"status"`
	Version      int64  `json:"version"`
	Entitlements []struct {
		ID int64 `json:"id"`
	} `json:"entitlements"`
}

// read loads the role (nil when it is gone or retired).
func (r *businessRoleResource) read(ctx context.Context, id string) (*roleRead, error) {
	var v roleRead
	if err := r.c.Do(ctx, "GET", "/roles/"+url.PathEscape(id), nil, &v); err != nil {
		if client.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if v.Status != "active" && v.Status != "" {
		return nil, nil
	}
	return &v, nil
}

func (m *businessRoleModel) fromServer(v *roleRead) {
	m.ID, m.Name, m.Description = types.StringValue(v.ID), types.StringValue(v.Name), types.StringValue(v.Description)
	m.Risk, m.Requestable, m.Version = types.StringValue(v.Risk), types.BoolValue(v.Requestable), types.Int64Value(v.Version)
	ids := make([]attr.Value, 0, len(v.Entitlements))
	for _, e := range v.Entitlements {
		ids = append(ids, types.Int64Value(e.ID))
	}
	m.EntitlementGroupIDs = types.SetValueMust(types.Int64Type, ids)
}

func (r *businessRoleResource) put(ctx context.Context, plan *businessRoleModel, id string, d *diag.Diagnostics) {
	b := businessRoleBody{Key: plan.Key.ValueString(), Name: plan.Name.ValueString(), Description: plan.Description.ValueString(),
		Risk: plan.Risk.ValueString(), Requestable: plan.Requestable.ValueBool(), Entitlements: int64Set(ctx, d, plan.EntitlementGroupIDs),
		Note: plan.Note.ValueString()}
	if known(plan.OwnerIdentityID) {
		v := plan.OwnerIdentityID.ValueInt64()
		b.Owner = &v
	}
	pth, what := "/proposals/roles", "create the business role"
	if id != "" {
		b.Version = plan.Version.ValueInt64()
		pth, what = "/proposals/roles/"+url.PathEscape(id), "update the business role"
	}
	if d.HasError() {
		return
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new business role", "The change "+ch.ChangeID+" was applied but the server did not say which role it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	v, err := r.read(ctx, id)
	if err != nil || v == nil {
		d.AddError("Cannot read the business role back", fmt.Sprintf("change %s was applied; reading role %s failed: %v", ch.ChangeID, id, err))
		return
	}
	// the answer is what the server holds now; the plan's own values (key, note, owner) are not part of the read
	key, note, owner := plan.Key, plan.Note, plan.OwnerIdentityID
	plan.fromServer(v)
	plan.Key, plan.Note, plan.OwnerIdentityID = key, note, owner
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *businessRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan businessRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *businessRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state businessRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Version = state.Version // the version the proposal is made against: the one last read
	if r.put(ctx, &plan, state.ID.ValueString(), &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *businessRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state businessRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the business role", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	key, note, owner, cid, curl := state.Key, state.Note, state.OwnerIdentityID, state.ChangeID, state.ChangeURL
	state.fromServer(v)
	state.Key, state.Note, state.OwnerIdentityID, state.ChangeID, state.ChangeURL = key, note, owner, cid, curl
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *businessRoleResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The business role")
}

// ---------------------------------------------------------------- tessera_sod_ruleset

var (
	_ resource.Resource              = (*sodRulesetResource)(nil)
	_ resource.ResourceWithConfigure = (*sodRulesetResource)(nil)
)

// NewSoDRulesetResource is tessera_sod_ruleset: a separation-of-duties ruleset, the container of SoD risks.
func NewSoDRulesetResource() resource.Resource { return &sodRulesetResource{} }

type sodRulesetResource struct{ proposer }

type sodRulesetModel struct {
	ID          types.String `tfsdk:"id"`
	Key         types.String `tfsdk:"key"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Note        types.String `tfsdk:"note"`
	Version     types.Int64  `tfsdk:"version"`
	ChangeID    types.String `tfsdk:"change_id"`
	ChangeURL   types.String `tfsdk:"change_url"`
}

func (r *sodRulesetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sod_ruleset"
}

func (r *sodRulesetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A separation-of-duties ruleset: the named set of SoD risks that are checked together. " + proposalNote +
			"Rulesets are retired in the admin center, not by Terraform: destroy leaves the ruleset on the server.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The ruleset id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"key": schema.StringAttribute{Required: true, Description: "The ruleset's stable key (letters, digits, `.`, `_`, `:` and `-`). A new key is a new ruleset.",
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 64)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"name":        schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthBetween(1, 200), noEdgeSpace}},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "A disabled ruleset is not checked. Default true."},
			"note":    schema.StringAttribute{Optional: true, Description: "Why the change was made. Not read back."},
			"version": schema.Int64Attribute{Computed: true, Description: "The ruleset's version on the server; an update is refused if it moved on."},
		}),
	}
}

func (r *sodRulesetResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type sodRulesetBody struct {
	Version     int64  `json:"version"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Note        string `json:"note"`
}

type sodRulesetRead struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Status      string `json:"status"`
	Version     int64  `json:"version"`
}

func (r *sodRulesetResource) read(ctx context.Context, id string) (*sodRulesetRead, error) {
	var v sodRulesetRead
	if err := r.c.Do(ctx, "GET", "/sod/rulesets/"+url.PathEscape(id), nil, &v); err != nil {
		if client.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if v.Status != "active" && v.Status != "" {
		return nil, nil
	}
	return &v, nil
}

func (m *sodRulesetModel) fromServer(v *sodRulesetRead) {
	m.ID, m.Name, m.Description = types.StringValue(v.ID), types.StringValue(v.Name), types.StringValue(v.Description)
	m.Enabled, m.Version = types.BoolValue(v.Enabled), types.Int64Value(v.Version)
	if v.Key != "" {
		m.Key = types.StringValue(v.Key)
	}
}

func (r *sodRulesetResource) put(ctx context.Context, plan *sodRulesetModel, id string, d *diag.Diagnostics) {
	b := sodRulesetBody{Key: plan.Key.ValueString(), Name: plan.Name.ValueString(), Description: plan.Description.ValueString(),
		Enabled: plan.Enabled.ValueBool(), Note: plan.Note.ValueString()}
	pth, what := "/proposals/sod-rulesets", "create the SoD ruleset"
	if id != "" {
		b.Version = plan.Version.ValueInt64()
		pth, what = "/proposals/sod-rulesets/"+url.PathEscape(id), "update the SoD ruleset"
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new SoD ruleset", "The change "+ch.ChangeID+" was applied but the server did not say which ruleset it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	v, err := r.read(ctx, id)
	if err != nil || v == nil {
		d.AddError("Cannot read the SoD ruleset back", fmt.Sprintf("change %s was applied; reading ruleset %s failed: %v", ch.ChangeID, id, err))
		return
	}
	note := plan.Note
	plan.fromServer(v)
	plan.Note = note
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *sodRulesetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan sodRulesetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *sodRulesetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state sodRulesetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Version = state.Version
	if r.put(ctx, &plan, state.ID.ValueString(), &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *sodRulesetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sodRulesetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the SoD ruleset", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	note, cid, curl := state.Note, state.ChangeID, state.ChangeURL
	state.fromServer(v)
	state.Note, state.ChangeID, state.ChangeURL = note, cid, curl
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sodRulesetResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The SoD ruleset")
}
