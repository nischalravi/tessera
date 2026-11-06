package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/client"
)

// Resources for policy objects, proposed like the others in proposal_resources.go (server issue #719): a birthright rule
// condition, a mitigating control and an approval policy. Each is read back through a viewer route (graph.read, which
// the tessera:read scope grants), so refresh sees changes made in the admin center, and each can be imported by its id.
// None carries a secret. Destroy removes the resource from state only: the server has no proposal that retires them.

// jsonNormal parses s as JSON and writes it back with sorted keys and no spacing, so two spellings of one document
// compare equal. ok is false when s is not JSON.
func jsonNormal(s string) (string, bool) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", false
	}
	b, err := json.Marshal(v)
	return string(b), err == nil
}

// sameJSON keeps what the user wrote (prior) when the server holds the same document, and takes the server's otherwise.
func sameJSON(prior types.String, server json.RawMessage) types.String {
	srv, _ := jsonNormal(string(server))
	if known(prior) {
		if p, ok := jsonNormal(prior.ValueString()); ok && p == srv {
			return prior
		}
	}
	return types.StringValue(srv)
}

type jsonValidator struct{ array bool }

func (v jsonValidator) Description(context.Context) string {
	if v.array {
		return "a JSON array"
	}
	return "a JSON object"
}
func (v jsonValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v jsonValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if !known(req.ConfigValue) {
		return
	}
	var x any
	if err := json.Unmarshal([]byte(req.ConfigValue.ValueString()), &x); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid JSON", err.Error())
		return
	}
	_, isArray := x.([]any)
	_, isObject := x.(map[string]any)
	if (v.array && !isArray) || (!v.array && !isObject) {
		resp.Diagnostics.AddAttributeError(req.Path, "Wrong JSON type", "must be "+v.Description(context.Background()))
	}
}

// ---------------------------------------------------------------- tessera_birthright_rule

var (
	_ resource.Resource                = (*birthrightRuleResource)(nil)
	_ resource.ResourceWithConfigure   = (*birthrightRuleResource)(nil)
	_ resource.ResourceWithImportState = (*birthrightRuleResource)(nil)
)

// NewBirthrightRuleResource is tessera_birthright_rule: the attribute condition a business role's birthright rule names.
func NewBirthrightRuleResource() resource.Resource { return &birthrightRuleResource{} }

type birthrightRuleResource struct{ proposer }

type birthrightRuleModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	ConditionJSON types.String `tfsdk:"condition_json"`
	Note          types.String `tfsdk:"note"`
	Version       types.Int64  `tfsdk:"version"`
	ChangeID      types.String `tfsdk:"change_id"`
	ChangeURL     types.String `tfsdk:"change_url"`
}

func (r *birthrightRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_birthright_rule"
}

func (r *birthrightRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A birthright rule: the attribute condition (for example `identity.department = Finance`) that a business role's birthright " +
			"rule names in its `policy` field, so everyone who matches holds the role. " + proposalNote +
			"Policies are retired in the admin center, not by Terraform: destroy leaves the rule on the server.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The policy id, which a business role's birthright rule names.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "A unique name, 1 to 120 characters.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 120), noEdgeSpace}},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"condition_json": schema.StringAttribute{Required: true, Description: "The condition as a JSON object, for example " +
				"`jsonencode({attr = \"identity.department\", op = \"eq\", value = \"Finance\"})`; `all`, `any` and `not` combine conditions.",
				Validators: []validator.String{jsonValidator{}}},
			"note":    schema.StringAttribute{Optional: true, Description: "Why the change was made. Not read back."},
			"version": schema.Int64Attribute{Computed: true, Description: "The policy's version on the server; an update is refused if it moved on."},
		}),
	}
}

func (r *birthrightRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type birthrightRuleBody struct {
	Version     int64           `json:"version"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Condition   json.RawMessage `json:"condition"`
	Note        string          `json:"note"`
}

type birthrightRuleRead struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Condition   json.RawMessage `json:"condition"`
	Status      string          `json:"status"`
	Version     int64           `json:"version"`
}

func (r *birthrightRuleResource) read(ctx context.Context, id string) (*birthrightRuleRead, error) {
	var v birthrightRuleRead
	if err := r.c.Do(ctx, "GET", "/abac/policies/"+url.PathEscape(id), nil, &v); err != nil {
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

func (m *birthrightRuleModel) fromServer(v *birthrightRuleRead) {
	m.ID, m.Name, m.Description = types.StringValue(v.ID), types.StringValue(v.Name), types.StringValue(v.Description)
	m.Version = types.Int64Value(v.Version)
	m.ConditionJSON = sameJSON(m.ConditionJSON, v.Condition)
}

func (r *birthrightRuleResource) put(ctx context.Context, plan *birthrightRuleModel, id string, d *diag.Diagnostics) {
	b := birthrightRuleBody{Name: plan.Name.ValueString(), Description: plan.Description.ValueString(),
		Condition: json.RawMessage(plan.ConditionJSON.ValueString()), Note: plan.Note.ValueString()}
	pth, what := "/proposals/birthright-rules", "create the birthright rule"
	if id != "" {
		b.Version = plan.Version.ValueInt64()
		pth, what = "/proposals/birthright-rules/"+url.PathEscape(id), "update the birthright rule"
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new birthright rule", "The change "+ch.ChangeID+" was applied but the server did not say which policy it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	v, err := r.read(ctx, id)
	if err != nil || v == nil {
		d.AddError("Cannot read the birthright rule back", fmt.Sprintf("change %s was applied; reading policy %s failed: %v", ch.ChangeID, id, err))
		return
	}
	plan.fromServer(v)
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *birthrightRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan birthrightRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *birthrightRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state birthrightRuleModel
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

func (r *birthrightRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state birthrightRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the birthright rule", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromServer(v)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *birthrightRuleResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The birthright rule")
}

func (r *birthrightRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// ---------------------------------------------------------------- tessera_mitigating_control

var (
	_ resource.Resource                = (*mitigatingControlResource)(nil)
	_ resource.ResourceWithConfigure   = (*mitigatingControlResource)(nil)
	_ resource.ResourceWithImportState = (*mitigatingControlResource)(nil)
)

// NewMitigatingControlResource is tessera_mitigating_control: a control of the SoD library that a mitigation can cite.
func NewMitigatingControlResource() resource.Resource { return &mitigatingControlResource{} }

type mitigatingControlResource struct{ proposer }

type mitigatingControlModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	OwnerIdentityID     types.Int64  `tfsdk:"owner_identity_id"`
	Type                types.String `tfsdk:"type"`
	Frequency           types.String `tfsdk:"frequency"`
	EvidenceRequirement types.String `tfsdk:"evidence_requirement"`
	Version             types.Int64  `tfsdk:"version"`
	ChangeID            types.String `tfsdk:"change_id"`
	ChangeURL           types.String `tfsdk:"change_url"`
}

func (r *mitigatingControlResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mitigating_control"
}

func (r *mitigatingControlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A mitigating control: an entry of the separation-of-duties control library (a review, a limit, a report) that a " +
			"person's SoD mitigation cites. " + proposalNote + "Controls are retired in the admin center, not by Terraform: destroy leaves the control on the server.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The control id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "A unique name.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 200), noEdgeSpace}},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"owner_identity_id": schema.Int64Attribute{Required: true, Description: "The identity accountable for the control (see `tessera_identities`).",
				Validators: []validator.Int64{int64validator.AtLeast(1)}},
			"type":      schema.StringAttribute{Required: true, Description: "`preventive`, `detective` or `corrective`.", Validators: []validator.String{oneOf("preventive", "detective", "corrective")}},
			"frequency": schema.StringAttribute{Required: true, Description: "`continuous`, `daily`, `weekly`, `monthly`, `quarterly` or `annually`.", Validators: []validator.String{oneOf("continuous", "daily", "weekly", "monthly", "quarterly", "annually")}},
			"evidence_requirement": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""),
				Description: "What the person who runs the control must keep as evidence."},
			"version": schema.Int64Attribute{Computed: true, Description: "The control's version on the server; an update is refused if it moved on."},
		}),
	}
}

func (r *mitigatingControlResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type mitigatingControlBody struct {
	Version             int64  `json:"version"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	OwnerID             int64  `json:"owner_id"`
	Type                string `json:"type"`
	Frequency           string `json:"frequency"`
	EvidenceRequirement string `json:"evidence_requirement"`
}

type mitigatingControlRead struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       *struct {
		ID int64 `json:"id"`
	} `json:"owner"`
	Type                string `json:"type"`
	Frequency           string `json:"frequency"`
	EvidenceRequirement string `json:"evidence_requirement"`
	Status              string `json:"status"`
	Version             int64  `json:"version"`
}

func (r *mitigatingControlResource) read(ctx context.Context, id string) (*mitigatingControlRead, error) {
	var v mitigatingControlRead
	if err := r.c.Do(ctx, "GET", "/sod/controls/"+url.PathEscape(id), nil, &v); err != nil {
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

func (m *mitigatingControlModel) fromServer(v *mitigatingControlRead) {
	m.ID, m.Name, m.Description = types.StringValue(v.ID), types.StringValue(v.Name), types.StringValue(v.Description)
	m.Type, m.Frequency, m.EvidenceRequirement = types.StringValue(v.Type), types.StringValue(v.Frequency), types.StringValue(v.EvidenceRequirement)
	m.Version = types.Int64Value(v.Version)
	if v.Owner != nil {
		m.OwnerIdentityID = types.Int64Value(v.Owner.ID)
	}
}

func (r *mitigatingControlResource) put(ctx context.Context, plan *mitigatingControlModel, id string, d *diag.Diagnostics) {
	b := mitigatingControlBody{Name: plan.Name.ValueString(), Description: plan.Description.ValueString(), OwnerID: plan.OwnerIdentityID.ValueInt64(),
		Type: plan.Type.ValueString(), Frequency: plan.Frequency.ValueString(), EvidenceRequirement: plan.EvidenceRequirement.ValueString()}
	pth, what := "/proposals/mitigating-controls", "create the mitigating control"
	if id != "" {
		b.Version = plan.Version.ValueInt64()
		pth, what = "/proposals/mitigating-controls/"+url.PathEscape(id), "update the mitigating control"
	}
	ch := r.propose(ctx, d, what, pth, b)
	if ch == nil {
		return
	}
	if id == "" {
		if ch.ResultID == nil || *ch.ResultID == "" {
			d.AddError("Cannot find the new mitigating control", "The change "+ch.ChangeID+" was applied but the server did not say which control it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	v, err := r.read(ctx, id)
	if err != nil || v == nil {
		d.AddError("Cannot read the mitigating control back", fmt.Sprintf("change %s was applied; reading control %s failed: %v", ch.ChangeID, id, err))
		return
	}
	plan.fromServer(v)
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *mitigatingControlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mitigatingControlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *mitigatingControlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state mitigatingControlModel
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

func (r *mitigatingControlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mitigatingControlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the mitigating control", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromServer(v)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *mitigatingControlResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The mitigating control")
}

func (r *mitigatingControlResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// ---------------------------------------------------------------- tessera_approval_policy

var (
	_ resource.Resource                = (*approvalPolicyResource)(nil)
	_ resource.ResourceWithConfigure   = (*approvalPolicyResource)(nil)
	_ resource.ResourceWithImportState = (*approvalPolicyResource)(nil)
)

// NewApprovalPolicyResource is tessera_approval_policy: an approval workflow and the catalog items and request types it routes.
func NewApprovalPolicyResource() resource.Resource { return &approvalPolicyResource{} }

type approvalPolicyResource struct{ proposer }

type approvalPolicyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Scope       types.String `tfsdk:"scope"`
	StepsJSON   types.String `tfsdk:"steps_json"`
	Targets     types.Set    `tfsdk:"targets"`
	Version     types.Int64  `tfsdk:"version"`
	ChangeID    types.String `tfsdk:"change_id"`
	ChangeURL   types.String `tfsdk:"change_url"`
}

var approvalTargetType = types.ObjectType{AttrTypes: map[string]attr.Type{"kind": types.StringType, "target_id": types.StringType}}

func (r *approvalPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_approval_policy"
}

func (r *approvalPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An approval policy: a versioned workflow (approval, questionnaire, notify, wait and condition steps) that routes " +
			"access requests, and the catalog items and request types it applies to. " + proposalNote +
			"Policies are retired in the admin center, not by Terraform: destroy leaves the policy on the server.",
		Attributes: commonAttrs(map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The workflow id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "A unique name, 1 to 80 characters.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 80), noEdgeSpace}},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"scope": schema.StringAttribute{Required: true, Description: "`access` (access requests) or `service_account`. It cannot change.",
				Validators:    []validator.String{oneOf("access", "service_account")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"steps_json": schema.StringAttribute{Required: true, Description: "The steps as a JSON array, for example " +
				"`jsonencode([{id = \"d\", type = \"approval\", approver = \"decider\"}])`. The server validates them (every path ends, groups and " +
				"questionnaires exist) before it asks anyone to approve.",
				Validators: []validator.String{jsonValidator{array: true}}},
			"targets": schema.SetNestedAttribute{Optional: true, Computed: true,
				Description:   "Where the policy applies. Leave it out to keep the assignments as they are; set it to `[]` to route nothing.",
				PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"kind":      schema.StringAttribute{Required: true, Description: "`catalog_item` or `request_type`.", Validators: []validator.String{oneOf("catalog_item", "request_type")}},
					"target_id": schema.StringAttribute{Required: true, Description: "The catalog item id, or the request type (`access`, `service_account_create`, ...)."},
				}}},
			"version": schema.Int64Attribute{Computed: true, Description: "The policy's version on the server; an update is refused if it moved on."},
		}),
	}
}

func (r *approvalPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

type approvalTarget struct {
	Kind     string `json:"kind" tfsdk:"kind"`
	TargetID string `json:"target_id" tfsdk:"target_id"`
}

type approvalPolicyBody struct {
	Version     int64             `json:"version"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Scope       string            `json:"scope,omitempty"`
	Steps       json.RawMessage   `json:"steps"`
	Targets     *[]approvalTarget `json:"targets,omitempty"`
}

type approvalPolicyRead struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Scope       string           `json:"scope"`
	Status      string           `json:"status"`
	Version     int64            `json:"version"`
	Steps       json.RawMessage  `json:"steps"`
	Targets     []approvalTarget `json:"targets"`
}

func (r *approvalPolicyResource) read(ctx context.Context, id string) (*approvalPolicyRead, error) {
	var v approvalPolicyRead
	if err := r.c.Do(ctx, "GET", "/workflows/"+url.PathEscape(id), nil, &v); err != nil {
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

// sameSteps is sameJSON for the steps: the server leaves out empty fields, which the user's JSON may spell out, so two
// documents are equal when the server's is what the user's reads as with empty values dropped.
func sameSteps(prior types.String, server json.RawMessage) types.String {
	srv, _ := jsonNormal(string(server))
	if known(prior) {
		if p, ok := jsonNormal(prior.ValueString()); ok {
			if p == srv {
				return prior
			}
			var a, b any
			if json.Unmarshal([]byte(p), &a) == nil && json.Unmarshal([]byte(srv), &b) == nil && reflect.DeepEqual(dropEmpty(a), dropEmpty(b)) {
				return prior
			}
		}
	}
	return types.StringValue(srv)
}

func dropEmpty(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			e = dropEmpty(e)
			if e == nil || e == "" || e == float64(0) {
				continue
			}
			out[k] = e
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = dropEmpty(e)
		}
		return out
	}
	return v
}

func (m *approvalPolicyModel) fromServer(v *approvalPolicyRead, d *diag.Diagnostics) {
	m.ID, m.Name, m.Description = types.StringValue(v.ID), types.StringValue(v.Name), types.StringValue(v.Description)
	m.Scope, m.Version = types.StringValue(v.Scope), types.Int64Value(v.Version)
	m.StepsJSON = sameSteps(m.StepsJSON, v.Steps)
	els := make([]attr.Value, 0, len(v.Targets))
	for _, t := range v.Targets {
		els = append(els, types.ObjectValueMust(approvalTargetType.AttrTypes, map[string]attr.Value{
			"kind": types.StringValue(t.Kind), "target_id": types.StringValue(t.TargetID)}))
	}
	set, dd := types.SetValue(approvalTargetType, els)
	d.Append(dd...)
	m.Targets = set
}

func (r *approvalPolicyResource) put(ctx context.Context, plan *approvalPolicyModel, id string, d *diag.Diagnostics) {
	b := approvalPolicyBody{Name: plan.Name.ValueString(), Description: plan.Description.ValueString(), Scope: plan.Scope.ValueString(),
		Steps: json.RawMessage(plan.StepsJSON.ValueString())}
	if known(plan.Targets) {
		ts := []approvalTarget{}
		d.Append(plan.Targets.ElementsAs(ctx, &ts, false)...)
		b.Targets = &ts
	}
	pth, what := "/proposals/approval-policies", "create the approval policy"
	if id != "" {
		b.Version = plan.Version.ValueInt64()
		pth, what = "/proposals/approval-policies/"+url.PathEscape(id), "update the approval policy"
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
			d.AddError("Cannot find the new approval policy", "The change "+ch.ChangeID+" was applied but the server did not say which workflow it made. See "+ch.URL)
			return
		}
		id = *ch.ResultID
	}
	v, err := r.read(ctx, id)
	if err != nil || v == nil {
		d.AddError("Cannot read the approval policy back", fmt.Sprintf("change %s was applied; reading workflow %s failed: %v", ch.ChangeID, id, err))
		return
	}
	plan.fromServer(v, d)
	setChange(&plan.ChangeID, &plan.ChangeURL, ch)
}

func (r *approvalPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan approvalPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &plan, "", &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *approvalPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state approvalPolicyModel
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

func (r *approvalPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state approvalPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the approval policy", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromServer(v, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *approvalPolicyResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.leftOnServer(&resp.Diagnostics, "The approval policy")
}

func (r *approvalPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
