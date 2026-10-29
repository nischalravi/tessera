package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/client"
)

var (
	_ resource.Resource                   = (*reviewScheduleResource)(nil)
	_ resource.ResourceWithConfigure      = (*reviewScheduleResource)(nil)
	_ resource.ResourceWithImportState    = (*reviewScheduleResource)(nil)
	_ resource.ResourceWithValidateConfig = (*reviewScheduleResource)(nil)
)

// NewReviewScheduleResource is tessera_review_schedule: a scheduled access review template
// (/api/v1/reviews/schedules, the "review templates" of the provider issue).
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var noEdgeSpace = stringvalidator.RegexMatches(regexp.MustCompile(`^(?s)\S(.*\S)?$`), "must not start or end with whitespace")

func NewReviewScheduleResource() resource.Resource { return &reviewScheduleResource{} }

type reviewScheduleResource struct{ c *client.Client }

type reviewScheduleModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	System               types.String `tfsdk:"system"`
	PrivilegedOnly       types.Bool   `tfsdk:"privileged_only"`
	UnusedDays           types.Int64  `tfsdk:"unused_days"`
	DurationDays         types.Int64  `tfsdk:"duration_days"`
	ReminderDays         types.Int64  `tfsdk:"reminder_days"`
	CloseOut             types.String `tfsdk:"close_out"`
	EscalationIdentityID types.Int64  `tfsdk:"escalation_identity_id"`
	EscalationDays       types.Int64  `tfsdk:"escalation_days"`
	Recurrence           types.String `tfsdk:"recurrence"`
	FirstRunAt           types.String `tfsdk:"first_run_at"`
	NextRunAt            types.String `tfsdk:"next_run_at"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	RoleIDs              types.Set    `tfsdk:"role_ids"`
	ReviewType           types.String `tfsdk:"review_type"`
}

// scheduleWire is the API's request body; the answer is read into scheduleView.
type scheduleWire struct {
	Name                 string   `json:"name"`
	System               *string  `json:"system"`
	PrivilegedOnly       bool     `json:"privileged_only"`
	UnusedDays           int64    `json:"unused_days"`
	DurationDays         int64    `json:"duration_days"`
	ReminderDays         int64    `json:"reminder_days"`
	CloseOut             string   `json:"close_out"`
	EscalationIdentityID *int64   `json:"escalation_identity_id"`
	EscalationDays       int64    `json:"escalation_days"`
	Recurrence           string   `json:"recurrence"`
	FirstRunAt           *string  `json:"first_run_at,omitempty"`
	Enabled              bool     `json:"enabled"`
	RoleIDs              []string `json:"role_ids"`
	ReviewType           string   `json:"review_type"`
}

type scheduleView struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	System             *string `json:"system"`
	PrivilegedOnly     bool    `json:"privileged_only"`
	UnusedDays         int64   `json:"unused_days"`
	DurationDays       int64   `json:"duration_days"`
	ReminderDays       int64   `json:"reminder_days"`
	CloseOut           string  `json:"close_out"`
	EscalationReviewer *struct {
		ID int64 `json:"id"`
	} `json:"escalation_reviewer"`
	EscalationDays int64    `json:"escalation_days"`
	Recurrence     string   `json:"recurrence"`
	NextRunAt      *string  `json:"next_run_at"`
	Enabled        bool     `json:"enabled"`
	RoleIDs        []string `json:"role_ids"`
	ReviewType     *string  `json:"review_type"`
}

func (r *reviewScheduleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_review_schedule"
}

type rfc3339Validator struct{}

func (rfc3339Validator) Description(context.Context) string {
	return "an RFC 3339 timestamp, for example 2027-01-01T00:00:00Z"
}
func (v rfc3339Validator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (rfc3339Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := time.Parse(time.RFC3339, req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid timestamp", "Use an RFC 3339 timestamp, for example 2027-01-01T00:00:00Z.")
	}
}

func (r *reviewScheduleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A scheduled access review (a review template): which grants are certified, how long reviewers have, what happens " +
			"to undecided items, and when it runs. Needs the operator role with the `tessera:write` scope. The API has no delete route, " +
			"so destroying the resource disables the schedule (it stops launching reviews and keeps its history) and removes it from state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The schedule id (a UUID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "1 to 200 characters.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 200), noEdgeSpace}},
			"system": schema.StringAttribute{Optional: true,
				Description: "Review only this connected system's access (as named in the `system` of `tessera_connectors`). Unset: all systems. " +
					"The server refuses a name that is not one of the tenant's systems.",
				Validators: []validator.String{stringvalidator.LengthBetween(1, 200), noEdgeSpace}},
			"privileged_only": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Certify privileged access only."},
			"unused_days": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(60),
				Description: "Include access unused for this many days (1 to 365). Default 60.",
				Validators:  []validator.Int64{int64validator.Between(1, 365)}},
			"duration_days": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(14),
				Description: "Days reviewers have (1 to 90). Default 14.",
				Validators:  []validator.Int64{int64validator.Between(1, 90)}},
			"reminder_days": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(3),
				Description: "Days before the due date reviewers are reminded (0 up to `duration_days` minus 1). Default 3.",
				Validators:  []validator.Int64{int64validator.Between(0, 89)}},
			"close_out": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("revoke"),
				Description: "What happens to undecided items at the due date: `revoke` or `escalate` (needs `escalation_identity_id`). Default `revoke`.",
				Validators:  []validator.String{oneOf("revoke", "escalate")}},
			"escalation_identity_id": schema.Int64Attribute{Optional: true,
				Description: "The id of the active person who decides escalated items (an id from `tessera_identities`).",
				Validators:  []validator.Int64{int64validator.AtLeast(1)}},
			"escalation_days": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(7),
				Description: "Days the escalation reviewer has (1 to 30). Default 7.",
				Validators:  []validator.Int64{int64validator.Between(1, 30)}},
			"recurrence": schema.StringAttribute{Required: true, Description: "`once`, `quarterly`, `semiannual` or `annual`.",
				Validators: []validator.String{oneOf("once", "quarterly", "semiannual", "annual")}},
			"first_run_at": schema.StringAttribute{Optional: true,
				Description: "RFC 3339 time of the first run. Required to enable a new schedule. It is sent on create and whenever you change it; " +
					"the server then moves the run forward on its own, see `next_run_at`. Not read back, and null after an import.",
				Validators: []validator.String{rfc3339Validator{}}},
			"next_run_at": schema.StringAttribute{Computed: true, Description: "When the schedule runs next (null once a `once` schedule has run or while disabled)."},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "A disabled schedule launches nothing. Default true."},
			"role_ids": schema.SetAttribute{Optional: true, Computed: true, ElementType: types.StringType,
				Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				Description: "Scope the review to the memberships of these business roles. Empty: not scoped by role."},
			"review_type": schema.StringAttribute{Optional: true,
				Description: "Run the schedule as this review type, whose reviewers and close-out settings then apply. Unset: none."},
		},
	}
}

func (r *reviewScheduleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.c = c
}

// ValidateConfig checks what the server would refuse, without calling it.
func (r *reviewScheduleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m reviewScheduleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// reminder_days and duration_days default to 3 and 14 when unset
	if reminderOK, durationOK := known(m.ReminderDays) || m.ReminderDays.IsNull(), known(m.DurationDays) || m.DurationDays.IsNull(); reminderOK && durationOK {
		reminder, duration := int64(3), int64(14)
		if known(m.ReminderDays) {
			reminder = m.ReminderDays.ValueInt64()
		}
		if known(m.DurationDays) {
			duration = m.DurationDays.ValueInt64()
		}
		if reminder >= duration {
			resp.Diagnostics.AddAttributeError(path.Root("reminder_days"), "Invalid reminder_days",
				fmt.Sprintf("reminder_days (%d) must be less than duration_days (%d).", reminder, duration))
		}
	}
	if known(m.CloseOut) && m.CloseOut.ValueString() == "escalate" && m.EscalationIdentityID.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("escalation_identity_id"), "Missing escalation reviewer",
			"close_out = \"escalate\" needs escalation_identity_id.")
	}
}

type knownValue interface {
	IsNull() bool
	IsUnknown() bool
}

func known(v knownValue) bool { return !v.IsNull() && !v.IsUnknown() }

func (m *reviewScheduleModel) wire(ctx context.Context, includeFirstRun bool) (scheduleWire, diag.Diagnostics) {
	var diags diag.Diagnostics
	w := scheduleWire{Name: m.Name.ValueString(), PrivilegedOnly: m.PrivilegedOnly.ValueBool(), UnusedDays: m.UnusedDays.ValueInt64(),
		DurationDays: m.DurationDays.ValueInt64(), ReminderDays: m.ReminderDays.ValueInt64(), CloseOut: m.CloseOut.ValueString(),
		EscalationDays: m.EscalationDays.ValueInt64(), Recurrence: m.Recurrence.ValueString(), Enabled: m.Enabled.ValueBool(),
		ReviewType: m.ReviewType.ValueString(), RoleIDs: []string{}}
	if known(m.System) {
		s := m.System.ValueString()
		w.System = &s
	}
	if known(m.EscalationIdentityID) {
		i := m.EscalationIdentityID.ValueInt64()
		w.EscalationIdentityID = &i
	}
	if includeFirstRun && known(m.FirstRunAt) {
		s := m.FirstRunAt.ValueString()
		w.FirstRunAt = &s
	}
	if known(m.RoleIDs) {
		diags.Append(m.RoleIDs.ElementsAs(ctx, &w.RoleIDs, false)...)
	}
	return w, diags
}

// apply copies the server's answer into the model. first_run_at is configuration, not state of the server, and is left alone.
func (m *reviewScheduleModel) apply(v *scheduleView) {
	m.ID, m.Name = types.StringValue(v.ID), types.StringValue(v.Name)
	m.System = types.StringPointerValue(v.System)
	m.PrivilegedOnly = types.BoolValue(v.PrivilegedOnly)
	m.UnusedDays, m.DurationDays, m.ReminderDays = types.Int64Value(v.UnusedDays), types.Int64Value(v.DurationDays), types.Int64Value(v.ReminderDays)
	m.CloseOut, m.EscalationDays, m.Recurrence = types.StringValue(v.CloseOut), types.Int64Value(v.EscalationDays), types.StringValue(v.Recurrence)
	m.EscalationIdentityID = types.Int64Null()
	if v.EscalationReviewer != nil {
		m.EscalationIdentityID = types.Int64Value(v.EscalationReviewer.ID)
	}
	m.NextRunAt = types.StringPointerValue(v.NextRunAt)
	m.Enabled = types.BoolValue(v.Enabled)
	elems := make([]attr.Value, 0, len(v.RoleIDs))
	for _, id := range v.RoleIDs {
		elems = append(elems, types.StringValue(id))
	}
	m.RoleIDs = types.SetValueMust(types.StringType, elems)
	m.ReviewType = types.StringPointerValue(v.ReviewType)
	if m.FirstRunAt.IsUnknown() {
		m.FirstRunAt = types.StringNull()
	}
}

func (r *reviewScheduleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan reviewScheduleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, d := plan.wire(ctx, true)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out scheduleView
	if err := r.c.Do(ctx, http.MethodPost, "/reviews/schedules", body, &out); err != nil {
		resp.Diagnostics.AddError("Cannot create the review schedule", err.Error())
		return
	}
	plan.apply(&out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// find reads the schedule from the list: there is no route that reads one.
func (r *reviewScheduleResource) find(ctx context.Context, id string) (*scheduleView, error) {
	items, err := r.c.List(ctx, "/reviews/schedules", url.Values{})
	if err != nil {
		return nil, err
	}
	for _, raw := range items {
		var v scheduleView
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		if v.ID == id {
			return &v, nil
		}
	}
	return nil, nil
}

func (r *reviewScheduleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state reviewScheduleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.find(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the review schedule", err.Error())
		return
	}
	if v == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.apply(v)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *reviewScheduleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state reviewScheduleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// the server keeps the current next run unless one is given, so only a changed first_run_at is sent
	body, d := plan.wire(ctx, !plan.FirstRunAt.Equal(state.FirstRunAt))
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out scheduleView
	if err := r.c.Do(ctx, http.MethodPut, "/reviews/schedules/"+url.PathEscape(state.ID.ValueString()), body, &out); err != nil {
		resp.Diagnostics.AddError("Cannot update the review schedule", err.Error())
		return
	}
	plan.apply(&out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete disables the schedule: the API has no delete route (a schedule keeps its launch history).
func (r *reviewScheduleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state reviewScheduleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Enabled = types.BoolValue(false)
	body, d := state.wire(ctx, false)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out scheduleView
	err := r.c.Do(ctx, http.MethodPut, "/reviews/schedules/"+url.PathEscape(state.ID.ValueString()), body, &out)
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Cannot disable the review schedule", err.Error())
	}
}

func (r *reviewScheduleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !uuidRE.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import id", "The import id is the schedule's id (a UUID), as listed by GET /api/v1/reviews/schedules.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
