package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nischalravi/tessera/mvp/terraform-provider-tessera/internal/client"
)

// The data sources read the same lists the admin center shows. A machine client needs `tessera:read`; the connectors list also needs
// the auditor role.

type dsBase struct{ c *client.Client }

func (d *dsBase) configure(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.c = c
}

func decodeAll[T any](items []json.RawMessage) ([]T, error) {
	out := make([]T, 0, len(items))
	for _, raw := range items {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ---------------------------------------------------------------- identities

// NewIdentitiesDataSource is tessera_identities (GET /api/v1/identities).
func NewIdentitiesDataSource() datasource.DataSource { return &identitiesDS{} }

type identitiesDS struct{ dsBase }

type identityRow struct {
	ID         types.Int64  `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	Type       types.String `tfsdk:"type"`
	Status     types.String `tfsdk:"status"`
	Email      types.String `tfsdk:"email"`
	Department types.String `tfsdk:"department"`
	Title      types.String `tfsdk:"title"`
}

type identitiesModel struct {
	Type       types.String  `tfsdk:"type"`
	Status     types.String  `tfsdk:"status"`
	Query      types.String  `tfsdk:"query"`
	Identities []identityRow `tfsdk:"identities"`
}

func (d *identitiesDS) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identities"
}

func (d *identitiesDS) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.configure(req, resp)
}

func (d *identitiesDS) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The tenant's identities (people, service accounts, agents). Use an `id` for `escalation_identity_id` of a `tessera_review_schedule`.",
		Attributes: map[string]schema.Attribute{
			"type":   schema.StringAttribute{Optional: true, Description: "Only this identity type, such as `human`.", Validators: nonEmptyString()},
			"status": schema.StringAttribute{Optional: true, Description: "Only this status, such as `active`.", Validators: nonEmptyString()},
			"query": schema.StringAttribute{Optional: true, Validators: nonEmptyString(),
				Description: "Match this text in the name, email, department or title (case-insensitive)."},
			"identities": schema.ListNestedAttribute{Computed: true, Description: "The matching identities, in the order the API returns them.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id": schema.Int64Attribute{Computed: true}, "name": schema.StringAttribute{Computed: true},
					"type": schema.StringAttribute{Computed: true}, "status": schema.StringAttribute{Computed: true},
					"email": schema.StringAttribute{Computed: true}, "department": schema.StringAttribute{Computed: true},
					"title": schema.StringAttribute{Computed: true},
				}}},
		},
	}
}

func (d *identitiesDS) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m identitiesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	q := url.Values{}
	for k, v := range map[string]types.String{"type": m.Type, "status": m.Status, "q": m.Query} {
		if known(v) {
			q.Set(k, v.ValueString())
		}
	}
	items, err := d.c.List(ctx, "/identities", q)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read identities", err.Error())
		return
	}
	type wire struct {
		ID         int64   `json:"id"`
		Name       string  `json:"name"`
		Type       string  `json:"type"`
		Status     string  `json:"status"`
		Email      *string `json:"email"`
		Department *string `json:"department"`
		Title      *string `json:"title"`
	}
	rows, err := decodeAll[wire](items)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read identities", err.Error())
		return
	}
	m.Identities = make([]identityRow, 0, len(rows))
	for _, w := range rows {
		m.Identities = append(m.Identities, identityRow{ID: types.Int64Value(w.ID), Name: types.StringValue(w.Name), Type: types.StringValue(w.Type),
			Status: types.StringValue(w.Status), Email: types.StringPointerValue(w.Email), Department: types.StringPointerValue(w.Department),
			Title: types.StringPointerValue(w.Title)})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------- entitlements

// NewEntitlementsDataSource is tessera_entitlements: the groups, roles and permission sets of the connected systems
// (GET /api/v1/groups).
func NewEntitlementsDataSource() datasource.DataSource { return &entitlementsDS{} }

type entitlementsDS struct{ dsBase }

type entitlementRow struct {
	ID          types.Int64  `tfsdk:"id"`
	Key         types.String `tfsdk:"key"`
	System      types.String `tfsdk:"system"`
	Name        types.String `tfsdk:"name"`
	Kind        types.String `tfsdk:"kind"`
	Privileged  types.Bool   `tfsdk:"privileged"`
	Requestable types.Bool   `tfsdk:"requestable"`
	Description types.String `tfsdk:"description"`
}

type entitlementsModel struct {
	System       types.String     `tfsdk:"system"`
	Requestable  types.Bool       `tfsdk:"requestable"`
	Entitlements []entitlementRow `tfsdk:"entitlements"`
}

func (d *entitlementsDS) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entitlements"
}

func (d *entitlementsDS) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.configure(req, resp)
}

func (d *entitlementsDS) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The entitlements (groups, roles, permission sets) found in the connected systems.",
		Attributes: map[string]schema.Attribute{
			"system":      schema.StringAttribute{Optional: true, Description: "Only this system, for example `aws`.", Validators: nonEmptyString()},
			"requestable": schema.BoolAttribute{Optional: true, Description: "Only entitlements that are (true) or are not (false) in the request catalog."},
			"entitlements": schema.ListNestedAttribute{Computed: true, Description: "The matching entitlements.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id": schema.Int64Attribute{Computed: true}, "key": schema.StringAttribute{Computed: true, Description: "`group:<id>`."},
					"system": schema.StringAttribute{Computed: true}, "name": schema.StringAttribute{Computed: true},
					"kind": schema.StringAttribute{Computed: true}, "privileged": schema.BoolAttribute{Computed: true},
					"requestable": schema.BoolAttribute{Computed: true}, "description": schema.StringAttribute{Computed: true},
				}}},
		},
	}
}

func (d *entitlementsDS) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m entitlementsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	q := url.Values{}
	if known(m.Requestable) {
		q.Set("requestable", fmt.Sprint(m.Requestable.ValueBool()))
	}
	items, err := d.c.List(ctx, "/groups", q)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read entitlements", err.Error())
		return
	}
	type wire struct {
		ID          int64   `json:"id"`
		Key         string  `json:"key"`
		System      string  `json:"system"`
		Name        string  `json:"name"`
		Kind        string  `json:"kind"`
		Privileged  bool    `json:"privileged"`
		Requestable bool    `json:"requestable"`
		Description *string `json:"description"`
	}
	rows, err := decodeAll[wire](items)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read entitlements", err.Error())
		return
	}
	m.Entitlements = make([]entitlementRow, 0, len(rows))
	for _, w := range rows {
		if known(m.System) && !strings.EqualFold(w.System, m.System.ValueString()) {
			continue
		}
		m.Entitlements = append(m.Entitlements, entitlementRow{ID: types.Int64Value(w.ID), Key: types.StringValue(w.Key), System: types.StringValue(w.System),
			Name: types.StringValue(w.Name), Kind: types.StringValue(w.Kind), Privileged: types.BoolValue(w.Privileged),
			Requestable: types.BoolValue(w.Requestable), Description: types.StringPointerValue(w.Description)})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------- connectors

// NewConnectorsDataSource is tessera_connectors (GET /api/v1/connections).
func NewConnectorsDataSource() datasource.DataSource { return &connectorsDS{} }

type connectorsDS struct{ dsBase }

type connectorRow struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	ConnectorType types.String `tfsdk:"connector_type"`
	System        types.String `tfsdk:"system"`
	Role          types.String `tfsdk:"role"`
	State         types.String `tfsdk:"state"`
	Health        types.String `tfsdk:"health"`
	Simulated     types.Bool   `tfsdk:"simulated"`
}

type connectorsModel struct {
	System     types.String   `tfsdk:"system"`
	State      types.String   `tfsdk:"state"`
	Connectors []connectorRow `tfsdk:"connectors"`
}

func (d *connectorsDS) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connectors"
}

func (d *connectorsDS) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.configure(req, resp)
}

func (d *connectorsDS) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The tenant's connectors (connections to source and target systems). Their settings and credentials are never returned. " +
			"The machine client needs the auditor role as well as `tessera:read`.",
		Attributes: map[string]schema.Attribute{
			"system": schema.StringAttribute{Optional: true, Description: "Only connectors of this system.", Validators: nonEmptyString()},
			"state":  schema.StringAttribute{Optional: true, Description: "Only connectors in this lifecycle state, such as `active`.", Validators: nonEmptyString()},
			"connectors": schema.ListNestedAttribute{Computed: true, Description: "The matching connectors.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{Computed: true}, "name": schema.StringAttribute{Computed: true},
					"connector_type": schema.StringAttribute{Computed: true}, "system": schema.StringAttribute{Computed: true},
					"role":  schema.StringAttribute{Computed: true, Description: "For example `account_source`."},
					"state": schema.StringAttribute{Computed: true}, "health": schema.StringAttribute{Computed: true},
					"simulated": schema.BoolAttribute{Computed: true},
				}}},
		},
	}
}

func (d *connectorsDS) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m connectorsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := d.c.List(ctx, "/connections", url.Values{})
	if err != nil {
		resp.Diagnostics.AddError("Cannot read connectors", err.Error())
		return
	}
	type wire struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		ConnectorType string `json:"connector_type"`
		System        string `json:"system"`
		Role          string `json:"role"`
		State         string `json:"state"`
		Health        string `json:"health"`
		Simulated     bool   `json:"simulated"`
	}
	rows, err := decodeAll[wire](items)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read connectors", err.Error())
		return
	}
	m.Connectors = make([]connectorRow, 0, len(rows))
	for _, w := range rows {
		if (known(m.System) && !strings.EqualFold(w.System, m.System.ValueString())) || (known(m.State) && w.State != m.State.ValueString()) {
			continue
		}
		m.Connectors = append(m.Connectors, connectorRow{ID: types.StringValue(w.ID), Name: types.StringValue(w.Name),
			ConnectorType: types.StringValue(w.ConnectorType), System: types.StringValue(w.System), Role: types.StringValue(w.Role),
			State: types.StringValue(w.State), Health: types.StringValue(w.Health), Simulated: types.BoolValue(w.Simulated)})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
