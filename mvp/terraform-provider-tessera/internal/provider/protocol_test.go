package provider

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// protocol drives the provider through the Terraform plugin protocol (what `terraform plan` and `apply` do), in process and
// without the terraform binary: it builds the configuration and prior state values, asks for a plan, applies it, and reads back.

type protocol struct {
	t      *testing.T
	srv    tfprotov6.ProviderServer
	schema *tfprotov6.GetProviderSchemaResponse
}

func newProtocol(t *testing.T) *protocol {
	t.Helper()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatal(err)
	}
	sch, err := srv.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	mustNoDiags(t, sch.Diagnostics)
	return &protocol{t: t, srv: srv, schema: sch}
}

func mustNoDiags(t *testing.T, ds []*tfprotov6.Diagnostic) {
	t.Helper()
	for _, d := range ds {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("unexpected error diagnostic: %s: %s", d.Summary, d.Detail)
		}
	}
}

func diagText(ds []*tfprotov6.Diagnostic) string {
	var b strings.Builder
	for _, d := range ds {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			b.WriteString(d.Summary + ": " + d.Detail + "\n")
		}
	}
	return b.String()
}

// objectType returns the value type of a schema.
func objectType(s *tfprotov6.Schema) tftypes.Object { return s.ValueType().(tftypes.Object) }

// object builds a value of typ from vals; an attribute not in vals is null. Values are Go bool, string, int, []string (a set of
// strings), nil, or a ready tftypes.Value.
func object(t *testing.T, typ tftypes.Object, vals map[string]any) tftypes.Value {
	t.Helper()
	m := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		v, ok := vals[name]
		if !ok || v == nil {
			m[name] = tftypes.NewValue(at, nil)
			continue
		}
		switch x := v.(type) {
		case tftypes.Value:
			m[name] = x
		case int:
			m[name] = tftypes.NewValue(at, big.NewFloat(float64(x)))
		case []string:
			els := make([]tftypes.Value, len(x))
			for i, s := range x {
				els[i] = tftypes.NewValue(tftypes.String, s)
			}
			m[name] = tftypes.NewValue(at, els)
		default:
			m[name] = tftypes.NewValue(at, x)
		}
	}
	for name := range vals {
		if _, ok := typ.AttributeTypes[name]; !ok {
			t.Fatalf("the schema has no attribute %q", name)
		}
	}
	return tftypes.NewValue(typ, m)
}

func (p *protocol) dv(typ tftypes.Type, v tftypes.Value) *tfprotov6.DynamicValue {
	p.t.Helper()
	d, err := tfprotov6.NewDynamicValue(typ, v)
	if err != nil {
		p.t.Fatal(err)
	}
	return &d
}

func (p *protocol) configure(vals map[string]any) []*tfprotov6.Diagnostic {
	p.t.Helper()
	typ := objectType(p.schema.Provider)
	resp, err := p.srv.ConfigureProvider(context.Background(), &tfprotov6.ConfigureProviderRequest{
		TerraformVersion: "1.13.0", Config: p.dv(typ, object(p.t, typ, vals))})
	if err != nil {
		p.t.Fatal(err)
	}
	return resp.Diagnostics
}

func (p *protocol) resourceType(name string) tftypes.Object {
	s, ok := p.schema.ResourceSchemas[name]
	if !ok {
		p.t.Fatalf("no resource %s", name)
	}
	return objectType(s)
}

func (p *protocol) validate(name string, vals map[string]any) []*tfprotov6.Diagnostic {
	p.t.Helper()
	typ := p.resourceType(name)
	resp, err := p.srv.ValidateResourceConfig(context.Background(), &tfprotov6.ValidateResourceConfigRequest{
		TypeName: name, Config: p.dv(typ, object(p.t, typ, vals))})
	if err != nil {
		p.t.Fatal(err)
	}
	return resp.Diagnostics
}

// proposed is what Terraform core hands to PlanResourceChange: the configuration, with an unset computed attribute taking its prior value.
func (p *protocol) proposed(name string, config, prior tftypes.Value) tftypes.Value {
	typ := p.resourceType(name)
	var cm, pm map[string]tftypes.Value
	_ = config.As(&cm)
	if !prior.IsNull() {
		_ = prior.As(&pm)
	}
	out := map[string]tftypes.Value{}
	for _, a := range p.schema.ResourceSchemas[name].Block.Attributes {
		v := cm[a.Name]
		if v.IsNull() && a.Computed {
			if pv, ok := pm[a.Name]; ok {
				v = pv
			}
		}
		out[a.Name] = v
	}
	return tftypes.NewValue(typ, out)
}

// apply plans and applies config over prior (a null value to create) and returns the new state. A refused plan or apply returns its
// diagnostics and a null state.
func (p *protocol) apply(name string, vals map[string]any, prior tftypes.Value) (tftypes.Value, []*tfprotov6.Diagnostic) {
	p.t.Helper()
	ctx := context.Background()
	typ := p.resourceType(name)
	config := object(p.t, typ, vals)
	plan, err := p.srv.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{TypeName: name,
		PriorState: p.dv(typ, prior), ProposedNewState: p.dv(typ, p.proposed(name, config, prior)), Config: p.dv(typ, config)})
	if err != nil {
		p.t.Fatal(err)
	}
	if len(plan.Diagnostics) > 0 {
		return tftypes.NewValue(typ, nil), plan.Diagnostics
	}
	res, err := p.srv.ApplyResourceChange(ctx, &tfprotov6.ApplyResourceChangeRequest{TypeName: name,
		PriorState: p.dv(typ, prior), PlannedState: plan.PlannedState, Config: p.dv(typ, config)})
	if err != nil {
		p.t.Fatal(err)
	}
	if len(res.Diagnostics) > 0 {
		return tftypes.NewValue(typ, nil), res.Diagnostics
	}
	st, err := res.NewState.Unmarshal(typ)
	if err != nil {
		p.t.Fatal(err)
	}
	return st, nil
}

func (p *protocol) read(name string, state tftypes.Value) (tftypes.Value, []*tfprotov6.Diagnostic) {
	p.t.Helper()
	typ := p.resourceType(name)
	res, err := p.srv.ReadResource(context.Background(), &tfprotov6.ReadResourceRequest{TypeName: name, CurrentState: p.dv(typ, state)})
	if err != nil {
		p.t.Fatal(err)
	}
	if len(res.Diagnostics) > 0 {
		return state, res.Diagnostics
	}
	st, err := res.NewState.Unmarshal(typ)
	if err != nil {
		p.t.Fatal(err)
	}
	return st, nil
}

func (p *protocol) importState(name, id string) (tftypes.Value, []*tfprotov6.Diagnostic) {
	p.t.Helper()
	res, err := p.srv.ImportResourceState(context.Background(), &tfprotov6.ImportResourceStateRequest{TypeName: name, ID: id})
	if err != nil {
		p.t.Fatal(err)
	}
	if len(res.Diagnostics) > 0 {
		return tftypes.Value{}, res.Diagnostics
	}
	if len(res.ImportedResources) != 1 {
		p.t.Fatalf("import returned %d resources", len(res.ImportedResources))
	}
	typ := p.resourceType(name)
	st, err := res.ImportedResources[0].State.Unmarshal(typ)
	if err != nil {
		p.t.Fatal(err)
	}
	return st, nil
}

func (p *protocol) destroy(name string, state tftypes.Value) []*tfprotov6.Diagnostic {
	p.t.Helper()
	typ := p.resourceType(name)
	null := tftypes.NewValue(typ, nil)
	res, err := p.srv.ApplyResourceChange(context.Background(), &tfprotov6.ApplyResourceChangeRequest{TypeName: name,
		PriorState: p.dv(typ, state), PlannedState: p.dv(typ, null), Config: p.dv(typ, null)})
	if err != nil {
		p.t.Fatal(err)
	}
	return res.Diagnostics
}

func (p *protocol) readData(name string, vals map[string]any) (map[string]tftypes.Value, []*tfprotov6.Diagnostic) {
	p.t.Helper()
	s, ok := p.schema.DataSourceSchemas[name]
	if !ok {
		p.t.Fatalf("no data source %s", name)
	}
	typ := objectType(s)
	res, err := p.srv.ReadDataSource(context.Background(), &tfprotov6.ReadDataSourceRequest{TypeName: name, Config: p.dv(typ, object(p.t, typ, vals))})
	if err != nil {
		p.t.Fatal(err)
	}
	if len(res.Diagnostics) > 0 {
		return nil, res.Diagnostics
	}
	st, err := res.State.Unmarshal(typ)
	if err != nil {
		p.t.Fatal(err)
	}
	var m map[string]tftypes.Value
	if err := st.As(&m); err != nil {
		p.t.Fatal(err)
	}
	return m, nil
}

// attrs flattens an object value for assertions.
func attrs(t *testing.T, v tftypes.Value) map[string]tftypes.Value {
	t.Helper()
	var m map[string]tftypes.Value
	if err := v.As(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func str(t *testing.T, v tftypes.Value) string {
	t.Helper()
	if v.IsNull() {
		return "<null>"
	}
	var s string
	if err := v.As(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func num(t *testing.T, v tftypes.Value) int64 {
	t.Helper()
	var f big.Float
	if err := v.As(&f); err != nil {
		t.Fatal(err)
	}
	i, _ := f.Int64()
	return i
}
