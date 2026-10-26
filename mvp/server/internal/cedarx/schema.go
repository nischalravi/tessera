package cedarx

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
)

// Facts is what the schema generator reads from a tenant's graph: only the
// names that vary per tenant, never values or identities.
type Facts struct {
	// IdentityAttrs are the keys of the identity attributes (abac.Attrs) in the
	// tenant, each readable as a String under principal.attrs.
	IdentityAttrs []string
}

// Schema is a parsed and resolved Cedar schema.
type Schema struct {
	resolved *resolved.Schema
	text     []byte
}

// Text is the schema in Cedar's human-readable format, canonical as generated.
func (s *Schema) Text() []byte { return append([]byte(nil), s.text...) }

// ParseSchema parses and resolves a schema in the human-readable format,
// subject to the limits.
func ParseSchema(name string, src []byte) (*Schema, error) {
	if err := Check(src, true); err != nil {
		return nil, err
	}
	var s schema.Schema
	s.SetFilename(name)
	if err := s.UnmarshalCedar(src); err != nil {
		return nil, errf(CodeSchema, 0, "%v", err)
	}
	r, err := s.Resolve()
	if err != nil {
		return nil, errf(CodeSchema, 0, "%v", err)
	}
	return &Schema{resolved: r, text: append([]byte(nil), src...)}, nil
}

// Generate builds the tenant's schema (design §3, schema/tessera.cedarschema)
// from the facts of its graph. The output depends only on the set of attribute
// names, so equal facts give equal bytes.
func Generate(f Facts) (*Schema, error) {
	attrs, err := attrNames(f.IdentityAttrs)
	if err != nil {
		return nil, err
	}
	var rec strings.Builder
	for i, a := range attrs {
		if i > 0 {
			rec.WriteString(",\n")
		}
		fmt.Fprintf(&rec, "    %s?: String", a)
	}
	text := strings.ReplaceAll(tesseraSchema, "@SHAPE@", identityShape)
	return ParseSchema("tessera.cedarschema", []byte(strings.ReplaceAll(text, "@ATTRS@", rec.String())))
}

// attrNames returns the sorted, deduplicated names, refusing one that is not a
// plain identifier (it would be spliced into the schema text).
func attrNames(in []string) ([]string, error) {
	if len(in) > MaxEntities {
		return nil, errf(CodeTooComplex, 0, "%d identity attributes; at most %d", len(in), MaxEntities)
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range in {
		if !ident(a) {
			return nil, errf(CodeSchema, 0, "identity attribute %q is not a valid Cedar identifier", a)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, nil
}

// identityShape is the attributes every principal has. Design §3 gives an Agent
// only source, kind and blueprint, but `reach` and `exist` apply to
// [Identity, Agent] and an invariant such as principal.type == "ai_agent" must
// type-check for both, so an Agent carries the identity attributes too (it is a
// view of an ai_agent Identity). One text is spliced into both entity types.
const identityShape = `
    type: String,
    status: String,
    department?: String,
    title?: String,
    location?: String,
    attrs: {
@ATTRS@
    },
    owner?: Identity,
    sponsor?: Identity,
    mfa_strength?: String,
    created_days: Long
  `

// tesseraSchema is design §3 in the syntax cedar-go reads. '@ATTRS@' is the open
// record of identity attributes, one optional String per attribute name.
const tesseraSchema = `namespace Tessera {
  entity Identity in [Group] = {@SHAPE@};
  entity Group = { system: String, name: String, privileged: Bool, requestable: Bool };
  entity Resource = { system: String, environment?: String, tags: Set<String>, privileged: Bool };
  entity Credential = { kind: String, age_days: Long, holder: Identity };
  entity Agent in [Group] = {@SHAPE@,
    source: String, kind: String, blueprint?: String
  };

  entity Role = {
    key: String, name: String, risk: String, requestable: Bool,
    owner?: Identity, entitlements: Set<Group>
  };
  entity JitEligibility = {
    key: String, principals: Set<Group>, entitlements: Set<Group>,
    max_hours: Long, approvers: Set<Group>, min_approvals: Long, step_up: Bool
  };
  entity SodFunction = { key: String, selectors: Set<{ system: String, permission: String }> };
  entity SodRisk = { key: String, priority: String, functions: Set<SodFunction>, ruleset: SodRuleset };
  entity SodRuleset = { key: String, enabled: Bool };

  action birthright appliesTo { principal: Identity, resource: Role };
  action jit_request appliesTo {
    principal: Identity, resource: Group,
    context: { hours: Long, eligibility: JitEligibility }
  };
  action reach appliesTo {
    principal: [Identity, Agent], resource: Resource,
    context: {
      action: String, action_class: String, system: String,
      standing: Bool, via_jit: Bool, via_role?: Role, fidelity: String
    }
  };
  action exist appliesTo { principal: [Identity, Agent], resource: Resource };
  action hold_credential appliesTo { principal: Identity, resource: Credential };
}
`

// GroupAttr is one identity attribute a policy group file may use (groups design
// §8.4), mirroring policygroups.AttrDef without importing it.
type GroupAttr struct {
	Name     string
	Set      bool // a Set<String>; otherwise a String
	Required bool
}

// GroupsSchema generates the Cedar schema of the policy groups fragment: an
// Identity with the given attributes, a Group, and the member action. The
// groups fragment parser is checked against cedar-go with it.
func GroupsSchema(attrs []GroupAttr) (*Schema, error) {
	sorted := append([]GroupAttr(nil), attrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for i, a := range sorted {
		if !ident(a.Name) {
			return nil, errf(CodeSchema, 0, "attribute %q is not a valid Cedar identifier", a.Name)
		}
		if i > 0 && sorted[i-1].Name == a.Name {
			return nil, errf(CodeSchema, 0, "attribute %q is given twice", a.Name)
		}
		typ := "String"
		if a.Set {
			typ = "Set<String>"
		}
		opt := "?"
		if a.Required {
			opt = ""
		}
		fmt.Fprintf(&b, "    %s%s: %s,\n", a.Name, opt, typ)
	}
	src := "namespace Tessera {\n  entity Identity in [Group] = {\n" + strings.TrimSuffix(b.String(), ",\n") +
		"\n  };\n  entity Group;\n  action member appliesTo { principal: Identity, resource: Group };\n}\n"
	return ParseSchema("groups.cedarschema", []byte(src))
}
