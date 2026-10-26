package cedarx

import (
	"strings"
	"testing"
)

func TestParseUID(t *testing.T) {
	cases := []struct {
		in      string
		want    UID
		wantErr bool
	}{
		{`Tessera::Identity::"alice"`, UID{"Tessera::Identity", "alice"}, false},
		{`Tessera::Group::"okta:sre"`, UID{"Tessera::Group", "okta:sre"}, false},
		{`alice`, UID{}, true},
		{`::"x"`, UID{}, true},
		{`Tessera::Identity::alice`, UID{}, true},
		{strings.Repeat("a", 2000), UID{}, true},
	}
	for _, c := range cases {
		got, err := ParseUID(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("ParseUID(%q) = %v, %v", c.in, got, err)
		}
		if err == nil && got.String() != c.in {
			t.Errorf("String() = %s, want %s", got, c.in)
		}
	}
}

func TestDecide(t *testing.T) {
	ents, err := ParseEntities([]byte(`[{"uid":{"type":"Tessera::Identity","id":"a"},"parents":[],"attrs":{"type":"human"}}]`))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := ParsePolicies("p", []byte(`@id("permit-human") permit (principal, action, resource) when { principal.type == "human" };
@id("no-exist") forbid (principal, action == Tessera::Action::"exist", resource);`))
	if err != nil {
		t.Fatal(err)
	}
	req := func(action string, ctx string) Request {
		return Request{Principal: UID{"Tessera::Identity", "a"}, Action: UID{"Tessera::Action", action}, Resource: UID{"Tessera::Resource", "r"}, Context: []byte(ctx)}
	}
	cases := []struct {
		name   string
		req    Request
		allow  bool
		reason string
	}{
		{"permit", req("reach", ""), true, "permit-human"},
		{"forbid wins", req("exist", `{}`), false, "no-exist"},
	}
	for _, c := range cases {
		d, err := Decide(ents, c.req, ps)
		if err != nil || d.Allow != c.allow || len(d.Reasons) != 1 || d.Reasons[0].ID != c.reason {
			t.Errorf("%s: %+v, %v", c.name, d, err)
		}
	}
	if d, _ := Decide(nil, req("reach", ""), ps); d.Allow || len(d.Errors) == 0 {
		t.Errorf("missing principal entity: %+v", d)
	}
	if _, err := Decide(ents, req("reach", `{`), ps); code(err) != CodeSyntax {
		t.Errorf("bad context: %v", err)
	}
	if v, ok := ps.Annotation("policy1", "id"); !ok || v != "no-exist" || ps.Effect("policy1") != "forbid" || ps.Line("policy1") != 2 {
		t.Errorf("annotation %q %v effect %s line %d", v, ok, ps.Effect("policy1"), ps.Line("policy1"))
	}
}

func TestParseEntitiesLimits(t *testing.T) {
	if _, err := ParseEntities([]byte(`{`)); code(err) != CodeSyntax {
		t.Errorf("syntax: %v", err)
	}
	if _, err := ParseEntities([]byte(strings.Repeat(" ", MaxEntityBytes+1))); code(err) != CodeTooLarge {
		t.Errorf("size: %v", err)
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i <= MaxEntities; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"uid":{"type":"T","id":"` + strings.Repeat("x", 1+i/26) + string(rune('a'+i%26)) + `"},"parents":[],"attrs":{}}`)
	}
	sb.WriteString("]")
	if _, err := ParseEntities([]byte(sb.String())); code(err) != CodeTooManyEntity {
		t.Errorf("count: %v", err)
	}
}
