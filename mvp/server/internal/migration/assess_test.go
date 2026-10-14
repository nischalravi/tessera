package migration

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func options(format string) Options {
	return Options{Tenant: "tenant-a", Product: "sailpoint-iiq", Instance: "fixture", Format: format}
}
func hasCode(r *Report, code string) bool {
	for _, d := range r.Diagnostics {
		if d.Code == code {
			return true
		}
	}
	return false
}

func TestNormalizedAssessmentAndNamespaces(t *testing.T) {
	b := fixture(t, "normalized.json")
	for _, product := range []string{"sailpoint-iiq", "sailpoint-isc", "saviynt"} {
		o := options("normalized-json")
		o.Product = product
		r, err := Assess(o, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Diagnostics) != 0 || len(r.Snapshot.Accounts) != 1 || len(r.RoleProposals) != 1 || len(r.SoDProposals) != 1 {
			t.Fatalf("unexpected report: %+v", r)
		}
		if r.Digest != digest(b) || r.ComparisonStatus != "not_performed" {
			t.Fatal("missing provenance/coverage")
		}
		o.Tenant = "tenant-b"
		other, err := Assess(o, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if r.RoleProposals[0].SourceRef == other.RoleProposals[0].SourceRef {
			t.Fatal("tenant collision")
		}
		o = options("normalized-json")
		o.Tenant = "a/b"
		a, _ := Assess(o, bytes.NewReader(b))
		o.Tenant = "a"
		o.Product = "sailpoint-iiq"
		o.Instance = "b/fixture"
		c, _ := Assess(o, bytes.NewReader(b))
		if a.ref("role", "r") == c.ref("role", "r") {
			t.Fatal("namespace separator collision")
		}
	}
}

func TestSoDProposalMatchesRealEngineAndIsDisabled(t *testing.T) {
	r, err := Assess(options("normalized-json"), bytes.NewReader(fixture(t, "normalized.json")))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(r.SoDProposals[0].Definition, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled {
		t.Fatal("proposal enabled")
	}
	g := graph.New()
	g.AddNode(&graph.Node{Key: "identity:1", Kind: "identity", ID: 1, Label: "fixture", Status: "active"})
	for i, action := range []string{"payment:Create", "payment:Approve"} {
		key := []string{"perm:1", "perm:2"}[i]
		g.AddNode(&graph.Node{Key: key, Kind: "perm", ID: int64(i + 1), Action: action})
		if err := g.AddEdge("identity:1", key, "grant", "simulated", nil); err != nil {
			t.Fatal(err)
		}
	}
	violations, err := policy.Evaluate([]*policy.Policy{p}, policy.NewContext(g, nil, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatal("disabled proposal evaluated")
	}
	p.Enabled = true
	violations, err = policy.Evaluate([]*policy.Policy{p}, policy.NewContext(g, nil, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 {
		t.Fatalf("wrong SoD engine shape: %v", violations)
	}
}

func TestXMLSubsetAndUnsupportedContentNeverEchoed(t *testing.T) {
	r, err := Assess(options("iiq-xml"), bytes.NewReader(fixture(t, "iiq.xml")))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Snapshot.Identities) != 1 || len(r.Snapshot.Accounts) != 1 || len(r.Snapshot.Entitlements) != 1 || len(r.RoleProposals) != 1 {
		t.Fatal("subset normalization failed")
	}
	if r.Snapshot.Accounts[0].IdentityID != "person-1" || r.Snapshot.Entitlements[0].OwnerID != "person-1" {
		t.Fatal("explicit source references lost")
	}
	if !hasCode(r, "unsupported_xml_semantics") || !hasCode(r, "incomplete_source") {
		t.Fatal("unsupported content dropped")
	}
	var out bytes.Buffer
	if err := WriteReport(&out, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "DO_NOT_EXECUTE_OR_ECHO") || strings.Contains(out.String(), "Constraints") {
		t.Fatal("embedded logic echoed")
	}
	for _, d := range r.Diagnostics {
		if d.Code == "unsupported_xml_semantics" && len(d.Digest) != 64 {
			t.Fatal("missing logic digest")
		}
	}
}

func TestStrictJSONAndLimits(t *testing.T) {
	valid := string(fixture(t, "normalized.json"))
	cases := map[string]string{
		"duplicate key":  `{"schema_version":1,"schema_version":1}`,
		"unknown field":  strings.Replace(valid, `"complete": true`, `"complete": true, "password":"secret"`, 1),
		"unknown nested": strings.Replace(valid, `"name":"Synthetic Person"`, `"name":"Synthetic Person", "password":"secret"`, 1),
		"trailing":       valid + ` {}`,
		"duplicate id":   strings.Replace(valid, `"identities": [`, `"identities": [{"id":"person-1","name":"duplicate"},`, 1),
		"missing id":     strings.Replace(valid, `"person-1"`, `""`, 1),
		"schema":         strings.Replace(valid, `"schema_version": 1`, `"schema_version": 2`, 1),
		"oversize":       strings.Repeat(" ", MaxBytes+1),
		"deep":           strings.Repeat("[", MaxDepth+2) + "0" + strings.Repeat("]", MaxDepth+2),
		"value":          `{"value":"` + strings.Repeat("x", MaxValueBytes+1) + `"}`,
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Assess(options("normalized-json"), strings.NewReader(s)); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	if err := validateJSON([]byte(`{"a":1,"b":{"a":2}}`)); err != nil {
		t.Fatal("different objects may reuse keys")
	}
	if err := validateJSON([]byte("[" + strings.Repeat("0,", MaxTokens) + "0]")); err == nil {
		t.Fatal("token cap not enforced")
	}
}

func TestMaliciousXMLRejected(t *testing.T) {
	cases := map[string]string{
		"billion laughs": string(fixture(t, "billion-laughs.xml")),
		"xxe":            string(fixture(t, "xxe.xml")),
		"deep":           strings.Repeat("<x>", MaxDepth+1) + strings.Repeat("</x>", MaxDepth+1),
		"attribute":      `<Identity id="i" name="` + strings.Repeat("x", MaxValueBytes+1) + `"/>`,
		"text":           `<Identity id="i"><Source>` + strings.Repeat("x", MaxValueBytes+1) + `</Source></Identity>`,
		"malformed":      `<Identity secret="DO_NOT_LEAK"><Source>bad`,
		"multiple roots": `<Identity id="1"/><Identity id="2"/>`,
		"namespace":      `<x:Identity xmlns:x="http://example.test" id="1"/>`,
		"empty":          "",
		"long name":      "<" + strings.Repeat("x", MaxValueBytes+1) + "/>",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Assess(options("iiq-xml"), strings.NewReader(s))
			if err == nil {
				t.Fatal("accepted malicious XML")
			}
			if strings.Contains(err.Error(), "DO_NOT_LEAK") {
				t.Fatal("error leaks raw input")
			}
		})
	}
	if _, err := Assess(options("iiq-xml"), strings.NewReader("<sailpoint>"+strings.Repeat("<x/>", MaxRecords+1)+"</sailpoint>")); err == nil {
		t.Fatal("object cap not enforced")
	}
	if _, err := Assess(options("iiq-xml"), strings.NewReader("<sailpoint>"+strings.Repeat("<!--x-->", MaxTokens)+"</sailpoint>")); err == nil {
		t.Fatal("XML token cap not enforced")
	}
}

func TestExplicitReferencesAndRedactedUnsupportedLogic(t *testing.T) {
	var p Pack
	if err := json.Unmarshal(fixture(t, "normalized.json"), &p); err != nil {
		t.Fatal(err)
	}
	p.Accounts[0].IdentityID = "unknown"
	p.Entitlements[0].OwnerID = "unknown"
	p.Roles[0].EntitlementIDs = []string{"unknown"}
	p.Complete = false
	p.Unsupported = []Unsupported{{"rule-1", "saviynt.sql_rule", "SECRET_SENTINEL"}}
	b, _ := json.Marshal(p)
	r, err := Assess(options("normalized-json"), bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(r, "unresolved_reference") || !hasCode(r, "unsupported_logic") || !hasCode(r, "incomplete_source") {
		t.Fatal("missing blockers")
	}
	var out bytes.Buffer
	_ = WriteReport(&out, r)
	if strings.Contains(out.String(), "SECRET_SENTINEL") {
		t.Fatal("logic leaked")
	}
	a, err := Assess(options("normalized-json"), bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var again bytes.Buffer
	_ = WriteReport(&again, a)
	if out.String() != again.String() {
		t.Fatal("assessment is not deterministic")
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, o := range []Options{{}, {Tenant: "x", Product: "unknown", Instance: "y", Format: "normalized-json"}, {Tenant: "x", Product: "saviynt", Instance: "y", Format: "iiq-xml"}} {
		if _, err := Assess(o, strings.NewReader("{}")); err == nil {
			t.Fatal("accepted options")
		}
	}
}

func TestXMLWrapperTextCannotDisappear(t *testing.T) {
	r, err := Assess(options("iiq-xml"), strings.NewReader(`<sailpoint>DO_NOT_ECHO<Identity id="i" name="fixture"/></sailpoint>`))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(r, "unsupported_xml_semantics") {
		t.Fatal("wrapper content silently ignored")
	}
	var out bytes.Buffer
	if err := WriteReport(&out, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "DO_NOT_ECHO") {
		t.Fatal("wrapper text leaked")
	}
}

func TestDeferredVendorTypesAreDigestOnlyBlockers(t *testing.T) {
	for _, kind := range []string{"isc.transform", "isc.approval_scheme", "isc.correlation_config", "saviynt.analytics", "saviynt.sql_rule", "saviynt.custom_query_entitlement"} {
		t.Run(kind, func(t *testing.T) {
			var p Pack
			if err := json.Unmarshal(fixture(t, "normalized.json"), &p); err != nil {
				t.Fatal(err)
			}
			p.Unsupported = []Unsupported{{"custom-1", kind, "PRIVATE_LOGIC_SNIPPET"}}
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			r, err := Assess(options("normalized-json"), bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, d := range r.Diagnostics {
				if d.Code == "unsupported_logic" && d.Field == kind && d.Blocking && d.Digest == digest([]byte("PRIVATE_LOGIC_SNIPPET")) {
					found = true
				}
			}
			if !found {
				t.Fatal("deferred mapping lost")
			}
			var out bytes.Buffer
			if err := WriteReport(&out, r); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "PRIVATE_LOGIC_SNIPPET") {
				t.Fatal("raw logic leaked")
			}
		})
	}
	for _, kind := range []string{"Workflow", "Rule", "PolicyViolation", "Certification", "Form", "Source", "Script", "RuleRef"} {
		t.Run(kind, func(t *testing.T) {
			r, err := Assess(options("iiq-xml"), strings.NewReader(`<sailpoint><Bundle id="role" name="fixture"><`+kind+`>PRIVATE_LOGIC_SNIPPET</`+kind+`></Bundle></sailpoint>`))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, d := range r.Diagnostics {
				if d.Code == "unsupported_xml_semantics" && d.Field == kind && d.Blocking && len(d.Digest) == 64 {
					found = true
				}
			}
			if !found {
				t.Fatal("deferred XML type lost")
			}
			var out bytes.Buffer
			if err := WriteReport(&out, r); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "PRIVATE_LOGIC_SNIPPET") {
				t.Fatal("raw XML logic leaked")
			}
		})
	}
}

// TestAssess_DeferredIIQTypesHaveReasonCodes: recognised but unmapped IIQ object
// types get their own reason code (a scoping worksheet), stay blocking, and keep
// only a digest of their content.
func TestAssess_DeferredIIQTypesHaveReasonCodes(t *testing.T) {
	for kind, reason := range deferredIIQ {
		t.Run(kind, func(t *testing.T) {
			r, err := Assess(options("iiq-xml"), strings.NewReader(`<sailpoint><`+kind+` id="x1">PRIVATE_LOGIC_SNIPPET</`+kind+`></sailpoint>`))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, d := range r.Diagnostics {
				if d.Code == "deferred_mapping:"+reason && d.Field == kind && d.Blocking && len(d.Digest) == 64 {
					found = true
				}
			}
			if !found {
				t.Fatalf("no deferred_mapping:%s diagnostic: %+v", reason, r.Diagnostics)
			}
			var out bytes.Buffer
			if err := WriteReport(&out, r); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "PRIVATE_LOGIC_SNIPPET") {
				t.Fatal("raw logic leaked")
			}
		})
	}
}

// TestAssess_ProvisionalIDIsInformational: a provisional source id describes the
// report; it is listed but does not block.
func TestAssess_ProvisionalIDIsInformational(t *testing.T) {
	r, err := Assess(options("iiq-xml"), strings.NewReader(`<sailpoint><Identity name="no-id"/></sailpoint>`))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Diagnostics {
		if d.Code == "provisional_source_id" && d.Blocking {
			t.Fatal("provisional_source_id must not block")
		}
	}
	if !hasCode(r, "provisional_source_id") {
		t.Fatal("provisional id not reported")
	}
}
