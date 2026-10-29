package policybundle

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
)

// good loads testdata/good, a repository that validates and whose tests pass.
func good(t testing.TB) Files {
	t.Helper()
	files := Files{}
	root := filepath.Join("testdata", "good")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func with(base Files, edits map[string]string) Files {
	out := Files{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range edits {
		if v == "\x00" {
			delete(out, k)
		} else {
			out[k] = []byte(v)
		}
	}
	return out
}

func codes(ds []Diag) string {
	var s []string
	for _, d := range ds {
		s = append(s, d.Path+"|"+d.Code)
	}
	return strings.Join(s, ",")
}

func TestLoadGood(t *testing.T) {
	b, diags := Load(good(t), nil)
	if len(diags) > 0 {
		t.Fatalf("diags: %v", diags)
	}
	if len(b.Roles) != 1 || len(b.Jit) != 1 || len(b.Sod) != 1 || len(b.Birthright) != 1 || len(b.Agents) != 1 || len(b.Invariants) != 2 || len(b.Tests) != 2 {
		t.Errorf("counts: %d roles %d jit %d sod %d birthright %d agents %d invariants %d tests",
			len(b.Roles), len(b.Jit), len(b.Sod), len(b.Birthright), len(b.Agents), len(b.Invariants), len(b.Tests))
	}
	for _, r := range b.RunTests() {
		if !r.OK() {
			t.Errorf("%s", r)
		}
	}
}

func TestLoadFindings(t *testing.T) {
	const badPolicy = `@id("x") @role("payments-analyst") permit (principal, action == Tessera::Action::"birthright", resource) when { principal.nope == 1 };`
	cases := []struct {
		name  string
		edits map[string]string
		want  string // path|code of the findings, in order
	}{
		{"no tessera.yaml", map[string]string{"tessera.yaml": "\x00"}, "tessera.yaml|missing"},
		{"wrong repo schema", map[string]string{"tessera.yaml": "schema: x\ntenant: larkspur\n"}, "tessera.yaml|invalid_schema"},
		{"bad tenant", map[string]string{"tessera.yaml": "schema: tessera.repo/v1\ntenant: Bad Tenant\n"}, "tessera.yaml|invalid_tenant"},
		{"bad manage mode", map[string]string{"tessera.yaml": "schema: tessera.repo/v1\ntenant: a\nmanage: {roles: some}\n"}, "tessera.yaml|invalid_manage"},
		{"unknown field", map[string]string{"tessera.yaml": "schema: tessera.repo/v1\ntenant: a\nextra: 1\n"}, "tessera.yaml|invalid"},
		{"alias refused", map[string]string{"tessera.yaml": "schema: tessera.repo/v1\ntenant: &t a\nmanage: {}\n"}, "tessera.yaml|invalid"},
		{"two documents", map[string]string{"tessera.yaml": "schema: tessera.repo/v1\ntenant: a\n---\nx: 1\n"}, "tessera.yaml|invalid"},
		{"role risk", map[string]string{"roles/payments-analyst.yaml": "schema: tessera.role/v1\nkey: payments-analyst\nname: P\nrisk: extreme\n"}, "roles/payments-analyst.yaml|invalid_risk"},
		{"role entitlement form", map[string]string{"roles/payments-analyst.yaml": "schema: tessera.role/v1\nkey: payments-analyst\nname: P\nrisk: low\nentitlements: [nocolon]\n"}, "roles/payments-analyst.yaml|invalid_entitlements"},
		{"duplicate role key", map[string]string{"roles/zeta.yaml": "schema: tessera.role/v1\nkey: payments-analyst\nname: Q\nrisk: low\n"}, "roles/zeta.yaml|duplicate_key"},
		{"jit hours", map[string]string{"jit/prod-db-admin.yaml": "schema: tessera.jit/v1\nkey: k\nprincipals: [okta:a]\nentitlements: [aws:b]\nmax_hours: 73\n"}, "jit/prod-db-admin.yaml|invalid_max_hours"},
		{"jit approvals", map[string]string{"jit/prod-db-admin.yaml": "schema: tessera.jit/v1\nkey: k\nprincipals: [okta:a]\nentitlements: [aws:b]\nmax_hours: 2\nmin_approvals: 1\n"}, "jit/prod-db-admin.yaml|invalid_min_approvals"},
		{"sod unknown function", map[string]string{"sod/finance.yaml": strings.Replace(string(good(t)["sod/finance.yaml"]), "approve-payment]", "nope]", 1)}, "sod/finance.yaml|invalid_functions"},
		{"sod wrong tag", map[string]string{"sod/finance.yaml": strings.Replace(string(good(t)["sod/finance.yaml"]), "tessera.sod/v1", "tessera.sod/v2", 1)}, "sod/finance.yaml|invalid_schema"},
		{"cedar syntax", map[string]string{"invariants/bad.cedar": "forbid (principal"}, "invariants/bad.cedar|syntax"},
		{"cedar type error", map[string]string{"birthright/extra.cedar": badPolicy}, "birthright/extra.cedar|validation"},
		{"too deep", map[string]string{"invariants/deep.cedar": "forbid (principal, action, resource) when { " + strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40) + " };"}, "invariants/deep.cedar|too_deep"},
		{"invariant must forbid", map[string]string{"invariants/p.cedar": `@id("p") permit (principal, action == Tessera::Action::"exist", resource);`}, "invariants/p.cedar|wrong_effect"},
		{"missing id", map[string]string{"invariants/p.cedar": `forbid (principal, action == Tessera::Action::"exist", resource);`}, "invariants/p.cedar|missing_id"},
		{"duplicate id", map[string]string{"invariants/p.cedar": `@id("secret-max-age") forbid (principal, action == Tessera::Action::"exist", resource);`}, "invariants/p.cedar|duplicate_id"},
		{"bad severity", map[string]string{"invariants/p.cedar": `@id("p") @severity("urgent") forbid (principal, action == Tessera::Action::"exist", resource);`}, "invariants/p.cedar|invalid_severity"},
		{"birthright unknown role", map[string]string{"birthright/x.cedar": `@id("x") @role("ghost") permit (principal, action == Tessera::Action::"birthright", resource);`}, "birthright/x.cedar|unknown_role"},
		{"birthright no role", map[string]string{"birthright/x.cedar": `@id("x") permit (principal, action == Tessera::Action::"birthright", resource);`}, "birthright/x.cedar|missing_role"},
		{"two birthright rules for a role", map[string]string{"birthright/x.cedar": `@id("x") @role("payments-analyst") permit (principal, action == Tessera::Action::"birthright", resource);`}, "birthright/x.cedar|duplicate_birthright"},
		{"agent scope without agent", map[string]string{"agents/x.cedar": `@id("x") permit (principal, action == Tessera::Action::"reach", resource);`}, "agents/x.cedar|missing_agent"},
		{"stray file", map[string]string{"roles/readme.txt": "hi"}, "roles/readme.txt|unexpected_file"},
		{"schema syntax", map[string]string{"schema/tessera.cedarschema": "entity"}, "schema/tessera.cedarschema|schema"},
		{"test bad expect", map[string]string{"tests/b.yaml": "schema: tessera.test/v1\ncases:\n  - {name: a, principal: 'Tessera::Identity::\"a\"', action: birthright, resource: 'Tessera::Role::\"r\"', expect: maybe}\n"}, "tests/b.yaml|invalid_case"},
		{"test bad uid", map[string]string{"tests/b.yaml": "schema: tessera.test/v1\ncases:\n  - {name: a, principal: alice, action: birthright, resource: 'Tessera::Role::\"r\"', expect: allow}\n"}, "tests/b.yaml|invalid_case"},
		{"test bad action", map[string]string{"tests/b.yaml": "schema: tessera.test/v1\ncases:\n  - {name: a, principal: 'Tessera::Identity::\"a\"', action: delete, resource: 'Tessera::Role::\"r\"', expect: allow}\n"}, "tests/b.yaml|invalid_case"},
		{"test entity type error", map[string]string{"tests/b.yaml": "schema: tessera.test/v1\nentities:\n  - {uid: {type: Tessera::Identity, id: a}, attrs: {type: 1}}\ncases:\n  - {name: a, principal: 'Tessera::Identity::\"a\"', action: birthright, resource: 'Tessera::Role::\"r\"', expect: allow}\n"}, "tests/b.yaml|validation"},
		{"empty test", map[string]string{"tests/b.yaml": "schema: tessera.test/v1\n"}, "tests/b.yaml|empty_test"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, diags := Load(with(good(t), c.edits), nil)
			if got := codes(diags); got != c.want {
				t.Errorf("findings = %q, want %q\n%v", got, c.want, diags)
			}
		})
	}
}

// A group reference is system:name; the name may hold spaces, as group names in Workday, Entra and Okta do
// (issue #729), but no control character and no leading or trailing whitespace.
func TestEntitlementReference(t *testing.T) {
	for ref, ok := range map[string]bool{
		"workday:AP Clerk": true, "okta:eng": true, "aws:arn:aws:iam::1:role/x": true, "snowflake:FINANCE_ANALYST": true,
		"nocolon": false, "okta:": false, ":eng": false, "okta: eng": false, "okta:eng ": false, "okta:a\tb": false,
		"okta:a\nb": false, "okta:a\x00b": false, "ok ta:eng": false,
	} {
		if got := entRE.MatchString(ref); got != ok {
			t.Errorf("%q: valid = %v, want %v", ref, got, ok)
		}
	}
}

func TestLoadLimits(t *testing.T) {
	big := Files{}
	for i := 0; i <= MaxFiles; i++ {
		big["roles/f"+strconv.Itoa(i)+".yaml"] = nil
	}
	if _, d := Load(big, nil); codes(d) != ".|too_many_files" {
		t.Errorf("many files: %v", codes(d))
	}
	huge := with(good(t), map[string]string{"invariants/huge.cedar": strings.Repeat(" ", 256<<10+1)})
	if _, d := Load(huge, nil); codes(d) != "invariants/huge.cedar|too_large" {
		t.Errorf("one huge file: %v", codes(d))
	}
	if _, d := Load(with(good(t), map[string]string{"../evil.cedar": ""}), nil); codes(d) != "../evil.cedar|bad_path" {
		t.Errorf("path: %v", codes(d))
	}
}

func TestRunTestsFailures(t *testing.T) {
	flip := func(from, to string) Files {
		f := good(t)
		return with(f, map[string]string{"tests/birthright.yaml": strings.Replace(string(f["tests/birthright.yaml"]), from, to, 1)})
	}
	snap := func(from, to string) Files {
		f := good(t)
		return with(f, map[string]string{"tests/invariants.yaml": strings.Replace(string(f["tests/invariants.yaml"]), from, to, 1)})
	}
	cases := []struct {
		name  string
		files Files
		want  string // substring of the first failure
	}{
		{"wrong expectation", flip("    expect: allow\n    by: [payments-analyst-birthright]", "    expect: deny"), "expected deny, got allow (decided by payments-analyst-birthright)"},
		{"wrong by", flip("by: [payments-analyst-birthright]", "by: [other]"), "wanted other"},
		{"missing violation", snap("  violations:\n", "  violations:\n    - {invariant: terminated-with-access, principal: 'Tessera::Identity::\"gone\"', action: reach, resource: 'Tessera::Resource::\"aws:dev-db\"'}\n"), "expected violation"},
		{"unexpected violation", snap("    - {invariant: secret-max-age, principal: 'Tessera::Identity::\"svc-batch\"', action: hold_credential, resource: 'Tessera::Credential::\"key-1\"'}\n", ""), "unexpected violation [secret-max-age"},
		{"approximate fact must not block", snap("fidelity: APPROXIMATE", "fidelity: EXACT"), "unexpected violation [terminated-with-access"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, diags := Load(c.files, nil)
			if len(diags) > 0 {
				t.Fatal(diags)
			}
			var failed string
			for _, r := range b.RunTests() {
				if !r.OK() {
					failed = r.Err
					break
				}
			}
			if !strings.Contains(failed, c.want) {
				t.Errorf("failure = %q, want it to contain %q", failed, c.want)
			}
		})
	}
}

func TestAgentScopeCases(t *testing.T) {
	f := with(good(t), map[string]string{"tests/agents.yaml": `schema: tessera.test/v1
entities:
  - uid: {type: Tessera::Agent, id: "entra:7f3c"}
    attrs: {type: ai_agent, status: active, created_days: 3, attrs: {}, source: entra, kind: bot}
  - uid: {type: Tessera::Resource, id: "aws:support-bucket"}
    attrs: {system: aws, tags: [support], privileged: false}
  - uid: {type: Tessera::Resource, id: "aws:pii-bucket"}
    attrs: {system: aws, tags: [pii], privileged: false}
cases:
  - name: in scope
    against: agents
    principal: 'Tessera::Agent::"entra:7f3c"'
    action: reach
    resource: 'Tessera::Resource::"aws:support-bucket"'
    context: {action: "s3:GetObject", action_class: read, system: aws, standing: true, via_jit: false, fidelity: EXACT}
    expect: allow
    by: [support-bot]
  - name: out of scope
    against: agents
    principal: 'Tessera::Agent::"entra:7f3c"'
    action: reach
    resource: 'Tessera::Resource::"aws:pii-bucket"'
    context: {action: "s3:GetObject", action_class: read, system: aws, standing: true, via_jit: false, fidelity: EXACT}
    expect: deny
`})
	b, diags := Load(f, nil)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	for _, r := range b.RunTests() {
		if !r.OK() {
			t.Error(r)
		}
	}
}

// The sod folder reads internal/sod's tessera.sod/v1 unchanged: a file the
// server exports loads here, and the good fixture is one the server accepts.
func TestSodDocumentIsTheServers(t *testing.T) {
	data := good(t)["sod/finance.yaml"]
	if _, err := sod.ParseYAML(data); err != nil {
		t.Fatalf("the server refuses the fixture: %v", err)
	}
	if TagSod != sod.SchemaTag {
		t.Errorf("tag %q != %q", TagSod, sod.SchemaTag)
	}
	b := sod.Bundle{Schema: sod.SchemaTag, Ruleset: sod.RulesetDoc{Key: "x", Name: "X", Enabled: true},
		Functions: []sod.FunctionDoc{
			{Key: "a", Name: "A", Selectors: []sod.Selector{{System: "erp", NamePattern: "a*"}}},
			{Key: "b", Name: "B", Selectors: []sod.Selector{{System: "erp", Attribute: "role", Value: "b"}}}},
		Risks: []sod.RiskDoc{{Key: "r", Name: "R", Priority: "low", Functions: []string{"a", "b"}, Remediation: []string{"revoke"},
			Subjects: &sod.Subjects{IdentityTypes: []string{"human"}}}}}
	out, err := b.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	_, diags := Load(with(good(t), map[string]string{"sod/x.yaml": string(out)}), nil)
	if len(diags) > 0 {
		t.Errorf("an exported ruleset does not load: %v", diags)
	}
	if maxJitHours != jit.MaxHours {
		t.Errorf("maxJitHours %d != jit.MaxHours %d", maxJitHours, jit.MaxHours)
	}
}

func TestDiagString(t *testing.T) {
	if s := (Diag{Path: "a.cedar", Line: 3, Code: "syntax", Msg: "m"}).String(); s != "a.cedar:3: syntax: m" {
		t.Error(s)
	}
	if s := (Diag{Path: "a.yaml", Code: "c", Msg: "m"}).String(); s != "a.yaml: c: m" {
		t.Error(s)
	}
}

func FuzzLoad(f *testing.F) {
	g := good(f)
	f.Add(string(g["tessera.yaml"]), string(g["roles/payments-analyst.yaml"]), string(g["invariants/access.cedar"]), string(g["tests/invariants.yaml"]))
	f.Add("a: &x [*x]", "key: [", "forbid (", "entities: [{uid: 1}]\ncases: [{}]")
	f.Add("", "", strings.Repeat("(", 5000), "snapshot: {facts: [{}]}")
	f.Fuzz(func(t *testing.T, cfg, role, cedar, test string) {
		files := with(g, map[string]string{"tessera.yaml": cfg, "roles/x.yaml": role, "invariants/x.cedar": cedar, "tests/x.yaml": test})
		b, diags := Load(files, nil)
		if len(diags) == 0 {
			b.RunTests()
		}
	})
}
