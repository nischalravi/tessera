package agentscope_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
)

const good = `schema: tessera.agentscope/v1
key: support-bot
name: Support bot
agent:
  source: entra
  external_id: 7f3c
allow:
  actions: [write, read]
  resources:
    - systems: [AWS]
      tags_any: [Support]
    - systems: [snowflake]
      environments: [prod]
      sensitivity: [internal, public]
`

func codes(fs []agentscope.Finding) string {
	var cs []string
	for _, f := range fs {
		cs = append(cs, f.Code)
	}
	return strings.Join(cs, ",")
}

func TestParseRefusals(t *testing.T) {
	swap := func(from, to string) string { return strings.Replace(good, from, to, 1) }
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"valid", good, ""},
		{"empty", "  \n", "invalid_document"},
		{"unknown field", swap("name: Support bot", "name: Support bot\nextra: 1"), "invalid_document"},
		{"duplicate key", swap("name: Support bot", "name: Support bot\nname: Other"), "invalid_document"},
		{"anchor", swap("source: entra", "source: &a entra"), "invalid_document"},
		{"alias", swap("name: Support bot", "name: &n Support bot\ndescription: *n"), "invalid_document"},
		{"two documents", good + "---\n" + good, "invalid_document"},
		{"not yaml", "a: [", "invalid_document"},
		{"wrong schema", swap("tessera.agentscope/v1", "tessera.agentscope/v2"), "invalid_schema"},
		{"bad key", swap("key: support-bot", "key: ../x"), "invalid_key"},
		{"no name", swap("name: Support bot", "name: ''"), "invalid_name"},
		{"bad severity", swap("name: Support bot", "name: x\nseverity: urgent"), "invalid_severity"},
		{"no agent", swap("  source: entra\n  external_id: 7f3c\n", "  source: entra\n"), "invalid_agent"},
		{"agent and blueprint", swap("external_id: 7f3c", "external_id: 7f3c\n  blueprint: bp1"), "invalid_agent"},
		{"bad agent value", swap("external_id: 7f3c", "external_id: 'a;b'"), "invalid_agent"},
		{"unknown class", swap("[write, read]", "[read, execute]"), "invalid_actions"},
		{"no classes", swap("[write, read]", "[]"), "invalid_actions"},
		{"no resources", good[:strings.Index(good, "  resources:")] + "  resources: []\n", "invalid_resources"},
		{"empty class matches everything", swap("    - systems: [AWS]\n      tags_any: [Support]\n", "    - {}\n"), "invalid_resources"},
		{"bad resource value", swap("[Support]", "['a b;']"), "invalid_resources"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := agentscope.Parse([]byte(tc.doc))
			if got := codes(fs); !strings.Contains(got, tc.want) || (tc.want == "" && got != "") {
				t.Errorf("findings = %q; want %q", got, tc.want)
			}
		})
	}
}

// A document normalises to one form: the order and case of lists do not matter, and what is written back loads as
// the same document.
func TestNormalizeRoundTrip(t *testing.T) {
	d, fs := agentscope.Parse([]byte(good))
	if len(fs) > 0 {
		t.Fatal(fs)
	}
	if d.Severity != "high" || strings.Join(d.Allow.Actions, ",") != "read,write" || d.Allow.Resources[0].Systems[0] != "aws" && d.Allow.Resources[0].Systems[0] != "snowflake" {
		t.Errorf("not normalised: %+v", d)
	}
	y, err := d.YAML()
	if err != nil {
		t.Fatal(err)
	}
	d2, fs := agentscope.Parse(y)
	if len(fs) > 0 {
		t.Fatalf("export does not load: %v\n%s", fs, y)
	}
	j1, _ := d.JSON()
	j2, _ := d2.JSON()
	if j1 != j2 {
		t.Errorf("round trip changed the document:\n%s\n%s", j1, j2)
	}
	if back, err := agentscope.FromJSON(j1); err != nil {
		t.Errorf("FromJSON: %v", err)
	} else if j3, _ := back.JSON(); j3 != j1 {
		t.Errorf("FromJSON changed the document: %s", j3)
	}
	if _, err := agentscope.FromJSON(`{"key":"x","bogus":1}`); err == nil {
		t.Error("a stored document with an unknown field was read")
	}
	// the ceiling default is not written, an opt-out is
	if strings.Contains(string(y), "owner_ceiling") || !d.Ceiling() {
		t.Errorf("default ceiling written or off: %s", y)
	}
	off, _ := agentscope.Parse([]byte(good + "owner_ceiling: false\n"))
	if y, _ := off.YAML(); !strings.Contains(string(y), "owner_ceiling: false") || off.Ceiling() {
		t.Errorf("opt-out lost: %s", y)
	}
	on, _ := agentscope.Parse([]byte(good + "owner_ceiling: true\n"))
	if jo, _ := on.JSON(); jo != j1 {
		t.Error("an explicit owner_ceiling: true differs from the default")
	}
}

func TestPermits(t *testing.T) {
	d, fs := agentscope.Parse([]byte(good))
	if len(fs) > 0 {
		t.Fatal(fs)
	}
	prod, dev := "prod", "dev"
	tests := []struct {
		name   string
		class  string
		system string
		env    *string
		tags   []string
		want   bool
	}{
		{"read support on aws", "read", "aws", nil, []string{"support"}, true},
		{"case does not matter", "write", "AWS", nil, []string{"SUPPORT", "pii"}, true},
		{"admin is not listed", "admin", "aws", nil, []string{"support"}, false},
		{"delegate is not listed", "delegate", "aws", nil, []string{"support"}, false},
		{"write does not imply read of another class", "read", "aws", nil, []string{"pii"}, false},
		{"wrong system", "read", "gcp", nil, []string{"support"}, false},
		{"second class: system, env and sensitivity all match", "read", "snowflake", &prod, []string{"internal"}, true},
		{"second class: wrong env", "read", "snowflake", &dev, []string{"internal"}, false},
		{"second class: no env", "read", "snowflake", nil, []string{"internal"}, false},
		{"second class: wrong sensitivity", "read", "snowflake", &prod, []string{"pii"}, false},
		{"second class: no tags", "read", "snowflake", &prod, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := d.Permits(tc.class, tc.system, tc.env, tc.tags); got != tc.want {
				t.Errorf("Permits = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestClassOf(t *testing.T) {
	tests := []struct {
		action     string
		privileged bool
		want       string
	}{
		{"s3:GetObject", false, "read"},
		{"s3:ListBucket", false, "read"},
		{"snowflake:SELECT", false, "read"},
		{"read", false, "read"},
		{"s3:Get*", false, "admin"},
		{"iam:List?", false, "admin"},
		{"ec2:DescribeInstances", false, "read"},
		{"s3:GetBucketAcl", false, "read"},
		{"s3:PutObject", false, "write"},
		{"payments:create", false, "write"},
		{"payments:approve", false, "write"},
		{"invoke", false, "write"},
		{"something-new", false, "write"},
		{"s3:PutBucketPolicy", false, "admin"},
		{"s3:PutBucketAcl", false, "admin"},
		{"iam:*", false, "admin"},
		{"*", false, "admin"},
		{"s3:*", false, "admin"},
		{"ec2:RunInstances", true, "admin"},
		{"iam:AttachRolePolicy", false, "admin"},
		{"kms:ScheduleKeyDeletion", false, "admin"},
		{"Owner", false, "admin"},
		{"iam:PassRole", false, "delegate"},
		{"sts:AssumeRole", true, "delegate"},
		{"run_as", false, "delegate"},
		{"impersonate", false, "delegate"},
		// credential minting reads like a get but hands out a principal's authority
		{"sts:GetFederationToken", false, "delegate"},
		{"sts:GetSessionToken", false, "delegate"},
		{"redshift:GetClusterCredentials", false, "delegate"},
		{"ecr:GetAuthorizationToken", false, "delegate"},
		{"iam.serviceAccounts.actAs", false, "delegate"},
		{"iam.serviceAccounts.getAccessToken", false, "delegate"},
		{"iam.serviceAccounts.signJwt", false, "delegate"},
		{"iam:CreateLoginProfile", false, "admin"},
		{"iam:AddUserToGroup", false, "admin"},
		{"iam:CreateServiceLinkedRole", false, "admin"},
		{"iam:DeactivateMFADevice", false, "admin"},
		// Azure and GCP names: the verb is the last segment, the object before it counts for admin
		{"Microsoft.Authorization/roleAssignments/write", false, "admin"},
		{"Microsoft.Authorization/roleAssignments/read", false, "read"},
		{"Microsoft.Storage/storageAccounts/read", false, "read"},
		{"Microsoft.Compute/virtualMachines/write", false, "write"},
		{"resourcemanager.projects.setIamPolicy", false, "admin"},
		{"storage.objects.get", false, "read"},
		{"storage.objects.create", false, "write"},
		{"secretsmanager:PutSecretValue", false, "write"},
	}
	for _, tc := range tests {
		if got := agentscope.ClassOf(tc.action, tc.privileged); got != tc.want {
			t.Errorf("ClassOf(%q, %v) = %s; want %s", tc.action, tc.privileged, got, tc.want)
		}
	}
}
