package awsorg

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
)

// readerCatalog is a catalog holding the actions the connector uses and a few
// it must never be allowed, with the access levels of the AWS Service
// Reference. (The compiled catalog is built by `tessera catalog compile`;
// TestReaderPolicyAgainstCompiledCatalog checks against it when one exists.)
func readerCatalog(t *testing.T, extra map[string]catalog.AccessLevel) *catalog.Catalog {
	t.Helper()
	levels := map[string]catalog.AccessLevel{
		"iam:GetAccountAuthorizationDetails":     catalog.AccessRead,
		"iam:GenerateServiceLastAccessedDetails": catalog.AccessRead, "iam:GetServiceLastAccessedDetails": catalog.AccessRead,
		"cloudtrail:GetEventSelectors": catalog.AccessRead, "s3:ListBucket": catalog.AccessList,
		"iam:SimulatePrincipalPolicy":        catalog.AccessRead,
		"organizations:DescribeOrganization": catalog.AccessRead, "organizations:ListRoots": catalog.AccessList,
		"organizations:ListOrganizationalUnitsForParent": catalog.AccessList, "organizations:ListAccountsForParent": catalog.AccessList,
		"organizations:ListPolicies": catalog.AccessList, "organizations:DescribePolicy": catalog.AccessRead,
		"organizations:ListTargetsForPolicy": catalog.AccessList,
		"s3:ListAllMyBuckets":                catalog.AccessList, "s3:GetBucketPolicy": catalog.AccessRead, "s3:GetBucketAcl": catalog.AccessRead,
		"s3:GetBucketOwnershipControls": catalog.AccessRead, "s3:GetBucketPublicAccessBlock": catalog.AccessRead,
		"s3:GetAccountPublicAccessBlock": catalog.AccessRead, "s3:ListAccessPoints": catalog.AccessList, "s3:GetAccessPointPolicy": catalog.AccessRead,
		"kms:ListKeys": catalog.AccessList, "kms:DescribeKey": catalog.AccessRead, "kms:GetKeyPolicy": catalog.AccessRead, "kms:ListGrants": catalog.AccessList,
		"sqs:ListQueues": catalog.AccessList, "sqs:GetQueueAttributes": catalog.AccessRead,
		"sns:ListTopics": catalog.AccessList, "sns:GetTopicAttributes": catalog.AccessRead,
		"secretsmanager:ListSecrets": catalog.AccessList, "secretsmanager:GetResourcePolicy": catalog.AccessRead,
		"lambda:ListFunctions": catalog.AccessList, "lambda:GetPolicy": catalog.AccessRead,
		"ecr:DescribeRepositories": catalog.AccessList, "ecr:GetRepositoryPolicy": catalog.AccessRead,
		"ec2:DescribeVpcEndpoints": catalog.AccessList,
		"sso:ListInstances":        catalog.AccessList, "sso:ListPermissionSets": catalog.AccessList, "sso:DescribePermissionSet": catalog.AccessRead,
		"sso:ListAccountAssignments": catalog.AccessList,
		// actions the connector must not be given
		"iam:CreateUser": catalog.AccessWrite, "iam:PutUserPolicy": catalog.AccessPermissionsManagement,
		"s3:PutBucketPolicy": catalog.AccessPermissionsManagement, "s3:GetObject": catalog.AccessRead, "kms:Decrypt": catalog.AccessWrite,
		"sts:AssumeRole": catalog.AccessWrite, "sqs:TagQueue": catalog.AccessTagging, "secretsmanager:GetSecretValue": catalog.AccessRead,
	}
	for k, v := range extra {
		levels[k] = v
	}
	byService := map[string][]catalog.CAction{}
	for a, l := range levels {
		svc := a[:strings.Index(a, ":")]
		byService[svc] = append(byService[svc], catalog.CAction{Name: a, Level: l})
	}
	var c catalog.Compiled
	c.Version = "2026-10-08-0123456789abcdef"
	for _, svc := range sortedKeys(byService) {
		acts := byService[svc]
		sort.Slice(acts, func(i, j int) bool { return acts[i].Name < acts[j].Name })
		c.Services = append(c.Services, catalog.CService{Prefix: svc, Actions: acts})
	}
	cat, err := catalog.New(&c)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestReaderPolicyIsReadOnly(t *testing.T) {
	cat := readerCatalog(t, nil)
	raw := ReaderPolicy()
	if err := CheckReadOnly(raw, cat); err != nil {
		t.Fatalf("the connector's own policy is not read-only: %v", err)
	}
	// it is exactly ReaderActions, with no wildcard, on all resources
	var doc struct {
		Version   string
		Statement []struct {
			Sid, Effect, Resource string
			Action                []string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version != "2012-10-17" || len(doc.Statement) != 1 {
		t.Fatalf("policy = %s, %v", raw, err)
	}
	st := doc.Statement[0]
	if st.Effect != "Allow" || st.Resource != "*" || !slices.Equal(st.Action, ReaderActions) {
		t.Errorf("statement = %+v", st)
	}
	seen := map[string]bool{}
	for _, a := range ReaderActions {
		if seen[a] {
			t.Errorf("%s is listed twice", a)
		}
		seen[a] = true
		if strings.ContainsAny(a, "*?") || strings.HasPrefix(a, "sts:") {
			t.Errorf("unexpected action %s", a)
		}
	}
}

func TestCheckReadOnlyRefuses(t *testing.T) {
	cat := readerCatalog(t, nil)
	policy := func(stmt string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[` + stmt + `]}`)
	}
	for name, raw := range map[string][]byte{
		"a write action":              policy(`{"Effect":"Allow","Action":["iam:GetAccountAuthorizationDetails","iam:CreateUser"],"Resource":"*"}`),
		"permissions management":      policy(`{"Effect":"Allow","Action":"s3:PutBucketPolicy","Resource":"*"}`),
		"a read of data":              policy(`{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}`),
		"tagging":                     policy(`{"Effect":"Allow","Action":"sqs:TagQueue","Resource":"*"}`),
		"a wildcard that is all read": policy(`{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}`),
		"a service wildcard":          policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`),
		"NotAction":                   policy(`{"Effect":"Allow","NotAction":"iam:CreateUser","Resource":"*"}`),
		"a Deny statement":            policy(`{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}`),
		"an action not in catalog":    policy(`{"Effect":"Allow","Action":"s3:GetNothing","Resource":"*"}`),
		"a second, bad statement":     policy(`{"Effect":"Allow","Action":"s3:GetBucketPolicy","Resource":"*"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}`),
		"not a policy":                []byte(`{"Statement":"x"}`),
		"not json":                    []byte(`nope`),
	} {
		if err := CheckReadOnly(raw, cat); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckReadOnly(ReaderPolicy(), nil); err == nil {
		t.Error("checked against no catalog")
	}
	// a catalog that classifies one of the reader's actions as a write fails the connector's own policy
	if err := CheckReadOnly(ReaderPolicy(), readerCatalog(t, map[string]catalog.AccessLevel{"kms:ListGrants": catalog.AccessWrite})); err == nil ||
		!strings.Contains(err.Error(), "kms:ListGrants") {
		t.Errorf("err = %v", err)
	}
}

// TestReaderPolicyAgainstCompiledCatalog verifies the policy against the real
// action catalog (mvp/server/catalog/aws/compiled) when one has been built.
func TestReaderPolicyAgainstCompiledCatalog(t *testing.T) {
	const dir = "../../../catalog/aws"
	vs, err := catalog.ListCompiled(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Skip("no compiled catalog under catalog/aws/compiled (run `tessera catalog compile`)")
	}
	cat, err := catalog.Load(dir, vs[len(vs)-1].Version)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckReadOnly(ReaderPolicy(), cat); err != nil {
		t.Errorf("against catalog %s: %v", cat.Version(), err)
	}
}
