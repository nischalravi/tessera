package awsorg

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// ReaderActions are the only IAM actions the connector's role needs, and the
// only ones it calls. Every one is a List or Read action; ReaderPolicy turns
// the list into the policy the customer attaches to the role the connector
// assumes, and CheckReadOnly verifies it against the action catalog (the
// connector is the crown jewel of design risk R1: it can read every policy in
// the organization, so it must not be able to change one).
//
// sts:AssumeRole is not here: it is the permission of the caller in the role's
// trust policy, not of the role.
var ReaderActions = []string{
	"iam:GetAccountAuthorizationDetails",
	"iam:SimulatePrincipalPolicy", // the production shadow agreement (EP-6)
	"organizations:DescribeOrganization",
	"organizations:ListRoots",
	"organizations:ListOrganizationalUnitsForParent",
	"organizations:ListAccountsForParent",
	"organizations:ListPolicies",
	"organizations:DescribePolicy",
	"organizations:ListTargetsForPolicy",
	"s3:ListAllMyBuckets",
	"s3:GetBucketPolicy",
	"s3:GetBucketAcl",
	"s3:GetBucketOwnershipControls",
	"s3:GetBucketPublicAccessBlock",
	"s3:GetAccountPublicAccessBlock",
	"s3:ListAccessPoints",
	"s3:GetAccessPointPolicy",
	"kms:ListKeys",
	"kms:DescribeKey",
	"kms:GetKeyPolicy",
	"kms:ListGrants",
	"sqs:ListQueues",
	"sqs:GetQueueAttributes",
	"sns:ListTopics",
	"sns:GetTopicAttributes",
	"secretsmanager:ListSecrets",
	"secretsmanager:GetResourcePolicy",
	"lambda:ListFunctions",
	"lambda:GetPolicy",
	"ecr:DescribeRepositories",
	"ecr:GetRepositoryPolicy",
	"ec2:DescribeVpcEndpoints",
	"sso:ListInstances",
	"sso:ListPermissionSets",
	"sso:DescribePermissionSet",
	"sso:ListAccountAssignments",
}

// ReaderPolicy returns the IAM permissions policy of the connector's role: one
// Allow statement over ReaderActions.
func ReaderPolicy() []byte {
	b, err := json.MarshalIndent(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Sid": "TesseraReadOnly", "Effect": "Allow", "Action": ReaderActions, "Resource": "*",
		}},
	}, "", "  ")
	if err != nil {
		panic(err) // static data
	}
	return b
}

// CheckReadOnly parses an IAM policy and verifies that it allows nothing but
// List and Read actions known to the catalog: every statement is an Allow of
// named actions (no wildcard, no NotAction), and every action's access level
// in cat is list or read. A Deny statement, an unknown action, or any other
// level (write, permissions management, tagging) is an error.
func CheckReadOnly(raw []byte, cat *catalog.Catalog) error {
	if cat == nil {
		return fmt.Errorf("awsorg: no catalog to check the reader policy against")
	}
	res, err := policy.Parse(raw, policy.Options{Kind: model.PolicyIdentity, SourceARN: "tessera:reader-policy"})
	if err != nil {
		return fmt.Errorf("awsorg: reader policy: %w", err)
	}
	if len(res.Anomalies) > 0 {
		return fmt.Errorf("awsorg: reader policy has an ingest anomaly: %s", res.Anomalies[0].Code)
	}
	for _, st := range res.Doc.Statements {
		if st.Effect != model.EffectAllow {
			return fmt.Errorf("awsorg: reader policy statement %d is not an Allow", st.Index)
		}
		if st.Actions == nil || st.NotActions != nil {
			return fmt.Errorf("awsorg: reader policy statement %d must list Action", st.Index)
		}
		for _, a := range st.Actions.Patterns {
			if strings.ContainsAny(a, "*?") {
				return fmt.Errorf("awsorg: reader policy statement %d: wildcard action %q", st.Index, a)
			}
			switch lvl := cat.AccessLevel(a); lvl {
			case catalog.AccessList, catalog.AccessRead:
			case catalog.AccessUnknown:
				return fmt.Errorf("awsorg: reader policy action %q is not in catalog %s", a, cat.Version())
			default:
				return fmt.Errorf("awsorg: reader policy action %q has access level %s, not list or read", a, lvl)
			}
		}
	}
	return nil
}
