// Package awstest is the shared test kit of the AWS evaluator: a fake catalog
// and a generator of synthetic snapshots, from tiny random worlds for the
// equivalence tests to a tenant at the design's target scale (§12.1) for the
// performance tests. Only tests import it (internal/archtest enforces that).
package awstest

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// Catalog is a small stand-in for internal/aws/catalog: eight services, the KMS
// cross-account allowlist, the S3 ACL map and the public-policy key rules.
type Catalog struct{}

var services = map[string]bool{"s3": true, "ec2": true, "iam": true, "sts": true, "sqs": true, "sns": true, "lambda": true, "kms": true}
var rcpServices = map[string]bool{"s3": true, "sts": true, "sqs": true, "kms": true}

// Version implements eval.Catalog.
func (Catalog) Version() string { return "awstest-1" }

// CanonicalAction implements eval.Catalog: any action of a known service exists.
func (Catalog) CanonicalAction(a string) (string, bool) {
	svc, _, ok := strings.Cut(a, ":")
	l := strings.ToLower(svc)
	// The scale generator names its extra services "svc" and a number.
	return a, ok && (services[l] || strings.HasPrefix(l, "svc"))
}

// RCPSupportedService implements eval.Catalog.
func (Catalog) RCPSupportedService(p string) bool { return rcpServices[p] }

// MultivaluedKey implements eval.Catalog.
func (Catalog) MultivaluedKey(k string) bool { return policy.IsGlobalMultivaluedKey(k) }

// ResourceTagsSupported implements eval.Catalog.
func (Catalog) ResourceTagsSupported(a string) bool { return !strings.HasPrefix(a, "iam:") }

// RequiresExplicitRBP implements eval.Catalog.
func (Catalog) RequiresExplicitRBP(p string) (bool, bool) {
	if p == "iam" || p == "kms" {
		return true, true
	}
	return false, false
}

var kmsCrossAccountOps = map[string]bool{
	"kms:creategrant": true, "kms:decrypt": true, "kms:describekey": true, "kms:encrypt": true,
	"kms:generatedatakey": true, "kms:getkeyrotationstatus": true, "kms:getpublickey": true, "kms:listgrants": true,
	"kms:retiregrant": true, "kms:revokegrant": true, "kms:sign": true, "kms:verify": true,
}

// KMSCrossAccountOp implements eval.Catalog.
func (Catalog) KMSCrossAccountOp(a string) bool { return kmsCrossAccountOps[strings.ToLower(a)] }

var aclMap = map[eval.S3ACLScope]map[string][]string{
	eval.S3ACLBucket: {
		"READ":         {"s3:ListBucket"},
		"WRITE":        {"s3:DeleteObject", "s3:PutObject"},
		"READ_ACP":     {"s3:GetBucketAcl"},
		"WRITE_ACP":    {"s3:PutBucketAcl"},
		"FULL_CONTROL": {"s3:DeleteObject", "s3:GetBucketAcl", "s3:ListBucket", "s3:PutBucketAcl", "s3:PutObject"},
	},
	eval.S3ACLObject: {
		"READ":         {"s3:GetObject"},
		"READ_ACP":     {"s3:GetObjectAcl"},
		"WRITE_ACP":    {"s3:PutObjectAcl"},
		"FULL_CONTROL": {"s3:GetObject", "s3:GetObjectAcl", "s3:PutObjectAcl"},
	},
}

// S3ACLActions implements eval.Catalog.
func (Catalog) S3ACLActions(s eval.S3ACLScope, perm string) []string { return aclMap[s][perm] }

// The predefined ACL groups.
const (
	AllUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	AuthenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	LogDeliveryURI        = "http://acs.amazonaws.com/groups/s3/LogDelivery"
)

var aclGroups = map[string]eval.S3ACLGroup{
	AllUsersURI:           {Name: "AllUsers", Public: true},
	AuthenticatedUsersURI: {Name: "AuthenticatedUsers", Public: true},
	LogDeliveryURI:        {Name: "LogDelivery"},
}

// S3ACLGroup implements eval.Catalog.
func (Catalog) S3ACLGroup(uri string) (eval.S3ACLGroup, bool) { g, ok := aclGroups[uri]; return g, ok }

var publicKeys = map[string]eval.S3PublicKeyRule{
	"aws:principalarn":     {Kind: eval.S3FixedValue},
	"aws:principalaccount": {Kind: eval.S3FixedValue},
	"aws:principalorgid":   {Kind: eval.S3FixedValue},
	"aws:sourceip":         {Kind: eval.S3IPRange, IPv4MaxCIDR: 8, IPv6MaxCIDR: 32},
}

// S3PublicFixedKey implements eval.Catalog.
func (Catalog) S3PublicFixedKey(k string) (eval.S3PublicKeyRule, bool) {
	r, ok := publicKeys[k]
	return r, ok
}

var _ eval.Catalog = Catalog{}

// Actions is the action universe of the generators: the actions the generated
// policies name, plus a few that nothing names, so the atoms have a default.
func Actions() []string {
	return []string{
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketAcl", "s3:PutBucketAcl",
		"s3:PutBucketPolicy", "s3:GetObjectAcl", "s3:PutObjectAcl", "s3:GetBucketLocation", "s3:ListAllMyBuckets",
		"kms:Decrypt", "kms:Encrypt", "kms:DescribeKey", "kms:CreateGrant", "kms:RetireGrant", "kms:ScheduleKeyDeletion",
		"kms:GenerateDataKey", "sts:AssumeRole", "sts:TagSession", "iam:GetUser", "iam:PassRole", "iam:CreateRole",
		"sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:PurgeQueue", "sns:Publish", "sns:Subscribe",
		"ec2:RunInstances", "ec2:DescribeInstances", "ec2:TerminateInstances", "lambda:InvokeFunction", "lambda:GetFunction",
	}
}
