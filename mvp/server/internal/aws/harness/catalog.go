package harness

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// OfflineCatalog is the eval.Catalog the offline replay uses until the real
// catalog (PR-2, internal/aws/catalog) is on this branch. It carries the same
// facts as the golden corpus's stand-in: eight services and the three overlay
// tables. The nightly job (PR-9) passes the pinned catalog instead; a Runner
// takes any eval.Catalog.
type OfflineCatalog struct{}

var (
	offlineServices    = map[string]bool{"s3": true, "ec2": true, "iam": true, "sts": true, "sqs": true, "sns": true, "lambda": true, "kms": true}
	offlineRCPServices = map[string]bool{"s3": true, "sts": true, "sqs": true, "kms": true}

	offlineKMSCrossAccountOps = map[string]bool{
		"kms:creategrant": true, "kms:decrypt": true, "kms:derivesharedsecret": true, "kms:describekey": true,
		"kms:encrypt": true, "kms:generatedatakey": true, "kms:generatedatakeypair": true,
		"kms:generatedatakeypairwithoutplaintext": true, "kms:generatedatakeywithoutplaintext": true,
		"kms:generatemac": true, "kms:getkeyrotationstatus": true, "kms:getpublickey": true, "kms:listgrants": true,
		"kms:reencryptfrom": true, "kms:reencryptto": true, "kms:retiregrant": true, "kms:revokegrant": true,
		"kms:sign": true, "kms:verify": true, "kms:verifymac": true,
	}

	offlineACLMap = map[eval.S3ACLScope]map[string][]string{
		eval.S3ACLBucket: {
			"READ":         {"s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions"},
			"WRITE":        {"s3:DeleteObject", "s3:PutObject"},
			"READ_ACP":     {"s3:GetBucketAcl"},
			"WRITE_ACP":    {"s3:PutBucketAcl"},
			"FULL_CONTROL": {"s3:DeleteObject", "s3:GetBucketAcl", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions", "s3:PutBucketAcl", "s3:PutObject"},
		},
		eval.S3ACLObject: {
			"READ":         {"s3:GetObject", "s3:GetObjectVersion"},
			"WRITE":        {},
			"READ_ACP":     {"s3:GetObjectAcl", "s3:GetObjectVersionAcl"},
			"WRITE_ACP":    {"s3:PutObjectAcl", "s3:PutObjectVersionAcl"},
			"FULL_CONTROL": {"s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:PutObjectAcl", "s3:PutObjectVersionAcl"},
		},
	}

	offlineACLGroups = map[string]eval.S3ACLGroup{
		"http://acs.amazonaws.com/groups/global/AllUsers":           {Name: "AllUsers", Public: true},
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers": {Name: "AuthenticatedUsers", Public: true},
		"http://acs.amazonaws.com/groups/s3/LogDelivery":            {Name: "LogDelivery"},
	}

	offlinePublicKeys = map[string]eval.S3PublicKeyRule{
		"aws:principalarn":          {Kind: eval.S3FixedValue},
		"aws:principalaccount":      {Kind: eval.S3FixedValue},
		"aws:principalorgid":        {Kind: eval.S3FixedValue},
		"aws:userid":                {Kind: eval.S3FixedValue, ExceptPatterns: []string{"AROLEID:*"}},
		"aws:sourceip":              {Kind: eval.S3IPRange, IPv4MaxCIDR: 8, IPv6MaxCIDR: 32},
		"aws:sourcearn":             {Kind: eval.S3FixedValue},
		"aws:sourcevpc":             {Kind: eval.S3FixedValue},
		"aws:sourcevpce":            {Kind: eval.S3FixedValue},
		"aws:sourceowner":           {Kind: eval.S3FixedValue},
		"aws:sourceaccount":         {Kind: eval.S3FixedValue},
		"s3:dataaccesspointarn":     {Kind: eval.S3FixedValue, BucketPoliciesOnly: true},
		"s3:dataaccesspointaccount": {Kind: eval.S3FixedValue},
	}
)

var _ eval.Catalog = OfflineCatalog{}

// Version implements eval.Catalog.
func (OfflineCatalog) Version() string { return "harness-offline-1" }

// CanonicalAction implements eval.Catalog.
func (OfflineCatalog) CanonicalAction(a string) (string, bool) {
	svc, _, ok := strings.Cut(a, ":")
	return a, ok && offlineServices[strings.ToLower(svc)]
}

// RCPSupportedService implements eval.Catalog.
func (OfflineCatalog) RCPSupportedService(p string) bool { return offlineRCPServices[p] }

// MultivaluedKey implements eval.Catalog.
func (OfflineCatalog) MultivaluedKey(k string) bool { return policy.IsGlobalMultivaluedKey(k) }

// ResourceTagsSupported implements eval.Catalog.
func (OfflineCatalog) ResourceTagsSupported(string) bool { return true }

// RequiresExplicitRBP implements eval.Catalog.
func (OfflineCatalog) RequiresExplicitRBP(p string) (bool, bool) {
	if p == "iam" || p == "kms" {
		return true, true
	}
	return false, false
}

// KMSCrossAccountOp implements eval.Catalog.
func (OfflineCatalog) KMSCrossAccountOp(a string) bool {
	return offlineKMSCrossAccountOps[strings.ToLower(a)]
}

// S3ACLActions implements eval.Catalog.
func (OfflineCatalog) S3ACLActions(s eval.S3ACLScope, perm string) []string {
	return offlineACLMap[s][perm]
}

// S3ACLGroup implements eval.Catalog.
func (OfflineCatalog) S3ACLGroup(uri string) (eval.S3ACLGroup, bool) {
	g, ok := offlineACLGroups[uri]
	return g, ok
}

// S3PublicFixedKey implements eval.Catalog.
func (OfflineCatalog) S3PublicFixedKey(k string) (eval.S3PublicKeyRule, bool) {
	r, ok := offlinePublicKeys[k]
	return r, ok
}
