package target

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// AWS operation kinds (issue #660, LP-4; design least-privilege-loop §4.1, §6.3). They are changes of an AWS
// account's IAM or IAM Identity Center, made by the writer role and verified by re-reading with the reader
// role. Account.Username of the request is the ARN of the principal the change is for (the user, group or role,
// or the Identity Center principal id); Request.AWS says the rest. Each revoke kind has a restore kind that
// puts back the state recorded in the request.
const (
	AWSDetachPolicy       = "aws_detach_policy"        // detach a managed policy from a role, user or group
	AWSDeleteInlinePolicy = "aws_delete_inline_policy" // delete an inline policy of a role, user or group
	AWSSetPolicyVersion   = "aws_set_policy_version"   // right-size: a new default version of a managed policy; the old one is kept
	AWSRemoveFromGroup    = "aws_remove_from_group"    // remove a user from an IAM group
	AWSDeleteAssignment   = "aws_delete_assignment"    // delete an Identity Center account assignment

	AWSAttachPolicy         = "aws_attach_policy"          // restore of aws_detach_policy
	AWSPutInlinePolicy      = "aws_put_inline_policy"      // restore of aws_delete_inline_policy
	AWSRestorePolicyVersion = "aws_restore_policy_version" // restore of aws_set_policy_version: make the old version the default again
	AWSAddToGroup           = "aws_add_to_group"           // restore of aws_remove_from_group
	AWSCreateAssignment     = "aws_create_assignment"      // restore of aws_delete_assignment
)

// AWSKinds lists the AWS operation kinds: the revoking ones, then their restores.
var AWSKinds = []string{AWSDetachPolicy, AWSDeleteInlinePolicy, AWSSetPolicyVersion, AWSRemoveFromGroup, AWSDeleteAssignment,
	AWSAttachPolicy, AWSPutInlinePolicy, AWSRestorePolicyVersion, AWSAddToGroup, AWSCreateAssignment}

// AWSRestoreKind maps a revoking kind to the kind that undoes it ("" for any other).
func AWSRestoreKind(kind string) string {
	switch kind {
	case AWSDetachPolicy:
		return AWSAttachPolicy
	case AWSDeleteInlinePolicy:
		return AWSPutInlinePolicy
	case AWSSetPolicyVersion:
		return AWSRestorePolicyVersion
	case AWSRemoveFromGroup:
		return AWSAddToGroup
	case AWSDeleteAssignment:
		return AWSCreateAssignment
	}
	return ""
}

// IsAWSKind reports whether k is an AWS operation kind.
func IsAWSKind(k string) bool {
	for _, x := range AWSKinds {
		if x == k {
			return true
		}
	}
	return false
}

// AWSChange is the AWS-specific part of a Request. Only the fields of the kind are set.
type AWSChange struct {
	// PrincipalType is "role", "user" or "group" (IAM kinds). The name is the last segment of Account.Username.
	PrincipalType string `json:"principal_type,omitempty"`
	// PolicyARN: the managed policy to detach, attach or right-size.
	PolicyARN string `json:"policy_arn,omitempty"`
	// PolicyName: the inline policy to delete or put back.
	PolicyName string `json:"policy_name,omitempty"`
	// Document is the policy document the change leaves in place: the new default version (aws_set_policy_version) or
	// the inline policy to put back (aws_put_inline_policy).
	Document string `json:"document,omitempty"`
	// Prior is the state the change removes, verbatim as it was read: the inline policy's document, or the default
	// version's. Restore puts exactly this back. PriorSHA256 is DocDigest of it, recorded at the time of the revoke;
	// every step that uses Prior refuses it when the digest differs, and a revoke refuses to run when the target no
	// longer holds it (the estate changed since it was evaluated).
	Prior       string `json:"prior,omitempty"`
	PriorSHA256 string `json:"prior_sha256,omitempty"`
	// PriorVersionID is the default version a right-size replaces; restore makes it the default again.
	PriorVersionID string `json:"prior_version_id,omitempty"`
	// Group is the IAM group of a membership change (Account.Username is the user).
	Group string `json:"group,omitempty"`
	// Identity Center (the account is AccountID of the assignment; the principal is Account.Username).
	AccountID        string `json:"account_id,omitempty"`
	InstanceARN      string `json:"instance_arn,omitempty"`
	PermissionSetARN string `json:"permission_set_arn,omitempty"`
	SSOPrincipalType string `json:"sso_principal_type,omitempty"` // USER or GROUP
	// RestoreOf is the id of the operation a restore undoes.
	RestoreOf string `json:"restore_of,omitempty"`
}

// DocDigest is the SHA-256 (hex) of a policy document in canonical form: the JSON decoded and encoded again with
// sorted keys and no insignificant space, so a document IAM returns re-formatted still has the digest it had
// when recorded. A document that is not JSON is hashed as given.
func DocDigest(doc string) string {
	var v any
	b := []byte(doc)
	if json.Unmarshal(b, &v) == nil {
		if c, err := json.Marshal(v); err == nil {
			b = c
		}
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
