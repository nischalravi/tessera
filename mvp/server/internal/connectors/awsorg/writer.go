package awsorg

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// The writer role (issue #660, LP-4; design least-privilege-loop §6.3). It is a different role from the reader, with
// its own trust policy (a token whose sub is WriterSubject: the reader's token is refused by it, and the writer's by
// the reader's), and it is the only AWS permission Tessera has to change anything. Verification of a change uses the
// reader: the role that made a change never certifies it.

// DefaultWriterRoleName is the name of the role the write target assumes in each account.
const DefaultWriterRoleName = "TesseraWriter"

// WriterActions are the actions that take access away: detach a managed policy, delete an inline one, put a new
// default version of a managed policy (and delete a version, which the finalize step of a later stage does), take a
// user out of a group, delete an Identity Center assignment.
var WriterActions = []string{
	"iam:DetachRolePolicy",
	"iam:DetachUserPolicy",
	"iam:DetachGroupPolicy",
	"iam:DeleteRolePolicy",
	"iam:DeleteUserPolicy",
	"iam:DeleteGroupPolicy",
	"iam:CreatePolicyVersion",
	"iam:SetDefaultPolicyVersion",
	"iam:DeletePolicyVersion",
	"iam:RemoveUserFromGroup",
	"sso:DeleteAccountAssignment",
}

// RestoreActions are the actions that put access back. Restore uses the writer role (design §11 decision 4): Tessera
// puts back only a payload whose digest it recorded when it revoked, to a principal of an operation it made, which
// is checked in Go because AWS cannot express it.
var RestoreActions = []string{
	"iam:AttachRolePolicy",
	"iam:AttachUserPolicy",
	"iam:AttachGroupPolicy",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:PutGroupPolicy",
	"iam:AddUserToGroup",
	"sso:CreateAccountAssignment",
}

// WriterDenyActions are refused outright, on every resource: nothing the writer does may create an identity, mint a
// credential, change who can assume a role, hand a role to a service, move a permissions boundary, tag, or reach
// Organizations or STS.
var WriterDenyActions = []string{
	"iam:CreatePolicy",
	"iam:CreateRole",
	"iam:CreateUser",
	"iam:CreateAccessKey",
	"iam:UpdateAssumeRolePolicy",
	"iam:PassRole",
	"iam:PutRolePermissionsBoundary",
	"iam:PutUserPermissionsBoundary",
	"iam:DeleteRolePermissionsBoundary",
	"iam:DeleteUserPermissionsBoundary",
	"iam:TagRole",
	"iam:UntagRole",
	"iam:TagUser",
	"iam:UntagUser",
	"iam:TagPolicy",
	"iam:UntagPolicy",
	"organizations:*",
	"sts:*",
}

// ProtectedTag is the tag that makes a resource untouchable by the writer.
const ProtectedTag = "tessera:protected"

// WriterPolicy returns the permissions policy of the writer role: an Allow of WriterActions and RestoreActions, an
// explicit Deny of WriterDenyActions, and an explicit Deny of every write action on a resource tagged
// tessera:protected=true. (The writer and reader roles are protected by their tag, and in Go: see WriteTarget.)
func WriterPolicy() []byte {
	allow := append(slices.Clone(WriterActions), RestoreActions...)
	b, err := json.MarshalIndent(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{"Sid": "TesseraRevokeAndRestore", "Effect": "Allow", "Action": allow, "Resource": "*"},
			map[string]any{"Sid": "TesseraNeverCreateOrEscalate", "Effect": "Deny", "Action": WriterDenyActions, "Resource": "*"},
			map[string]any{"Sid": "TesseraNeverTouchProtected", "Effect": "Deny", "Action": allow, "Resource": "*",
				"Condition": map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/" + ProtectedTag: "true"}}},
		},
	}, "", "  ")
	if err != nil {
		panic(err) // static data
	}
	return b
}

// CheckWriterPolicy verifies a writer policy against the contract: the Allow statement names only WriterActions and
// RestoreActions (no wildcard), and the policy has the two Deny statements of WriterPolicy. It is the check the
// Terraform module's policy is held to in tests.
func CheckWriterPolicy(raw []byte) error {
	var doc struct {
		Statement []struct {
			Effect, Resource string
			Action           []string
			Condition        map[string]map[string]string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("awsorg: writer policy: %w", err)
	}
	allowed := append(slices.Clone(WriterActions), RestoreActions...)
	var allows, denyEscalation, denyProtected int
	for i, st := range doc.Statement {
		switch st.Effect {
		case "Allow":
			allows++
			for _, a := range st.Action {
				if strings.ContainsAny(a, "*?") || !slices.Contains(allowed, a) {
					return fmt.Errorf("awsorg: writer policy statement %d allows %q, which is not a writer or restore action", i, a)
				}
			}
		case "Deny":
			switch {
			case st.Condition == nil && slices.Equal(sorted(st.Action), sorted(WriterDenyActions)):
				denyEscalation++
			case st.Condition["StringEquals"]["aws:ResourceTag/"+ProtectedTag] == "true" && slices.Equal(sorted(st.Action), sorted(allowed)):
				denyProtected++
			default:
				return fmt.Errorf("awsorg: writer policy statement %d is a Deny this contract does not know", i)
			}
		default:
			return fmt.Errorf("awsorg: writer policy statement %d has no effect", i)
		}
	}
	if allows != 1 || denyEscalation != 1 || denyProtected != 1 {
		return fmt.Errorf("awsorg: writer policy must have one Allow, one Deny of creation and escalation, and one Deny on protected resources")
	}
	return nil
}

func sorted(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}
