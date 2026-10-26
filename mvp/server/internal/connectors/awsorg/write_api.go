package awsorg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
)

// The IAM and Identity Center calls of the write target (issue #660). Reads (Get*, List*, Describe*) are made with
// the reader role's session and writes with the writer role's: the target (write_target.go) chooses.

const (
	iamVersion = "2010-05-08"
	iamRegion  = "us-east-1" // IAM is global: the endpoint and signing region are us-east-1
)

// iamKinds are the principal types whose IAM calls differ only in the name of the action and the parameter.
var iamParam = map[string]string{"role": "RoleName", "user": "UserName", "group": "GroupName"}

func titleKind(kind string) string {
	switch kind {
	case "role":
		return "Role"
	case "user":
		return "User"
	}
	return "Group"
}

// iamWrite sends a write action. IAM answers a write with an empty result element, which the decoder may report as
// end of input: that is success.
func (s session) iamWrite(ctx context.Context, action string, p url.Values) error {
	var r struct{}
	err := s.query(ctx, svcIAM, iamRegion, iamVersion, action, p, &r)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// iamInlinePolicy reads an inline policy: its document decoded, and whether it exists.
func (s session) iamInlinePolicy(ctx context.Context, kind, name, policyName string) (string, bool, error) {
	var r struct {
		Role struct {
			Doc string `xml:"PolicyDocument"`
		} `xml:"GetRolePolicyResult"`
		User struct {
			Doc string `xml:"PolicyDocument"`
		} `xml:"GetUserPolicyResult"`
		Group struct {
			Doc string `xml:"PolicyDocument"`
		} `xml:"GetGroupPolicyResult"`
	}
	p := url.Values{iamParam[kind]: {name}, "PolicyName": {policyName}}
	if err := s.query(ctx, svcIAM, iamRegion, iamVersion, "Get"+titleKind(kind)+"Policy", p, &r); err != nil {
		if IsCode(err, "NoSuchEntity") {
			return "", false, nil
		}
		return "", false, err
	}
	enc := r.Role.Doc + r.User.Doc + r.Group.Doc
	doc, err := decodeIAMDocument(enc)
	if err != nil {
		return "", false, fmt.Errorf("aws: iam Get%sPolicy: the document is not decodable", titleKind(kind))
	}
	return doc, true, nil
}

type attachedPage struct {
	Items     []xmlAttached `xml:"AttachedPolicies>member"`
	Truncated bool          `xml:"IsTruncated"`
	Marker    string        `xml:"Marker"`
}

// iamAttached lists the managed policies attached to a role, user or group; found is false when the principal does
// not exist.
func (s session) iamAttached(ctx context.Context, kind, name string) (arns []string, found bool, err error) {
	err = paginate(ctx, func(marker string) (string, error) {
		p := url.Values{iamParam[kind]: {name}, "MaxItems": {"1000"}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			Role  attachedPage `xml:"ListAttachedRolePoliciesResult"`
			User  attachedPage `xml:"ListAttachedUserPoliciesResult"`
			Group attachedPage `xml:"ListAttachedGroupPoliciesResult"`
		}
		if err := s.query(ctx, svcIAM, iamRegion, iamVersion, "ListAttached"+titleKind(kind)+"Policies", p, &r); err != nil {
			return "", err
		}
		for _, pg := range []attachedPage{r.Role, r.User, r.Group} {
			for _, a := range pg.Items {
				arns = append(arns, a.PolicyARN)
			}
			if pg.Truncated {
				if pg.Marker == "" {
					return "", fmt.Errorf("aws: iam ListAttached%sPolicies: truncated page with no marker", titleKind(kind))
				}
				return pg.Marker, nil
			}
		}
		return "", nil
	})
	if IsCode(err, "NoSuchEntity") {
		return nil, false, nil
	}
	return arns, err == nil, err
}

// iamDefaultVersion is the default version id of a managed policy ("" and found false when it does not exist).
func (s session) iamDefaultVersion(ctx context.Context, policyARN string) (string, bool, error) {
	var r struct {
		Policy struct {
			DefaultVersionID string `xml:"DefaultVersionId"`
		} `xml:"GetPolicyResult>Policy"`
	}
	if err := s.query(ctx, svcIAM, iamRegion, iamVersion, "GetPolicy", url.Values{"PolicyArn": {policyARN}}, &r); err != nil {
		if IsCode(err, "NoSuchEntity") {
			return "", false, nil
		}
		return "", false, err
	}
	return r.Policy.DefaultVersionID, true, nil
}

// iamPolicyVersion reads one version's document, decoded ("" and found false when the version does not exist).
func (s session) iamPolicyVersion(ctx context.Context, policyARN, versionID string) (string, bool, error) {
	var r struct {
		Version struct {
			Document string `xml:"Document"`
		} `xml:"GetPolicyVersionResult>PolicyVersion"`
	}
	if err := s.query(ctx, svcIAM, iamRegion, iamVersion, "GetPolicyVersion", url.Values{"PolicyArn": {policyARN}, "VersionId": {versionID}}, &r); err != nil {
		if IsCode(err, "NoSuchEntity") {
			return "", false, nil
		}
		return "", false, err
	}
	doc, err := decodeIAMDocument(r.Version.Document)
	if err != nil {
		return "", false, errors.New("aws: iam GetPolicyVersion: the document is not decodable")
	}
	return doc, true, nil
}

// iamPolicyVersions lists the version ids of a managed policy.
func (s session) iamPolicyVersions(ctx context.Context, policyARN string) ([]string, error) {
	var r struct {
		Versions []struct {
			ID string `xml:"VersionId"`
		} `xml:"ListPolicyVersionsResult>Versions>member"`
	}
	if err := s.query(ctx, svcIAM, iamRegion, iamVersion, "ListPolicyVersions", url.Values{"PolicyArn": {policyARN}}, &r); err != nil {
		return nil, err
	}
	var out []string
	for _, v := range r.Versions {
		out = append(out, v.ID)
	}
	return out, nil // a policy has at most five versions: one page
}

// iamGroupsForUser lists the names of the groups a user is in; found is false when the user does not exist.
func (s session) iamGroupsForUser(ctx context.Context, user string) (groups []string, found bool, err error) {
	err = paginate(ctx, func(marker string) (string, error) {
		p := url.Values{"UserName": {user}, "MaxItems": {"1000"}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r struct {
			Groups []struct {
				Name string `xml:"GroupName"`
			} `xml:"ListGroupsForUserResult>Groups>member"`
			Truncated bool   `xml:"ListGroupsForUserResult>IsTruncated"`
			Marker    string `xml:"ListGroupsForUserResult>Marker"`
		}
		if err := s.query(ctx, svcIAM, iamRegion, iamVersion, "ListGroupsForUser", p, &r); err != nil {
			return "", err
		}
		for _, g := range r.Groups {
			groups = append(groups, g.Name)
		}
		if r.Truncated {
			if r.Marker == "" {
				return "", errors.New("aws: iam ListGroupsForUser: truncated page with no marker")
			}
			return r.Marker, nil
		}
		return "", nil
	})
	if IsCode(err, "NoSuchEntity") {
		return nil, false, nil
	}
	return groups, err == nil, err
}

// ---------------------------------------------------------------- Identity Center

// ssoAssignmentIn is the body of Create/DeleteAccountAssignment.
type ssoAssignmentIn struct {
	InstanceArn      string
	TargetId         string
	TargetType       string
	PermissionSetArn string
	PrincipalType    string
	PrincipalId      string
}

type ssoStatus struct {
	Status        string `json:"Status"` // IN_PROGRESS | FAILED | SUCCEEDED
	RequestID     string `json:"RequestId"`
	FailureReason string `json:"FailureReason"`
}

// ssoAssignment creates or deletes an assignment (asynchronous: the answer is the request's status).
func (s session) ssoAssignment(ctx context.Context, region string, del bool, in ssoAssignmentIn) (*ssoStatus, error) {
	op, key := "CreateAccountAssignment", "AccountAssignmentCreationStatus"
	if del {
		op, key = "DeleteAccountAssignment", "AccountAssignmentDeletionStatus"
	}
	var r map[string]ssoStatus
	if err := s.jsonCall(ctx, svcSSO, region, ssoTarget+op, json11, in, &r); err != nil {
		return nil, err
	}
	st := r[key]
	return &st, nil
}

// ssoRequestStatus polls the status of a create or delete request.
func (s session) ssoRequestStatus(ctx context.Context, region string, del bool, instanceARN, requestID string) (*ssoStatus, error) {
	op, key := "DescribeAccountAssignmentCreationStatus", "AccountAssignmentCreationStatus"
	if del {
		op, key = "DescribeAccountAssignmentDeletionStatus", "AccountAssignmentDeletionStatus"
	}
	var r map[string]ssoStatus
	if err := s.jsonCall(ctx, svcSSO, region, ssoTarget+op, json11,
		map[string]string{"InstanceArn": instanceARN, "AccountAssignmentRequestId": requestID}, &r); err != nil {
		return nil, err
	}
	st := r[key]
	return &st, nil
}
