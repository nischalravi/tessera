package awsorg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// ---------------------------------------------------------------- STS

type assumeRoleResp struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
}

// webIdentityResp is the reply of AssumeRoleWithWebIdentity: the credentials
// are the same, the result element is named after the action.
type webIdentityResp struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

// assumeRole is sts:AssumeRole with the connector's external id. The session
// lasts one hour; a run that outlives it assumes again (see credsFor).
func (s session) assumeRole(ctx context.Context, region, roleARN, externalID, sessionName string) (sigv4.Credentials, time.Time, error) {
	p := url.Values{"RoleArn": {roleARN}, "RoleSessionName": {sessionName}, "DurationSeconds": {"3600"}}
	if externalID != "" {
		p.Set("ExternalId", externalID)
	}
	var r assumeRoleResp
	if err := s.query(ctx, svcSTS, region, "2011-06-15", "AssumeRole", p, &r); err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	c := r.Result.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return sigv4.Credentials{}, time.Time{}, fmt.Errorf("aws: sts AssumeRole returned no credentials")
	}
	exp, _ := time.Parse(time.RFC3339, c.Expiration) // zero when unparseable: assumed again on the next use
	return sigv4.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}, exp, nil
}

// assumeRoleWithWebIdentity is sts:AssumeRoleWithWebIdentity: an unsigned call
// that trades the Tessera-issued token for one hour of credentials in the role.
// No error it returns holds the token.
func (s session) assumeRoleWithWebIdentity(ctx context.Context, region, roleARN, token, sessionName string) (sigv4.Credentials, time.Time, error) {
	p := url.Values{"RoleArn": {roleARN}, "RoleSessionName": {sessionName}, "WebIdentityToken": {token}, "DurationSeconds": {"3600"}}
	var r webIdentityResp
	us := session{cl: s.cl, unsigned: true}
	if err := us.query(ctx, svcSTS, region, "2011-06-15", "AssumeRoleWithWebIdentity", p, &r); err != nil {
		return sigv4.Credentials{}, time.Time{}, redact(err, token)
	}
	c := r.Result.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return sigv4.Credentials{}, time.Time{}, fmt.Errorf("aws: sts AssumeRoleWithWebIdentity returned no credentials")
	}
	exp, _ := time.Parse(time.RFC3339, c.Expiration) // zero when unparseable: assumed again on the next use
	return sigv4.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}, exp, nil
}

// redact removes secret from an error. An AWS error keeps its code, status and
// operation; any other error that mentions the secret is replaced.
func redact(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	var ae *Error
	if errors.As(err, &ae) {
		cp := *ae
		cp.Message = strings.ReplaceAll(cp.Message, secret, "[redacted]")
		if strings.Contains(err.Error(), secret) {
			cp.Message = "[redacted]"
		}
		return &cp
	}
	if strings.Contains(err.Error(), secret) {
		return errors.New("aws: sts AssumeRoleWithWebIdentity failed (details withheld: they held the token)")
	}
	return err
}

// ---------------------------------------------------------------- IAM

type xmlTag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type xmlInline struct {
	PolicyName     string `xml:"PolicyName"`
	PolicyDocument string `xml:"PolicyDocument"` // URL-encoded (RFC 3986)
}

type xmlAttached struct {
	PolicyName string `xml:"PolicyName"`
	PolicyARN  string `xml:"PolicyArn"`
}

type xmlUser struct {
	Path       string        `xml:"Path"`
	UserName   string        `xml:"UserName"`
	UserID     string        `xml:"UserId"`
	ARN        string        `xml:"Arn"`
	Groups     []string      `xml:"GroupList>member"`
	Inline     []xmlInline   `xml:"UserPolicyList>member"`
	Attached   []xmlAttached `xml:"AttachedManagedPolicies>member"`
	BoundaryAR string        `xml:"PermissionsBoundary>PermissionsBoundaryArn"`
	Tags       []xmlTag      `xml:"Tags>member"`
}

type xmlGroup struct {
	Path      string        `xml:"Path"`
	GroupName string        `xml:"GroupName"`
	GroupID   string        `xml:"GroupId"`
	ARN       string        `xml:"Arn"`
	Inline    []xmlInline   `xml:"GroupPolicyList>member"`
	Attached  []xmlAttached `xml:"AttachedManagedPolicies>member"`
}

type xmlRole struct {
	Path       string        `xml:"Path"`
	RoleName   string        `xml:"RoleName"`
	RoleID     string        `xml:"RoleId"`
	ARN        string        `xml:"Arn"`
	Trust      string        `xml:"AssumeRolePolicyDocument"` // URL-encoded
	Inline     []xmlInline   `xml:"RolePolicyList>member"`
	Attached   []xmlAttached `xml:"AttachedManagedPolicies>member"`
	BoundaryAR string        `xml:"PermissionsBoundary>PermissionsBoundaryArn"`
	Tags       []xmlTag      `xml:"Tags>member"`
}

type xmlPolicyVersion struct {
	Document  string `xml:"Document"` // URL-encoded
	VersionID string `xml:"VersionId"`
	IsDefault bool   `xml:"IsDefaultVersion"`
}

type xmlManagedPolicy struct {
	PolicyName   string             `xml:"PolicyName"`
	ARN          string             `xml:"Arn"`
	Path         string             `xml:"Path"`
	DefaultVer   string             `xml:"DefaultVersionId"`
	Versions     []xmlPolicyVersion `xml:"PolicyVersionList>member"`
	AttachCount  int                `xml:"AttachmentCount"`
	IsAttachable bool               `xml:"IsAttachable"`
}

// authDetails is the merged result of every page of
// iam:GetAccountAuthorizationDetails for one account.
type authDetails struct {
	Users    []xmlUser
	Groups   []xmlGroup
	Roles    []xmlRole
	Policies []xmlManagedPolicy
}

type authDetailsResp struct {
	Result struct {
		IsTruncated bool               `xml:"IsTruncated"`
		Marker      string             `xml:"Marker"`
		Users       []xmlUser          `xml:"UserDetailList>member"`
		Groups      []xmlGroup         `xml:"GroupDetailList>member"`
		Roles       []xmlRole          `xml:"RoleDetailList>member"`
		Policies    []xmlManagedPolicy `xml:"Policies>member"`
	} `xml:"GetAccountAuthorizationDetailsResult"`
}

// getAccountAuthorizationDetails reads every user, group, role and managed
// policy of the account, following Marker across pages.
func (s session) getAccountAuthorizationDetails(ctx context.Context) (*authDetails, error) {
	out := &authDetails{}
	err := paginate(ctx, func(marker string) (string, error) {
		p := url.Values{"MaxItems": {"1000"}}
		if marker != "" {
			p.Set("Marker", marker)
		}
		var r authDetailsResp
		if err := s.query(ctx, svcIAM, "us-east-1", "2010-05-08", "GetAccountAuthorizationDetails", p, &r); err != nil {
			return "", err
		}
		out.Users = append(out.Users, r.Result.Users...)
		out.Groups = append(out.Groups, r.Result.Groups...)
		out.Roles = append(out.Roles, r.Result.Roles...)
		out.Policies = append(out.Policies, r.Result.Policies...)
		if r.Result.IsTruncated {
			if r.Result.Marker == "" {
				return "", fmt.Errorf("aws: iam GetAccountAuthorizationDetails: truncated page with no marker")
			}
			return r.Result.Marker, nil
		}
		return "", nil
	})
	return out, err
}

// decodeIAMDocument undoes the RFC 3986 percent-encoding IAM applies to the
// policy documents of GetAccountAuthorizationDetails. It must not turn "+"
// into a space (PathUnescape, not QueryUnescape): IAM encodes a literal plus
// as %2B and never emits "+" for a space.
func decodeIAMDocument(enc string) (string, error) {
	return url.PathUnescape(enc)
}
