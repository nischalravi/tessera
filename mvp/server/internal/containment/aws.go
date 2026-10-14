package containment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment/sigv4"
)

// AWS IAM Identity Center. AWS has no API that ends a workforce user's
// sessions. The documented procedure
// (https://docs.aws.amazon.com/singlesignon/latest/userguide/revoke-user-permissions.html,
// prepared by prereqs-revoking-user-permissions.html) is what revoke_sessions
// automates, up to the console-only parts:
//
//  1. the identity store UserId is the account's external id (checked with
//     identitystore:DescribeUser, so a stale id fails the step);
//  2. the UserId is added to the Deny policy, a service control policy
//     prepared in advance whose condition is "identitystore:userId"
//     (organizations:DescribePolicy, then UpdatePolicy);
//  3. the user's permission set assignments are deleted
//     (sso-admin:ListAccountAssignmentsForPrincipal, DeleteAccountAssignment),
//     so no new role session can start;
//  4. deleting the AWS access portal session is console-only: it is reported
//     as a manual task;
//  5. the Deny entry stays for at least 12 hours (role sessions last up to
//     12). Tessera never removes it: a sweeper deleting entries from a policy
//     the customer owns is a risk for no gain, and an entry is 36 bytes of a
//     5,120 character policy. The manual task says when it may be removed.
//
// Verify re-reads the policy (the UserId is present) and the assignments
// (none left). The calls are signed with SigV4 (internal/containment/sigv4)
// and sent through the safehttp client.

// AWSIdentityCenter is the system name of an IAM Identity Center account.
const AWSIdentityCenter = "aws_identity_center"

// DenyConditionKey is the condition key of the Deny policy's statement
// (documented by AWS in "Prepare to revoke an active IAM role session").
const DenyConditionKey = "identitystore:userId"

// maxSCPChars is the size limit of a service control policy.
const maxSCPChars = 5120

// AWSCredential is what the AWS revoker needs. It is stored as JSON, sealed
// as the connection's containment token. Endpoint (the credential's base URL)
// replaces the endpoint of every service: a VPC endpoint, or a test server
// (requests are told apart by their X-Amz-Target header).
type AWSCredential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
	Region          string `json:"region"`            // the Identity Center region
	PolicyID        string `json:"policy_id"`         // the Deny SCP, p-...
	IdentityStoreID string `json:"identity_store_id"` // d-...
	InstanceARN     string `json:"instance_arn"`      // arn:aws:sso:::instance/ssoins-...
}

var (
	awsAccessKeyRE = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	awsRegionRE    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	awsPolicyIDRE  = regexp.MustCompile(`^p-[0-9a-z]{8,128}$`)
	awsStoreIDRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	awsInstanceRE  = regexp.MustCompile(`^arn:aws[a-z-]*:sso:::instance/ssoins-[0-9a-f]{8,64}$`)
	awsUserIDRE    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	awsAccountRE   = regexp.MustCompile(`^[0-9]{12}$`)
)

// Check reports what is wrong with the credential ("" when it is usable).
func (c AWSCredential) check() string {
	switch {
	case !awsAccessKeyRE.MatchString(c.AccessKeyID):
		return "access_key_id is required (an AWS access key id)"
	case c.SecretAccessKey == "" || len(c.SecretAccessKey) > 256:
		return "secret_access_key is required"
	case len(c.SessionToken) > 4096:
		return "session_token is too long"
	case !awsRegionRE.MatchString(c.Region):
		return "region is required (the IAM Identity Center region, for example us-east-1)"
	case !awsPolicyIDRE.MatchString(c.PolicyID):
		return "policy_id is required (the id of the Deny service control policy, p-...)"
	case !awsStoreIDRE.MatchString(c.IdentityStoreID):
		return "identity_store_id is required (d-...)"
	case !awsInstanceRE.MatchString(c.InstanceARN):
		return "instance_arn is required (arn:aws:sso:::instance/ssoins-...)"
	}
	return ""
}

// awsService is one AWS JSON-protocol service Tessera calls.
type awsService struct {
	sign, host, target string
	global             bool // signed and addressed in us-east-1 whatever the Identity Center region
}

var (
	svcOrganizations = awsService{sign: "organizations", host: "organizations", target: "AWSOrganizationsV20161128", global: true}
	svcIdentityStore = awsService{sign: "identitystore", host: "identitystore", target: "AWSIdentityStore"}
	svcSSOAdmin      = awsService{sign: "sso", host: "sso", target: "SWBExternalService"}
)

// AWS error types Tessera tells apart.
const (
	awsConcurrent = "ConcurrentModificationException"
	awsNotFound   = "ResourceNotFoundException"
	awsConflict   = "ConflictException"
)

// awsError is an AWS error answer. It carries the error type, never the body.
type awsError struct {
	Service, Op, Type string
	Status            int
}

func (e *awsError) Error() string {
	return fmt.Sprintf("aws %s %s answered %d %s", e.Service, e.Op, e.Status, e.Type)
}

func isThrottle(status int, typ string) bool {
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		return true
	}
	switch typ {
	case "ThrottlingException", "TooManyRequestsException", "Throttling", "RequestLimitExceeded", "ThrottledException":
		return true
	}
	return false
}

// ErrPolicyTooLarge: the Deny policy has no room for another user id.
var ErrPolicyTooLarge = errors.New("the Deny service control policy is full: remove user ids of past revocations (older than 12 hours) from it")

type awsRevoker struct {
	hc    *http.Client
	cred  AWSCredential
	base  *url.URL // endpoint override, nil: the AWS endpoints
	sleep sleepFunc
	now   func() time.Time
}

func newAWS(hc *http.Client, c Credential, sleep sleepFunc, now func() time.Time) (Revoker, error) {
	var ac AWSCredential
	dec := json.NewDecoder(strings.NewReader(c.Token))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ac); err != nil {
		return nil, errors.New("containment: the stored AWS credential is not readable; set it again")
	}
	if why := ac.check(); why != "" {
		return nil, errors.New("containment: AWS credential: " + why)
	}
	r := &awsRevoker{hc: hc, cred: ac, sleep: sleep, now: now}
	if r.sleep == nil {
		r.sleep = sleepCtx
	}
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("containment: base_url is not a valid URL")
		}
		u.RawQuery, u.Fragment, u.Path = "", "", ""
		r.base = u
	}
	return r, nil
}

// call sends one signed request. Throttling is retried after Retry-After (or
// a short backoff); other errors return an *awsError.
func (a *awsRevoker) call(ctx context.Context, svc awsService, op string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	region := a.cred.Region
	if svc.global {
		region = "us-east-1"
	}
	endpoint := a.base
	if endpoint == nil {
		endpoint = &url.URL{Scheme: "https", Host: svc.host + "." + region + ".amazonaws.com"}
	}
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String()+"/", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", svc.target+"."+op)
		cr := sigv4.Credentials{AccessKeyID: a.cred.AccessKeyID, SecretAccessKey: a.cred.SecretAccessKey,
			SessionToken: a.cred.SessionToken}
		if err := sigv4.Sign(req, payload, cr, region, svc.sign, a.now()); err != nil {
			return err
		}
		resp, err := a.hc.Do(req) // #nosec G704 -- hc is an internal/safehttp client
		if err != nil {
			return fmt.Errorf("aws %s %s: %w", svc.sign, op, scrub(err))
		}
		raw, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr != nil {
			return fmt.Errorf("aws %s %s: %w", svc.sign, op, scrub(rerr))
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			if out != nil && len(bytes.TrimSpace(raw)) > 0 {
				if err := json.Unmarshal(raw, out); err != nil {
					return fmt.Errorf("aws %s %s: unreadable answer", svc.sign, op)
				}
			}
			return nil
		}
		ae := &awsError{Service: svc.sign, Op: op, Status: resp.StatusCode, Type: awsErrorType(resp.Header, raw)}
		if isThrottle(ae.Status, ae.Type) {
			if attempt >= maxAttempts {
				return fmt.Errorf("aws %s %s: %w", svc.sign, op, ErrRateLimited)
			}
			if err := a.sleep(ctx, retryWait(resp.Header.Get("Retry-After"), attempt)); err != nil {
				return err
			}
			continue
		}
		return ae
	}
}

// awsErrorType extracts the error type from the x-amzn-ErrorType header or
// the body's __type ("com.amazonaws.organizations#ConcurrentModificationException").
func awsErrorType(h http.Header, body []byte) string {
	t := h.Get("X-Amzn-Errortype")
	if t == "" {
		var b struct {
			Type string `json:"__type"`
			Code string `json:"code"`
		}
		if json.Unmarshal(body, &b) == nil {
			if t = b.Type; t == "" {
				t = b.Code
			}
		}
	}
	if i := strings.IndexAny(t, ":"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "#"); i >= 0 {
		t = t[i+1:]
	}
	if len(t) > 64 || strings.ContainsAny(t, " \r\n\t\"") {
		return ""
	}
	return t
}

func isAWSType(err error, typ string) bool {
	var ae *awsError
	return errors.As(err, &ae) && ae.Type == typ
}

// ---------------------------------------------------------------- the Deny policy

// denyStatement finds the condition value of the Deny statement keyed by
// DenyConditionKey. It returns the statement's StringEquals map.
func denyCondition(doc map[string]any) (map[string]any, bool) {
	var stmts []any
	switch s := doc["Statement"].(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	}
	for _, s := range stmts {
		st, _ := s.(map[string]any)
		if st["Effect"] != "Deny" {
			continue
		}
		cond, _ := st["Condition"].(map[string]any)
		eq, _ := cond["StringEquals"].(map[string]any)
		if _, ok := eq[DenyConditionKey]; ok {
			return eq, true
		}
	}
	return nil, false
}

func condValues(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

var errNoDenyStatement = errors.New("the policy has no Deny statement with the " + DenyConditionKey +
	" condition: create the Deny policy first (see the README)")

// policyHasUser reports whether the Deny policy content names userID.
func policyHasUser(content, userID string) (bool, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return false, errors.New("the Deny policy is not valid JSON")
	}
	eq, ok := denyCondition(doc)
	if !ok {
		return false, errNoDenyStatement
	}
	return slices.Contains(condValues(eq[DenyConditionKey]), userID), nil
}

// addUserToPolicy returns the policy content with userID in the Deny list,
// and whether it changed.
func addUserToPolicy(content, userID string) (string, bool, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return "", false, errors.New("the Deny policy is not valid JSON")
	}
	eq, ok := denyCondition(doc)
	if !ok {
		return "", false, errNoDenyStatement
	}
	vals := condValues(eq[DenyConditionKey])
	if slices.Contains(vals, userID) {
		return content, false, nil
	}
	list := make([]any, 0, len(vals)+1)
	for _, v := range vals {
		list = append(list, v)
	}
	eq[DenyConditionKey] = append(list, userID)
	out, err := json.Marshal(doc)
	if err != nil {
		return "", false, err
	}
	if len(out) > maxSCPChars {
		return "", false, ErrPolicyTooLarge
	}
	return string(out), true, nil
}

type describePolicyOut struct {
	Policy struct {
		Content string `json:"Content"`
	} `json:"Policy"`
}

func (a *awsRevoker) policy(ctx context.Context) (string, error) {
	var out describePolicyOut
	if err := a.call(ctx, svcOrganizations, "DescribePolicy", map[string]string{"PolicyId": a.cred.PolicyID}, &out); err != nil {
		return "", err
	}
	return out.Policy.Content, nil
}

// denyUser adds userID to the Deny policy. A concurrent edit of the policy
// (ConcurrentModificationException) is retried from a fresh read.
func (a *awsRevoker) denyUser(ctx context.Context, userID string) error {
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var content string
		if content, err = a.policy(ctx); err != nil {
			return err
		}
		next, changed, perr := addUserToPolicy(content, userID)
		if perr != nil {
			return perr
		}
		if !changed {
			return nil
		}
		err = a.call(ctx, svcOrganizations, "UpdatePolicy", map[string]string{"PolicyId": a.cred.PolicyID, "Content": next}, nil)
		var ae *awsError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &ae) && ae.Type == awsConcurrent:
			if serr := a.sleep(ctx, retryWait("", attempt)); serr != nil {
				return serr
			}
		case errors.As(err, &ae) && ae.Type == "ConstraintViolationException":
			return fmt.Errorf("%w (%s)", ErrPolicyTooLarge, ae)
		default:
			return err
		}
	}
	return err
}

// ---------------------------------------------------------------- assignments

type awsAssignment struct {
	AccountID        string `json:"AccountId"`
	PermissionSetARN string `json:"PermissionSetArn"`
}

// maxAssignments bounds one revoke (a user with more is revoked in several passes).
const maxAssignments = 500

func (a *awsRevoker) assignments(ctx context.Context, userID string) ([]awsAssignment, error) {
	var all []awsAssignment
	token := ""
	for {
		in := map[string]any{"InstanceArn": a.cred.InstanceARN, "PrincipalId": userID, "PrincipalType": "USER", "MaxResults": 100}
		if token != "" {
			in["NextToken"] = token
		}
		var out struct {
			AccountAssignments []awsAssignment `json:"AccountAssignments"`
			NextToken          string          `json:"NextToken"`
		}
		if err := a.call(ctx, svcSSOAdmin, "ListAccountAssignmentsForPrincipal", in, &out); err != nil {
			return nil, err
		}
		all = append(all, out.AccountAssignments...)
		if out.NextToken == "" || len(all) >= maxAssignments {
			return all, nil
		}
		token = out.NextToken
	}
}

type awsDeletionStatus struct {
	Status        string `json:"Status"`
	RequestID     string `json:"RequestId"`
	FailureReason string `json:"FailureReason"`
}

// deletePolls is how often a deletion is polled before the step fails (and retries).
const deletePolls = 6

func (a *awsRevoker) deleteAssignment(ctx context.Context, userID string, as awsAssignment) error {
	if !awsAccountRE.MatchString(as.AccountID) || !strings.HasPrefix(as.PermissionSetARN, "arn:") {
		return errors.New("aws returned an unexpected account assignment")
	}
	in := map[string]string{"InstanceArn": a.cred.InstanceARN, "TargetId": as.AccountID, "TargetType": "AWS_ACCOUNT",
		"PermissionSetArn": as.PermissionSetARN, "PrincipalType": "USER", "PrincipalId": userID}
	var out struct {
		Status awsDeletionStatus `json:"AccountAssignmentDeletionStatus"`
	}
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err = a.call(ctx, svcSSOAdmin, "DeleteAccountAssignment", in, &out); err == nil || !isAWSType(err, awsConflict) {
			break
		}
		// another assignment operation is in progress: wait and try again
		if serr := a.sleep(ctx, retryWait("", attempt)); serr != nil {
			return serr
		}
	}
	if err != nil {
		if isAWSType(err, awsNotFound) {
			return nil // already gone
		}
		return err
	}
	st := out.Status
	for poll := 1; st.Status != "SUCCEEDED"; poll++ {
		if st.Status == "FAILED" {
			return fmt.Errorf("aws could not delete an account assignment: %s", truncateText(st.FailureReason, 120))
		}
		if poll > deletePolls || st.RequestID == "" {
			return errors.New("aws is still deleting an account assignment")
		}
		if err := a.sleep(ctx, retryWait("", poll)); err != nil {
			return err
		}
		var d struct {
			Status awsDeletionStatus `json:"AccountAssignmentDeletionStatus"`
		}
		err := a.call(ctx, svcSSOAdmin, "DescribeAccountAssignmentDeletionStatus", map[string]string{
			"InstanceArn": a.cred.InstanceARN, "AccountAssignmentDeletionRequestId": st.RequestID}, &d)
		if err != nil {
			return err
		}
		st = d.Status
		if st.RequestID == "" {
			st.RequestID = out.Status.RequestID
		}
	}
	return nil
}

func truncateText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- Revoker

func (a *awsRevoker) check(t Target) error {
	if !awsUserIDRE.MatchString(t.UserID) {
		return ErrBadTarget
	}
	return nil
}

// awsManual are the parts of the procedure no API can do.
var awsManual = []string{
	"Delete the user's AWS access portal session: IAM Identity Center console, Users, the user, Active sessions, Delete session. AWS offers no API for it.",
	"If the user signs in through an external identity provider or Active Directory, disable the user there; access granted through groups is not removed by Tessera, so remove the user from those groups at the source.",
	"Leave the user id in the Deny service control policy for at least 12 hours (until role sessions have expired). Tessera never removes it; remove the entry by hand after that.",
}

// RevokeSessions follows the documented procedure: the user must exist, the
// Deny policy names the user, and the user's permission set assignments are
// deleted.
func (a *awsRevoker) RevokeSessions(ctx context.Context, t Target) (Outcome, error) {
	if err := a.check(t); err != nil {
		return Outcome{}, err
	}
	err := a.call(ctx, svcIdentityStore, "DescribeUser", map[string]string{"IdentityStoreId": a.cred.IdentityStoreID, "UserId": t.UserID}, nil)
	if isAWSType(err, awsNotFound) {
		return Outcome{}, fmt.Errorf("%w: identity store user", ErrNotFound)
	}
	if err != nil {
		return Outcome{}, err
	}
	if err := a.denyUser(ctx, t.UserID); err != nil {
		return Outcome{}, err
	}
	assigned, err := a.assignments(ctx, t.UserID)
	if err != nil {
		return Outcome{}, err
	}
	for _, as := range assigned {
		if err := a.deleteAssignment(ctx, t.UserID, as); err != nil {
			return Outcome{}, err
		}
	}
	return Outcome{Revoked: 1 + len(assigned), Manual: slices.Clone(awsManual)}, nil
}

// RevokeGrants: IAM Identity Center has no OAuth consents to revoke (the
// assignments go with revoke_sessions), so the step does not exist for it.
func (a *awsRevoker) RevokeGrants(context.Context, Target) (Outcome, error) {
	return Outcome{}, errors.New("aws_identity_center has no revoke_grants step")
}

// Verify re-reads the Deny policy (it names the user) and the assignments
// (none left). A missing Deny entry or a remaining assignment counts as a
// remaining session.
func (a *awsRevoker) Verify(ctx context.Context, t Target, _ time.Time, c Check) (Remaining, error) {
	var r Remaining
	if err := a.check(t); err != nil {
		return r, err
	}
	if c&CheckSessions == 0 {
		return r, nil
	}
	content, err := a.policy(ctx)
	if err != nil {
		return r, err
	}
	has, err := policyHasUser(content, t.UserID)
	if err != nil {
		return r, err
	}
	if !has {
		r.Sessions++
	}
	left, err := a.assignments(ctx, t.UserID)
	if err != nil {
		return r, err
	}
	r.Sessions += len(left)
	r.Unverified = append(r.Unverified, "aws access portal session: no API lists or ends it; the Deny policy and the removed assignments stop role sessions")
	return r, nil
}
