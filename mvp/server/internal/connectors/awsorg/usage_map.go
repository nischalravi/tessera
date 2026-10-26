package awsorg

import (
	"regexp"
	"strings"
)

// Mapping what AWS logs to what the evaluator evaluates (issue #644). The
// evaluator speaks IAM actions ("s3:GetObject") and resource ARNs; CloudTrail
// speaks event sources ("s3.amazonaws.com") and API names, and the two differ
// for a known set of services and calls. The tables here are the exceptions;
// everything else is "<source prefix>:<event name>". A mapped action is then
// checked against the action catalog (ActionMapper.Canonical) and spelled as
// the catalog spells it, so leastpriv compares like with like; an event whose
// action is not in the catalog is counted as unmapped, never guessed.

// eventPrefixes are CloudTrail event source prefixes whose IAM prefix differs.
var eventPrefixes = map[string]string{
	"monitoring":           "cloudwatch",
	"email":                "ses",
	"tagging":              "tag",
	"streams.dynamodb":     "dynamodb",
	"sso-directory":        "sso-directory",
	"identitystore":        "identitystore",
	"elasticloadbalancing": "elasticloadbalancing",
	"cognito-idp":          "cognito-idp",
	"cognito-identity":     "cognito-identity",
	"runtime.sagemaker":    "sagemaker",
	"api.ecr":              "ecr",
	"api.sagemaker":        "sagemaker",
	"ssm-messages":         "ssmmessages",
	"ec2messages":          "ec2messages",
}

// s3Events are the S3 API names CloudTrail logs that are authorized by another
// action (HeadObject is s3:GetObject, ListObjectsV2 is s3:ListBucket, ...).
var s3Events = map[string]string{
	"ListBuckets":             "ListAllMyBuckets",
	"HeadBucket":              "ListBucket",
	"ListObjects":             "ListBucket",
	"ListObjectsV2":           "ListBucket",
	"ListObjectVersions":      "ListBucketVersions",
	"HeadObject":              "GetObject",
	"CopyObject":              "PutObject",
	"CreateMultipartUpload":   "PutObject",
	"UploadPart":              "PutObject",
	"UploadPartCopy":          "PutObject",
	"CompleteMultipartUpload": "PutObject",
	"DeleteObjects":           "DeleteObject",
	"PostObject":              "PutObject",
}

var (
	eventSourceRE = regexp.MustCompile(`^[a-z0-9.-]{1,64}\.amazonaws\.com(\.cn)?$`)
	eventNameRE   = regexp.MustCompile(`^[A-Za-z0-9]{1,128}$`)
)

// ActionMapper turns a CloudTrail event into an evaluator action.
type ActionMapper struct {
	// Canonical returns the catalog's spelling of an action and whether the
	// catalog has it (catalog.Catalog.CanonicalAction). Nil: the mapped name is
	// used as it is.
	Canonical func(action string) (string, bool)
}

// Map returns the evaluator action of an event. ok is false for an event whose
// source or name is malformed, or whose action the catalog does not know.
func (m ActionMapper) Map(eventSource, eventName string) (action string, ok bool) {
	if !eventSourceRE.MatchString(eventSource) || !eventNameRE.MatchString(eventName) {
		return "", false
	}
	prefix := eventSource[:strings.Index(eventSource, ".amazonaws.com")]
	if p, ok := eventPrefixes[prefix]; ok {
		prefix = p
	}
	name := eventName
	if prefix == "s3" {
		if n, ok := s3Events[name]; ok {
			name = n
		}
	}
	action = prefix + ":" + name
	if m.Canonical != nil {
		return m.Canonical(action)
	}
	return action, true
}

// ServiceAction is the action that stands for "the service was used" when a
// source reports no action (Access Advisor at service level): "s3:*".
func ServiceAction(namespace string) (string, bool) {
	if !serviceNSRE.MatchString(namespace) {
		return "", false
	}
	return strings.ToLower(namespace) + ":*", true
}

var serviceNSRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// ActionMapper for Access Advisor: namespace and action name to an action.
func (m ActionMapper) advisorAction(namespace, name string) (string, bool) {
	if !serviceNSRE.MatchString(namespace) || !eventNameRE.MatchString(name) {
		return "", false
	}
	a := strings.ToLower(namespace) + ":" + name
	if m.Canonical != nil {
		return m.Canonical(a)
	}
	return a, true
}

var (
	iamPrincipalRE = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:(user|role|root)(/[A-Za-z0-9_+=,.@/-]{1,512})?$`)
	arnRE          = regexp.MustCompile(`^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[^\s]{1,400}$`)
)

// ctIdentity is the part of a CloudTrail userIdentity the ingest reads.
type ctIdentity struct {
	Type           string `json:"type"`
	ARN            string `json:"arn"`
	SessionContext struct {
		SessionIssuer struct {
			Type string `json:"type"`
			ARN  string `json:"arn"`
		} `json:"sessionIssuer"`
	} `json:"sessionContext"`
}

// principalARN is the principal a usage row is filed under: the IAM user, the
// root user, or for a role session the role (the session name is not a
// principal, and the evaluator's principals are users and roles). ok is false
// for identities with no IAM principal (a service, a federated user, an
// unknown caller): their calls are not counted as the usage of anyone we
// could recommend a change for.
func principalARN(id ctIdentity) (string, bool) {
	var arn string
	switch id.Type {
	case "IAMUser", "Root":
		arn = id.ARN
	case "AssumedRole":
		if id.SessionContext.SessionIssuer.Type != "Role" {
			return "", false
		}
		arn = id.SessionContext.SessionIssuer.ARN
	default:
		return "", false
	}
	if !iamPrincipalRE.MatchString(arn) {
		return "", false
	}
	return arn, true
}

// resourceScope is the resource a row is filed under: the bucket's objects for
// an S3 object ARN (so the scope matches a policy's "bucket/*"), the first
// resource ARN otherwise, and "*" when the event names none or the run has
// already filed as many distinct scopes as it may.
func resourceScope(resources []struct {
	ARN string `json:"ARN"`
}, widen bool) string {
	if widen || len(resources) == 0 || !arnRE.MatchString(resources[0].ARN) {
		return "*"
	}
	arn := resources[0].ARN
	if rest, ok := strings.CutPrefix(arn, "arn:aws:s3:::"); ok {
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return "arn:aws:s3:::" + rest[:i] + "/*"
		}
	}
	return arn
}
