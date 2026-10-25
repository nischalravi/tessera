package awsorg

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// The three wire protocols the connector speaks, over the one signed client:
// "query" (IAM, STS, SNS, EC2: a form POST answered with XML), "json" (the
// X-Amz-Target protocols: Organizations, KMS, SQS, Secrets Manager, ECR,
// Identity Center), and REST (S3, S3 Control, Lambda).

var (
	regionRE  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	accountRE = regexp.MustCompile(`^[0-9]{12}$`)
	// bucketRE is the S3 bucket-name grammar. A name from a ListBuckets
	// response is data, and it becomes part of a host name: anything else is
	// refused rather than sent.
	bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// Service signing names.
const (
	svcIAM           = "iam"
	svcSTS           = "sts"
	svcOrganizations = "organizations"
	svcS3            = "s3"
	svcKMS           = "kms"
	svcSQS           = "sqs"
	svcSNS           = "sns"
	svcSecrets       = "secretsmanager"
	svcLambda        = "lambda"
	svcECR           = "ecr"
	svcEC2           = "ec2"
	svcSSO           = "sso"
)

// endpoint returns the host and the signing region of a service in a region.
// IAM and Organizations are global: they live in us-east-1.
func endpoint(service, region string) (host, signRegion string) {
	switch service {
	case svcIAM:
		return "iam.amazonaws.com", "us-east-1"
	case svcOrganizations:
		return "organizations.us-east-1.amazonaws.com", "us-east-1"
	case svcECR:
		return "api.ecr." + region + ".amazonaws.com", region
	}
	return service + "." + region + ".amazonaws.com", region
}

// session is a client with the credentials of one account.
type session struct {
	cl    *Client
	creds sigv4.Credentials
	// unsigned sends query calls without a signature (AssumeRoleWithWebIdentity).
	unsigned bool
}

const formType = "application/x-www-form-urlencoded; charset=utf-8"

// query calls a query-protocol action and decodes the XML response into out.
func (s session) query(ctx context.Context, service, region, version, action string, p url.Values, out any) error {
	if !regionRE.MatchString(region) {
		return fmt.Errorf("aws: invalid region %q", region)
	}
	form := url.Values{}
	for k, v := range p {
		form[k] = v
	}
	form.Set("Action", action)
	form.Set("Version", version)
	host, signRegion := endpoint(service, region)
	body, _, err := s.cl.do(ctx, s.creds, call{Service: service, Host: host, Region: signRegion, Method: http.MethodPost, Path: "/",
		Header: http.Header{"Content-Type": {formType}}, Body: []byte(encodeQuery(form)), Op: action, Unsigned: s.unsigned})
	if err != nil {
		return err
	}
	return decodeXML(body, out, service, action)
}

// jsonCall calls an X-Amz-Target action and decodes the JSON response into out.
func (s session) jsonCall(ctx context.Context, service, region, target, contentType string, in, out any) error {
	if !regionRE.MatchString(region) {
		return fmt.Errorf("aws: invalid region %q", region)
	}
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	host, signRegion := endpoint(service, region)
	op := target
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == '.' {
			op = target[i+1:]
			break
		}
	}
	body, _, err := s.cl.do(ctx, s.creds, call{Service: service, Host: host, Region: signRegion, Method: http.MethodPost, Path: "/",
		Header: http.Header{"Content-Type": {contentType}, "X-Amz-Target": {target}}, Body: b, Op: op})
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("aws: %s %s: bad JSON response: %w", service, op, err)
	}
	return nil
}

// rest sends a REST request to host and returns the raw response body.
func (s session) rest(ctx context.Context, service, region, host, op, path string, q url.Values, hdr http.Header) ([]byte, error) {
	if !regionRE.MatchString(region) {
		return nil, fmt.Errorf("aws: invalid region %q", region)
	}
	body, _, err := s.cl.do(ctx, s.creds, call{Service: service, Host: host, Region: region, Method: http.MethodGet, Path: path,
		Query: q, Header: hdr, Op: op})
	return body, err
}

func decodeXML(body []byte, out any, service, op string) error {
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(out); err != nil {
		return fmt.Errorf("aws: %s %s: bad XML response: %w", service, op, err)
	}
	return nil
}

// maxPages bounds a paginated call, so a service that keeps returning a token
// cannot make a collection run forever.
const maxPages = 100000

// paginate calls page with each token, starting with "", until it returns an
// empty next token. A repeated token is an error.
func paginate(ctx context.Context, page func(token string) (next string, err error)) error {
	token, seen := "", map[string]bool{}
	for i := 0; i < maxPages; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := page(token)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		if seen[next] {
			return fmt.Errorf("aws: pagination token repeated")
		}
		seen[next] = true
		token = next
	}
	return fmt.Errorf("aws: more than %d pages", maxPages)
}
