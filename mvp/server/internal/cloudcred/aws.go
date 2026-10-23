package cloudcred

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// AWS finds credentials for SigV4 requests.
type AWS struct {
	Env
	// HTTP is the guarded client (STS). Meta is the safehttp metadata client.
	HTTP, Meta *http.Client
	// STSURL replaces https://sts.<region>.amazonaws.com/ (tests).
	STSURL string

	creds  cached[sigv4.Credentials]
	region cached[string]
}

const (
	imdsBase = "http://169.254.169.254"
	ecsBase  = "http://169.254.170.2"
)

// Region is AWS_REGION or AWS_DEFAULT_REGION, else the instance's region.
func (a *AWS) Region(ctx context.Context) (string, error) {
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := strings.TrimSpace(a.get(k)); v != "" {
			return v, nil
		}
	}
	return a.region.get(a.now(), func() (string, time.Time, error) {
		tok, err := a.imdsToken(ctx)
		if err != nil {
			return "", time.Time{}, errors.New("cloudcred: no AWS region (set AWS_REGION)")
		}
		b, err := a.imdsGet(ctx, tok, "/latest/meta-data/placement/region")
		if err != nil {
			return "", time.Time{}, err
		}
		r := strings.TrimSpace(string(b))
		if r == "" {
			return "", time.Time{}, errors.New("cloudcred: empty AWS region")
		}
		return r, a.now().Add(24 * time.Hour), nil
	})
}

// Credentials returns the current credentials, fetching new ones shortly
// before the old expire.
func (a *AWS) Credentials(ctx context.Context) (sigv4.Credentials, error) {
	if id, sec := strings.TrimSpace(a.get("AWS_ACCESS_KEY_ID")), strings.TrimSpace(a.get("AWS_SECRET_ACCESS_KEY")); id != "" && sec != "" {
		return sigv4.Credentials{AccessKeyID: id, SecretAccessKey: sec, SessionToken: strings.TrimSpace(a.get("AWS_SESSION_TOKEN"))}, nil
	}
	return a.creds.get(a.now(), func() (sigv4.Credentials, time.Time, error) {
		switch {
		case a.get("AWS_WEB_IDENTITY_TOKEN_FILE") != "" && a.get("AWS_ROLE_ARN") != "":
			return a.webIdentity(ctx)
		case a.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "":
			return a.ecs(ctx)
		}
		return a.instanceRole(ctx)
	})
}

type stsResponse struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string    `xml:"AccessKeyId"`
			SecretAccessKey string    `xml:"SecretAccessKey"`
			SessionToken    string    `xml:"SessionToken"`
			Expiration      time.Time `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

func (a *AWS) webIdentity(ctx context.Context) (sigv4.Credentials, time.Time, error) {
	tok, err := a.read(a.get("AWS_WEB_IDENTITY_TOKEN_FILE"))
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: cannot read AWS_WEB_IDENTITY_TOKEN_FILE")
	}
	endpoint := a.STSURL
	if endpoint == "" {
		region, err := a.Region(ctx)
		if err != nil {
			return sigv4.Credentials{}, time.Time{}, err
		}
		endpoint = "https://sts." + url.PathEscape(region) + ".amazonaws.com/"
	}
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {a.get("AWS_ROLE_ARN")}, "RoleSessionName": {"tessera"},
		"WebIdentityToken": {strings.TrimSpace(string(tok))}, "DurationSeconds": {"3600"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := do(a.HTTP, req, "AWS web identity")
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	var r stsResponse
	if err := xml.Unmarshal(b, &r); err != nil || r.Result.Credentials.AccessKeyID == "" {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: AWS web identity: unexpected response")
	}
	c := r.Result.Credentials
	return sigv4.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}, c.Expiration, nil
}

type roleCreds struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

func (r roleCreds) result() (sigv4.Credentials, time.Time, error) {
	if r.AccessKeyID == "" || r.SecretAccessKey == "" {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: AWS credentials response is incomplete")
	}
	return sigv4.Credentials{AccessKeyID: r.AccessKeyID, SecretAccessKey: r.SecretAccessKey, SessionToken: r.Token}, r.Expiration, nil
}

func (a *AWS) ecs(ctx context.Context) (sigv4.Credentials, time.Time, error) {
	rel := a.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if !strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: bad AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ecsBase+rel, nil)
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	b, err := do(a.Meta, req, "ECS credentials")
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	var r roleCreds
	if err := json.Unmarshal(b, &r); err != nil {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: ECS credentials: unexpected response")
	}
	return r.result()
}

func (a *AWS) imdsToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsBase+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	b, err := do(a.Meta, req, "IMDSv2 token")
	return strings.TrimSpace(string(b)), err
}

func (a *AWS) imdsGet(ctx context.Context, token, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	return do(a.Meta, req, "IMDSv2")
}

// instanceRole reads the EC2 instance profile's credentials through IMDSv2
// (session-token protected; IMDSv1 is never used).
func (a *AWS) instanceRole(ctx context.Context) (sigv4.Credentials, time.Time, error) {
	tok, err := a.imdsToken(ctx)
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, ErrNoCredentials
	}
	list, err := a.imdsGet(ctx, tok, "/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	role := strings.TrimSpace(strings.SplitN(string(list), "\n", 2)[0])
	if role == "" || strings.ContainsAny(role, "/?# ") {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: the instance has no IAM role")
	}
	b, err := a.imdsGet(ctx, tok, "/latest/meta-data/iam/security-credentials/"+role)
	if err != nil {
		return sigv4.Credentials{}, time.Time{}, err
	}
	var r roleCreds
	if err := json.Unmarshal(b, &r); err != nil {
		return sigv4.Credentials{}, time.Time{}, errors.New("cloudcred: IMDSv2: unexpected response")
	}
	return r.result()
}
