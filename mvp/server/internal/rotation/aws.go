package rotation

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ---------------------------------------------------------------- shared

// awsClient signs and sends requests to one AWS endpoint.
type awsClient struct {
	http     *http.Client
	creds    awsCreds
	region   string // signing region
	endpoint string // base URL, no trailing slash
	service  string
	now      func() time.Time
}

func (a *awsClient) do(ctx context.Context, op string, req *http.Request, body []byte) (int, []byte, error) {
	req = req.WithContext(ctx)
	signV4(req, body, a.creds, a.region, a.service, a.now())
	return send(a.http, op, req)
}

var (
	regionRE  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	iamUserRE = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	keyIDRE   = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	smNameRE  = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)
)

func parseAWSTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// ---------------------------------------------------------------- IAM access keys

// iamAdapter rotates an IAM user's access key through the IAM query API.
// Target: Account is the IAM user name, Ref the access key id.
type iamAdapter struct{ awsClient }

func newIAM(c *http.Client, creds awsCreds, region, endpoint string, now func() time.Time) *iamAdapter {
	if region == "" {
		region = "us-east-1"
	}
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	return &iamAdapter{awsClient{http: c, creds: creds, region: region, endpoint: strings.TrimRight(endpoint, "/"),
		service: "iam", now: now}}
}

func (*iamAdapter) Type() string { return TypeAWSIAM }
func (*iamAdapter) Capabilities() Capabilities {
	return Capabilities{CanDisable: true, ReportsLastUsed: true, NeedsDestination: true}
}

func (*iamAdapter) Validate(t Target) error {
	if !iamUserRE.MatchString(t.Account) {
		return badRef("aws_iam", "an IAM user name as the account username")
	}
	if !keyIDRE.MatchString(t.Ref) {
		return badRef("aws_iam", "an access key id (AKIA...)")
	}
	return nil
}

type iamErrorResponse struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

func (a *iamAdapter) call(ctx context.Context, action string, params url.Values, out any) error {
	op := "iam " + action
	v := url.Values{"Action": {action}, "Version": {"2010-05-08"}}
	for k, vs := range params {
		v[k] = vs
	}
	body := []byte(v.Encode())
	req, err := http.NewRequest(http.MethodPost, a.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return fail(op, "bad_endpoint", "", false)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	status, resp, err := a.do(ctx, op, req, body)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		var e iamErrorResponse
		_ = xml.Unmarshal(resp, &e)
		code := e.Error.Code
		if code == "" {
			code = http.StatusText(status)
		}
		transient := transientStatus(status) || code == "Throttling" || code == "RequestLimitExceeded" ||
			code == "ServiceUnavailable"
		return fail(op, code, e.Error.Message, transient)
	}
	if out != nil {
		if err := xml.Unmarshal(resp, out); err != nil {
			return fail(op, "bad_response", "the response is not the expected XML", false)
		}
	}
	return nil
}

func (a *iamAdapter) Create(ctx context.Context, t Target) (*Minted, error) {
	var out struct {
		Key struct {
			ID     string `xml:"AccessKeyId"`
			Secret string `xml:"SecretAccessKey"`
		} `xml:"CreateAccessKeyResult>AccessKey"`
	}
	if err := a.call(ctx, "CreateAccessKey", url.Values{"UserName": {t.Account}}, &out); err != nil {
		return nil, err
	}
	if out.Key.ID == "" || out.Key.Secret == "" {
		return nil, fail("iam CreateAccessKey", "bad_response", "no access key in the response", false)
	}
	return &Minted{Ref: out.Key.ID, Material: map[string]string{"access_key_id": out.Key.ID,
		"secret_access_key": out.Key.Secret}}, nil
}

func (*iamAdapter) HandOver(ctx context.Context, t Target, m *Minted, dest Destination, path string) error {
	return handOverToDestination(ctx, t, m, dest, path)
}

func (a *iamAdapter) DisableOld(ctx context.Context, t Target) error {
	return a.call(ctx, "UpdateAccessKey", url.Values{"UserName": {t.Account}, "AccessKeyId": {t.Ref},
		"Status": {"Inactive"}}, nil)
}

func (a *iamAdapter) ObserveOld(ctx context.Context, t Target) (Observation, error) {
	var list struct {
		Keys []struct {
			ID      string `xml:"AccessKeyId"`
			Status  string `xml:"Status"`
			Created string `xml:"CreateDate"`
		} `xml:"ListAccessKeysResult>AccessKeyMetadata>member"`
	}
	if err := a.call(ctx, "ListAccessKeys", url.Values{"UserName": {t.Account}}, &list); err != nil {
		var e *Error
		if asError(err, &e) && e.Code == "NoSuchEntity" {
			return Observation{LastUsedKnown: true, Detail: "the IAM user no longer exists"}, nil
		}
		return Observation{}, err
	}
	obs := Observation{LastUsedKnown: true}
	for _, k := range list.Keys {
		if k.ID != t.Ref {
			continue
		}
		obs.Exists, obs.Active, obs.CreatedAt = true, k.Status == "Active", parseAWSTime(k.Created)
		obs.Detail = "status " + k.Status
	}
	if !obs.Exists {
		obs.Detail = "the access key is not listed for the user"
		return obs, nil
	}
	var used struct {
		When string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>LastUsedDate"`
	}
	if err := a.call(ctx, "GetAccessKeyLastUsed", url.Values{"AccessKeyId": {t.Ref}}, &used); err != nil {
		return Observation{}, err
	}
	obs.LastUsedAt = parseAWSTime(used.When)
	return obs, nil
}

func (a *iamAdapter) DeleteOld(ctx context.Context, t Target) error {
	return a.deleteKey(ctx, t.Account, t.Ref)
}

func (a *iamAdapter) DeleteNew(ctx context.Context, t Target, newRef string) error {
	return a.deleteKey(ctx, t.Account, newRef)
}

func (a *iamAdapter) deleteKey(ctx context.Context, user, key string) error {
	if !keyIDRE.MatchString(key) {
		return fail("iam DeleteAccessKey", "invalid_reference", "", false)
	}
	err := a.call(ctx, "DeleteAccessKey", url.Values{"UserName": {user}, "AccessKeyId": {key}}, nil)
	var e *Error
	if asError(err, &e) && e.Code == "NoSuchEntity" {
		return nil // already gone
	}
	return err
}

func (*iamAdapter) InventoryRef(_, newRef string) string { return newRef }

// ---------------------------------------------------------------- Secrets Manager

// smAdapter rotates an AWS Secrets Manager secret in place and is also a hand-over
// destination (it writes a new version of a named secret).
//
// Target: Ref is "<secret id or name>" and, once a rotation starts,
// "<secret id>#<version id>" (see Create). If the secret has rotation enabled
// (a rotation function), Tessera calls RotateSecret and lets AWS run it;
// otherwise it writes a new random value as a new version. The previous value
// is the AWSPREVIOUS version: disabling removes that label, which leaves the
// version deprecated (Secrets Manager deletes it), and Tessera never reads a
// secret value.
type smAdapter struct{ awsClient }

func newSM(c *http.Client, creds awsCreds, region, endpoint string, now func() time.Time) *smAdapter {
	if region == "" {
		region = "us-east-1"
	}
	if endpoint == "" {
		endpoint = "https://secretsmanager." + region + ".amazonaws.com"
	}
	return &smAdapter{awsClient{http: c, creds: creds, region: region, endpoint: strings.TrimRight(endpoint, "/"),
		service: "secretsmanager", now: now}}
}

func (*smAdapter) Type() string { return TypeAWSSM }
func (*smAdapter) Capabilities() Capabilities {
	// "Disable" is removing the AWSPREVIOUS label; the version itself is
	// deprecated and deleted by Secrets Manager.
	return Capabilities{CanDisable: true, ReportsLastUsed: true, MaterialFree: true}
}

func (*smAdapter) Validate(t Target) error {
	id, _, _ := splitRef(t.Ref)
	if id == "" {
		id = t.Ref
	}
	if !smNameRE.MatchString(id) && !strings.HasPrefix(id, "arn:aws") {
		return badRef("aws_secretsmanager", "the secret's name or ARN")
	}
	if len(id) > 2048 || strings.ContainsAny(id, " \t\r\n\"") {
		return badRef("aws_secretsmanager", "the secret's name or ARN")
	}
	return nil
}

type smError struct {
	Type    string `json:"__type"`
	Message string `json:"Message"`
	Lower   string `json:"message"`
}

func (a *smAdapter) call(ctx context.Context, action string, in, out any) error {
	op := "secretsmanager " + action
	body, err := json.Marshal(in)
	if err != nil {
		return fail(op, "bad_request", "", false)
	}
	req, err := http.NewRequest(http.MethodPost, a.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return fail(op, "bad_endpoint", "", false)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager."+action)
	status, resp, err := a.do(ctx, op, req, body)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		var e smError
		_ = json.Unmarshal(resp, &e)
		code := e.Type
		if i := strings.LastIndex(code, "#"); i >= 0 {
			code = code[i+1:]
		}
		if code == "" {
			code = http.StatusText(status)
		}
		msg := e.Message
		if msg == "" {
			msg = e.Lower
		}
		transient := transientStatus(status) || code == "ThrottlingException" || code == "InternalServiceError"
		return fail(op, code, msg, transient)
	}
	if out != nil {
		if err := json.Unmarshal(resp, out); err != nil {
			return fail(op, "bad_response", "the response is not the expected JSON", false)
		}
	}
	return nil
}

type smVersion struct {
	VersionID string   `json:"VersionId"`
	Stages    []string `json:"VersionStages"`
	Created   float64  `json:"CreatedDate"`
	Accessed  float64  `json:"LastAccessedDate"`
}

func (a *smAdapter) versions(ctx context.Context, secret string) ([]smVersion, error) {
	var out struct {
		Versions []smVersion `json:"Versions"`
	}
	if err := a.call(ctx, "ListSecretVersionIds", map[string]any{"SecretId": secret, "IncludeDeprecated": true}, &out); err != nil {
		return nil, err
	}
	return out.Versions, nil
}

func hasStage(v smVersion, stage string) bool {
	for _, s := range v.Stages {
		if s == stage {
			return true
		}
	}
	return false
}

func epoch(f float64) *time.Time {
	if f <= 0 {
		return nil
	}
	t := time.Unix(int64(f), 0).UTC()
	return &t
}

func (a *smAdapter) Create(ctx context.Context, t Target) (*Minted, error) {
	secret, _, _ := splitRef(t.Ref)
	if secret == "" {
		secret = t.Ref
	}
	var desc struct {
		RotationEnabled bool `json:"RotationEnabled"`
	}
	if err := a.call(ctx, "DescribeSecret", map[string]any{"SecretId": secret}, &desc); err != nil {
		return nil, err
	}
	vs, err := a.versions(ctx, secret)
	if err != nil {
		return nil, err
	}
	var current string
	for _, v := range vs {
		if hasStage(v, "AWSCURRENT") {
			current = v.VersionID
		}
	}
	if current == "" {
		return nil, fail("secretsmanager Create", "no_current_version", "the secret has no AWSCURRENT version", false)
	}
	token := store.NewID()
	if desc.RotationEnabled {
		var out struct {
			VersionID string `json:"VersionId"`
		}
		if err := a.call(ctx, "RotateSecret", map[string]any{"SecretId": secret, "ClientRequestToken": token,
			"RotateImmediately": true}, &out); err != nil {
			return nil, err
		}
		if out.VersionID != "" {
			token = out.VersionID
		}
	} else {
		value := seal.RandomString(40, "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
		if err := a.call(ctx, "PutSecretValue", map[string]any{"SecretId": secret, "ClientRequestToken": token,
			"SecretString": value}, nil); err != nil {
			return nil, err
		}
	}
	return &Minted{Ref: secret + hashSeparator + token, OldRef: secret + hashSeparator + current}, nil
}

// HandOver confirms the new version is AWSCURRENT, where consumers read it. A
// rotation function may still be running: that is a transient error, retried.
func (a *smAdapter) HandOver(ctx context.Context, t Target, _ *Minted, _ Destination, _ string) error {
	secret, newV, ok := splitRef(t.NewRef)
	if !ok {
		return fail("secretsmanager HandOver", "invalid_reference", "", false)
	}
	vs, err := a.versions(ctx, secret)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.VersionID == newV && hasStage(v, "AWSCURRENT") {
			return nil
		}
	}
	return fail("secretsmanager HandOver", "rotation_in_progress", "the new version is not AWSCURRENT yet", true)
}

func (a *smAdapter) DisableOld(ctx context.Context, t Target) error {
	secret, oldV, ok := splitRef(t.Ref)
	if !ok {
		return fail("secretsmanager DisableOld", "invalid_reference", "", false)
	}
	vs, err := a.versions(ctx, secret)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.VersionID != oldV {
			continue
		}
		if hasStage(v, "AWSCURRENT") {
			return fail("secretsmanager DisableOld", "old_version_is_current", "the old version still holds AWSCURRENT", false)
		}
		if hasStage(v, "AWSPREVIOUS") {
			return a.call(ctx, "UpdateSecretVersionStage", map[string]any{"SecretId": secret, "VersionStage": "AWSPREVIOUS",
				"RemoveFromVersionId": oldV}, nil)
		}
	}
	return nil
}

func (a *smAdapter) ObserveOld(ctx context.Context, t Target) (Observation, error) {
	secret, oldV, ok := splitRef(t.Ref)
	if !ok {
		return Observation{}, fail("secretsmanager ObserveOld", "invalid_reference", "", false)
	}
	vs, err := a.versions(ctx, secret)
	if err != nil {
		return Observation{}, err
	}
	obs := Observation{LastUsedKnown: true}
	for _, v := range vs {
		if v.VersionID != oldV {
			continue
		}
		obs.Exists, obs.Active = true, len(v.Stages) > 0
		obs.CreatedAt, obs.LastUsedAt = epoch(v.Created), epoch(v.Accessed)
		obs.Detail = "stages: " + strings.Join(v.Stages, ",")
	}
	if !obs.Exists {
		obs.Detail = "the version is gone"
	}
	return obs, nil
}

// DeleteOld takes every remaining stage off the old version, which deprecates
// it. Secrets Manager has no call to delete a version.
func (a *smAdapter) DeleteOld(ctx context.Context, t Target) error {
	secret, oldV, ok := splitRef(t.Ref)
	if !ok {
		return fail("secretsmanager DeleteOld", "invalid_reference", "", false)
	}
	vs, err := a.versions(ctx, secret)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.VersionID != oldV {
			continue
		}
		if hasStage(v, "AWSCURRENT") {
			return fail("secretsmanager DeleteOld", "old_version_is_current", "the old version still holds AWSCURRENT", false)
		}
		for _, s := range v.Stages {
			if err := a.call(ctx, "UpdateSecretVersionStage", map[string]any{"SecretId": secret, "VersionStage": s,
				"RemoveFromVersionId": oldV}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (*smAdapter) DeleteNew(context.Context, Target, string) error { return ErrUnsupported }

// InventoryRef: a secret keeps its name when its value rotates.
func (*smAdapter) InventoryRef(oldRef, _ string) string {
	if secret, _, ok := splitRef(oldRef); ok {
		return secret
	}
	return oldRef
}

// ValidatePath and Put make Secrets Manager a hand-over destination: Put writes
// a new version of the named secret, creating it if it does not exist.
func (*smAdapter) ValidatePath(path string) error {
	if !smNameRE.MatchString(path) {
		return fail("secretsmanager", "invalid_path", "a destination secret name uses letters, digits and /_+=.@-", false)
	}
	return nil
}

func (a *smAdapter) Put(ctx context.Context, path string, data map[string]string) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fail("secretsmanager Put", "bad_request", "", false)
	}
	token := store.NewID()
	err = a.call(ctx, "PutSecretValue", map[string]any{"SecretId": path, "ClientRequestToken": token,
		"SecretString": string(payload)}, nil)
	var e *Error
	if asError(err, &e) && e.Code == "ResourceNotFoundException" {
		return a.call(ctx, "CreateSecret", map[string]any{"Name": path, "ClientRequestToken": token,
			"SecretString": string(payload), "Description": "Written by Tessera secret rotation"}, nil)
	}
	return err
}
