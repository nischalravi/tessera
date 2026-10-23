// Package kekwrap wraps and unwraps the key-encryption key (KEK) with a cloud
// key service, so the KEK never sits in plaintext in the deployment's
// configuration: TESSERA_KEK_WRAPPED holds the ciphertext and
// TESSERA_KEK_KMS names the key that opens it. The server unwraps it once at
// start with its workload identity (internal/cloudcred) and then behaves
// exactly as with TESSERA_KEK.
//
//	aws:arn:aws:kms:eu-west-1:111122223333:key/1234abcd-...   AWS KMS Encrypt/Decrypt (symmetric key)
//	azure:https://myvault.vault.azure.net/keys/tessera-kek/<version>   Key Vault wrapKey/unwrapKey (RSA-OAEP-256)
//	gcp:projects/p/locations/l/keyRings/r/cryptoKeys/k          Cloud KMS encrypt/decrypt (symmetric key)
//
// Every call is bound to the purpose "tessera-kek" (AWS encryption context,
// GCP additional authenticated data), so a ciphertext made for something else
// under the same key does not open as a KEK. All requests go through the
// SSRF-guarded client in Deps; the key reference is operator configuration,
// validated here (fixed hosts per provider), never taken from a request.
package kekwrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
)

// KEKSize is the length of a KEK in bytes.
const KEKSize = 32

const purpose = "tessera-kek"

// Ref is a validated TESSERA_KEK_KMS value.
type Ref struct {
	Provider string // aws, azure or gcp
	ID       string // the ARN, key URL or resource name
	region   string // aws: from the ARN
	vault    *url.URL
}

var (
	awsARN   = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:kms:([a-z0-9-]+):[0-9]{12}:(?:key|alias)/[A-Za-z0-9/_+=.@-]+$`)
	gcpName  = regexp.MustCompile(`^projects/[a-z0-9][a-z0-9:.-]*/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`)
	azurePat = regexp.MustCompile(`^/keys/[A-Za-z0-9-]+(/[A-Za-z0-9]+)?$`)
	vaultSfx = []string{".vault.azure.net", ".managedhsm.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net"}
)

// ParseRef validates a TESSERA_KEK_KMS value.
func ParseRef(s string) (Ref, error) {
	prov, id, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return Ref{}, errors.New("TESSERA_KEK_KMS must start with aws:, azure: or gcp:")
	}
	r := Ref{Provider: prov, ID: id}
	switch prov {
	case "aws":
		m := awsARN.FindStringSubmatch(id)
		if m == nil {
			return Ref{}, errors.New("aws: want a KMS key or alias ARN (aws:arn:aws:kms:<region>:<account>:key/<id>)")
		}
		r.region = m[1]
	case "azure":
		u, err := url.Parse(id)
		if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || !azurePat.MatchString(u.Path) {
			return Ref{}, errors.New("azure: want https://<vault>.vault.azure.net/keys/<name>[/<version>]")
		}
		okHost := false
		for _, sfx := range vaultSfx {
			okHost = okHost || (strings.HasSuffix(u.Hostname(), sfx) && len(u.Hostname()) > len(sfx))
		}
		if !okHost {
			return Ref{}, fmt.Errorf("azure: the vault host must end in one of %v", vaultSfx)
		}
		r.vault = u
	case "gcp":
		if !gcpName.MatchString(id) {
			return Ref{}, errors.New("gcp: want projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>")
		}
	default:
		return Ref{}, fmt.Errorf("unknown KMS provider %q (want aws, azure or gcp)", prov)
	}
	return r, nil
}

// String is the reference without anything secret (there is nothing secret in it).
func (r Ref) String() string { return r.Provider + ":" + r.ID }

// Deps are the process's clients and credential sources.
type Deps struct {
	HTTP  *http.Client // the guarded client
	AWS   *cloudcred.AWS
	Azure *cloudcred.Azure
	GCP   *cloudcred.GCP
	Now   func() time.Time
	// Endpoint, when set, replaces the provider's API origin (tests with a fake
	// provider server). Production code leaves it empty.
	Endpoint string
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Unwrap decrypts wrapped (the raw ciphertext) and returns the KEK bytes.
func Unwrap(ctx context.Context, r Ref, wrapped []byte, d Deps) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, errors.New("kekwrap: empty wrapped KEK")
	}
	var kek []byte
	var err error
	switch r.Provider {
	case "aws":
		kek, err = awsCall(ctx, r, d, "Decrypt", wrapped)
	case "azure":
		kek, err = azureCall(ctx, r, d, "unwrapkey", wrapped)
	case "gcp":
		kek, err = gcpCall(ctx, r, d, "decrypt", wrapped)
	default:
		err = fmt.Errorf("unknown provider %q", r.Provider)
	}
	if err != nil {
		return nil, fmt.Errorf("kekwrap: unwrap with %s: %w", r.Provider, err)
	}
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("kekwrap: the unwrapped key is %d bytes, not %d: it was not made with `tessera admin wrap-kek`", len(kek), KEKSize)
	}
	return kek, nil
}

// Wrap encrypts kek (32 bytes) with the key service.
func Wrap(ctx context.Context, r Ref, kek []byte, d Deps) ([]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("kekwrap: a KEK is %d bytes", KEKSize)
	}
	var out []byte
	var err error
	switch r.Provider {
	case "aws":
		out, err = awsCall(ctx, r, d, "Encrypt", kek)
	case "azure":
		out, err = azureCall(ctx, r, d, "wrapkey", kek)
	case "gcp":
		out, err = gcpCall(ctx, r, d, "encrypt", kek)
	default:
		err = fmt.Errorf("unknown provider %q", r.Provider)
	}
	if err != nil {
		return nil, fmt.Errorf("kekwrap: wrap with %s: %w", r.Provider, err)
	}
	return out, nil
}

const maxResp = 64 << 10

// post sends a JSON request and returns the body of a 2xx answer. Errors
// carry the status only: the body of a key-service answer is not logged.
func post(d Deps, req *http.Request, what string) ([]byte, error) {
	if d.HTTP == nil {
		return nil, errors.New("no HTTP client")
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
	if err != nil || len(b) > maxResp {
		return nil, fmt.Errorf("%s: unreadable response", what)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s%s", what, resp.Status, apiReason(b))
	}
	return b, nil
}

// apiReason extracts a short error code from a provider's JSON error (never
// the message, which may echo input).
func apiReason(b []byte) string {
	var e struct {
		Type  string `json:"__type"`
		Error struct {
			Code   any    `json:"code"`
			Status string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil {
		return ""
	}
	switch {
	case e.Type != "":
		return " (" + cleanCode(e.Type) + ")"
	case e.Error.Status != "":
		return " (" + cleanCode(e.Error.Status) + ")"
	}
	if s, ok := e.Error.Code.(string); ok && s != "" {
		return " (" + cleanCode(s) + ")"
	}
	return ""
}

var codeRE = regexp.MustCompile(`[^A-Za-z0-9_.#-]`)

func cleanCode(s string) string {
	s = codeRE.ReplaceAllString(s, "")
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func awsCall(ctx context.Context, r Ref, d Deps, op string, in []byte) ([]byte, error) {
	if d.AWS == nil {
		return nil, errors.New("no AWS credentials source")
	}
	creds, err := d.AWS.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := d.Endpoint
	if endpoint == "" {
		endpoint = "https://kms." + r.region + ".amazonaws.com/"
	}
	body := map[string]any{"KeyId": r.ID, "EncryptionContext": map[string]string{"purpose": purpose}}
	if op == "Decrypt" {
		body["CiphertextBlob"] = b64(in)
		body["EncryptionAlgorithm"] = "SYMMETRIC_DEFAULT"
	} else {
		body["Plaintext"] = b64(in)
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	if err := sigv4.Sign(req, raw, creds, r.region, "kms", d.now()); err != nil {
		return nil, err
	}
	resp, err := post(d, req, "AWS KMS "+op)
	if err != nil {
		return nil, err
	}
	var out struct{ Plaintext, CiphertextBlob string }
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, errors.New("AWS KMS: unexpected response")
	}
	field := out.Plaintext
	if op == "Encrypt" {
		field = out.CiphertextBlob
	}
	return base64.StdEncoding.DecodeString(field)
}

func azureCall(ctx context.Context, r Ref, d Deps, op string, in []byte) ([]byte, error) {
	if d.Azure == nil {
		return nil, errors.New("no Azure credentials source")
	}
	tok, err := d.Azure.Token(ctx, "https://vault.azure.net")
	if err != nil {
		return nil, err
	}
	base := r.vault.Scheme + "://" + r.vault.Host
	if d.Endpoint != "" {
		base = d.Endpoint
	}
	raw, _ := json.Marshal(map[string]string{"alg": "RSA-OAEP-256", "value": base64.RawURLEncoding.EncodeToString(in)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+r.vault.Path+"/"+op+"?api-version=7.4", strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := post(d, req, "Key Vault "+op)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.Value == "" {
		return nil, errors.New("Key Vault: unexpected response")
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(out.Value, "="))
}

func gcpCall(ctx context.Context, r Ref, d Deps, op string, in []byte) ([]byte, error) {
	if d.GCP == nil {
		return nil, errors.New("no GCP credentials source")
	}
	tok, err := d.GCP.Token(ctx, "https://www.googleapis.com/auth/cloudkms")
	if err != nil {
		return nil, err
	}
	base := "https://cloudkms.googleapis.com"
	if d.Endpoint != "" {
		base = d.Endpoint
	}
	body := map[string]string{"additionalAuthenticatedData": b64([]byte(purpose))}
	if op == "decrypt" {
		body["ciphertext"] = b64(in)
	} else {
		body["plaintext"] = b64(in)
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/"+r.ID+":"+op, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := post(d, req, "Cloud KMS "+op)
	if err != nil {
		return nil, err
	}
	var out struct{ Plaintext, Ciphertext string }
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, errors.New("Cloud KMS: unexpected response")
	}
	field := out.Plaintext
	if op == "encrypt" {
		field = out.Ciphertext
	}
	return base64.StdEncoding.DecodeString(field)
}
