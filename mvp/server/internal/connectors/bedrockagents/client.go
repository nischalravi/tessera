// Package bedrockagents inventories the agents of Amazon Bedrock Agents (issue #562) through the bedrock-agent
// control-plane API: each agent, its execution role, foundation model, enabled action groups (the tools it can
// call) and knowledge bases, as an ai_agent non-human identity linked to its owner. It is read-only: only
// list and get operations are sent (the list operations of this API are POSTs, and are reads).
//
// Authentication is an IAM user or role key pair (the connection's credential, JSON with access_key_id,
// secret_access_key and optionally session_token), signed with SigV4 (service "bedrock") by internal/aws/sigv4.
// There is no AWS SDK. The one policy the key needs is BedrockAgentsReaderPolicy.
//
// Mapping, per agent:
//
//	identity  bedrock:<agent id>, type ai_agent, owned by its "sponsor" (or "owner") tag, a person's e-mail address
//	account   <agent id>, kind agent; an agent record of kind bedrock_agent (creator: the "creator" tag)
//	access    the execution role (assume_role), the foundation model (bedrock:InvokeModel), each ENABLED action
//	          group (lambda:InvokeFunction on its Lambda, or return_control when the caller runs the action;
//	          privileged for the code interpreter) and each ENABLED knowledge base (bedrock:Retrieve), each a
//	          direct_grant from the agent. A "pii" tag with the value true marks everything the agent reaches
//	          as holding PII, so the ai-agents-no-pii policy applies.
//
// What the execution role itself can do is the AWS Organizations connector's job (it reads IAM): the agent
// links to the role by ARN.
package bedrockagents

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
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const (
	signingName = "bedrock" // the signing name of the bedrock-agent API
	pageSize    = 100
	maxPages    = 200
	maxAgents   = 5000
	maxAttempts = 5
)

var (
	regionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d{1,2}$`)
	keyIDRE  = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	// idRE is an agent, action group or knowledge base id: AWS ids are 10 upper-case letters and digits.
	idRE = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	// arnRE is an ARN that goes into a request path or a graph id.
	arnRE = regexp.MustCompile(`^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:[A-Za-z0-9_+=,.@:/-]{1,512}$`)
)

// ErrCredential: AWS refused the keys (401, or 403 with an authentication error code).
var ErrCredential = errors.New("bedrockagents: the credential was refused")

// ReaderPolicy is the IAM policy the connection's key needs: list and get on agents, and their tags.
const ReaderPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["bedrock:ListAgents","bedrock:GetAgent",` +
	`"bedrock:ListAgentActionGroups","bedrock:GetAgentActionGroup","bedrock:ListAgentKnowledgeBases","bedrock:ListTagsForResource"],"Resource":"*"}]}`

// Config configures one region of one account.
type Config struct {
	// Region is the AWS region whose agents are read.
	Region string
	// Secret is the credential JSON.
	Secret connsync.Secret
	// AgentURL overrides the bedrock-agent endpoint. Dev and test only; Open refuses it outside dev.
	AgentURL string
	// Sleep waits between attempts (default: a timer that ends with ctx). Tests replace it.
	Sleep func(context.Context, time.Duration) error
}

type credentialJSON struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

// Client is a signed, retrying bedrock-agent client.
type Client struct {
	hc    *http.Client
	base  *url.URL
	creds sigv4.Credentials
	cfg   Config
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// Open validates cfg and returns the client. hc must be the server's shared safehttp client.
func Open(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Client, error) {
	if hc == nil {
		return nil, errors.New("bedrockagents: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	if !regionRE.MatchString(cfg.Region) {
		return nil, errors.New("bedrockagents: the region is an AWS region name such as us-east-1")
	}
	var cj credentialJSON
	dec := json.NewDecoder(strings.NewReader(cfg.Secret.Reveal()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cj); err != nil {
		return nil, connsync.CredentialFormat("bedrockagents: the credential is JSON with access_key_id and secret_access_key (and optionally session_token)")
	}
	if !keyIDRE.MatchString(cj.AccessKeyID) || len(cj.SecretAccessKey) < 16 || len(cj.SecretAccessKey) > 256 || strings.ContainsAny(cj.SecretAccessKey, " \t\r\n") ||
		len(cj.SessionToken) > 4096 || strings.ContainsAny(cj.SessionToken, " \t\r\n") {
		return nil, connsync.CredentialFormat("bedrockagents: the credential's access key id or secret is malformed")
	}
	base, err := endpoint(cfg, rt)
	if err != nil {
		return nil, err
	}
	return &Client{hc: hc, base: base, cfg: cfg, now: now, creds: sigv4.Credentials{AccessKeyID: cj.AccessKeyID, SecretAccessKey: cj.SecretAccessKey,
		SessionToken: cj.SessionToken}, sleep: sleepFn(cfg.Sleep)}, nil
}

// DefaultURL is the public bedrock-agent endpoint of a region.
func DefaultURL(region string) string {
	suffix := ".amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = ".amazonaws.com.cn"
	}
	return "https://bedrock-agent." + region + suffix
}

func endpoint(cfg Config, rt connsync.Runtime) (*url.URL, error) {
	def := DefaultURL(cfg.Region)
	override := cfg.AgentURL != "" && strings.TrimRight(cfg.AgentURL, "/") != def
	if override && rt.Env != config.Dev {
		return nil, errors.New("bedrockagents: an endpoint override is a dev setting and is refused outside dev")
	}
	raw := cfg.AgentURL
	if raw == "" {
		raw = def
	}
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, fmt.Errorf("bedrockagents: endpoint: %w", err)
	}
	if !override && (u.Hostname() != strings.TrimPrefix(def, "https://") || u.Port() != "" || u.Path != "") {
		return nil, errors.New("bedrockagents: the host is not the Bedrock agent endpoint of the region")
	}
	return u, nil
}

// Identity is the access key id the client signs as, for a prober.
func (c *Client) Identity() string { return c.creds.AccessKeyID }

// Mode names how the client authenticates, for a prober.
func (c *Client) Mode() string {
	if c.creds.SessionToken != "" {
		return "sigv4_session"
	}
	return "sigv4_access_key"
}

// apiError is a non-2xx answer: the status and AWS's error type token, never the message.
type apiError struct {
	Op     string
	Status int
	Code   string
}

func (e *apiError) Error() string {
	s := fmt.Sprintf("bedrockagents: %s: HTTP %d", e.Op, e.Status)
	if e.Code != "" {
		s += " (" + e.Code + ")"
	}
	return s
}

// Status returns the HTTP status of an API error in err's chain, or 0.
func Status(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

var authCodes = map[string]bool{"UnrecognizedClientException": true, "InvalidSignatureException": true, "ExpiredTokenException": true,
	"IncompleteSignature": true, "InvalidClientTokenId": true, "SignatureDoesNotMatch": true, "MissingAuthenticationToken": true}

// errCode reads the short error type of an AWS REST-JSON answer.
func errCode(h http.Header) string {
	c, _, _ := strings.Cut(h.Get("X-Amzn-Errortype"), ":")
	if len(c) > 64 {
		return ""
	}
	for _, r := range c {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return ""
		}
	}
	return c
}

// do sends one signed request (retrying throttling and 5xx) and decodes a JSON object answer into v. The
// path is its decoded segments; each goes on the wire strictly encoded (an ARN's ":" and "/" too).
func (c *Client) do(ctx context.Context, op, method string, segs []string, body any, v any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return errors.New("bedrockagents: cannot encode the request")
		}
	}
	var last error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := time.Duration(1<<attempt) * 200 * time.Millisecond
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
		}
		status, hdr, data, err := c.once(ctx, method, segs, payload)
		if err != nil {
			return err
		}
		switch {
		case status >= 200 && status < 300:
			if v == nil {
				return nil
			}
			return connsync.DecodeJSON(data, v)
		case status == http.StatusTooManyRequests || status >= 500 || errCode(hdr) == "ThrottlingException":
			last = &apiError{Op: op, Status: status, Code: errCode(hdr)}
			continue
		}
		ae := &apiError{Op: op, Status: status, Code: errCode(hdr)}
		if status == http.StatusUnauthorized || status == http.StatusForbidden && authCodes[ae.Code] {
			return fmt.Errorf("%w: %w", ErrCredential, ae)
		}
		return ae
	}
	return fmt.Errorf("bedrockagents: %s: gave up after %d attempts: %w", op, maxAttempts, last)
}

func (c *Client) once(ctx context.Context, method string, segs []string, payload []byte) (int, http.Header, []byte, error) {
	u := *c.base
	enc := make([]string, len(segs))
	for i, s := range segs {
		enc[i] = sigv4.Encode(s)
	}
	u.Path, u.RawPath = "/"+strings.Join(segs, "/"), "/"+strings.Join(enc, "/")
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return 0, nil, nil, errors.New("bedrockagents: cannot build the request")
	}
	req.Header.Set("User-Agent", "tessera-connector/bedrock-agents")
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// req.URL keeps the strictly encoded RawPath, and the signer canonicalises its segments: an ARN segment
	// ("%3A", "%2F" on the wire) signs as "%253A", "%252F", as AWS canonicalises a non-S3 path
	if err := sigv4.Sign(req, payload, c.creds, c.cfg.Region, signingName, c.now()); err != nil {
		return 0, nil, nil, errors.New("bedrockagents: cannot sign the request")
	}
	resp, err := c.hc.Do(req) // #nosec G107 G704 -- hc is the SSRF-guarded safehttp client; the host is the region's Bedrock endpoint
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, nil, fmt.Errorf("bedrockagents: request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, errors.New("bedrockagents: the response could not be read")
	}
	return resp.StatusCode, resp.Header, data, nil
}

// Format prints the client without its credentials (every verb): fmt cannot call the redacting methods of
// unexported fields, so a bare %+v would show the keys.
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "bedrockagents.Client{"+c.cfg.Region+"}")
}

func sleepFn(f func(context.Context, time.Duration) error) func(context.Context, time.Duration) error {
	if f != nil {
		return f
	}
	return connsync.SleepCtx
}
