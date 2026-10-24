// Package gcpiam is the read connector for Google Cloud IAM (issue #557): the IAM policies of an
// organization, its folders and projects (Cloud Resource Manager v3 getIamPolicy), the roles those
// policies bind (IAM v1 roles.get) and the service accounts of each project (IAM v1
// serviceAccounts.list), for the effective-permission analysis. It is read-only: only GET requests
// and the getIamPolicy POST (a read) are sent, and the service account needs only viewer roles
// (Security Reviewer or Folder/Project IAM Viewer plus Service Account Viewer and Role Viewer).
//
// Authentication is a service account key: a JWT signed with the key (RS256) is exchanged at
// oauth2.googleapis.com/token for an access token. There is no Google SDK, only plain HTTP through
// the shared safehttp client.
//
// Mapping onto Tessera's model:
//
//	organization, folder, project -> resource (kind gcp_organization, gcp_folder, gcp_project)
//	role bound on a resource      -> permission "<resource>|<role>", Action = the role name, on that
//	                                 resource; privileged for basic Owner/Editor, a role that can set IAM
//	                                 policy or act as a service account (read from its permissions)
//	user:, serviceAccount: member -> account (kind user, service) -direct_grant-> permission
//	group:, domain:, allUsers, allAuthenticatedUsers, federated principals -> group -grants-> permission
//	service account of a project  -> account (kind service; disabled when the project says so)
//
// A binding holds only on the resource that carries the policy. Inheritance down the hierarchy is
// not flattened here: each resource names its parent in its tags (parent:folders/123), and the
// analysis follows them. A conditional binding is its own permission, marked "(conditional)".
package gcpiam

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name.
const System = "gcp"

// Google endpoints. A production connection reaches only these (and any *.googleapis.com name, which
// they are): an override is a dev or test setting and is refused outside dev.
const (
	DefaultCRMURL   = "https://cloudresourcemanager.googleapis.com"
	DefaultIAMURL   = "https://iam.googleapis.com"
	DefaultTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- a public endpoint URL, not a credential
	// Scope is the one OAuth scope requested. IAM v1 accepts no read-only scope; the service
	// account's own roles are what limit it, and the connector only reads.
	Scope = "https://www.googleapis.com/auth/cloud-platform"
)

// Bounds, so a source that never stops cannot keep a sync running.
const (
	maxResources = 20000
	maxRoles     = 2000
)

var (
	orgRE     = regexp.MustCompile(`^[0-9]{1,20}$`)
	projectRE = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	emailRE   = regexp.MustCompile(`^[^@\s/]{1,200}@[A-Za-z0-9.-]{1,253}$`)
	// roleRE is a role name that goes into a request path.
	roleRE = regexp.MustCompile(`^(roles|projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/roles|organizations/[0-9]{1,20}/roles)/[A-Za-z0-9_.]{1,64}$`)
)

// ErrCredential: Google refused the service account (a token endpoint answer of 400, 401 or 403).
var ErrCredential = errors.New("gcpiam: the credential was refused")

// Config configures one Google Cloud estate.
type Config struct {
	// Key is the service account key JSON.
	Key connsync.Secret
	// OrganizationID is the numeric organization id; its folders and projects are walked.
	OrganizationID string
	// FolderIDs and ProjectIDs are further roots (a folder is walked, a project is read as is).
	FolderIDs, ProjectIDs []string
	// CRMURL, IAMURL and TokenURL override the Google endpoints. Dev and test only; New refuses
	// them outside the dev runtime.
	CRMURL, IAMURL, TokenURL string
}

// Connector implements connectors.Connector for Google Cloud IAM.
type Connector struct {
	cfg      Config
	crm, iam *url.URL
	api      *connsync.Client
	tok      *tokenSource
	now      func() time.Time
	email    string
}

// New builds a connector. hc must be the server's shared outbound client (safehttp.ForConfig).
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	if cfg.OrganizationID != "" && !orgRE.MatchString(cfg.OrganizationID) {
		return nil, errors.New("gcpiam: the organization id is a number")
	}
	for _, f := range cfg.FolderIDs {
		if !orgRE.MatchString(f) {
			return nil, errors.New("gcpiam: a folder id is a number")
		}
	}
	for _, p := range cfg.ProjectIDs {
		if !projectRE.MatchString(p) {
			return nil, errors.New("gcpiam: a project id is 6 to 30 lower-case letters, digits and hyphens")
		}
	}
	if cfg.OrganizationID == "" && len(cfg.FolderIDs) == 0 && len(cfg.ProjectIDs) == 0 {
		return nil, errors.New("gcpiam: an organization, a folder or a project is required")
	}
	if hc == nil {
		return nil, errors.New("gcpiam: an internal/safehttp client is required")
	}
	key, err := parseKey(cfg.Key.Reveal())
	if err != nil {
		return nil, err
	}
	crm, err := endpoint(cfg.CRMURL, DefaultCRMURL, "Resource Manager URL", rt)
	if err != nil {
		return nil, err
	}
	iam, err := endpoint(cfg.IAMURL, DefaultIAMURL, "IAM URL", rt)
	if err != nil {
		return nil, err
	}
	tokenURL, err := endpoint(cfg.TokenURL, DefaultTokenURL, "token URL", rt)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	hc = safehttp.WithConfiguredPorts(hc, crm.String(), iam.String(), tokenURL.String())
	c := &Connector{cfg: cfg, crm: crm, iam: iam, now: now, email: key.email}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{"Accept": {"application/json"}, "User-Agent": {"tessera-connector/gcpiam"}},
		RetryOn: connsync.IsGoogleRateLimit}
	c.tok = &tokenSource{key: key, tokenURL: tokenURL.String(), now: now, api: &connsync.Client{HC: hc, Now: now, Header: c.api.Header}}
	c.api.Authorize = c.tok.authorization
	c.api.OnUnauthorized = c.tok.invalidate
	return c, nil
}

// endpoint resolves an endpoint: the Google default when raw is empty or equal to it, an override only
// in the dev runtime. In prod the host must be a Google API host.
func endpoint(raw, def, what string, rt connsync.Runtime) (*url.URL, error) {
	override := raw != "" && strings.TrimRight(raw, "/") != def
	if override && rt.Env != config.Dev {
		return nil, fmt.Errorf("gcpiam: %s: an endpoint override is a dev setting and is refused outside dev", what)
	}
	if raw == "" {
		raw = def
	}
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, fmt.Errorf("gcpiam: %s: %w", what, err)
	}
	if !override && (!strings.HasSuffix(strings.ToLower(u.Hostname()), ".googleapis.com") || u.Port() != "") {
		return nil, fmt.Errorf("gcpiam: %s: host is not a Google API endpoint", what)
	}
	return u, nil
}

func (c *Connector) System() string      { return System }
func (c *Connector) DisplayName() string { return "Google Cloud IAM" }
func (c *Connector) TypeName() string    { return "GCPIAMConnector" }

// Identity is the service account the connector signs in as.
func (c *Connector) Identity() string { return c.email }

// StreamEvents: Cloud IAM reports no usage here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// serviceAccountKey is the part of a service account key file the connector uses.
type serviceAccountKey struct {
	email, keyID string
	key          *rsa.PrivateKey
}

func parseKey(raw string) (*serviceAccountKey, error) {
	var f struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
	}
	if len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &f) != nil {
		return nil, errors.New("gcpiam: the credential must be a service account key (JSON)")
	}
	if f.Type != "service_account" || !emailRE.MatchString(f.ClientEmail) {
		return nil, errors.New("gcpiam: the credential is not a service account key")
	}
	b, _ := pem.Decode([]byte(f.PrivateKey))
	if b == nil {
		return nil, errors.New("gcpiam: the key has no private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	rk, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("gcpiam: the private key must be an RSA key in PKCS#8 form")
	}
	return &serviceAccountKey{email: f.ClientEmail, keyID: f.PrivateKeyID, key: rk}, nil
}

// assertion builds the signed JWT of the service account flow: iss the service account, the scope,
// aud the token endpoint, one hour of life, RS256.
func (k *serviceAccountKey) assertion(audience string, now time.Time) (string, error) {
	h := map[string]string{"alg": "RS256", "typ": "JWT"}
	if k.keyID != "" {
		h["kid"] = k.keyID
	}
	hdr, _ := json.Marshal(h)
	claims, _ := json.Marshal(map[string]any{"iss": k.email, "scope": Scope, "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// tokenSource exchanges the signed JWT for an access token and caches it. The key, the assertion and
// the token are never logged or put in an error.
type tokenSource struct {
	key      *serviceAccountKey
	tokenURL string
	api      *connsync.Client // without Authorize, for the token endpoint
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (t *tokenSource) authorization(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.now().Before(t.expires.Add(-time.Minute)) {
		return "Bearer " + t.token, nil
	}
	a, err := t.key.assertion(t.tokenURL, t.now())
	if err != nil {
		return "", errors.New("gcpiam: the token request cannot be signed")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a}}
	resp, err := t.api.Do(ctx, http.MethodPost, t.tokenURL, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		if s := connsync.Status(err); s == http.StatusBadRequest || s == http.StatusUnauthorized || s == http.StatusForbidden {
			return "", fmt.Errorf("gcpiam: token request: %w (%v)", ErrCredential, err)
		}
		return "", fmt.Errorf("gcpiam: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("gcpiam: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("gcpiam: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 600
	}
	t.token, t.expires = tr.AccessToken, t.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + t.token, nil
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}
