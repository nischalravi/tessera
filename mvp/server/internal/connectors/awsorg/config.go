package awsorg

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// DefaultRoleName is the name of the read-only role the connector assumes in
// every account (the customer creates it; see ReaderPolicy).
const DefaultRoleName = "TesseraReader"

// Limits on connector input. They bound what one API call can make the
// collector do.
const (
	MaxRegions  = 30
	MaxAccounts = 1000
)

var roleNameRE = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)

// Config is a connector's non-secret settings (aws_connectors.config).
type Config struct {
	// RoleName is the role assumed in each account (default TesseraReader).
	RoleName string `json:"role_name"`
	// Regions are the regions of the regional services (S3 access points,
	// KMS, SQS, SNS, Secrets Manager, Lambda, ECR, VPC endpoints). The first
	// is also where STS and S3's ListBuckets are called.
	Regions []string `json:"regions"`
	// AccountIDs are the accounts to read. With ManagementAccountID set they
	// limit the organization's accounts to these; empty means all active ones.
	AccountIDs []string `json:"account_ids"`
	// ManagementAccountID, when set, makes the run organization-wide: the
	// management account is read for the Organizations tree, SCPs and RCPs.
	ManagementAccountID string `json:"management_account_id"`
	// IdentityCenterRegion is the region of the IAM Identity Center instance;
	// empty skips Identity Center.
	IdentityCenterRegion string `json:"identity_center_region"`
	// Usage turns on usage ingest (CloudTrail, Access Advisor); nil: none.
	Usage *UsageConfig `json:"usage,omitempty"`
	// Auth is how the connector gets AWS credentials: AuthFederated (STS
	// AssumeRoleWithWebIdentity with a Tessera-issued token; nothing secret is
	// stored) or AuthStaticKey (a sealed access key; only where the server
	// allows it). A config stored before federation has none: AuthStaticKey.
	Auth string `json:"auth,omitempty"`
}

// The connector's authentication modes.
const (
	AuthFederated = "federated"
	AuthStaticKey = "static_key"
)

// Mode is the effective authentication mode.
func (c *Config) Mode() string {
	if c.Auth == "" {
		return AuthStaticKey
	}
	return c.Auth
}

// Validate normalizes c (default role name, sorted unique ids) and checks
// every field against its grammar.
func (c *Config) Validate() error {
	if c.RoleName == "" {
		c.RoleName = DefaultRoleName
	}
	if !roleNameRE.MatchString(c.RoleName) {
		return errors.New("role_name is not a valid IAM role name")
	}
	if c.Auth != "" && c.Auth != AuthFederated && c.Auth != AuthStaticKey {
		return errors.New("auth must be federated or static_key")
	}
	if len(c.Regions) == 0 || len(c.Regions) > MaxRegions {
		return fmt.Errorf("regions: between 1 and %d regions are required", MaxRegions)
	}
	seen := map[string]bool{}
	for _, r := range c.Regions {
		if !regionRE.MatchString(r) {
			return fmt.Errorf("regions: %q is not a region name", clip(r, 40))
		}
		if seen[r] {
			return fmt.Errorf("regions: %q is listed twice", r)
		}
		seen[r] = true
	}
	if c.IdentityCenterRegion != "" && !regionRE.MatchString(c.IdentityCenterRegion) {
		return errors.New("identity_center_region is not a region name")
	}
	if len(c.AccountIDs) > MaxAccounts {
		return fmt.Errorf("account_ids: at most %d accounts", MaxAccounts)
	}
	for _, a := range c.AccountIDs {
		if !accountRE.MatchString(a) {
			return fmt.Errorf("account_ids: %q is not a 12-digit account id", clip(a, 20))
		}
	}
	slices.Sort(c.AccountIDs)
	c.AccountIDs = slices.Compact(c.AccountIDs)
	if c.ManagementAccountID != "" && !accountRE.MatchString(c.ManagementAccountID) {
		return errors.New("management_account_id is not a 12-digit account id")
	}
	if c.ManagementAccountID == "" && len(c.AccountIDs) == 0 {
		return errors.New("account_ids: list the accounts to read, or set management_account_id")
	}
	if c.Usage != nil {
		return c.Usage.validate(c)
	}
	return nil
}

// ParseConfig decodes and validates a stored config.
func ParseConfig(raw []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("awsorg: bad connector config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("awsorg: bad connector config: %w", err)
	}
	return &c, nil
}

// Credentials are the access keys the connector signs its STS AssumeRole
// calls with. They are sealed at rest (SealCredentials) and never returned by
// the API. The keys' only permission should be sts:AssumeRole on the reader
// role; everything the connector reads it reads as that role.
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// String never reveals the secret.
func (c Credentials) String() string { return "awsorg.Credentials{REDACTED}" }

// GoString never reveals the secret (fmt %#v).
func (c Credentials) GoString() string { return c.String() }

func toSigV4(c Credentials) sigv4.Credentials {
	return sigv4.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
}

var accessKeyRE = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)

// Validate checks the shape of the keys (not that AWS accepts them).
func (c Credentials) Validate() error {
	if !accessKeyRE.MatchString(c.AccessKeyID) {
		return errors.New("credentials: access_key_id is not an access key id")
	}
	if n := len(c.SecretAccessKey); n < 16 || n > 256 || strings.ContainsAny(c.SecretAccessKey, " \t\r\n") {
		return errors.New("credentials: secret_access_key is not a secret access key")
	}
	if len(c.SessionToken) > 4096 || strings.ContainsAny(c.SessionToken, " \t\r\n") {
		return errors.New("credentials: session_token is not a session token")
	}
	return nil
}

// credentialsAAD binds a sealed credential to its tenant, table, column and
// connector, so the blob cannot be copied to another tenant or connector.
func credentialsAAD(t tenancy.ID, connectorID string) []byte {
	return seal.AAD(t, "aws_connectors", "credentials_enc", connectorID)
}

// SealCredentials seals c for the connector id of tenant t.
func SealCredentials(s *seal.Sealer, t tenancy.ID, connectorID string, c Credentials) ([]byte, error) {
	if s == nil {
		return nil, errors.New("awsorg: no sealer")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(c) // #nosec G117 -- the plaintext is sealed on the next line and never stored or logged
	if err != nil {
		return nil, err
	}
	return s.Seal(b, credentialsAAD(t, connectorID))
}

// OpenCredentials opens credentials sealed by SealCredentials. It fails
// (seal.ErrOpen) for another tenant, another connector or a tampered blob.
func OpenCredentials(s *seal.Sealer, t tenancy.ID, connectorID string, sealed []byte) (Credentials, error) {
	var c Credentials
	if s == nil {
		return c, errors.New("awsorg: no sealer")
	}
	b, err := s.Open(sealed, credentialsAAD(t, connectorID))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, errors.New("awsorg: sealed credentials are malformed")
	}
	return c, c.Validate()
}
