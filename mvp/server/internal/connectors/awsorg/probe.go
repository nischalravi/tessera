package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
)

// ProbeResult is what the readiness probe saw: counts and identifiers, never
// policy text or credentials.
type ProbeResult struct {
	// RoleARN is the reader role assumed (the management account's for an
	// organization, otherwise the first configured account's).
	RoleARN string
	// OrgID is set for an organization-wide connector.
	OrgID string
	// Accounts is the number of accounts the connector would read: the
	// organization's top-level accounts, or the configured ones.
	Accounts int
}

// Probe is the read-only access check of a connector (deployment readiness):
// sts:AssumeRole into the reader role of the management account (or of the
// first configured account) and, for an organization, Organizations
// DescribeOrganization and one page of accounts. It reads no policy and
// stores nothing; Collect is the full read.
func (c *Collector) Probe(ctx context.Context) (*ProbeResult, error) {
	if err := c.Config.Validate(); err != nil {
		return nil, err
	}
	account := c.Config.ManagementAccountID
	if account == "" {
		if len(c.Config.AccountIDs) == 0 {
			return nil, errors.New("awsorg: no account is configured")
		}
		account = c.Config.AccountIDs[0]
	}
	s, err := c.assume(ctx, map[string]*accountSession{}, account)
	if err != nil {
		return nil, fmt.Errorf("awsorg: assume the reader role: %w", err)
	}
	res := &ProbeResult{RoleARN: "arn:aws:iam::" + account + ":role/" + c.Config.RoleName, Accounts: len(c.Config.AccountIDs)}
	if c.Config.ManagementAccountID == "" {
		return res, nil
	}
	info, err := s.describeOrganization(ctx)
	if err != nil {
		return nil, fmt.Errorf("awsorg: read the organization: %w", err)
	}
	res.OrgID = info.ID
	roots, err := s.listRoots(ctx)
	if err != nil {
		return nil, fmt.Errorf("awsorg: read the organization: %w", err)
	}
	res.Accounts = 0
	for _, r := range roots {
		as, err := s.listAccounts(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("awsorg: read the organization: %w", err)
		}
		res.Accounts += len(as)
	}
	return res, nil
}

// ConfigOf is the connector configuration of a governed connection's settings
// (role_name, regions, account_ids, management_account_id, identity_center_region).
// A governed connection holds its access key, so it is a static-key config.
func ConfigOf(p governed.Params) Config {
	s := func(k string) string { return strings.TrimSpace(p.Settings[k]) }
	return Config{RoleName: s("role_name"), Regions: governed.List(s("regions")), AccountIDs: governed.List(s("account_ids")),
		ManagementAccountID: s("management_account_id"), IdentityCenterRegion: s("identity_center_region"), Auth: AuthStaticKey}
}

// ErrStaticKeysDisabled is the refusal of a connection that stores an AWS
// access key where the server allows none (production).
var ErrStaticKeysDisabled = errors.New("awsorg: stored AWS access keys are disabled on this server; connect AWS with a federated connector (POST /api/aws/connectors without credentials)")

// GovernedProber is the readiness prober of a governed AWS Organizations
// connection: AssumeRole into the reader role with the connection's keys and
// external id, then one cheap read (Probe). hc is the guarded client.
func GovernedProber(p governed.Params, hc Doer, now func() time.Time) (connectors.Prober, error) {
	var creds Credentials
	if err := ParseCredentials(p.Secret, &creds); err != nil {
		return nil, err
	}
	cfg := ConfigOf(p)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &govProber{col: &Collector{Client: &Client{HTTP: hc, Now: now}, Config: &cfg, Base: toSigV4(creds),
		ExternalID: strings.TrimSpace(p.Settings["external_id"]), Now: now}}, nil
}

// govProber answers the readiness operations an AWS connection can: one
// Probe serves the authentication and the read.
type govProber struct {
	col  *Collector
	res  *ProbeResult
	err  error
	done bool
}

func (p *govProber) probe(ctx context.Context) error {
	if !p.done {
		p.res, p.err = p.col.Probe(ctx)
		p.done = true
	}
	return p.err
}

func (p *govProber) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if err := p.probe(ctx); err != nil {
		if IsAuthRefused(err) {
			return connectors.AuthInfo{OK: false, Mode: "assume_role"}, nil
		}
		return connectors.AuthInfo{}, err
	}
	return connectors.AuthInfo{OK: true, Identity: p.res.RoleARN, Mode: "assume_role"}, nil
}

func (p *govProber) Sample(ctx context.Context, _ connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := p.probe(ctx); err != nil {
		return connectors.SampleStats{}, err
	}
	return connectors.SampleStats{Objects: min(p.res.Accounts, connectors.MaxSample), Available: true,
		PerClass: map[string]int{"account": p.res.Accounts}}, nil
}

func (*govProber) Connect(context.Context) (connectors.ConnInfo, error) {
	return connectors.ConnInfo{}, connectors.ErrUnsupported
}
func (*govProber) RootInfo(context.Context) (connectors.RootInfo, error) {
	return connectors.RootInfo{}, connectors.ErrUnsupported
}
func (*govProber) ObjectExists(context.Context, string) (bool, error) {
	return false, connectors.ErrUnsupported
}
func (*govProber) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return connectors.Rights{}, connectors.ErrUnsupported
}
func (*govProber) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{}, connectors.ErrUnsupported
}
func (*govProber) RateLimits(context.Context) (connectors.RateInfo, error) {
	return connectors.RateInfo{}, connectors.ErrUnsupported
}
func (*govProber) Time(context.Context) (time.Time, error) {
	return time.Time{}, connectors.ErrUnsupported
}

// ParseCredentials reads the JSON a connection's sealed credential holds
// ({"access_key_id", "secret_access_key", "session_token"}) and checks its shape.
func ParseCredentials(raw string, out *Credentials) error {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Credentials
	if err := dec.Decode(&c); err != nil {
		return errors.New("awsorg: the credential is JSON with access_key_id and secret_access_key")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	*out = c
	return nil
}

// SigV4 is the signing form of credentials.
func SigV4(c Credentials) sigv4.Credentials { return toSigV4(c) }

// IsAuthRefused reports whether AWS refused the credentials or the role
// (the answer to an authentication check, not a failure of the probe).
func IsAuthRefused(err error) bool {
	var ae *Error
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.Code {
	case "AccessDenied", "AccessDeniedException", "InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException":
		return true
	}
	return ae.Status == http.StatusForbidden || ae.Status == http.StatusUnauthorized
}
