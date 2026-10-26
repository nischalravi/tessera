package awsorg

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Federated reader credentials (differentiators plan EP-2). The connector
// holds no AWS secret: for each account it signs a short-lived JWT with the
// tenant's key (internal/keys) and trades it at STS for one hour of
// credentials (AssumeRoleWithWebIdentity, which is itself unsigned). The
// customer trusts Tessera by creating an IAM OIDC provider for the tenant's AWS
// issuer (IssuerURL) and a role whose trust policy names that provider and
// restricts aud and sub (see README "AWS connector").
//
// The token is never served: the only public documents are the OIDC discovery
// document and the JWKS (internal/api aws_federation.go).
const (
	// FederationAudience is the token's aud and the client id the customer
	// registers on the IAM OIDC provider.
	FederationAudience = "sts.amazonaws.com"
	// TokenTTL is a token's lifetime. STS reads it once, at the call.
	TokenTTL = 5 * time.Minute
	// IssuerPath is the issuer's path below /t/{slug}. It differs from the API's
	// and the MCP server's issuers: all sign with the tenant's access-token
	// key, and the issuer (with the audience) is what keeps this token from
	// being accepted as an API token, and an API token from being accepted by
	// AWS.
	IssuerPath = "/aws"
	// tokenSkew backdates nbf and iat a little for clock differences with AWS.
	tokenSkew = 30 * time.Second
)

// IssuerURL is the OIDC issuer of a tenant's AWS federation:
// {PUBLIC_URL}/t/{slug}/aws.
func IssuerURL(publicURL, slug string) string { return publicURL + "/t/" + slug + IssuerPath }

// Subject is the sub claim of a connector's token. It names the tenant and the
// connector, so a role trust policy can pin one connector, and no two tenants'
// tokens share a subject (their issuers differ as well).
func Subject(t tenancy.ID, connectorID string) string {
	return "tessera:tenant:" + t.String() + ":aws-connector:" + connectorID
}

// TokenSource returns a fresh web identity token.
type TokenSource func(ctx context.Context) (string, error)

// Federation mints connector tokens.
type Federation struct {
	DB     *store.DB
	Sealer *seal.Sealer
	// PublicURL is the server's TESSERA_PUBLIC_URL.
	PublicURL string
	// Clock defaults to time.Now.
	Clock func() time.Time
}

func (f *Federation) now() time.Time {
	if f.Clock != nil {
		return f.Clock()
	}
	return time.Now()
}

type webIdentityClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	JTI       string `json:"jti"`
}

// Source is the TokenSource of one connector of tenant t.
func (f *Federation) Source(t tenancy.ID, connectorID string) TokenSource {
	return func(ctx context.Context) (string, error) { return f.Token(ctx, t, connectorID) }
}

// Token signs a web identity token for a connector of tenant t, with t's
// active access-token key. The connector must exist in t: the subject of a
// connector of another tenant, or of none, is never signed. Errors name no
// token.
func (f *Federation) Token(ctx context.Context, t tenancy.ID, connectorID string) (string, error) {
	return f.sign(ctx, t, connectorID, Subject(t, connectorID))
}

// WriterSubject is the sub claim of a connector's writer token (issue #660, LP-4). It differs from Subject, so the
// reader role's trust policy never accepts a writer token and the writer role's never accepts a reader token.
func WriterSubject(t tenancy.ID, connectorID string) string {
	return "tessera:tenant:" + t.String() + ":aws-writer:" + connectorID
}

// WriterSource is the TokenSource of the writer role of one connector of tenant t.
func (f *Federation) WriterSource(t tenancy.ID, connectorID string) TokenSource {
	return func(ctx context.Context) (string, error) {
		return f.sign(ctx, t, connectorID, WriterSubject(t, connectorID))
	}
}

// sign is Token for any subject.
func (f *Federation) sign(ctx context.Context, t tenancy.ID, connectorID, subject string) (string, error) {
	if f == nil || f.DB == nil || f.Sealer == nil || f.PublicURL == "" {
		return "", errors.New("awsorg: federation is not configured")
	}
	var slug string
	var key *keys.SigningKey
	if err := f.DB.ReadTenant(ctx, t, func(c *store.TenantTx) error {
		if _, err := c.AWSConnector(connectorID); err != nil {
			return err
		}
		rec, err := c.TenantRecord()
		if err != nil {
			return err
		}
		slug = rec.Slug
		key, err = keys.ActiveSigningKey(c, store.KeyPurposeAWSFederation, f.Sealer)
		return err
	}); err != nil {
		return "", fmt.Errorf("awsorg: federation token: %w", err)
	}
	priv, ok := key.Key.(*ecdsa.PrivateKey)
	if !ok || key.Alg != keys.AlgES256 {
		return "", errors.New("awsorg: federation signing key is not ES256")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: priv, KeyID: key.KID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	now := f.now().UTC()
	tok, err := jwt.Signed(signer).Claims(webIdentityClaims{Issuer: IssuerURL(f.PublicURL, slug), Subject: subject,
		Audience: FederationAudience, IssuedAt: now.Add(-tokenSkew).Unix(), NotBefore: now.Add(-tokenSkew).Unix(),
		Expiry: now.Add(TokenTTL).Unix(), JTI: "awsfed_" + seal.RandomSecret(16)}).Serialize()
	if err != nil {
		return "", errors.New("awsorg: federation token: cannot sign")
	}
	return tok, nil
}

// TrustPolicy is the trust policy the customer gives the reader role of one
// connector: only the account's IAM OIDC provider for issuer, only a token
// whose aud is FederationAudience and whose sub is subject. The account id is
// left as {ACCOUNT_ID} (an IAM OIDC provider is per account).
func TrustPolicy(issuer, subject string) []byte {
	host := strings.TrimPrefix(issuer, "https://")
	b, err := json.MarshalIndent(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]string{"Federated": "arn:aws:iam::{ACCOUNT_ID}:oidc-provider/" + host},
			"Action":    "sts:AssumeRoleWithWebIdentity",
			"Condition": map[string]any{"StringEquals": map[string]string{host + ":aud": FederationAudience, host + ":sub": subject}},
		}},
	}, "", "  ")
	if err != nil {
		panic(err) // static data
	}
	return b
}
