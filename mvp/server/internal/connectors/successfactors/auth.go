package successfactors

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// basicHeader is the Authorization value of basic authentication:
// base64(user@company:password), the form SuccessFactors takes. A user that
// already carries @company is sent as is.
func basicHeader(cfg Config) string {
	user := cfg.Username
	if !strings.Contains(user, "@") {
		user += "@" + cfg.CompanyID
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+cfg.Password.Reveal()))
}

const (
	samlGrant    = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	samlAudience = "www.successfactors.com"
	samlLifetime = 5 * time.Minute
	nsAssertion  = "urn:oasis:names:tc:SAML:2.0:assertion"
	nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" // #nosec G101 -- a SAML URN, not a credential
)

// samlSource gets and caches OAuth access tokens through the SAML bearer
// flow. The key, the assertion and the access token are never logged or put in
// an error.
type samlSource struct {
	signer   crypto.Signer
	cert     []byte // DER
	clientID string
	company  string
	user     string
	tokenURL string
	api      *connsync.Client // without Authorize, for the token endpoint
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newSAMLSource(cfg Config, base *url.URL, api *connsync.Client, now func() time.Time) (*samlSource, error) {
	signer, der, err := parseKeyBundle(cfg.PrivateKey.Reveal())
	if err != nil {
		return nil, err
	}
	tokenAPI := *api
	tokenAPI.Authorize, tokenAPI.OnUnauthorized = nil, nil
	u := *base
	u.Path = tokenPath
	return &samlSource{signer: signer, cert: der, clientID: cfg.ClientID, company: cfg.CompanyID, user: cfg.Username,
		tokenURL: u.String(), api: &tokenAPI, now: now}, nil
}

// parseKeyBundle reads the PEM bundle: one private key and the certificate
// that matches it. The error never quotes the bundle.
func parseKeyBundle(bundle string) (crypto.Signer, []byte, error) {
	var keyPEM, certPEM []byte
	rest := []byte(bundle)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch {
		case strings.HasSuffix(b.Type, "PRIVATE KEY") && keyPEM == nil:
			keyPEM = pem.EncodeToMemory(b)
		case b.Type == "CERTIFICATE" && certPEM == nil:
			certPEM = pem.EncodeToMemory(b)
		}
	}
	if keyPEM == nil || certPEM == nil {
		return nil, nil, errors.New("successfactors: the SAML credential must be a PEM bundle with one private key and its certificate")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, errors.New("successfactors: the private key is unusable or does not match the certificate")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || len(pair.Certificate) == 0 {
		return nil, nil, errors.New("successfactors: the private key cannot sign")
	}
	if c, err := x509.ParseCertificate(pair.Certificate[0]); err != nil || c.PublicKeyAlgorithm != x509.RSA {
		return nil, nil, errors.New("successfactors: the SAML certificate must hold an RSA key")
	}
	return signer, pair.Certificate[0], nil
}

// assertion builds the signed SAML 2.0 assertion SuccessFactors exchanges for
// a token: issued by the OAuth client, for the API user, to the token endpoint,
// valid for a few minutes, signed RSA-SHA256 (enveloped, exclusive c14n).
func (s *samlSource) assertion() ([]byte, error) {
	now := s.now().UTC()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
	a := etree.NewElement("saml2:Assertion")
	a.CreateAttr("xmlns:saml2", nsAssertion)
	a.CreateAttr("ID", "_"+hex.EncodeToString(id[:]))
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(now))
	a.CreateElement("saml2:Issuer").SetText(s.clientID)
	subj := a.CreateElement("saml2:Subject")
	nid := subj.CreateElement("saml2:NameID")
	nid.CreateAttr("Format", nameIDFormat)
	nid.SetText(s.user)
	scd := subj.CreateElement("saml2:SubjectConfirmation")
	scd.CreateAttr("Method", bearerMethod)
	data := scd.CreateElement("saml2:SubjectConfirmationData")
	data.CreateAttr("NotOnOrAfter", ts(now.Add(samlLifetime)))
	data.CreateAttr("Recipient", s.tokenURL)
	cond := a.CreateElement("saml2:Conditions")
	cond.CreateAttr("NotBefore", ts(now.Add(-time.Minute)))
	cond.CreateAttr("NotOnOrAfter", ts(now.Add(samlLifetime)))
	cond.CreateElement("saml2:AudienceRestriction").CreateElement("saml2:Audience").SetText(samlAudience)
	attr := a.CreateElement("saml2:AttributeStatement").CreateElement("saml2:Attribute")
	attr.CreateAttr("Name", "api_key")
	attr.CreateElement("saml2:AttributeValue").SetText(s.clientID)

	ctx, err := dsig.NewSigningContext(s.signer, [][]byte{s.cert})
	if err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	// The schema wants the signature right after the issuer; the enveloped
	// transform leaves it out of the digest wherever it sits.
	sig, err := ctx.ConstructSignature(a, true)
	if err != nil {
		return nil, errors.New("successfactors: the assertion could not be signed")
	}
	a.InsertChildAt(a.SelectElement("Issuer").Index()+1, sig)
	doc := etree.NewDocument()
	doc.SetRoot(a)
	return doc.WriteToBytes()
}

func (s *samlSource) authorization(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.expires.Add(-time.Minute)) {
		return "Bearer " + s.token, nil
	}
	assertion, err := s.assertion()
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {s.clientID}, "company_id": {s.company}, "grant_type": {samlGrant},
		"assertion": {base64.StdEncoding.EncodeToString(assertion)}}
	resp, err := s.api.Do(ctx, http.MethodPost, s.tokenURL, http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("successfactors: token request: %w", err)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := connsync.DecodeJSON(resp.Body, &tr); err != nil {
		return "", fmt.Errorf("successfactors: token response: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", errors.New("successfactors: token response has no bearer token")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 3600
	}
	s.token, s.expires = tr.AccessToken, s.now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	return "Bearer " + s.token, nil
}

func (s *samlSource) invalidate() {
	s.mu.Lock()
	s.token = ""
	s.mu.Unlock()
}
