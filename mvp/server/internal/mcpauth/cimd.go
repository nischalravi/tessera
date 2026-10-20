package mcpauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document,
// MCP authorization 2025-11-25). The client_id is an https URL; the document
// at that URL describes the client. The fetch goes to an attacker-chosen URL,
// so it uses internal/safehttp (no redirects, size cap, status and media
// type checks), the document must name the URL it was fetched from, and the
// validated result is cached for at most ClientDocTTL.
const (
	// MaxDocumentBytes caps a metadata document (the draft recommends 5 KB).
	MaxDocumentBytes = 16 << 10
	// ClientDocTTL is how long a validated document is trusted before it is
	// fetched again (a fixed bound: response cache headers are ignored).
	ClientDocTTL = time.Hour
	// MaxRedirectURIs and MaxClientKeys bound the document's lists.
	MaxRedirectURIs = 10
	MaxClientKeys   = 8
	// MaxClients caps the clients a tenant holds (any signed-in user can make
	// the server fetch a new document, so the table must not grow without bound).
	MaxClients = 500
)

// GrantTokenExchange is the RFC 8693 grant type.
const GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- an RFC 8693 grant URI, not a credential

// ErrClient is a client metadata document the server refuses.
type ErrClient struct{ Msg string }

func (e *ErrClient) Error() string { return e.Msg }

func clientErr(format string, a ...any) error { return &ErrClient{Msg: fmt.Sprintf(format, a...)} }

// ValidateClientID checks that id is usable as a CIMD client_id: an absolute
// https URL with a path, no fragment, no credentials, no dot segments.
func ValidateClientID(id string) error {
	if len(id) > 512 {
		return clientErr("client_id is too long")
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return clientErr("client_id must be an https URL")
	}
	switch {
	case u.User != nil:
		return clientErr("client_id must not carry credentials")
	case u.Fragment != "" || strings.Contains(id, "#"):
		return clientErr("client_id must not have a fragment")
	case u.Path == "" || u.Path == "/":
		return clientErr("client_id must have a path")
	case u.RawQuery != "" || strings.Contains(id, "?"):
		return clientErr("client_id must not have a query")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return clientErr("client_id must not contain dot segments")
		}
	}
	if u.String() != id {
		return clientErr("client_id must be in canonical form")
	}
	return nil
}

// Document is the validated subset of a client metadata document.
type Document struct {
	ClientID     string
	Name         string
	RedirectURIs []string
	JWKS         jose.JSONWebKeySet
	SHA256       string
}

type rawDocument struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	JWKS                    json.RawMessage `json:"jwks"`
}

// ParseDocument validates a fetched document for the client_id it was
// fetched from. The client_id inside must equal that URL exactly.
func ParseDocument(clientID string, body []byte) (*Document, error) {
	if len(body) > MaxDocumentBytes {
		return nil, clientErr("client metadata document is too large")
	}
	var raw rawDocument
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, clientErr("client metadata document is not a JSON object")
	}
	if raw.ClientID != clientID {
		return nil, clientErr("client_id in the document does not equal the document URL")
	}
	name := strings.TrimSpace(raw.ClientName)
	if name == "" || len([]rune(name)) > 100 {
		return nil, clientErr("client_name is required (at most 100 characters)")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return nil, clientErr("client_name has control characters")
		}
	}
	if n := len(raw.RedirectURIs); n == 0 || n > MaxRedirectURIs {
		return nil, clientErr("redirect_uris must list 1 to %d URIs", MaxRedirectURIs)
	}
	uris := slices.Clone(raw.RedirectURIs)
	for _, ru := range uris {
		if err := ValidateRedirectURI(ru); err != nil {
			return nil, err
		}
	}
	sort.Strings(uris)
	uris = slices.Compact(uris)
	switch raw.TokenEndpointAuthMethod {
	case "", "none", "private_key_jwt":
	default:
		return nil, clientErr("token_endpoint_auth_method %q is not supported (use none or private_key_jwt)", raw.TokenEndpointAuthMethod)
	}
	for _, g := range raw.GrantTypes {
		if g != "authorization_code" && g != GrantTokenExchange {
			return nil, clientErr("grant_type %q is not supported", g)
		}
	}
	for _, rt := range raw.ResponseTypes {
		if rt != "code" {
			return nil, clientErr("response_type %q is not supported", rt)
		}
	}
	doc := &Document{ClientID: clientID, Name: name, RedirectURIs: uris, JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}},
		SHA256: seal.SHA256Hex(body)}
	if len(bytes.TrimSpace(raw.JWKS)) > 0 && string(bytes.TrimSpace(raw.JWKS)) != "null" {
		if err := json.Unmarshal(raw.JWKS, &doc.JWKS); err != nil {
			return nil, clientErr("jwks is malformed")
		}
		if len(doc.JWKS.Keys) > MaxClientKeys {
			return nil, clientErr("jwks has too many keys")
		}
		for _, k := range doc.JWKS.Keys {
			if !k.IsPublic() || !k.Valid() || k.KeyID == "" {
				return nil, clientErr("jwks must hold valid public keys with a kid")
			}
		}
	}
	return doc, nil
}

// ValidateRedirectURI accepts an absolute https URI, or an http URI to a
// loopback host, with no fragment (OAuth 2.1 §2.3.1, MCP authorization).
func ValidateRedirectURI(ru string) error {
	if len(ru) > 512 {
		return clientErr("redirect_uri is too long")
	}
	u, err := url.Parse(ru)
	if err != nil || u.Host == "" || u.Fragment != "" || strings.Contains(ru, "#") || u.User != nil {
		return clientErr("redirect_uri %q is not an absolute URI without fragment or credentials", ru)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return clientErr("redirect_uri %q must be https (http only for localhost)", ru)
		}
	default:
		return clientErr("redirect_uri %q must be https (http only for localhost)", ru)
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HasLoopbackRedirect reports whether any redirect URI is a loopback one
// (shown to the user: a local app can impersonate any client name).
func HasLoopbackRedirect(uris []string) bool {
	for _, ru := range uris {
		if u, err := url.Parse(ru); err == nil && isLoopback(u.Hostname()) {
			return true
		}
	}
	return false
}

// fetchDocument fetches and validates the document of clientID. It never
// follows a redirect.
func (s *Service) fetchDocument(ctx context.Context, clientID string) (*Document, error) {
	if s.HTTP == nil {
		return nil, errors.New("mcpauth: no outbound HTTP client")
	}
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}
	u, err := s.fetchURL(clientID)
	if err != nil {
		return nil, err
	}
	hc := *s.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := safehttp.Get(ctx, &hc, u.String())
	if err != nil {
		return nil, clientErr("client metadata document could not be fetched: %s", fetchReason(err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, clientErr("client metadata document answered HTTP %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, clientErr("client metadata document is not application/json")
	}
	return ParseDocument(clientID, resp.Body)
}

// fetchURL re-parses clientID and refuses a host that is an IP literal in a
// private, loopback, link-local or metadata range (loopback only with
// AllowLoopback) before any request is built. The safehttp client repeats the
// check at dial time, after DNS resolution; this one makes the refusal visible
// at the call site and keeps a literal address from ever reaching the dialer.
func (s *Service) fetchURL(clientID string) (*url.URL, error) {
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, clientErr("client_id must be an https URL")
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		if a.Zone() != "" || (!(s.AllowLoopback && a.Unmap().IsLoopback()) && safehttp.Blocked(a)) {
			return nil, clientErr("client metadata document could not be fetched: address not allowed")
		}
	}
	return u, nil
}

func fetchReason(err error) string {
	switch {
	case errors.Is(err, safehttp.ErrBlockedAddress):
		return "address not allowed"
	case errors.Is(err, safehttp.ErrTooLarge):
		return "document too large"
	case errors.Is(err, safehttp.ErrURL):
		return "URL not allowed"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	}
	return "request failed"
}

// Client returns the cached client for clientID in tenant t, fetching and
// validating its metadata document when there is no unexpired cache entry
// (a new client starts pending and unbound). A fetch failure with an expired
// cache fails closed. A changed document re-pends an active client when its
// redirect URIs or keys changed.
func (s *Service) Client(ctx context.Context, db *store.DB, t tenancy.ID, clientID string) (*store.MCPClient, error) {
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}
	now := s.now()
	var cached *store.MCPClient
	err := db.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		c, err := tx.MCPClient(clientID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		cached = c
		return err
	})
	if err != nil {
		return nil, err
	}
	if cached != nil && now.Before(cached.ExpiresAt) {
		return cached, nil
	}
	doc, ferr := s.fetchDocument(ctx, clientID)
	if ferr != nil {
		return nil, ferr
	}
	uris, _ := json.Marshal(doc.RedirectURIs)
	jwks, _ := json.Marshal(doc.JWKS)
	var out *store.MCPClient
	err = db.InTenant(ctx, t, func(tx *store.TenantTx) error {
		c := &store.MCPClient{ClientID: clientID, Name: doc.Name, RedirectURIs: string(uris), JWKS: string(jwks),
			DocSHA256: doc.SHA256, ExpiresAt: now.Add(ClientDocTTL)}
		if err := tx.UpsertMCPClient(c, now); err != nil {
			return err
		}
		var err error
		if out, err = tx.MCPClient(clientID); err != nil {
			return err
		}
		if cached == nil {
			if all, err := tx.MCPClients(); err != nil {
				return err
			} else if len(all) > MaxClients {
				return clientErr("too many registered clients")
			}
			if err := tx.Audit(now, "mcp-authz", "mcp.client.discovered", ojson.Object{{Key: "client_id", Value: clientID},
				{Key: "client_name", Value: doc.Name}, {Key: "doc_sha256", Value: doc.SHA256}}); err != nil {
				return err
			}
		}
		if cached != nil && cached.Status == "active" && (cached.RedirectURIs != out.RedirectURIs || cached.JWKS != out.JWKS) {
			n, err := tx.RevokeMCPTokensOfClient(clientID, "client metadata changed", now)
			if err != nil {
				return err
			}
			if err := tx.Audit(now, "mcp-authz", "mcp.client.metadata_changed", ojson.Object{{Key: "client_id", Value: clientID},
				{Key: "tokens_revoked", Value: n}, {Key: "doc_sha256", Value: doc.SHA256}}); err != nil {
				return err
			}
			if err := tx.SetMCPClient(clientID, out.AgentIdentityID, "pending", now); err != nil {
				return err
			}
			if out, err = tx.MCPClient(clientID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// RedirectURIsOf decodes a client's stored redirect URIs.
func RedirectURIsOf(c *store.MCPClient) []string {
	var out []string
	_ = json.Unmarshal([]byte(c.RedirectURIs), &out)
	return out
}
