package mcpauth

import (
	"errors"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Binding of an MCP resource server to its authorization server (issue #479).
//
// A rogue MCP server steals an agent's OAuth credentials by posing as the
// server the agent was set up to use, or by naming an authorization server of
// its own (the MCP Python SDK flaw of 29 Sep, the OpenCode flaw of 22 Oct).
// Each registered resource is therefore bound to the issuer it expects its
// tokens from and the audience they carry:
//
//   - a token is issued (authorization, code redemption, token exchange) only
//     for a registered, active resource whose bound issuer is this tenant's
//     authorization server, and carries the bound audience;
//   - a token whose issuer or audience differs from the binding is refused at
//     introspection and at a tool-call decision, with the reason in the
//     decision log;
//   - an MCP server that is not registered (or is disabled) gets no token at
//     all: an agent cannot use it through Tessera.
//
// A resource with no explicit binding is bound to the defaults: the tenant's
// MCP issuer and the resource URI.

// Binding is the effective binding of a resource.
type Binding struct {
	Issuer   string
	Audience string
	// Explicit is set when an administrator bound the resource, false for the defaults.
	Explicit bool
}

// BindingOf returns the effective binding of a resource: the stored one, or
// the defaults (issuer is this authorization server's issuer).
func BindingOf(tx *store.TenantTx, res *store.MCPResource, issuer string) (Binding, error) {
	b, err := tx.MCPResourceBinding(res.ID)
	if errors.Is(err, store.ErrNotFound) {
		return Binding{Issuer: issuer, Audience: res.Resource}, nil
	}
	if err != nil {
		return Binding{}, err
	}
	return Binding{Issuer: b.Issuer, Audience: b.Audience, Explicit: true}, nil
}

// ValidateBinding checks the shape of an issuer and an audience: absolute
// https URIs (http for loopback) without fragment, like a resource indicator.
func ValidateBinding(issuer, audience string) error {
	if err := ValidateResource(issuer); err != nil {
		return errors.New("issuer must be an absolute https URL")
	}
	if err := ValidateResource(audience); err != nil {
		return errors.New("audience must be an absolute https URI")
	}
	if strings.Contains(issuer, "?") {
		return errors.New("issuer must not carry a query")
	}
	return nil
}

// Messages of the refusals. They are shown to the client and written to the
// decision log; they name no token.
const (
	msgUnregistered = "blocked by policy: the MCP server is not registered or is disabled; an administrator must register it before an agent can use it"
	msgIssuerBound  = "this MCP server is bound to another authorization server: no token is issued for it"
	msgIssuerWrong  = "token issuer does not match the authorization server this MCP server is bound to"
	msgAudWrong     = "token is for another audience"
)

// Policy action recorded when an agent asks for a token for an unregistered MCP server.
const ActionUnregistered = "mcp.policy.unregistered_server"

// Policy action recorded when a resource is bound to another authorization server.
const ActionIssuerMismatch = "mcp.policy.issuer_mismatch"

// bound checks that tokens for res may be issued by issuer, and returns the
// binding. A nil error with a nil binding error means go ahead.
func bound(tx *store.TenantTx, res *store.MCPResource, issuer string) (Binding, *OAuthError, error) {
	b, err := BindingOf(tx, res, issuer)
	if err != nil {
		return b, nil, err
	}
	if b.Issuer != issuer {
		return b, oerr(400, "invalid_target", msgIssuerBound), nil
	}
	return b, nil, nil
}
