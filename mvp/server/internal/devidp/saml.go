package devidp

import "net/http"

// SAML is a stub until PR9 (docs/design/phase-0-platform-security.md §19).
// PR9 adds /saml/metadata and /saml/sso (HTTP-Redirect AuthnRequest, the same
// sign-in page, an auto-POST form), responses built with etree and signed with
// goxmldsig, an X.509 signing certificate under the key directory, and the
// SAML faults listed in SAMLFaults. Until then the endpoints answer 501 so a
// relying party fails loudly instead of half-working.
func (s *Server) handleSAMLStub(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":             "not_implemented",
		"error_description": "the dev IdP's SAML endpoints arrive with the SAML SP (Phase 0 PR9)",
	})
}
