package devidp

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// CAS 3.0 (issue #152), shaped like Apereo CAS:
//
//	GET /cas/login?service=&renew=      the sign-in page; with an IdP session and no renew, single sign-on
//	GET /cas/p3/serviceValidate?service=&ticket=&renew=  the XML answer with attributes
//
// The service URL (without its query) must match a registered client
// redirect URI pattern. Tickets are service tickets (ST-), single use, valid
// 60 s, bound to the exact service URL; renew=true at validation refuses a
// ticket from single sign-on. Released attributes: email, displayName,
// memberOf, amr (RFC 8176, as the OIDC generic emulation), the
// authentication handler, authenticationDate and isFromNewLogin.

const (
	pathCASLogin    = "/cas/login"
	pathCASValidate = "/cas/p3/serviceValidate"
)

// CAS faults.
const (
	FaultCASFailure     Fault = "cas_failure"      // authenticationFailure INVALID_TICKET for a valid ticket
	FaultCASNoUser      Fault = "cas_no_user"      // authenticationSuccess without cas:user
	FaultCASTwoUsers    Fault = "cas_two_users"    // two cas:user elements (the second an admin)
	FaultCASCommentUser Fault = "cas_comment_user" // cas:user "<sub><!---->.evil": a flattening parser sees another user
	FaultCASProxied     Fault = "cas_proxied"      // the answer lists proxies (a proxy chain)
	FaultCASStaleAuth   Fault = "cas_stale_auth"   // authenticationDate a day old and isFromNewLogin=false, even on renew
	FaultCASTicketReuse Fault = "cas_ticket_reuse" // the previous ticket is issued, and validates, again
)

// CASFaults lists the CAS faults.
func CASFaults() []Fault {
	return []Fault{FaultCASFailure, FaultCASNoUser, FaultCASTwoUsers, FaultCASCommentUser, FaultCASProxied,
		FaultCASStaleAuth, FaultCASTicketReuse}
}

// CASServerURL is the CAS server base URL (the connection's issuer).
func (s *Server) CASServerURL() string { return s.issuer + "/cas" }

// casHandler is the Apereo-style authentication handler name for a method.
func casHandler(m Method) string {
	switch m {
	case MethodHardwareKey, MethodPasskey:
		return "WebAuthnAuthenticationHandler"
	case MethodPasswordOTP:
		return "GoogleAuthenticatorAuthenticationHandler"
	}
	return "QueryDatabaseAuthenticationHandler"
}

func (s *Server) casServiceAllowed(service string) bool {
	u, err := url.Parse(service)
	if err != nil || !absoluteHTTP(service) {
		return false
	}
	u.RawQuery = ""
	for _, c := range s.clients {
		if c.redirectAllowed(u.String()) {
			return true
		}
	}
	return false
}

// redirectRegistered redirects to base plus add, after checking base against
// the registered redirect URIs once more (OIDC redirect_uri, or a CAS
// service URL, whose query is not part of the registration). A target that
// matches nothing is refused with 400: the dev IdP never redirects to an
// unregistered address, whatever the caller did before.
func (s *Server) redirectRegistered(w http.ResponseWriter, r *http.Request, base string, add url.Values, status int, cas bool) {
	ok := false
	if cas {
		ok = s.casServiceAllowed(base)
	} else {
		for _, c := range s.clients {
			if c.redirectAllowed(base) {
				ok = true
				break
			}
		}
	}
	if !ok {
		s.errorPage(w, http.StatusBadRequest, "The redirect target is not registered.")
		return
	}
	http.Redirect(w, r, withParams(base, add), status) // #nosec G710 -- base matched a registered redirect URI just above
}

func (s *Server) handleCASLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	service := q.Get("service")
	for _, v := range q {
		if len(v) > 1 {
			s.errorPage(w, http.StatusBadRequest, "A parameter is repeated.")
			return
		}
	}
	if !s.casServiceAllowed(service) {
		s.errorPage(w, http.StatusBadRequest, "The service is not registered with this CAS server.")
		return
	}
	if q.Has("gateway") || q.Has("pgtUrl") {
		s.errorPage(w, http.StatusBadRequest, "gateway and proxy granting are not supported.")
		return
	}
	p := pendingAuthz{cas: true, redirectURI: service, clientID: "CAS service"}
	p.fault = s.currentFault()
	if q.Has("fault") {
		f := Fault(q.Get("fault"))
		if !s.faults || !slices.Contains(CASFaults(), f) {
			s.errorPage(w, http.StatusBadRequest, "Unknown or disabled CAS fault.")
			return
		}
		p.fault = f
	}
	if !slices.Contains(CASFaults(), p.fault) {
		p.fault = FaultNone
	}
	renew := q.Get("renew") == "true"
	if sess, ok := s.session(r, now); ok && !renew {
		s.issueCode(w, r, p, authCode{user: sess.user, method: sess.method, authTime: sess.authTime, sid: sess.sid}, http.StatusFound)
		return
	}
	id := rand.Text()
	if err := s.pending.put(id, p, now.Add(pendingTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sign-ins in progress.")
		return
	}
	d := pageData{Title: "Sign in (CAS)", Req: id, Action: s.issuer + pathAuthorize, ClientID: p.clientID, Fault: string(p.fault)}
	if renew {
		d.Message = "renew=true: you must sign in again."
	}
	s.renderUsers(w, &d, "")
}

// issueCASTicket stores a service ticket and redirects to the service.
func (s *Server) issueCASTicket(w http.ResponseWriter, r *http.Request, ac authCode, status int) {
	now := s.now()
	ticket := "ST-" + rand.Text()
	s.mu.Lock()
	if ac.authz.fault == FaultCASTicketReuse && s.lastCASTicket != "" {
		ticket = s.lastCASTicket
	}
	s.lastCASTicket = ticket
	s.mu.Unlock()
	if err := s.codes.put(ticket, ac, now.Add(codeTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many outstanding tickets.")
		return
	}
	s.redirectRegistered(w, r, ac.authz.redirectURI, url.Values{"ticket": {ticket}}, status, true)
}

func (s *Server) handleCASValidate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	failure := func(code, msg string) {
		var b bytes.Buffer
		b.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="`)
		_ = xml.EscapeText(&b, []byte(code))
		b.WriteString(`">`)
		_ = xml.EscapeText(&b, []byte(msg))
		b.WriteString(`</cas:authenticationFailure></cas:serviceResponse>`)
		_, _ = w.Write(b.Bytes())
	}
	ticket, service := q.Get("ticket"), q.Get("service")
	if ticket == "" || service == "" || q.Has("pgtUrl") {
		failure("INVALID_REQUEST", "ticket and service are required; proxy granting is not supported")
		return
	}
	ac, ok := s.codes.take(ticket, now)
	switch {
	case !ok || !ac.authz.cas:
		failure("INVALID_TICKET", "Ticket not recognized")
		return
	case service != ac.authz.redirectURI:
		failure("INVALID_SERVICE", "Ticket was issued for another service")
		return
	case q.Get("renew") == "true" && !ac.newLogin && ac.authz.fault != FaultCASStaleAuth:
		failure("INVALID_TICKET", "Ticket was not issued from a new login (renew)")
		return
	case ac.authz.fault == FaultCASFailure:
		failure("INVALID_TICKET", "Ticket not recognized")
		return
	}
	if ac.authz.fault == FaultCASTicketReuse { // a buggy server: the ticket validates again
		_ = s.codes.put(ticket, ac, now.Add(codeTTL), now)
	}
	u := ac.user
	authTime, newLogin := ac.authTime, ac.newLogin
	if ac.authz.fault == FaultCASStaleAuth {
		authTime, newLogin = now.Add(-staleAuthTimeAge), false
	}
	var b bytes.Buffer
	el := func(name, v string) {
		b.WriteString("<cas:" + name + ">")
		_ = xml.EscapeText(&b, []byte(v))
		b.WriteString("</cas:" + name + ">")
	}
	b.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess>`)
	switch ac.authz.fault {
	case FaultCASNoUser:
	case FaultCASTwoUsers:
		el("user", u.Sub)
		el("user", "00u-alice-admin")
	case FaultCASCommentUser:
		b.WriteString("<cas:user>")
		_ = xml.EscapeText(&b, []byte(u.Sub))
		b.WriteString("<!---->" + samlCommentSuffix + "</cas:user>")
	default:
		el("user", u.Sub)
	}
	b.WriteString("<cas:attributes>")
	el("email", u.Email)
	el("displayName", u.Name)
	for _, g := range u.Groups {
		el("memberOf", g)
	}
	for _, a := range ac.method.rfc8176AMR() {
		el("amr", a)
	}
	el("successfulAuthenticationHandlers", casHandler(ac.method))
	el("authenticationDate", authTime.UTC().Format(time.RFC3339Nano)+"[UTC]")
	el("isFromNewLogin", strconv.FormatBool(newLogin))
	el("longTermAuthenticationRequestTokenUsed", "false")
	b.WriteString("</cas:attributes>")
	if ac.authz.fault == FaultCASProxied {
		b.WriteString("<cas:proxies><cas:proxy>https://proxy.attacker.example/cas/proxy</cas:proxy></cas:proxies>")
	}
	b.WriteString("</cas:authenticationSuccess></cas:serviceResponse>")
	_, _ = w.Write(b.Bytes())
}
