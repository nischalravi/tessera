package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// CSRF protection for cookie sessions (design §11, threat T2). Every unsafe
// request (POST, PUT, PATCH, DELETE) of a cookie principal must carry
//
//   - X-Tessera-CSRF: the token GET /api/auth/session returned, which is
//     HMAC-SHA256(session.csrf_secret, "csrf"): bound to the session and
//     rotated with it; compared in constant time; and
//   - an Origin (or, without one, a Referer) in the allowed origins: the
//     PUBLIC_URL origin and TESSERA_CORS_ORIGINS.
//
// SameSite=Lax on the cookie is the first layer; these two are the second
// and third. JSON-only bodies (415 otherwise) are enforced by the API.

// CSRFHeader is the request header carrying the token.
const CSRFHeader = "X-Tessera-CSRF"

// ErrCSRF is a failed CSRF check (403 csrf_failed).
var ErrCSRF = errors.New("auth: csrf check failed")

// CSRFToken derives the session's CSRF token from its csrf_secret.
func CSRFToken(secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("csrf"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SafeMethod reports whether a method does not change state.
func SafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// CheckOrigin requires the request's Origin, or its Referer's origin when
// there is no Origin, to be one of allowed (exact match). A request with
// neither fails: every browser sends Origin on unsafe requests.
func CheckOrigin(r *http.Request, allowed []string) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			return ErrCSRF
		}
		u, err := url.Parse(ref)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return ErrCSRF
		}
		origin = u.Scheme + "://" + u.Host
	}
	if origin == "null" || !slices.Contains(allowed, strings.TrimRight(origin, "/")) {
		return ErrCSRF
	}
	return nil
}

// CheckCSRF enforces the token and the Origin check on an unsafe request of
// a cookie principal. Safe methods and token principals pass.
func CheckCSRF(r *http.Request, p *Principal, allowed []string) error {
	if SafeMethod(r.Method) || p == nil || p.Via != ViaCookie {
		return nil
	}
	if err := CheckOrigin(r, allowed); err != nil {
		return err
	}
	got := r.Header.Get(CSRFHeader)
	want := p.CSRFToken()
	if got == "" || want == "" || !hmac.Equal([]byte(got), []byte(want)) {
		return ErrCSRF
	}
	return nil
}
