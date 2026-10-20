package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// AuthnRequirement is what a route needs of the session's authentication
// context: an ACR at least as strong as ACR and, when MaxAge is set, an
// authentication no older than MaxAge (RFC 9470 acr_values and max_age).
type AuthnRequirement struct {
	ACR    ACR
	MaxAge time.Duration
}

// Step-up requirements (design §10.2, §12.4).
var (
	// StepUpPolicy: policy changes and approvals (grant revoke, HRIS execute,
	// JIT approve, review decisions): phishing-resistant, within 15 minutes.
	StepUpPolicy = AuthnRequirement{ACR: ACRPhr, MaxAge: 900 * time.Second}
	// StepUpAdmin: admin changes, device approval, break-glass enrolment:
	// phishing-resistant, within 5 minutes.
	StepUpAdmin = AuthnRequirement{ACR: ACRPhr, MaxAge: 300 * time.Second}
)

// Merge is the stricter of r and o: the higher ACR and the shorter positive
// MaxAge. Conditional access uses it to add its step-up to a route's own.
func (r AuthnRequirement) Merge(o AuthnRequirement) AuthnRequirement {
	out := r
	if o.ACR.Rank() > out.ACR.Rank() {
		out.ACR = o.ACR
	}
	if o.MaxAge > 0 && (out.MaxAge <= 0 || o.MaxAge < out.MaxAge) {
		out.MaxAge = o.MaxAge
	}
	return out
}

// describe is the human-readable reason of a step-up challenge.
func (r AuthnRequirement) describe() string {
	what := "a phishing-resistant sign-in"
	switch r.ACR {
	case ACRAAL1:
		what = "a sign-in"
	case ACRAAL2:
		what = "a multi-factor sign-in"
	case ACRPhrh:
		what = "a sign-in with a device-bound security key"
	}
	if r.MaxAge > 0 {
		return fmt.Sprintf("This action needs %s in the last %d minutes", what, int(r.MaxAge/time.Minute))
	}
	return "This action needs " + what
}

// WriteDenial writes the error-contract response of d (§16.2). A step-up
// denial carries the RFC 9470 challenge in WWW-Authenticate and, in the body,
// the requirement and the step_up_url that satisfies it (§9.4; the client
// adds return_to).
func WriteDenial(w http.ResponseWriter, d *Denial) { WriteDenialScheme(w, d, "Bearer") }

// WriteDenialScheme is WriteDenial with the challenge's authentication
// scheme: "DPoP" for a token principal, whose client reads the same
// insufficient_user_authentication error (RFC 9470, RFC 9449 §7.1).
func WriteDenialScheme(w http.ResponseWriter, d *Denial, scheme string) {
	body := map[string]any{"error": d.Error}
	if d.Permission != "" && d.Error != "login_required" {
		body["permission"] = string(d.Permission)
	}
	if d.Requirement != nil {
		req := *d.Requirement
		maxAge := int64(req.MaxAge / time.Second)
		body["acr"], body["max_age"] = string(req.ACR), maxAge
		body["step_up_url"] = StepUpURL(req)
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(
			`%s error="insufficient_user_authentication", error_description=%q, acr_values=%q, max_age=%d`,
			scheme, req.describe(), string(req.ACR), maxAge))
	}
	b, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(d.Status)
	_, _ = w.Write(b) // #nosec G705 -- JSON-encoded body served as application/json with nosniff
}

// StepUpURL is the URL that starts the step-up satisfying req (without
// return_to, which the client adds).
func StepUpURL(req AuthnRequirement) string {
	v := url.Values{"acr": {string(req.ACR)}, "max_age": {strconv.FormatInt(int64(req.MaxAge/time.Second), 10)}}
	return "/api/auth/step-up?" + v.Encode()
}
