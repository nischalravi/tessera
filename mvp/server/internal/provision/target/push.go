package target

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// PushSpec is one provisioning operation addressed to a target the server
// cannot reach, carried to a remote Directory Agent that can (issue #302).
// The agent applies it with the same SCIM or Okta connector the server would
// have used, then re-reads the target, and reports the outcome.
//
// It holds no credential. The bearer token is sealed to the agent's key by the
// server when the job is handed out, or named (CredName) in the agent's own
// store. The server builds a spec and the agent validates it again: it is the
// agent's input from the network.
type PushSpec struct {
	OpID string `json:"op_id"`
	// Target is the kind of target system: "scim" or "okta".
	Target string `json:"target"`
	// BaseURL is the target's base URL, https only. Its host:port must be on
	// the agent's own allowed_push_targets list.
	BaseURL string `json:"base_url"`
	// Dialect is the SCIM dialect ("standard" or "entra"); empty for Okta.
	Dialect string `json:"dialect,omitempty"`
	// Op is the operation kind (Kinds) and Key its idempotency key.
	Op      string  `json:"op"`
	Key     string  `json:"key"`
	Account Account `json:"account"`
	Group   Group   `json:"group,omitempty"`
	// CredName names the credential in the agent's own store. Empty: the job
	// carries a sealed credential instead.
	CredName string `json:"cred_name,omitempty"`
}

// Limits of a push spec; the agent refuses anything larger.
const (
	maxPushText  = 512
	maxPushURL   = 300
	maxPushAttrs = 50
)

// Request is the connector request the spec stands for.
func (p PushSpec) Request() Request {
	return Request{Kind: p.Op, Key: p.Key, Account: p.Account, Group: p.Group}
}

// HostPort returns the host and port of the base URL (443 when it names none).
func (p PushSpec) HostPort() (string, int, error) {
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Hostname() == "" {
		return "", 0, errors.New("base_url is not a URL")
	}
	port := 443
	if ps := u.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("base_url has no usable port")
		}
	}
	return u.Hostname(), port, nil
}

func cleanText(s string, required bool) bool {
	if (required && s == "") || len(s) > maxPushText || strings.ContainsAny(s, "\r\n\x00") {
		return false
	}
	return true
}

// Validate bounds and checks a spec.
func (p PushSpec) Validate() error {
	switch {
	case p.OpID == "" || len(p.OpID) > 64 || strings.ContainsAny(p.OpID, "|\r\n\x00"):
		return errors.New("op_id is not valid")
	case p.Target != "scim" && p.Target != "okta":
		return errors.New("target must be scim or okta")
	case len(p.BaseURL) > maxPushURL || !strings.HasPrefix(strings.ToLower(p.BaseURL), "https://"):
		return errors.New("base_url must be an https URL")
	case p.Dialect != "" && p.Dialect != "standard" && p.Dialect != "entra":
		return errors.New("dialect is not valid")
	case p.Target == "okta" && p.Dialect != "":
		return errors.New("dialect applies to SCIM targets only")
	case !validKind(p.Op):
		return errors.New("op is not an operation kind")
	case p.Key == "" || len(p.Key) > 200 || strings.ContainsAny(p.Key, "\r\n\x00"):
		return errors.New("key is not valid")
	case p.CredName != "" && (len(p.CredName) > 64 || strings.ContainsAny(p.CredName, "/\\|\r\n\x00 ")):
		return errors.New("cred_name is not valid")
	case !cleanText(p.Account.Username, true) || !cleanText(p.Account.ExternalID, false) || !cleanText(p.Account.Email, false) ||
		!cleanText(p.Account.DisplayName, false) || len(p.Account.Attrs) > maxPushAttrs:
		return errors.New("account is not valid")
	case !cleanText(p.Group.ExternalID, false) || !cleanText(p.Group.Name, false):
		return errors.New("group is not valid")
	case (p.Op == AddEntitlement || p.Op == RemoveEntitlement) && p.Group.ExternalID == "" && p.Group.Name == "":
		return errors.New("an entitlement operation needs a group")
	}
	for k, v := range p.Account.Attrs {
		if !cleanText(k, true) || !cleanText(v, false) {
			return errors.New("an account attribute is not valid")
		}
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base_url must be an https URL without credentials, query or fragment")
	}
	if _, _, err := p.HostPort(); err != nil {
		return err
	}
	return nil
}

func validKind(k string) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}
