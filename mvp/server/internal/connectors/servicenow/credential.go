package servicenow

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Target modes: Direct changes the instance's own tables; Ticket raises an incident for a person to act on.
const (
	ModeDirect = "direct"
	ModeTicket = "ticket"
)

// Credential is what a provisioning target keeps sealed, as JSON
//
//	{"auth":"basic","username":"tessera.integration","password":"..."}
//	{"auth":"oauth","client_id":"...","client_secret":"..."}
//
// plus, optionally, "mode":"ticket" (raise an incident per change instead of changing the instance) and
// "assignment_group":"<sys_id>" (the group the incident goes to). Its errors never repeat a secret.
type Credential struct {
	Auth            string `json:"auth"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	Mode            string `json:"mode,omitempty"`
	AssignmentGroup string `json:"assignment_group,omitempty"`
}

// ParseCredential reads and checks a target credential.
func ParseCredential(s string) (*Credential, error) {
	if len(s) > 8<<10 {
		return nil, errors.New("the ServiceNow credential is too long")
	}
	var c Credential
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, errors.New("the ServiceNow credential is JSON: auth (basic or oauth) with username and password, or client_id and client_secret")
	}
	switch c.Auth {
	case AuthBasic:
		if !clientRE.MatchString(c.Username) || c.Password == "" || c.ClientID != "" || c.ClientSecret != "" {
			return nil, errors.New("a basic ServiceNow credential needs username and password only")
		}
	case AuthOAuth:
		if !clientRE.MatchString(c.ClientID) || c.ClientSecret == "" || c.Username != "" || c.Password != "" {
			return nil, errors.New("an oauth ServiceNow credential needs client_id and client_secret only")
		}
	default:
		return nil, errors.New("auth must be basic or oauth")
	}
	switch c.Mode {
	case "", ModeDirect, ModeTicket:
	default:
		return nil, errors.New("mode must be direct or ticket")
	}
	if c.AssignmentGroup != "" && !sysIDRE.MatchString(c.AssignmentGroup) {
		return nil, errors.New("assignment_group is not a sys_id")
	}
	if c.AssignmentGroup != "" && c.Mode != ModeTicket {
		return nil, errors.New("assignment_group applies to ticket mode only")
	}
	return &c, nil
}

// Config is the client configuration the credential stands for.
func (c *Credential) config(baseURL string) Config {
	if c.Auth == AuthOAuth {
		return Config{BaseURL: baseURL, AuthMode: AuthOAuth, Username: c.ClientID, Secret: connsync.NewSecret(c.ClientSecret)}
	}
	return Config{BaseURL: baseURL, AuthMode: AuthBasic, Username: c.Username, Secret: connsync.NewSecret(c.Password)}
}

// OpenTarget builds the provisioning target of an instance from its base URL and sealed credential.
func OpenTarget(baseURL string, cred *Credential, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Target, error) {
	c, err := Open(cred.config(baseURL), rt, hc, now)
	if err != nil {
		return nil, err
	}
	return &Target{C: c, Ticket: cred.Mode == ModeTicket, AssignmentGroup: cred.AssignmentGroup}, nil
}
