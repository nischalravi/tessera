package salesforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Credential is what a provisioning target keeps sealed: the JWT bearer flow's identity and key, as JSON
//
//	{"client_id":"3MVG9...","username":"integration@acme.example","private_key":"-----BEGIN PRIVATE KEY-----...",
//	 "login_url":"https://test.salesforce.com","default_profile_id":"00e..."}
//
// login_url (a sandbox) and default_profile_id (the profile of a created user that names none) are optional.
type Credential struct {
	ClientID         string `json:"client_id"`
	Username         string `json:"username"`
	PrivateKey       string `json:"private_key"`
	LoginURL         string `json:"login_url,omitempty"`
	DefaultProfileID string `json:"default_profile_id,omitempty"`
}

// ParseCredential reads and checks a target credential. Its errors never repeat the key.
func ParseCredential(s string) (*Credential, error) {
	if len(s) > 16<<10 {
		return nil, errors.New("the Salesforce credential is too long")
	}
	var c Credential
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, errors.New("the Salesforce credential is JSON with client_id, username and private_key")
	}
	if c.ClientID == "" || c.Username == "" || c.PrivateKey == "" {
		return nil, errors.New("the Salesforce credential needs client_id, username and private_key")
	}
	if _, err := parseKey(c.PrivateKey); err != nil {
		return nil, err
	}
	if c.DefaultProfileID != "" && !idRE.MatchString(c.DefaultProfileID) {
		return nil, errors.New("default_profile_id is not a Salesforce id")
	}
	return &c, nil
}

// OpenTarget builds the provisioning target of an org from its base URL and sealed credential.
func OpenTarget(baseURL string, cred *Credential, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Target, error) {
	c, err := Open(Config{BaseURL: baseURL, LoginURL: cred.LoginURL, ClientID: cred.ClientID, Username: cred.Username,
		PrivateKey: connsync.NewSecret(cred.PrivateKey)}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return &Target{C: c, DefaultProfileID: cred.DefaultProfileID}, nil
}
