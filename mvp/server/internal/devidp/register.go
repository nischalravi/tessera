package devidp

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Runtime user registration (issue #69): the guest claim's dev credential
// authority registers the guest here, so the person who claimed an invitation
// can then sign in through the normal OIDC flow with a passkey. Dev and test
// only like the rest of the dev IdP.
//
//	POST /_register  {sub, email, name, tenant, authenticators}
//
// The caller authenticates as a registered client (client_secret_basic, the
// same secret as the token endpoint). Only subs that start with RegisterPrefix
// can be registered, and only runtime-registered users can be replaced, so a
// call can never overwrite a users.yaml user. Registration is idempotent.

// RegisterPrefix is what every runtime-registered subject starts with.
const RegisterPrefix = "guest-"

const (
	maxRegistered    = 1000
	maxRegisterBytes = 4 << 10
	maxFieldBytes    = 320
)

type registerIn struct {
	Sub            string   `json:"sub"`
	Email          string   `json:"email"`
	Name           string   `json:"name"`
	Tenant         string   `json:"tenant"`
	Authenticators []Method `json:"authenticators"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	id, pass, ok := r.BasicAuth()
	cid, err1 := url.QueryUnescape(id)
	secret, err2 := url.QueryUnescape(pass)
	c := s.clients[cid]
	if !ok || err1 != nil || err2 != nil || c == nil || c.Secret == "" ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="tessera-devidp"`)
		http.Error(w, "client authentication failed", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in registerIn
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "malformed registration", http.StatusBadRequest)
		return
	}
	switch {
	case !strings.HasPrefix(in.Sub, RegisterPrefix) || len(in.Sub) > maxFieldBytes || strings.ContainsAny(in.Sub, " \t\r\n\x00"),
		in.Email == "" || len(in.Email) > maxFieldBytes, in.Name == "" || len(in.Name) > maxFieldBytes,
		in.Tenant == "" || len(in.Tenant) > 64, len(in.Authenticators) == 0:
		http.Error(w, "sub (guest-...), email, name, tenant and authenticators are required", http.StatusBadRequest)
		return
	}
	for _, m := range in.Authenticators {
		if !slices.Contains(Methods(), m) {
			http.Error(w, "unknown authenticator", http.StatusBadRequest)
			return
		}
	}
	u := User{Sub: in.Sub, Email: in.Email, Name: in.Name, Tenant: in.Tenant, Authenticators: in.Authenticators}
	if err := s.register(u); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.log.Info("devidp registered a user", "sub", u.Sub, "tenant", u.Tenant)
	w.WriteHeader(http.StatusNoContent)
}

type registerError string

func (e registerError) Error() string { return string(e) }

// register adds u, or replaces the runtime-registered user with the same sub.
func (s *Server) register(u User) error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if s.registered == nil {
		s.registered = map[string]bool{}
	}
	for i := range s.users {
		if s.users[i].Sub == u.Sub {
			if !s.registered[u.Sub] {
				return registerError("that subject belongs to a configured user")
			}
			s.users[i] = u
			return nil
		}
	}
	if len(s.registered) >= maxRegistered {
		return registerError("too many registered users")
	}
	s.users = append(s.users, u)
	s.registered[u.Sub] = true
	return nil
}

// userList returns a copy of the users.
func (s *Server) userList() []User {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	return slices.Clone(s.users)
}

// findUser returns a copy of the user with this sub, or nil.
func (s *Server) findUser(sub string) *User {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	for i := range s.users {
		if s.users[i].Sub == sub {
			u := s.users[i]
			return &u
		}
	}
	return nil
}
