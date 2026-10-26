package readiness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestGoverned_AWSStoredKeyRefusedAtCreation (#675): with static keys off (always in
// prod) a secret on an awsorg connection is refused with static_keys_disabled and
// nothing is sealed; a vault reference and other governed types are unaffected, and
// the server's opt-in (dev) takes the secret.
func TestGoverned_AWSStoredKeyRefusedAtCreation(t *testing.T) {
	cases := []struct {
		name    string
		allow   bool
		typ     string
		in      CredentialInput
		wantErr bool
	}{
		{"aws secret, static keys off", false, "awsorg", CredentialInput{Secret: govSecret}, true},
		{"aws vault reference, static keys off", false, "awsorg", CredentialInput{Reference: "vault:kv/x"}, false},
		{"aws secret, static keys on", true, "awsorg", CredentialInput{Secret: govSecret}, false},
		{"other governed type, static keys off", false, "githubscan", CredentialInput{Secret: govSecret}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			s.AWSAllowStaticKeys = tc.allow
			id := createGov(t, s, st, tc.typ, "Gov "+tc.typ, govConfig[tc.typ])
			err := st.Write(context.Background(), func(c *store.TenantTx) error {
				_, err := s.SetCredential(c, id, tc.in, "admin", t0)
				return err
			})
			var re *Error
			if tc.wantErr {
				if !errors.As(err, &re) || re.Code != "static_keys_disabled" || strings.Contains(re.Msg, govSecret) {
					t.Fatalf("err = %v", err)
				}
			} else if err != nil {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
