package readiness

import (
	"encoding/json"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestLiveAttest_StaleWhenBindIdentityOrTrustChanges: a substitute attestation
// for ldap.svc.readonly is bound to the item hash, which covers the bind DN and
// the trusted CA bundle (and the port). Changing only one of them makes it
// stale and blocks the gate; an unrelated edit does not.
func TestLiveAttest_StaleWhenBindIdentityOrTrustChanges(t *testing.T) {
	ca, err := json.Marshal(caPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		patch string
		stale bool
	}{
		{"bind_dn", `{"bind_dn":"uid=other,ou=people,dc=tessera,dc=test"}`, true},
		{"ca_bundle", `{"ca_bundle":` + string(ca) + `}`, true},
		{"port", `{"port":389}`, true},
		{"unrelated", `{"stale_days":45}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, s, id, _ := attestSetup(t, "unsupported")
			validate(t, st, s, id, t0)
			if err := attestInstead(t, st, s, id, itemReadonly, goodAttest, t0); err != nil {
				t.Fatal(err)
			}
			before, _ := current(st, s, id, t0)
			if ok, why := liveAttestationFresh(before.Evidence.LiveAttestations[itemReadonly],
				mustItem(t, before, itemReadonly).ItemHash, t0, DefaultLiveTTL); !ok {
				t.Fatalf("attestation not fresh before the change: %s", why)
			}
			if tc.stale {
				patchAndRecredential(t, st, s, id, tc.patch, CredentialInput{Secret: bindPassword})
			} else {
				write(t, st, func(c *store.TenantTx) error {
					_, err := s.PatchConfig(c, id, []byte(tc.patch), "admin", t0)
					return err
				})
			}
			b, _ := current(st, s, id, t0)
			a := b.Evidence.LiveAttestations[itemReadonly]
			if a == nil {
				t.Fatal("attestation lost on a config change")
			}
			ok, why := liveAttestationFresh(a, mustItem(t, b, itemReadonly).ItemHash, t0, DefaultLiveTTL)
			if ok == tc.stale {
				t.Fatalf("fresh=%v (%q) after a change to %s, want stale=%v", ok, why, tc.name, tc.stale)
			}
			if !tc.stale {
				return
			}
			if !strings.Contains(why, "configuration changed") {
				t.Errorf("reason %q", why)
			}
			again := t0.Add(time.Minute)
			validate(t, st, s, id, again)
			b, _ = current(st, s, id, again)
			if p := part(t, b, itemReadonly); p.Status != StatusStale {
				t.Errorf("part after a change to %s: %+v", tc.name, p)
			}
			if !slices.Contains(blockers(b, again), itemReadonly) {
				t.Errorf("gate does not block on the stale attestation: %v", blockers(b, again))
			}
		})
	}
}
