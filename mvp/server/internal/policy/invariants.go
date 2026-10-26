package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A tenant's invariants (design access-as-code-repo.md sections 3.6 and 5): the
// Cedar source files in policy_sources replace, by @id, the embedded YAML
// policies, and add the ones the YAML does not have. A tenant with none, or
// whose sources do not load, keeps the YAML: the fallback.

// OverlayInvariants returns base with the invariants of the sources applied: a
// policy of a source replaces the policy of base with the same id in place
// (switched off, if the source is disabled), and a new id is appended in source
// order. Any source that does not load (digest mismatch, parse or schema
// error, an @id used by two sources) fails the whole overlay, so the caller
// falls back to base and never evaluates half a bundle.
func OverlayInvariants(base []*Policy, sources []*store.PolicySource) ([]*Policy, error) {
	out := append([]*Policy(nil), base...)
	at := map[string]int{}
	for i, p := range out {
		at[p.ID] = i
	}
	from := map[string]string{}
	for _, s := range sources {
		if s.Kind != store.PolicyKindInvariant {
			continue
		}
		if sum := sha256.Sum256([]byte(s.Cedar)); hex.EncodeToString(sum[:]) != s.SHA256 {
			return nil, fmt.Errorf("policy: invariant source %s: digest does not match its Cedar", s.Key)
		}
		ps, err := ParseInvariants(s.Key, []byte(s.Cedar))
		if err != nil {
			return nil, fmt.Errorf("invariant source %s: %w", s.Key, err)
		}
		for _, p := range ps {
			if other, dup := from[p.ID]; dup {
				return nil, fmt.Errorf("policy: invariant @id %q is in sources %s and %s", p.ID, other, s.Key)
			}
			from[p.ID] = s.Key
			if s.Status != store.PolicyActive {
				p.Enabled = false
			}
			if i, ok := at[p.ID]; ok {
				out[i] = p
			} else {
				at[p.ID] = len(out)
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// TenantPolicies is what a tenant's analysis evaluates over base: its invariant
// sources overlaid. When they do not load it returns base and the reason, so
// the caller can log it; a database error is returned as one.
func TenantPolicies(tx *store.TenantTx, base []*Policy) (pols []*Policy, unreadable, err error) {
	srcs, err := tx.PolicySources(store.PolicyKindInvariant)
	if err != nil {
		return nil, nil, err
	}
	if len(srcs) == 0 {
		return base, nil, nil
	}
	if pols, err = OverlayInvariants(base, srcs); err != nil {
		return base, err, nil
	}
	return pols, nil, nil
}

// ImportInvariant stores the Cedar of one invariant file as the tenant's source
// key (the file's id), active, after checking that it loads: parse, schema,
// one fact shape per policy, an @id and a severity on each. ref is the
// policy_ref JSON of the apply that wrote it, or "". It returns whether the
// stored source changed; importing what is stored is a no-op.
func ImportInvariant(tx *store.TenantTx, key string, cedar []byte, ref, actor string, now time.Time) (bool, error) {
	if _, err := ParseInvariants(key, cedar); err != nil {
		return false, err
	}
	return tx.PutPolicySource(&store.PolicySource{Kind: store.PolicyKindInvariant, Key: key, Cedar: string(cedar),
		Status: store.PolicyActive, PolicyRef: ref, UpdatedBy: actor}, now)
}

// SetInvariantStatus switches a stored invariant source on or off, keeping its Cedar.
func SetInvariantStatus(tx *store.TenantTx, key, status, actor string, now time.Time) (bool, error) {
	cur, err := tx.PolicySource(store.PolicyKindInvariant, key)
	if err != nil {
		return false, err
	}
	cur.Status, cur.UpdatedBy = status, actor
	return tx.PutPolicySource(cur, now)
}
