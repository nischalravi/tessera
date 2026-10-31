package admin_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// policy.sync.apply (issue #657): a payload that is not a whole, consistent sync is refused when it is filed, and a person
// files it only with a fresh step-up (the API tests cover the loop itself).
func TestPolicySyncPayloadIsValidated(t *testing.T) {
	h := newHarness(t)
	a := h.admins("admin1", "admin2")
	p := h.as(a[0])
	if !slices.Contains(admin.Types(), admin.TypePolicySyncApply) {
		t.Fatalf("%s is not a change type", admin.TypePolicySyncApply)
	}
	sha := strings.Repeat("a", 40)
	good := map[string]any{"repo": "o/policy", "sha": sha, "kind": "sync", "default_branch": "main", "bundle_sha256": strings.Repeat("0", 64),
		"plan_sha256": strings.Repeat("1", 64), "kinds": []any{}, "files": map[string]string{"tessera.yaml": "x"},
		"prediction": map[string]any{"perms": []any{}}}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, payload := range map[string]map[string]any{
		"a repo that is not owner/name": with("repo", "policy"),
		"a short sha":                   with("sha", "abc"),
		"a branch name for the sha":     with("sha", "main"),
		"an upper-case sha":             with("sha", strings.Repeat("A", 40)),
		"an unknown kind":               with("kind", "merge"),
		"a rollback without its origin": with("kind", "rollback"),
		"no files":                      with("files", map[string]string{}),
		"no prediction":                 with("prediction", nil),
		"a bundle digest that is wrong": with("bundle_sha256", strings.Repeat("0", 64)),
		"an unknown field":              with("extra", true),
	} {
		raw, _ := json.Marshal(payload)
		_, err := h.svc.Submit(h.ctx, p, admin.SubmitInput{Type: admin.TypePolicySyncApply, Payload: raw})
		var ae *admin.Error
		if !errors.As(err, &ae) || ae.Status < 400 || ae.Status >= 500 {
			t.Errorf("%s: %v, want a 4xx admin error", name, err)
		}
	}
	// a prediction whose total does not match its list (it would switch off the unexpected-change checks) is refused by the
	// sync filing path too
	forged := with("prediction", map[string]any{"perms": []any{}, "perms_total": 1})
	if _, err := h.svc.SubmitPolicySync(h.ctx, p, mustJSON(t, forged)); err == nil || !strings.Contains(err.Error(), "perms") {
		t.Errorf("a forged prediction: %v", err)
	}
	// nothing was filed
	h.tx(func(tx *store.TenantTx) error {
		if s, err := tx.RecentPolicySyncs("o/policy", 10); err != nil || len(s) != 0 {
			t.Errorf("syncs after refused payloads = %v, %v", s, err)
		}
		return nil
	})
	// a person's sign-in older than the step-up window files nothing
	if _, err := h.svc.SubmitPolicySync(h.ctx, h.asAged(a[0], 20*60*1e9), mustJSON(t, good)); err == nil {
		t.Error("a stale sign-in filed a sync")
	}
	// a machine principal with no client id is not a machine client: it is handled as a person and refused
	if _, err := h.svc.SubmitPolicySync(h.ctx, nil, mustJSON(t, good)); err == nil {
		t.Error("no principal filed a sync")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
