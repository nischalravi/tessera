package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Automatic mode as code (issue #664, LP-8): off by default, needs the policy applied through two people, and then
// a second two-person change to switch it on; the calibration blocks it when the false-positive rate is over 1 percent.
func TestLPAPI_AutoPolicyFlow(t *testing.T) {
	w := newAWSWB(t)
	w.enable()
	files := func(yaml string) string {
		raw, _ := json.Marshal(map[string]any{"commit": "c0ffee", "files": map[string]string{"lp/auto.yaml": yaml}})
		return string(raw)
	}
	const good = "version: 1\nkinds: [aws_set_policy_version]\nmin_unused_days: 90\nmax_per_day: 20\n"

	// off by default: no policy, mode off, not running
	g := w.c.json("GET", "/api/lp/auto-policy", "", 200).(map[string]any)
	if g["applied"] != false || g["mode"] != store.LPModeOff || g["running"] != false || g["policy"] != nil {
		t.Fatalf("default = %v", g)
	}

	// the file is checked at the boundary; nothing is stored by validating
	for _, bad := range []string{"version: 1\nkinds: [aws_set_policy_version]\nconfidence: medium\n", "version: 1\nkinds: [aws_set_policy_version]\nmin_unused_days: 30\n",
		"version: 1\nkinds: [aws_set_policy_version]\nexclude_break_glass: false\n", "version: 1\nkinds: [aws_trust_policy]\n"} {
		if r := w.c.do("POST", "/api/lp/auto-policy/validate", files(bad)); r.Code != 422 || !strings.Contains(r.Body.String(), "invalid_auto_policy") {
			t.Errorf("validate %q: %d %s", bad, r.Code, r.Body)
		}
		if r := w.c.do("POST", "/api/lp/auto-policy/apply", files(bad)); r.Code != 422 {
			t.Errorf("apply %q: %d %s", bad, r.Code, r.Body)
		}
	}
	if r := w.c.do("POST", "/api/lp/auto-policy/validate", `{"files":{"README.md":"x"}}`); r.Code != 422 {
		t.Errorf("a bundle without lp/auto.yaml: %d %s", r.Code, r.Body)
	}
	v := w.c.json("POST", "/api/lp/auto-policy/validate", files(good), 200).(map[string]any)
	digest := asString(v["policy_sha256"])
	if v["valid"] != true || len(digest) != 64 {
		t.Fatalf("validate = %v", v)
	}
	if g := w.c.json("GET", "/api/lp/auto-policy", "", 200).(map[string]any); g["applied"] != false {
		t.Fatalf("validate stored a policy: %v", g)
	}

	// auto cannot be switched on before a policy was applied
	modeAuto := fmt.Sprintf(`{"type":%q,"payload":{"mode":"auto"}}`, admin.TypeLPSettingsUpdate)
	if r := w.c.do("POST", "/api/admin/change-requests", modeAuto); r.Code != 422 || !strings.Contains(r.Body.String(), "auto_policy_missing") {
		t.Fatalf("auto without a policy: %d %s", r.Code, r.Body)
	}

	// a payload that names another digest than the files hash to is stale
	stale := fmt.Sprintf(`{"type":%q,"payload":{"commit":"c0ffee","files":{"lp/auto.yaml":%q},"bundle_sha256":%q,"policy_sha256":%q}}`,
		admin.TypeLPAutoPolicyApply, good, strings.Repeat("0", 64), strings.Repeat("0", 64))
	if r := w.c.do("POST", "/api/admin/change-requests", stale); r.Code < 400 {
		t.Errorf("a stale digest was filed: %d %s", r.Code, r.Body)
	}

	// applying files a change request: two people, never applied before the second approves
	ch := w.c.json("POST", "/api/lp/auto-policy/apply", files(good), http.StatusCreated).(map[string]any)
	req := ch["change_request"].(map[string]any)
	cid, approve := asString(req["id"]), fmt.Sprintf(`{"payload_hash":%q}`, asString(req["payload_hash"]))
	if req["type"] != admin.TypeLPAutoPolicyApply || req["two_person"] != true || req["status"] != "pending_approval" || ch["policy_sha256"] != digest {
		t.Fatalf("filed = %v", ch)
	}
	if g := w.c.json("GET", "/api/lp/auto-policy", "", 200).(map[string]any); g["applied"] != false {
		t.Fatalf("applied before approval: %v", g)
	}
	if r := w.c.do("POST", "/api/admin/change-requests/"+cid+"/approve", approve); r.Code != http.StatusForbidden {
		t.Fatalf("self approval: %d %s", r.Code, r.Body)
	}
	w.other.json("POST", "/api/admin/change-requests/"+cid+"/approve", approve, 200)
	g = w.c.json("GET", "/api/lp/auto-policy", "", 200).(map[string]any)
	if g["applied"] != true || g["policy_sha256"] != digest || g["commit"] != "c0ffee" || g["running"] != false || g["mode"] != store.LPModeOff {
		t.Fatalf("after the apply = %v", g)
	}
	if pol := g["policy"].(map[string]any); pol["confidence"] != "high" || pol["exclude_break_glass"] != true || pol["privileged_prod"] != "suggest" {
		t.Errorf("policy = %v", pol)
	}

	// calibration over 1 percent blocks switching auto on
	testkit.Write(t, w.st, func(tx *store.TenantTx) error {
		r := &store.LPRevocation{ID: "old-1", State: store.LPCandidate, Kind: "aws_set_policy_version", Eligibility: store.LPEligAuto, ConnectorID: "c",
			SnapshotID: "s", AccountID: "111122223333", Principal: "arn:aws:iam::111122223333:role/x", PolicyARN: "arn:aws:iam::111122223333:policy/P",
			UnusedDays: 100, Confidence: "high", Evidence: `{}`, CandidateSHA256: strings.Repeat("a", 64), RestorePayload: `{}`,
			RestoreSHA256: strings.Repeat("b", 64), CreatedBy: "u", CreatedAt: testkit.Now}
		if err := tx.InsertLPRevocation(r); err != nil {
			return err
		}
		r.State, r.ExecutedAt = store.LPRevoked, &testkit.Now
		if err := tx.UpdateLPRevocation(r, store.LPCandidate, testkit.Now); err != nil {
			return err
		}
		return tx.InsertLPFalsePositive(&store.LPFalsePositive{RevocationID: r.ID, Source: store.LPFPJIT, Principal: r.Principal,
			PolicyARN: r.PolicyARN, Confidence: "high", CreatedAt: testkit.Now})
	})
	if g := w.c.json("GET", "/api/lp/auto-policy", "", 200).(map[string]any); asString(g["calibration_review"]) == "" {
		t.Errorf("no review reported: %v", g)
	}
	if r := w.c.do("POST", "/api/admin/change-requests", modeAuto); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "calibration_review") {
		t.Fatalf("auto over the calibration threshold: %d %s", r.Code, r.Body)
	}
}

// With the policy applied and the calibration clean, switching auto on is a two-person change.
func TestLPAPI_AutoModeTwoPeople(t *testing.T) {
	w := newAWSWB(t)
	w.enable()
	testkit.Write(t, w.st, func(tx *store.TenantTx) error {
		return tx.PutLPAutoPolicy(&store.LPAutoPolicy{Policy: `{"version":1,"confidence":"high","min_unused_days":90,"max_per_day":100,` +
			`"kinds":["aws_set_policy_version"],"accounts":[],"exclude_break_glass":true,"privileged_prod":"suggest"}`,
			PolicySHA256: strings.Repeat("a", 64), Commit: "c0ffee", AppliedBy: "x"}, testkit.Now)
	})
	ch := w.c.json("POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":%q,"payload":{"mode":"auto"}}`, admin.TypeLPSettingsUpdate), http.StatusCreated).(map[string]any)
	cid, approve := asString(ch["id"]), fmt.Sprintf(`{"payload_hash":%q}`, asString(ch["payload_hash"]))
	if ch["two_person"] != true {
		t.Fatalf("auto is a loosening: %v", ch)
	}
	if g := w.c.json("GET", "/api/lp/settings", "", 200).(map[string]any); g["mode"] != store.LPModeOff {
		t.Fatalf("auto before approval: %v", g)
	}
	w.other.json("POST", "/api/admin/change-requests/"+cid+"/approve", approve, 200)
	if g := w.c.json("GET", "/api/lp/settings", "", 200).(map[string]any); g["mode"] != store.LPModeAuto {
		t.Fatalf("after approval: %v", g)
	}
}
