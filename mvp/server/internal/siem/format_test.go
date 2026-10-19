package siem_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func sp(s string) *string { return &s }

var goldenTenant = tenancy.MustParse("00000000-0000-4000-8000-0000000000aa")

func goldenEvent(seq int64, action, outcome string, detail string) *store.AuditEvent {
	return &store.AuditEvent{
		ID: uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", seq)), TenantID: goldenTenant, Seq: seq,
		OccurredAt: time.Date(2026, 10, 11, 9, 30, 0, 123000000, time.UTC), ActorType: "user", ActorID: sp("2b3c0e0e-1111-4222-8333-444455556666"),
		ActorDisplay: sp("Alice (tenant admin)"), Action: action, Outcome: outcome, IP: sp("203.0.113.7"), Detail: json.RawMessage(detail),
		SchemaVersion: 1, PrevHash: fmt.Sprintf("prev%d", seq), Hash: fmt.Sprintf("hash%d", seq),
	}
}

func goldenEvents() map[string]*store.AuditEvent {
	login := goldenEvent(1, "auth.login.success", "success", `{"protocol":"oidc"}`)
	login.Authn = json.RawMessage(`{"aal":2,"phr":true}`)
	login.SessionID = sp("sess-1")
	fail := goldenEvent(2, "auth.login.failure", "failure", `{"email":"mallory@example.com","reason":"unknown_user"}`)
	fail.ActorType, fail.ActorID, fail.ActorDisplay = "anonymous", nil, nil
	role := goldenEvent(3, "auth.role.granted", "success", `{"role":"tenant_admin","user":"pat@larkspur.example"}`)
	role.TargetType, role.TargetID = sp("platform_user"), sp("7c9e6679-7425-40de-944b-e07fc1f90ae7")
	httpReq := goldenEvent(4, "http.request", "success", `{}`)
	httpReq.HTTP = json.RawMessage(`{"method":"GET","route":"/api/identities/{identity_id}","path_params":{"identity_id":"12"},"query_keys":[],"status":200,"latency_ms":4}`)
	httpReq.RequestID = sp("req-4")
	alert := goldenEvent(5, "alert.raised", "success", `{"rule":"break_glass_used","severity":"critical","title":"Break-glass access used by Ivan"}`)
	alert.ActorType, alert.ActorID, alert.ActorDisplay = "system", sp("alerts.engine"), sp("alerts.engine")
	revoke := goldenEvent(6, "grant.revoke", "success", `{"edge_id":42}`)
	return map[string]*store.AuditEvent{"login_success": login, "login_failure": fail, "role_granted": role,
		"http_request": httpReq, "alert_raised": alert, "grant_revoke": revoke}
}

// TestOCSFGolden pins the OCSF mapping. Run with -update to rewrite.
func TestOCSFGolden(t *testing.T) {
	for name, e := range goldenEvents() {
		r, err := siem.Encode(siem.FormatOCSF, e, "larkspur")
		if err != nil {
			t.Fatal(err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, r.Payload, "", "  "); err != nil {
			t.Fatal(err)
		}
		pretty.WriteByte('\n')
		path := filepath.Join("testdata", "ocsf_"+name+".json")
		if *update {
			if err := os.WriteFile(path, pretty.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/siem -update)", name, err)
		}
		if !bytes.Equal(pretty.Bytes(), want) {
			t.Errorf("%s: OCSF mapping changed:\n%s", name, pretty.String())
		}
	}
}

func TestOCSFClasses(t *testing.T) {
	want := map[string][2]int{"login_success": {3002, 300201}, "login_failure": {3002, 300201}, "role_granted": {3001, 300107},
		"http_request": {6003, 600302}, "alert_raised": {6003, 600301}, "grant_revoke": {6003, 600304}}
	for name, e := range goldenEvents() {
		o := siem.OCSF(e, "larkspur")
		if o["class_uid"] != want[name][0] || o["type_uid"] != want[name][1] {
			t.Errorf("%s: class %v type %v, want %v", name, o["class_uid"], o["type_uid"], want[name])
		}
		tessera := o["unmapped"].(map[string]any)["tessera"].(map[string]any)
		if tessera["hash"] != e.Hash || tessera["prev_hash"] != e.PrevHash || tessera["seq"] != e.Seq {
			t.Errorf("%s: chain fields missing: %v", name, tessera)
		}
	}
	if o := siem.OCSF(goldenEvents()["login_failure"], "x"); o["status_id"] != 2 || o["status_detail"] != "unknown_user" {
		t.Errorf("failure status: %v %v", o["status_id"], o["status_detail"])
	}
	if o := siem.OCSF(goldenEvents()["alert_raised"], "x"); o["severity_id"] != 5 {
		t.Errorf("alert severity: %v", o["severity_id"])
	}
}

// TestNativeRecordVerifies: the json format is the export record, so its hash
// recomputes to the ledger's.
func TestNativeRecordVerifies(t *testing.T) {
	e := goldenEvents()["role_granted"]
	h, err := audit.EventHash(e)
	if err != nil {
		t.Fatal(err)
	}
	e.Hash = h
	r, err := siem.Encode(siem.FormatJSON, e, "larkspur")
	if err != nil {
		t.Fatal(err)
	}
	ok, got, err := audit.VerifyRecord(r.Payload)
	if err != nil || !ok || got != h {
		t.Fatalf("verify: %v %q %v", ok, got, err)
	}
	tampered := bytes.Replace(r.Payload, []byte("tenant_admin"), []byte("viewer"), 1)
	if ok, _, _ := audit.VerifyRecord(tampered); ok {
		t.Fatal("a tampered record verifies")
	}
}
