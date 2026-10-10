package api

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/readiness golden files")

// validatedConn creates a demo connection of the given type and drives it to
// validated (fixing the simulated range-retrieval gap for AD).
func (c rdClient) validatedConn(connectorType, name, extra string) string {
	c.t.Helper()
	cfg := `{"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"` + extra + `}`
	v := c.json("POST", "/api/connections", fmt.Sprintf(`{"name":%q,"connector_type":%q,"config":%s}`, name, connectorType, cfg), http.StatusCreated)
	id := v["id"].(string)
	c.json("PUT", "/api/connections/"+id+"/credential", `{"reference":"vault:kv/tessera/`+connectorType+`"}`, http.StatusOK)
	c.attest(id, "base.owner")
	c.attest(id, "base.correlation.key")
	c.json("POST", "/api/connections/"+id+"/transition", `{"to":"ready_to_validate"}`, http.StatusOK)
	c.json("POST", "/api/connections/"+id+"/validate", "", http.StatusAccepted)
	if v := c.json("GET", "/api/connections/"+id, "", http.StatusOK); v["state"] != "validated" {
		c.t.Fatalf("%s not validated: %v", name, v["next"])
	}
	return id
}

func (c rdClient) adValidated() string {
	return c.validatedConn("demo-ad", "Active Directory (demo)", `,"demo_fixed_checks":["range_retrieval"],"expected_counts":{"users":65,"groups":13}`)
}

// adValidatedMiscounted is AD with an expected user count 7% off (RF-12).
func (c rdClient) adValidatedMiscounted() string {
	return c.validatedConn("demo-ad", "Active Directory (demo)", `,"demo_fixed_checks":["range_retrieval"],"expected_counts":{"users":70,"groups":13}`)
}

func findings(dr map[string]any) []map[string]any {
	var out []map[string]any
	for _, f := range dr["findings"].([]any) {
		out = append(out, f.(map[string]any))
	}
	return out
}

func finding(dr map[string]any, code string) map[string]any {
	for _, f := range findings(dr) {
		if f["code"].(string)+f["variant"].(string) == code {
			return f
		}
	}
	return nil
}

// liveRows dumps every row of every live (graph and workflow) table of the
// tenant (storetest.Dump, through the tenant-scoped repositories), minus the
// audit log, which a dry run appends to.
func (c rdClient) liveRows() map[string]json.RawMessage {
	c.t.Helper()
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(storetest.Dump(c.t, c.st.DB, c.st.Tenant)), &out); err != nil {
		c.t.Fatal(err)
	}
	delete(out, "audit_log")
	return out
}

func TestStage_NoLiveWrites(t *testing.T) {
	c := newRD(t)
	ad := c.adValidated()
	okta := c.validatedConn("demo-okta", "Okta (demo)", "")
	before := c.liveRows()
	dr := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	c.json("POST", "/api/connections/"+okta+"/dry-run", "", http.StatusAccepted)
	after := c.liveRows()
	for k, v := range before {
		if string(after[k]) != string(v) {
			t.Errorf("dry run changed live table %s", k)
		}
	}
	if n := c.systemCounts("ad-corp").Accounts; n != 0 {
		t.Errorf("%d AD accounts in the live graph before activation", n)
	}
	staged := testkit.Get(t, c.st, func(tx *store.TenantTx) ([]*store.StagedAccount, error) {
		return tx.StagedAccounts(dr["id"].(string))
	})
	if len(staged) != 71 {
		t.Errorf("staged %d AD accounts", len(staged))
	}
}

func TestFindings_Golden(t *testing.T) {
	c := newRD(t)
	ad := c.adValidatedMiscounted()
	okta := c.validatedConn("demo-okta", "Okta (demo)", "")
	adRun := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	oktaRun := c.json("POST", "/api/connections/"+okta+"/dry-run", "", http.StatusAccepted)

	// RF-06(b) for Okta is exactly Oren Whitlock, the leaver the legacy process missed.
	rf06b := finding(oktaRun, "RF-06b")
	if rf06b == nil || rf06b["count"] != float64(1) || rf06b["severity"] != "high" {
		t.Fatalf("Okta RF-06b: %v", rf06b)
	}
	s := rf06b["samples"].([]any)[0].(map[string]any)
	if s["name"] != "oren.whitlock@larkspur.example" {
		t.Errorf("Okta RF-06b sample: %v", s)
	}
	if cause := rf06b["cause"].(map[string]any); !strings.HasPrefix(cause["sentence"].(string), "Oren Whitlock left 20 days ago and is still active in Okta.") {
		t.Errorf("leaver cause: %v", cause["sentence"])
	}
	// RF-08 contains the planted unexpected Domain Admin.
	rf08 := finding(adRun, "RF-08")
	if rf08 == nil || rf08["count"] != float64(1) || rf08["severity"] != "critical" ||
		rf08["samples"].([]any)[0].(map[string]any)["name"] != "callum.ferreira" {
		t.Fatalf("AD RF-08: %v", rf08)
	}
	// RF-09 equals three unowned service accounts.
	if rf09 := finding(adRun, "RF-09"); rf09 == nil || rf09["count"] != float64(3) {
		t.Fatalf("AD RF-09: %v", rf09)
	}
	// RF-01's cause explains it with the unmapped employeeID.
	if rf01 := finding(adRun, "RF-01"); !strings.Contains(rf01["cause"].(map[string]any)["sentence"].(string), "employeeID is empty on 96% of them") {
		t.Errorf("AD RF-01 cause: %v", rf01["cause"])
	}
	var b strings.Builder
	b.WriteString("# Findings of the demo dry runs (DemoCompany + simulated AD, gaps scenario).\n")
	b.WriteString("# Regenerate with: go test ./internal/api -run TestFindings_Golden -update\n")
	for _, run := range []struct {
		name string
		dr   map[string]any
	}{{"demo-ad", adRun}, {"demo-okta", oktaRun}} {
		fs := findings(run.dr)
		sort.Slice(fs, func(i, j int) bool {
			return fs[i]["code"].(string)+fs[i]["variant"].(string) < fs[j]["code"].(string)+fs[j]["variant"].(string)
		})
		for _, f := range fs {
			fmt.Fprintf(&b, "%-9s %-4s %-14s %-8s %3v/%-3v %s\n", run.name, f["code"].(string)[3:], f["variant"], f["severity"],
				f["count"], f["denominator"], f["impact"].(map[string]any)["sentence"])
		}
		counts, _ := json.Marshal(run.dr["counts"])
		fmt.Fprintf(&b, "%-9s counts %s\n", run.name, counts)
	}
	const golden = "../../testdata/readiness/findings.golden"
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Errorf("findings differ from %s:\n--- got\n%s--- want\n%s", golden, b.String(), want)
	}
}

// downstreamPerms counts, independently of package reconcile, the distinct
// permissions reachable from a person's live groups in one system through
// maps_to and grants edges.
func (c rdClient) downstreamPerms(name, system string) int {
	c.t.Helper()
	perms := map[string]bool{}
	c.read(func(tx *store.TenantTx) error {
		idents, err := tx.Identities()
		if err != nil {
			return err
		}
		accts, err := tx.Accounts()
		if err != nil {
			return err
		}
		edges, err := tx.Edges()
		if err != nil {
			return err
		}
		person := map[int64]bool{}
		for _, i := range idents {
			if i.Name == name {
				person[i.ID] = true
			}
		}
		var frontier []string
		for _, a := range accts {
			if a.System != system || a.IdentityID == nil || !person[*a.IdentityID] {
				continue
			}
			for _, e := range edges {
				if e.Src == fmt.Sprintf("account:%d", a.ID) && e.Relation == "member_of" {
					frontier = append(frontier, e.Dst)
				}
			}
		}
		seen := map[string]bool{}
		for len(frontier) > 0 {
			n := frontier[0]
			frontier = frontier[1:]
			if seen[n] {
				continue
			}
			seen[n] = true
			if strings.HasPrefix(n, "perm:") {
				perms[n] = true
			}
			for _, e := range edges {
				if e.Src == n && (e.Relation == "maps_to" || e.Relation == "grants") {
					frontier = append(frontier, e.Dst)
				}
			}
		}
		return nil
	})
	return len(perms)
}

func TestImpact_ThroughMapsTo(t *testing.T) {
	c := newRD(t)
	okta := c.validatedConn("demo-okta", "Okta (demo)", "")
	dr := c.json("POST", "/api/connections/"+okta+"/dry-run", "", http.StatusAccepted)
	rf06b := finding(dr, "RF-06b")
	im := rf06b["impact"].(map[string]any)
	// Independently: permissions reachable from Oren's live Okta groups via maps_to and grants.
	want := c.downstreamPerms("Oren Whitlock", "okta")
	if want == 0 || im["downstream_perms"] != float64(want) {
		t.Errorf("downstream permissions %v, want %d (through Okta groups mapped to AWS roles)", im["downstream_perms"], want)
	}
	if !strings.Contains(im["sentence"].(string), fmt.Sprintf("reaching %d permissions", want)) {
		t.Errorf("impact sentence: %v", im["sentence"])
	}
}

func TestSamples_CappedAndMinimal(t *testing.T) {
	c := newRD(t)
	ad := c.adValidated()
	dr := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	rf01 := finding(dr, "RF-01")
	if rf01["count"].(float64) <= 10 {
		t.Fatalf("RF-01 count %v: the cap is not exercised", rf01["count"])
	}
	for _, f := range findings(dr) {
		samples := f["samples"].([]any)
		if len(samples) > 10 {
			t.Errorf("%s: %d samples", f["code"], len(samples))
		}
		for _, x := range samples {
			m := x.(map[string]any)
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			if strings.Join(keys, ",") != "name,reason,ref" {
				t.Errorf("%s sample carries %v", f["code"], keys)
			}
			if r := m["reason"].(string); strings.Contains(r, "emp-") || strings.Contains(r, "@") {
				t.Errorf("%s sample reason leaks a value: %q", f["code"], r)
			}
		}
	}
}

func TestAccept_ReasonRequired(t *testing.T) {
	c := newRD(t)
	ad := c.adValidated()
	dr := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	rf08 := finding(dr, "RF-08")
	path := "/api/connections/" + ad + "/findings/" + rf08["id"].(string) + "/accept"
	r := c.json("POST", path, `{"reason":"looks fine to me"}`, http.StatusUnprocessableEntity)
	if r["error"] != "reason_too_short" {
		t.Fatalf("short reason: %v", r)
	}
	c.json("POST", path, `{}`, http.StatusUnprocessableEntity)
	r = c.json("POST", path, `{"reason":"Callum covers on-call until CHG-2210 removes him","expires_at":"2027-01-31"}`, http.StatusOK)
	if r["status"] != "accepted" || r["accepted_by"] != "j.rivera@larkspur.example" {
		t.Fatalf("accept: %v", r)
	}
	c.json("POST", path, `{"reason":"Callum covers on-call until CHG-2210 removes him"}`, http.StatusConflict)
	audit := c.do("GET", "/api/audit", "").Body.String()
	if !strings.Contains(audit, "readiness.finding.accepted") || !strings.Contains(audit, "CHG-2210") {
		t.Error("acceptance not audited")
	}
	// The data check that reads RF-08 passes once it is accepted.
	cl := c.json("GET", "/api/connections/"+ad+"/checklist", "", http.StatusOK)
	for _, it := range cl["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == "ad.groups.privileged" {
			for _, p := range m["parts"].([]any) {
				if p.(map[string]any)["kind"] == "data" && p.(map[string]any)["status"] != "pass" {
					t.Errorf("privileged_unexpected after acceptance: %v", p)
				}
			}
		}
	}
	// Filtering findings.
	var list []map[string]any
	rec := c.do("GET", "/api/connections/"+ad+"/findings?status=accepted", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0]["code"] != "RF-08" {
		t.Errorf("accepted findings: %s", rec.Body.String())
	}
	c.json("GET", "/api/connections/"+ad+"/findings?severity=urgent", "", http.StatusUnprocessableEntity)
}

// TestWalkthrough_ADToActive follows the design's demo walkthrough (§12) for
// Active Directory through activation and the first sync.
func TestWalkthrough_ADToActive(t *testing.T) {
	c := newRD(t)
	ad := c.adValidated()
	dr := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	r := c.json("POST", "/api/connections/"+ad+"/transition", `{"to":"dry_run_reconciled"}`, http.StatusConflict)
	if len(r["blocking"].([]any)) == 0 {
		t.Fatal("reconcile gate passed with open critical findings")
	}
	for _, f := range findings(dr) {
		if f["severity"] == "critical" || f["severity"] == "high" || f["code"] == "RF-09" {
			c.json("POST", "/api/connections/"+ad+"/findings/"+f["id"].(string)+"/accept",
				`{"reason":"Accepted for go-live; tracked in the remediation plan CHG-2210"}`, http.StatusOK)
		}
	}
	c.json("POST", "/api/connections/"+ad+"/transition", `{"to":"dry_run_reconciled"}`, http.StatusOK)
	// Activation still needs the remaining attestations, and every
	// Recommended item passed or skipped.
	r = c.json("POST", "/api/connections/"+ad+"/activate", "", http.StatusConflict)
	pending := map[string]bool{}
	for _, b := range r["blocking"].([]any) {
		m := b.(map[string]any)
		if m["level"] != "recommended" && m["reason"] != "attest with a note" {
			t.Fatalf("unexpected blocker after reconciliation: %v", m)
		}
		pending[m["item"].(string)] = true
	}
	if !pending["ad.tls.signing_cb"] || !pending["ad.key.employeeid"] {
		t.Errorf("pending: %v", pending)
	}
	for item := range pending {
		cl := c.json("GET", "/api/connections/"+ad+"/checklist", "", http.StatusOK)
		attestable := false
		for _, it := range cl["items"].([]any) {
			m := it.(map[string]any)
			if m["id"] == item {
				for _, v := range m["verify"].([]any) {
					if v.(map[string]any)["kind"] == "attestation" && m["status"] == "pending" && item != "ad.tls.signing_cb" {
						attestable = true
					}
				}
			}
		}
		if attestable {
			c.attest(ad, item)
		} else {
			c.json("POST", "/api/connections/"+ad+"/checklist/"+item+"/skip", `{"reason":"Scheduled for the Q1 domain controller upgrade"}`, http.StatusOK)
		}
	}
	v := c.json("POST", "/api/connections/"+ad+"/activate", "", http.StatusOK)
	if v["state"] != "active" || v["health"] != "ok" {
		t.Fatalf("after activation: %v %v", v["state"], v["health"])
	}
	// Activation ran the first sync: the AD accounts are in the live graph,
	// without the memberships in out-of-scope groups.
	if n := c.systemCounts("ad-corp").Accounts; n != 71 {
		t.Errorf("live AD accounts: %d", n)
	}
	if n := c.systemCounts("ad-corp").Groups; n != 13 {
		t.Errorf("live AD groups: %d", n)
	}
	// Tier 3 proposals were not linked by the sync either.
	linked := 0
	c.read(func(tx *store.TenantTx) error {
		accts, err := tx.Accounts()
		for _, a := range accts {
			if a.System == "ad-corp" && a.IdentityID != nil {
				linked++
			}
		}
		return err
	})
	if n := linked; n != 38 {
		t.Errorf("linked AD accounts: %d (tier 1 only, 36 people + 2 ambiguous)", n)
	}
	audit := c.do("GET", "/api/audit", "").Body.String()
	for _, ev := range []string{"connection.activated", "connection.first_sync", "readiness.dryrun.completed", "readiness.validation.completed"} {
		if !strings.Contains(audit, ev) {
			t.Errorf("audit lacks %s", ev)
		}
	}
	// Editing the active connection opens a new draft revision; the live one keeps syncing.
	p := c.json("PATCH", "/api/connections/"+ad+"/config", `{"stale_days":60}`, http.StatusOK)
	conn := p["connection"].(map[string]any)
	if p["new_revision"] != true || conn["state"] != "active" || conn["update_in_progress"] != true {
		t.Errorf("edit after activation: %v %v %v", p["new_revision"], conn["state"], conn["update_in_progress"])
	}
}
