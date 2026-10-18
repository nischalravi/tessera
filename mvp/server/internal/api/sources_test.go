package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

// activateAD drives a validated AD connection through dry run, reconciliation
// and activation, accepting every blocker the way the walkthrough does.
func (c rdClient) activateAD(ad string) {
	c.t.Helper()
	dr := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	for _, f := range findings(dr) {
		if f["severity"] == "critical" || f["severity"] == "high" || f["code"] == "RF-09" {
			c.json("POST", "/api/connections/"+ad+"/findings/"+f["id"].(string)+"/accept",
				`{"reason":"Accepted for go-live; tracked in the remediation plan CHG-2210"}`, http.StatusOK)
		}
	}
	c.json("POST", "/api/connections/"+ad+"/transition", `{"to":"dry_run_reconciled"}`, http.StatusOK)
	r := c.json("POST", "/api/connections/"+ad+"/activate", "", http.StatusConflict)
	for _, b := range r["blocking"].([]any) {
		item := b.(map[string]any)["item"].(string)
		if item == "ad.tls.signing_cb" || item == "ad.key.employeeid" {
			c.json("POST", "/api/connections/"+ad+"/checklist/"+item+"/skip", `{"reason":"Scheduled for the Q1 domain controller upgrade"}`, http.StatusOK)
		} else {
			c.attest(ad, item)
		}
	}
	if v := c.json("POST", "/api/connections/"+ad+"/activate", "", http.StatusOK); v["state"] != "active" {
		c.t.Fatalf("not active: %v", v["state"])
	}
}

// connectorSystems lists the systems of GET /api/connectors, and the name of
// the one for system (empty if absent).
func (c rdClient) connectorSystems(system string) ([]string, string) {
	c.t.Helper()
	var rows []struct{ System, Name string }
	if err := json.Unmarshal(c.do("GET", "/api/connectors", "").Body.Bytes(), &rows); err != nil {
		c.t.Fatal(err)
	}
	var systems []string
	name := ""
	for _, r := range rows {
		systems = append(systems, r.System)
		if r.System == system {
			name = r.Name
		}
	}
	return systems, name
}

// TestSources_ActiveGovernedConnection: an active governed connection is a
// source and an application, so /api/connectors (which the Applications list
// and page and the Home source counts read) agrees with /api/summary; draft,
// not-yet-active and retired connections are not counted (#139).
func TestSources_ActiveGovernedConnection(t *testing.T) {
	c := newRD(t)
	base, _ := c.connectorSystems("ad-corp")
	if slices.Contains(base, "ad-corp") {
		t.Fatalf("ad-corp listed before it exists: %v", base)
	}
	summarySystems := func() int { return int(c.json("GET", "/api/summary", "", http.StatusOK)["systems"].(float64)) }
	if n := summarySystems(); n != len(base) {
		t.Fatalf("baseline: summary systems %d, connectors %d", n, len(base))
	}

	// draft and validated: not a source yet
	ad := c.adValidated()
	if got, _ := c.connectorSystems("ad-corp"); len(got) != len(base) {
		t.Fatalf("validated connection counted: %v", got)
	}
	c.activateAD(ad)

	got, name := c.connectorSystems("ad-corp")
	if len(got) != len(base)+1 || name != "Active Directory (demo)" {
		t.Fatalf("active connection missing: %v name %q", got, name)
	}
	if n := summarySystems(); n != len(got) {
		t.Errorf("summary systems %d, connectors %d: counts drifted", n, len(got))
	}
	var rows []map[string]any
	if err := json.Unmarshal(c.do("GET", "/api/connectors", "").Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r["system"] == "ad-corp" && r["accounts"].(float64) != float64(c.systemCounts("ad-corp").Accounts) {
			t.Errorf("ad-corp accounts: %v", r["accounts"])
		}
	}

	// a second, draft connection on another type is not counted
	c.json("POST", "/api/connections", `{"name":"Workday (demo)","connector_type":"demo-workday"}`, http.StatusCreated)
	if again, _ := c.connectorSystems("ad-corp"); len(again) != len(got) {
		t.Errorf("draft connection counted: %v", again)
	}

	// retired: gone again
	c.json("POST", "/api/connections/"+ad+"/retire", `{"confirm":true}`, http.StatusOK)
	if after, _ := c.connectorSystems("ad-corp"); slices.Contains(after, "ad-corp") {
		t.Errorf("retired connection still listed: %v", after)
	}
}

var leadingInt = regexp.MustCompile(`^(\d+)( |$)`)

// TestDeploymentHealth_SentenceCountMatchesAffected: when a needs-attention
// sentence opens with a number, it is the entry's affected count, for every
// kind (item, finding, skip) and every finding code (#140).
func TestDeploymentHealth_SentenceCountMatchesAffected(t *testing.T) {
	c := newRD(t)
	for _, id := range []string{c.adValidatedMiscounted(), c.validatedConn("demo-okta", "Okta (demo)", "")} {
		c.json("POST", "/api/connections/"+id+"/dry-run", "", http.StatusAccepted)
	}
	d := c.json("GET", "/api/insights/deployment-health", "", http.StatusOK)
	seen := map[string]bool{}
	leavers, numbered := false, 0
	for _, e := range d["needs_attention"].([]any) {
		m := e.(map[string]any)
		kind, code, sentence := m["kind"].(string), "", m["sentence"].(string)
		if cd, ok := m["code"].(string); ok {
			code = cd
		}
		seen[kind] = true
		leavers = leavers || code == "RF-06b"
		mm := leadingInt.FindStringSubmatch(sentence)
		if mm == nil {
			continue
		}
		numbered++
		n, _ := strconv.Atoi(mm[1])
		if float64(n) != m["affected"].(float64) {
			t.Errorf("%s %s: sentence says %d, affected %v: %q", kind, code, n, m["affected"], sentence)
		}
	}
	if !seen["finding"] || !leavers || numbered == 0 {
		t.Errorf("fixture lacks entries: kinds %v, RF-06b %v, numbered %d", seen, leavers, numbered)
	}
}
