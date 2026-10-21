package sod_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Ruleset-level remediation options, the escalation approver and the expiry job
// of an accepted risk (issue #298).

func rulesetOf(t *testing.T, c *store.TenantTx, riskID string) *store.SodRuleset {
	t.Helper()
	r, err := c.SodRisk(riskID)
	must(t, err)
	rs, err := c.SodRuleset(r.RulesetID)
	must(t, err)
	return rs
}

func auditActions(t *testing.T, c *store.TenantTx) map[string]int {
	t.Helper()
	evs, err := c.AuditEvents(store.AuditFilter{})
	must(t, err)
	out := map[string]int{}
	for _, e := range evs {
		out[e.Action]++
	}
	return out
}

func TestRulesetRemediationIsInheritedUnlessTheRiskSetsItsOwn(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids) // the risk sets no options of its own
		rs := rulesetOf(t, c, wd.risk)
		rem, err := sod.RemediationOf(c, wd.risk)
		must(t, err)
		if rem.Source != sod.SourceDefault || len(rem.List()) != 4 {
			t.Fatalf("before: %+v", rem)
		}
		row, err := writer(c).SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{Options: []string{sod.OptEscalate, sod.OptRevoke}})
		must(t, err)
		if row.Options != `["revoke","escalate"]` {
			t.Errorf("stored options = %s", row.Options)
		}
		rem, _ = sod.RemediationOf(c, wd.risk)
		if rem.Source != sod.SourceRuleset || !slices.Equal(rem.List(), []string{sod.OptRevoke, sod.OptEscalate}) {
			t.Errorf("inherited: %+v", rem)
		}
		// the server refuses what the ruleset does not offer
		w := as(c, wd.req, testkit.Now)
		if _, err := w.RequestMitigation(wd.input(testkit.Now.Add(24*time.Hour)), sod.Settings{}); code(err) != "option_not_offered" {
			t.Errorf("mitigate on an inheriting risk: %v", err)
		}
		acc := wd.input(testkit.Now.Add(24 * time.Hour))
		acc.Kind, acc.ControlID = store.MitigationAccept, ""
		if _, err := w.RequestMitigation(acc, sod.Settings{}); code(err) != "option_not_offered" {
			t.Errorf("accept on an inheriting risk: %v", err)
		}
		// a risk with options of its own ignores the ruleset's
		risk, _ := c.SodRisk(wd.risk)
		fids, _ := sod.RiskFunctionIDs(c, risk.ID)
		_, err = writer(c).UpdateRisk(risk.ID, risk.Version, sod.RiskInput{Name: risk.Name, Priority: "high", RulesetID: risk.RulesetID,
			FunctionIDs: fids, OwnerID: risk.OwnerID, Remediation: []string{sod.OptAccept}})
		must(t, err)
		rem, _ = sod.RemediationOf(c, wd.risk)
		if rem.Source != sod.SourceRisk || !slices.Equal(rem.List(), []string{sod.OptAccept}) {
			t.Errorf("own options: %+v", rem)
		}
		if _, err := w.RequestMitigation(acc, sod.Settings{}); err != nil {
			t.Errorf("accept is the risk's own option: %v", err)
		}
		// all four (or none) clears the restriction
		_, err = writer(c).SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{Options: sod.RemediationOptions})
		must(t, err)
		if got := sod.RulesetOptions(mustRow(t, c, rs.ID)); len(got) != 0 {
			t.Errorf("all four stored as %v, want none", got)
		}
		if n := auditActions(t, c)["sod.ruleset.remediation"]; n != 2 {
			t.Errorf("%d sod.ruleset.remediation audit events, want 2", n)
		}
		return nil
	})
}

func mustRow(t *testing.T, c *store.TenantTx, rulesetID string) *store.SodRulesetRemediation {
	t.Helper()
	rows, err := c.SodRulesetRemediations()
	must(t, err)
	for _, r := range rows {
		if r.RulesetID == rulesetID {
			return r
		}
	}
	t.Fatalf("no remediation row for %s", rulesetID)
	return nil
}

func TestSetRulesetRemediationValidation(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		rs := rulesetOf(t, c, wd.risk)
		w := writer(c)
		ghost, dave := int64(999999), ids["dave"] // dave is terminated
		for name, tc := range map[string]struct {
			id   string
			in   sod.RulesetRemediationInput
			want string
		}{
			"unknown ruleset":   {"nope", sod.RulesetRemediationInput{}, "ruleset_not_found"},
			"unknown option":    {rs.ID, sod.RulesetRemediationInput{Options: []string{"ignore"}}, "invalid_remediation"},
			"unknown approver":  {rs.ID, sod.RulesetRemediationInput{EscalateTo: &ghost}, "approver_not_found"},
			"inactive approver": {rs.ID, sod.RulesetRemediationInput{EscalateTo: &dave}, "approver_not_active"},
			"fine":              {rs.ID, sod.RulesetRemediationInput{Options: []string{sod.OptRevoke}, EscalateTo: &wd.alice}, ""},
		} {
			if _, err := w.SetRulesetRemediation(tc.id, tc.in); code(err) != tc.want {
				t.Errorf("%s: %v, want %q", name, err, tc.want)
			}
		}
		if _, err := w.RetireRisk(wd.risk, "obsolete"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.RetireRuleset(rs.ID, "obsolete"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{}); code(err) != "ruleset_retired" {
			t.Errorf("retired ruleset: %v", err)
		}
		return nil
	})
}

func TestEscalateGoesToTheRulesetApprover(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		rs := rulesetOf(t, c, wd.risk)
		carol := ids["carol"]
		carolUser := user(t, c, "carol", &carol)
		_, err := writer(c).SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{EscalateTo: &carol})
		must(t, err)

		w := as(c, wd.req, testkit.Now)
		if _, err := w.Escalate(wd.risk, wd.bob, "needs a decision"); err != nil {
			t.Fatal(err)
		}
		// the inbox item is the approver's, not the risk owner's
		got, err := c.Notifications(carolUser.String(), false, 10)
		must(t, err)
		if len(got) != 1 || got[0].Link != "/insights/sod" {
			t.Errorf("approver's inbox: %+v", got)
		}
		if owner, _ := c.Notifications(wd.ownerUser.String(), false, 10); len(owner) != 0 {
			t.Errorf("the risk owner was told as well: %+v", owner)
		}
		if n := auditActions(t, c)["sod.violation.escalate"]; n != 1 {
			t.Errorf("%d escalation audit events, want 1", n)
		}

		// no approver set: the risk owner
		_, err = writer(c).SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{})
		must(t, err)
		if _, err := w.Escalate(wd.risk, wd.bob, "again"); err != nil {
			t.Fatal(err)
		}
		if owner, _ := c.Notifications(wd.ownerUser.String(), false, 10); len(owner) != 1 {
			t.Errorf("the risk owner's inbox: %+v", owner)
		}
		return nil
	})
}

func TestEscalateReachesAnApproverWithoutASignInByEmail(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		rs := rulesetOf(t, c, wd.risk)
		carol := ids["carol"] // no platform user: reached at her address
		_, err := writer(c).SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{EscalateTo: &carol})
		must(t, err)
		if _, err := as(c, wd.req, testkit.Now).Escalate(wd.risk, wd.bob, "x"); err != nil {
			t.Errorf("approver without a sign-in: %v", err)
		}
		return nil
	})
}

func TestEscalateNeedsTheOptionAndATarget(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		rs := rulesetOf(t, c, wd.risk)
		_, err := writer(c).SetRulesetRemediation(rs.ID, sod.RulesetRemediationInput{Options: []string{sod.OptRevoke}})
		must(t, err)
		if _, err := as(c, wd.req, testkit.Now).Escalate(wd.risk, wd.bob, "x"); code(err) != "option_not_offered" {
			t.Errorf("ruleset does not offer escalate: %v", err)
		}
		return nil
	})
}

func TestOnActivateRunsOnApprovalOnly(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		now := testkit.Now
		end := now.Add(48 * time.Hour)
		var seen []string
		hook := func(m *store.SodMitigation) error {
			if !m.EndsAt.Equal(end) || m.Status != store.MitigationActive {
				t.Errorf("hook saw %+v", m)
			}
			seen = append(seen, m.ID)
			return nil
		}
		acc := wd.input(end)
		acc.Kind, acc.ControlID = store.MitigationAccept, ""
		m, err := as(c, wd.req, now).RequestMitigation(acc, sod.Settings{})
		must(t, err)
		rej := as(c, wd.appr, now)
		rej.OnActivate = hook
		if _, err := rej.DecideMitigation(m.ID, false, "no"); err != nil || len(seen) != 0 {
			t.Fatalf("reject: %v, hook ran %v", err, seen)
		}
		m, err = as(c, wd.req, now).RequestMitigation(acc, sod.Settings{})
		must(t, err)
		ok := as(c, wd.appr, now)
		ok.OnActivate = hook
		if _, err := ok.DecideMitigation(m.ID, true, ""); err != nil || !slices.Equal(seen, []string{m.ID}) {
			t.Fatalf("approve: %v, hook ran %v", err, seen)
		}
		return nil
	})
}

func TestExpireOneReopensTheViolationAtTheEndDate(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		wd := setup(t, c, ids)
		now := testkit.Now
		end := now.Add(10 * 24 * time.Hour)
		acc := wd.input(end)
		acc.Kind, acc.ControlID = store.MitigationAccept, ""
		m, err := as(c, wd.req, now).RequestMitigation(acc, sod.Settings{})
		must(t, err)
		// not active yet: nothing to expire
		if ok, err := sod.ExpireOne(c, end.Add(time.Hour), m.ID); err != nil || ok {
			t.Fatalf("pending: %v %v", ok, err)
		}
		_, err = as(c, wd.appr, now).DecideMitigation(m.ID, true, "")
		must(t, err)
		if ok, err := sod.ExpireOne(c, end.Add(-time.Hour), m.ID); err != nil || ok {
			t.Fatalf("not due: %v %v", ok, err)
		}
		if ok, err := sod.ExpireOne(c, end.Add(time.Hour), "nope"); err != nil || ok {
			t.Fatalf("unknown id: %v %v", ok, err)
		}
		later := end.Add(time.Hour)
		if ok, err := sod.ExpireOne(c, later, m.ID); err != nil || !ok {
			t.Fatalf("due: %v %v", ok, err)
		}
		got, _ := c.SodMitigation(m.ID)
		if got.Status != store.MitigationExpired || got.ClosedAt == nil {
			t.Errorf("after: %+v", got)
		}
		if cov, _ := sod.Covers(c, later); cov.For(wd.risk, wd.bob) != nil {
			t.Error("the violation is still covered")
		}
		if n := auditActions(t, c)["sod.mitigation.expire"]; n != 1 {
			t.Errorf("%d expire audit events, want 1", n)
		}
		if owner, _ := c.Notifications(wd.ownerUser.String(), false, 10); len(owner) != 1 {
			t.Errorf("the risk owner is told once: %+v", owner)
		}
		// running it again (a retry, or the sweeper got there first) does nothing
		if ok, err := sod.ExpireOne(c, later, m.ID); err != nil || ok {
			t.Errorf("second run: %v %v", ok, err)
		}
		if _, e, _ := sod.Sweep(c, later, sod.Settings{}); e != 0 {
			t.Errorf("the sweep expired it again")
		}
		return nil
	})
}
