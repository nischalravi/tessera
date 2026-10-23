package transport

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func f64(v float64) *float64 { return &v }

// seedSections gives the source tenant what the version 2 sections carry, and
// the destination the groups the catalog items point at.
func (e *env) seedSections(t *testing.T) {
	t.Helper()
	for _, sc := range []readiness.Scope{e.src, e.dst} {
		write(t, sc, func(tx *store.TenantTx) error {
			for _, g := range []store.Group{{System: "okta", ExternalID: "g-eng", Name: "Engineering"}, {System: "okta", ExternalID: "g-adm", Name: "Admins", Privileged: true}} {
				g.TenantID, g.Requestable = tx.Tenant(), true
				if err := tx.UpsertGroup(&g); err != nil {
					return err
				}
			}
			return nil
		})
	}
	write(t, e.src, func(tx *store.TenantTx) error {
		eng, err := tx.GroupByXID("okta", "g-eng")
		if err != nil {
			return err
		}
		adm, err := tx.GroupByXID("okta", "g-adm")
		if err != nil {
			return err
		}
		if err := tx.PutCatalogItem(&store.CatalogItem{ID: "c-eng", GroupID: eng.ID, Requestable: true, Description: "Engineering tools",
			Risk: "low", EligibleTypes: []string{"human"}, EligibleDepartments: []string{"R&D"}, UpdatedAt: t0}); err != nil {
			return err
		}
		if err := tx.SetCatalogPopulations("c-eng", []string{"contractor"}); err != nil {
			return err
		}
		if err := tx.PutCatalogItem(&store.CatalogItem{ID: "c-adm", GroupID: adm.ID, Requestable: true, Risk: "high",
			DefaultHours: f64(4), MaxHours: f64(8), UpdatedAt: t0}); err != nil {
			return err
		}
		if err := tx.InsertReviewTemplate(&store.ReviewTemplate{ID: "rt-1", Name: "Quarterly privileged review", PrivilegedOnly: true,
			UnusedDays: 60, DurationDays: 14, ReminderDays: 3, CloseOut: "revoke", EscalationDays: 7, Recurrence: "quarterly",
			NextRunAt: &t0, Enabled: true, CreatedAt: t0, UpdatedAt: t0}); err != nil {
			return err
		}
		if err := tx.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: "access_drift", Enabled: true, Severity: "high", Threshold: 3,
			WindowMinutes: 30, UpdatedAt: t0}); err != nil {
			return err
		}
		if err := tx.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: "mfa_bypass", Enabled: false, Severity: "high", Threshold: 1,
			WindowMinutes: 60, UpdatedAt: t0}); err != nil {
			return err
		}
		return tx.InsertSiemSink(&store.SiemSink{ID: "k-1", Name: "Splunk", Kind: "webhook", Format: "json",
			Target: "https://splunk.example:8088/services/collector", Flavor: "hec", SecretSealed: []byte("sealed"), IncludeHTTP: true,
			Enabled: true, CreatedAt: t0, UpdatedAt: t0})
	})
}

func (e *env) bundleOf(t *testing.T) *Bundle {
	t.Helper()
	var b *Bundle
	write(t, e.src, func(tx *store.TenantTx) error {
		var err error
		_, b, err = Export(tx, e.rd, e.sealer, Source{Tenant: "larkspur-dev", Env: "dev"}, t0)
		return err
	})
	return b
}

func TestSections_ExportCarriesNoSecretsOrPeople(t *testing.T) {
	e := newEnv(t)
	e.seedSections(t)
	b := e.bundleOf(t)
	if b.Version != 2 || len(b.CatalogItems) != 2 || len(b.ReviewSchedules) != 1 || len(b.AlertRules) != 2 || len(b.SiemSinks) != 1 {
		t.Fatalf("bundle: v%d %d catalog, %d reviews, %d rules, %d sinks", b.Version, len(b.CatalogItems), len(b.ReviewSchedules), len(b.AlertRules), len(b.SiemSinks))
	}
	raw, _ := json.Marshal(b)
	for _, leak := range []string{"sealed", "next_run_at", "owner", "escalation_identity", "secret_sealed"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the bundle mentions %q: %s", leak, raw)
		}
	}
	if !b.SiemSinks[0].NeedsSecret {
		t.Error("a sink with a token should say the target needs one")
	}
	if got := b.AlertRules[0].ID; got != "mfa_bypass" { // the rules' display order, not alphabetical
		t.Errorf("rules not in a stable order: %s", got)
	}
}

func TestSections_RoundTrip(t *testing.T) {
	e := newEnv(t)
	e.seedSections(t)
	e.trust(t)
	raw := e.export(t).JWS

	p := e.plan(t, raw, Target{})
	want := map[string]string{
		"catalog_items/okta:Engineering": Add, "catalog_items/okta:Admins": Add,
		"review_schedules/Quarterly privileged review": Add,
		"alert_rules/access_drift":                     Change, "alert_rules/mfa_bypass": Change,
		"siem_sinks/Splunk": Add,
	}
	got := actions(p)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (plan %+v)", k, got[k], v, p.Items)
		}
	}
	for _, it := range p.Items {
		if it.Section == SecAlertRules && it.Name == "mfa_bypass" && !strings.Contains(strings.Join(it.Notes, " "), "loosens") {
			t.Errorf("disabling a rule is not flagged: %+v", it)
		}
	}
	if _, err := e.apply(t, raw, false); err != nil {
		t.Fatal(err)
	}

	write(t, e.dst, func(tx *store.TenantTx) error {
		eng, _ := tx.GroupByXID("okta", "g-eng")
		it, err := tx.CatalogItemForGroup(eng.ID)
		if err != nil || it.Description != "Engineering tools" || it.Risk != "low" || it.OwnerIdentityID != nil {
			t.Errorf("catalog item %+v %v", it, err)
		}
		if pops, _ := tx.CatalogPopulations(it.ID); len(pops) != 1 || pops[0].Population != "contractor" {
			t.Errorf("populations %+v", pops)
		}
		adm, _ := tx.GroupByXID("okta", "g-adm")
		if it, err := tx.CatalogItemForGroup(adm.ID); err != nil || it.DefaultHours == nil || *it.DefaultHours != 4 {
			t.Errorf("privileged item %+v %v", it, err)
		}
		ts, _ := tx.ReviewTemplates()
		if len(ts) != 1 || ts[0].Enabled || ts[0].NextRunAt != nil || !ts[0].PrivilegedOnly || ts[0].Recurrence != "quarterly" {
			t.Errorf("review schedule must arrive paused: %+v", ts)
		}
		rules, _ := tx.AlertRuleSettings()
		if len(rules) != 2 || rules[0].RuleID != "access_drift" || rules[0].Threshold != 3 || rules[1].Enabled {
			t.Errorf("alert rules %+v", rules)
		}
		sinks, _ := tx.SiemSinks()
		if len(sinks) != 1 || sinks[0].Enabled || len(sinks[0].SecretSealed) != 0 || sinks[0].Flavor != "hec" {
			t.Errorf("a sink must arrive disabled and without a token: %+v", sinks)
		}
		log, _ := tx.AuditLog(-1)
		seen := map[string]bool{}
		for _, ev := range log {
			seen[ev.Action] = true
		}
		for _, a := range []string{"catalog.item.put", "review.schedule.put", "alert.rule.updated", "siem.sink.created", "config.import.applied"} {
			if !seen[a] {
				t.Errorf("no %s audit event", a)
			}
		}
		return nil
	})

	// a second plan is all unchanged: the import converged
	for k, v := range actions(e.plan(t, raw, Target{})) {
		if (strings.HasPrefix(k, "catalog_items/") || strings.HasPrefix(k, "review_schedules/") || strings.HasPrefix(k, "alert_rules/") ||
			strings.HasPrefix(k, "siem_sinks/")) && v != Unchanged {
			t.Errorf("%s still %s after the import", k, v)
		}
	}
}

func TestSections_ChangesKeepWhatIsLocal(t *testing.T) {
	e := newEnv(t)
	e.seedSections(t)
	e.trust(t)
	// the destination already has the items, enabled, with its own first run
	write(t, e.dst, func(tx *store.TenantTx) error {
		eng, _ := tx.GroupByXID("okta", "g-eng")
		if err := tx.PutCatalogItem(&store.CatalogItem{ID: "d-eng", GroupID: eng.ID, Requestable: false, Risk: "high", UpdatedAt: t0}); err != nil {
			return err
		}
		if err := tx.InsertReviewTemplate(&store.ReviewTemplate{ID: "rt-d", Name: "Quarterly privileged review", UnusedDays: 90,
			DurationDays: 14, ReminderDays: 3, CloseOut: "revoke", EscalationDays: 7, Recurrence: "annual", NextRunAt: &t0, Enabled: true,
			CreatedAt: t0, UpdatedAt: t0}); err != nil {
			return err
		}
		return tx.InsertSiemSink(&store.SiemSink{ID: "k-d", Name: "Splunk", Kind: "webhook", Format: "ocsf",
			Target: "https://elsewhere.example/hook", Flavor: "json", Enabled: true, CreatedAt: t0, UpdatedAt: t0})
	})
	raw := e.export(t).JWS
	p := e.plan(t, raw, Target{})
	got := actions(p)
	if got["catalog_items/okta:Engineering"] != Change || got["review_schedules/Quarterly privileged review"] != Change {
		t.Fatalf("plan %+v", p.Items)
	}
	if got["siem_sinks/Splunk"] != Manual {
		t.Errorf("a sink that sends elsewhere must not be changed by an import: %+v", p.Items)
	}
	if _, err := e.apply(t, raw, true); err != nil {
		t.Fatal(err)
	}
	write(t, e.dst, func(tx *store.TenantTx) error {
		eng, _ := tx.GroupByXID("okta", "g-eng")
		it, _ := tx.CatalogItemForGroup(eng.ID)
		if it.ID != "d-eng" || !it.Requestable || it.Risk != "low" {
			t.Errorf("catalog item not updated in place: %+v", it)
		}
		ts, _ := tx.ReviewTemplates()
		if len(ts) != 1 || ts[0].ID != "rt-d" || ts[0].Recurrence != "quarterly" || ts[0].UnusedDays != 60 || !ts[0].Enabled || ts[0].NextRunAt == nil {
			t.Errorf("review schedule: %+v", ts)
		}
		sinks, _ := tx.SiemSinks()
		if len(sinks) != 1 || sinks[0].Target != "https://elsewhere.example/hook" || !sinks[0].Enabled {
			t.Errorf("sink was changed by an import: %+v", sinks)
		}
		return nil
	})
}

func TestSections_RefusalsAreManual(t *testing.T) {
	e := newEnv(t)
	e.seedSections(t)
	b := e.bundleOf(t)
	b.CatalogItems = append(b.CatalogItems, CatalogItem{System: "okta", ExternalID: "missing", Group: "Ghost", Risk: "low"},
		CatalogItem{System: "okta", ExternalID: "g-eng", Group: "Engineering", Risk: "extreme", EligibleTypes: []string{}, Populations: []string{}})
	b.ReviewSchedules = append(b.ReviewSchedules,
		ReviewSchedule{Name: "Escalating", UnusedDays: 60, DurationDays: 14, ReminderDays: 3, CloseOut: "escalate", EscalationDays: 7, Recurrence: "annual"},
		ReviewSchedule{Name: "Bad", UnusedDays: 0, DurationDays: 14, CloseOut: "revoke", EscalationDays: 7, Recurrence: "annual"})
	b.AlertRules = append(b.AlertRules, AlertRule{ID: "no_such_rule", Enabled: true, Severity: "high", Threshold: 1, WindowMinutes: 5},
		AlertRule{ID: "mfa_bypass", Enabled: true, Severity: "urgent", Threshold: 1, WindowMinutes: 5})
	b.SiemSinks = append(b.SiemSinks, SiemSink{Name: "Bad sink", Kind: "webhook", Format: "json", Target: "http://plain.example", Flavor: "json"})
	plan := planOf(t, e, b)
	for _, name := range []string{"catalog_items/okta:Ghost", "catalog_items/okta:Engineering", "review_schedules/Escalating", "review_schedules/Bad",
		"alert_rules/no_such_rule", "siem_sinks/Bad sink"} {
		found := false
		for _, it := range plan.Items {
			if it.Section+"/"+it.Name == name && it.Action == Manual && len(it.Notes) > 0 {
				found = true
			}
		}
		if !found {
			t.Errorf("%s should be manual with a note: %+v", name, plan.Items)
		}
	}
	// a repeated rule id is refused the second time only
	manual := 0
	for _, it := range plan.Items {
		if it.Section == SecAlertRules && it.Name == "mfa_bypass" && it.Action == Manual {
			manual++
		}
	}
	if manual != 1 {
		t.Errorf("want the repeated rule refused once, got %d", manual)
	}
}

// planOf plans an in-memory bundle against the destination (no signature: the
// planner takes a Verified).
func planOf(t *testing.T, e *env, b *Bundle) *Plan {
	t.Helper()
	var p *Plan
	write(t, e.dst, func(tx *store.TenantTx) error {
		var err error
		p, err = MakePlan(tx, e.rd, &Verified{Bundle: b, Hash: "h", Signer: &store.TrustedSigner{KID: "k", Label: "l"}}, Target{}, t0)
		return err
	})
	return p
}

func TestSections_OldBundlesLeaveThemAlone(t *testing.T) {
	e := newEnv(t)
	e.seedSections(t)
	b := e.bundleOf(t)
	b.Version, b.CatalogItems, b.ReviewSchedules, b.AlertRules, b.SiemSinks = 1, nil, nil, nil, nil
	for _, it := range planOf(t, e, b).Items {
		switch it.Section {
		case SecCatalogItems, SecReviewSchedules, SecAlertRules, SecSiemSinks:
			t.Errorf("a version 1 bundle planned %+v", it)
		}
	}
}

func TestSections_ProdRefusesLocalhostSinks(t *testing.T) {
	e := newEnv(t)
	b := e.bundleOf(t)
	b.SiemSinks = []SiemSink{{Name: "Local", Kind: "syslog", Format: "json", Target: "localhost:6514"}}
	var p *Plan
	write(t, e.dst, func(tx *store.TenantTx) error {
		var err error
		p, err = MakePlan(tx, e.rd, &Verified{Bundle: b, Hash: "h", Signer: &store.TrustedSigner{KID: "k", Label: "l"}}, Target{Prod: true}, t0)
		return err
	})
	if len(p.Refusals) == 0 || !strings.Contains(p.Refusals[0], "localhost") {
		t.Errorf("refusals %v", p.Refusals)
	}
}
