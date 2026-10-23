package transport

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The sections added in bundle version 2 (issue #497): catalog items, review
// schedules, alert rules and SIEM sinks. A version 1 bundle has none of them
// (the members decode to nil), and an import then leaves them alone; a
// version 2 bundle lists them (possibly empty) and the import compares them.
//
// What an import does with each, and what it never does:
//
//   - catalog items: matched to a group by (system, external id), so the group
//     must already exist here. An item is added or its metadata changed; its
//     owner (a person, not portable) is kept, never set.
//   - review schedules: matched by name. A new one is added paused, with no
//     first run and no escalation reviewer; a changed one keeps its first run,
//     its enabled state, its reviewer, its role scope and its review type.
//   - alert rules: matched by rule id. A rule here with the bundle's enabled
//     state, severity, threshold and window is the whole change.
//   - SIEM sinks: matched by name. A new one is added disabled, without its
//     token; where audit events are sent is never changed by an import, so a
//     sink that differs is shown for a person to change under Log streaming.
//
// None of the four is ever removed by an import, with prune or without.

// Section names in a Plan.
const (
	SecConnections     = "connections"
	SecOverlays        = "overlays"
	SecIdPs            = "identity_providers"
	SecCatalogItems    = "catalog_items"
	SecReviewSchedules = "review_schedules"
	SecAlertRules      = "alert_rules"
	SecSiemSinks       = "siem_sinks"
)

// CatalogItem is a requestable group's catalog metadata.
type CatalogItem struct {
	System              string   `json:"system"`
	ExternalID          string   `json:"external_id"`
	Group               string   `json:"group"` // the group's name, for people reading the bundle
	Requestable         bool     `json:"requestable"`
	Description         string   `json:"description"`
	Risk                string   `json:"risk"`
	EligibleTypes       []string `json:"eligible_types"`
	EligibleDepartments []string `json:"eligible_departments"`
	DefaultHours        *float64 `json:"default_hours,omitempty"`
	MaxHours            *float64 `json:"max_hours,omitempty"`
	Populations         []string `json:"populations"`
}

// ReviewSchedule is a recurring access review without its first run, its
// reviewer and its scope by role (people and roles are per environment).
type ReviewSchedule struct {
	Name           string  `json:"name"`
	System         *string `json:"system,omitempty"`
	PrivilegedOnly bool    `json:"privileged_only"`
	UnusedDays     int     `json:"unused_days"`
	DurationDays   int     `json:"duration_days"`
	ReminderDays   int     `json:"reminder_days"`
	CloseOut       string  `json:"close_out"`
	EscalationDays int     `json:"escalation_days"`
	Recurrence     string  `json:"recurrence"`
}

// AlertRule is a tenant's setting for a built-in alert rule (only rules the
// tenant changed travel).
type AlertRule struct {
	ID            string `json:"id"`
	Enabled       bool   `json:"enabled"`
	Severity      string `json:"severity"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
}

// SiemSink is a log-streaming destination without its token.
type SiemSink struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Format      string `json:"format"`
	Target      string `json:"target"`
	Flavor      string `json:"flavor,omitempty"`
	CAPEM       string `json:"ca_pem,omitempty"`
	IncludeHTTP bool   `json:"include_http"`
	// NeedsSecret: the source sink had a token; set one here before enabling.
	NeedsSecret bool `json:"needs_secret"`
}

// ------------------------------------------------------------------ export

func collectCatalog(tx *store.TenantTx, b *Bundle) error {
	b.CatalogItems = []CatalogItem{}
	items, err := tx.CatalogItems()
	if err != nil {
		return err
	}
	pops, err := tx.CatalogPopulations("")
	if err != nil {
		return err
	}
	popsOf := map[string][]string{}
	for _, p := range pops {
		popsOf[p.ItemID] = append(popsOf[p.ItemID], p.Population)
	}
	for _, it := range items {
		g, err := tx.Group(it.GroupID)
		if err != nil {
			return err
		}
		p := popsOf[it.ID]
		if p == nil {
			p = []string{}
		}
		slices.Sort(p)
		b.CatalogItems = append(b.CatalogItems, CatalogItem{System: g.System, ExternalID: g.ExternalID, Group: g.Name,
			Requestable: it.Requestable, Description: it.Description, Risk: it.Risk, EligibleTypes: sortedCopy(it.EligibleTypes),
			EligibleDepartments: sortedCopy(it.EligibleDepartments), DefaultHours: it.DefaultHours, MaxHours: it.MaxHours,
			Populations: p})
	}
	slices.SortFunc(b.CatalogItems, func(x, y CatalogItem) int {
		return strings.Compare(x.System+"\x00"+x.ExternalID, y.System+"\x00"+y.ExternalID)
	})
	return nil
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}

func collectReviewSchedules(tx *store.TenantTx, b *Bundle) error {
	b.ReviewSchedules = []ReviewSchedule{}
	ts, err := tx.ReviewTemplates() // by name, then id
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, t := range ts {
		if seen[t.Name] { // names are the key: a second schedule of the same name cannot travel
			b.Excluded = append(b.Excluded, ExcludedRef{SecReviewSchedules, t.Name, "another schedule has the same name"})
			continue
		}
		seen[t.Name] = true
		b.ReviewSchedules = append(b.ReviewSchedules, ReviewSchedule{Name: t.Name, System: t.System, PrivilegedOnly: t.PrivilegedOnly,
			UnusedDays: t.UnusedDays, DurationDays: t.DurationDays, ReminderDays: t.ReminderDays, CloseOut: t.CloseOut,
			EscalationDays: t.EscalationDays, Recurrence: t.Recurrence})
	}
	return nil
}

func collectAlertRules(tx *store.TenantTx, b *Bundle) error {
	b.AlertRules = []AlertRule{}
	eff, err := alerts.EffectiveRules(tx)
	if err != nil {
		return err
	}
	for _, e := range eff {
		if e.Setting == nil {
			continue
		}
		b.AlertRules = append(b.AlertRules, AlertRule{ID: e.ID, Enabled: e.Enabled, Severity: e.Severity, Threshold: e.Threshold,
			WindowMinutes: int(e.Window / time.Minute)})
	}
	return nil
}

func collectSiemSinks(tx *store.TenantTx, b *Bundle) error {
	b.SiemSinks = []SiemSink{}
	sinks, err := tx.SiemSinks()
	if err != nil {
		return err
	}
	for _, k := range sinks {
		s := SiemSink{Name: k.Name, Kind: k.Kind, Format: k.Format, Target: k.Target, Flavor: k.Flavor, IncludeHTTP: k.IncludeHTTP,
			NeedsSecret: len(k.SecretSealed) > 0}
		if k.CAPEM != nil {
			s.CAPEM = *k.CAPEM
		}
		b.SiemSinks = append(b.SiemSinks, s)
	}
	slices.SortFunc(b.SiemSinks, func(x, y SiemSink) int { return strings.Compare(x.Name, y.Name) })
	return nil
}

// ---------------------------------------------------------------- planning

func floatPtrEq(a, b *float64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func setEq(a, b []string) bool { return slices.Equal(sortedCopy(a), sortedCopy(b)) }

func fmtHours(h *float64) string {
	if h == nil {
		return "-"
	}
	return fmt.Sprint(*h)
}

func catalogName(c CatalogItem) string { return c.System + ":" + orStr(c.Group, c.ExternalID) }

func orStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func catalogSpec(c CatalogItem, owner *int64) requests.ItemSpec {
	return requests.ItemSpec{Requestable: c.Requestable, Description: c.Description, OwnerIdentityID: owner, Risk: c.Risk,
		EligibleTypes: c.EligibleTypes, EligibleDepartments: c.EligibleDepartments, DefaultHours: c.DefaultHours,
		MaxHours: c.MaxHours, Populations: c.Populations}
}

// errNote is the text of a refusal a person can act on.
func errNote(err error) string {
	var re *requests.Error
	var se *reviews.SpecError
	switch {
	case errors.As(err, &re):
		return re.Msg
	case errors.As(err, &se):
		return se.Msg
	}
	return err.Error()
}

func planCatalog(tx *store.TenantTx, b *Bundle, p *Plan) error {
	if b.CatalogItems == nil {
		return nil
	}
	pops, err := tx.CatalogPopulations("")
	if err != nil {
		return err
	}
	for _, c := range b.CatalogItems {
		it := Item{Section: SecCatalogItems, Name: catalogName(c)}
		g, err := tx.GroupByXID(c.System, c.ExternalID)
		if errors.Is(err, store.ErrNotFound) {
			it.Action = Manual
			it.Notes = append(it.Notes, fmt.Sprintf("this organization has no group %s/%s: connect the system and load its groups first", c.System, c.ExternalID))
			p.Items = append(p.Items, it)
			continue
		} else if err != nil {
			return err
		}
		cur, err := tx.CatalogItemForGroup(g.ID)
		var owner *int64
		var curPops []string
		switch {
		case errors.Is(err, store.ErrNotFound):
			cur = nil
		case err != nil:
			return err
		default:
			owner = cur.OwnerIdentityID
			for _, cp := range pops {
				if cp.ItemID == cur.ID {
					curPops = append(curPops, cp.Population)
				}
			}
		}
		if cur == nil {
			p.state = append(p.state, fmt.Sprintf("catalog|%d|none", g.ID))
		} else {
			p.state = append(p.state, fmt.Sprintf("catalog|%d|%s|%s|%s", g.ID, cur.ID, cur.UpdatedAt.UTC().Format(time.RFC3339Nano),
				strings.Join(sortedCopy(curPops), ",")))
		}
		if err := requests.CheckItem(tx, g, catalogSpec(c, owner)); err != nil {
			it.Action = Manual
			it.Notes = append(it.Notes, errNote(err))
			p.Items = append(p.Items, it)
			continue
		}
		if cur == nil {
			it.Action = Add
			it.Notes = append(it.Notes, "no owner is set: choose one here")
		} else {
			diff := func(name string, same bool) {
				if !same {
					it.Fields = append(it.Fields, name)
				}
			}
			diff("requestable", cur.Requestable == c.Requestable)
			diff("description", cur.Description == strings.TrimSpace(c.Description))
			diff("risk", cur.Risk == c.Risk)
			diff("eligible_types", setEq(cur.EligibleTypes, c.EligibleTypes))
			diff("eligible_departments", setEq(cur.EligibleDepartments, c.EligibleDepartments))
			diff("default_hours", floatPtrEq(cur.DefaultHours, c.DefaultHours))
			diff("max_hours", floatPtrEq(cur.MaxHours, c.MaxHours))
			diff("populations", setEq(curPops, c.Populations))
			it.Action = Unchanged
			if len(it.Fields) > 0 {
				it.Action = Change
				it.Notes = append(it.Notes, "the owner here is kept")
			}
		}
		p.Items = append(p.Items, it)
	}
	return nil
}

// reviewCandidate is the template an import would store for r over cur (nil: a new one).
func reviewCandidate(r ReviewSchedule, cur *store.ReviewTemplate) *store.ReviewTemplate {
	var t store.ReviewTemplate
	if cur != nil {
		t = *cur
	}
	t.Name, t.System, t.PrivilegedOnly, t.UnusedDays, t.DurationDays = r.Name, r.System, r.PrivilegedOnly, r.UnusedDays, r.DurationDays
	t.ReminderDays, t.CloseOut, t.EscalationDays, t.Recurrence = r.ReminderDays, r.CloseOut, r.EscalationDays, r.Recurrence
	if cur == nil {
		t.Enabled, t.NextRunAt, t.EscalationIdentityID = false, nil, nil
	}
	return &t
}

func reviewDiff(cur *store.ReviewTemplate, r ReviewSchedule) []string {
	var out []string
	add := func(name string, same bool) {
		if !same {
			out = append(out, name)
		}
	}
	sys := func(s *string) string {
		if s == nil {
			return ""
		}
		return strings.TrimSpace(*s)
	}
	add("system", sys(cur.System) == sys(r.System))
	add("privileged_only", cur.PrivilegedOnly == r.PrivilegedOnly)
	add("unused_days", cur.UnusedDays == r.UnusedDays)
	add("duration_days", cur.DurationDays == r.DurationDays)
	add("reminder_days", cur.ReminderDays == r.ReminderDays)
	add("close_out", cur.CloseOut == r.CloseOut)
	add("escalation_days", cur.EscalationDays == r.EscalationDays)
	add("recurrence", cur.Recurrence == r.Recurrence)
	return out
}

func planReviewSchedules(tx *store.TenantTx, b *Bundle, p *Plan) error {
	if b.ReviewSchedules == nil {
		return nil
	}
	ts, err := tx.ReviewTemplates()
	if err != nil {
		return err
	}
	byName := map[string][]*store.ReviewTemplate{}
	for _, t := range ts {
		byName[t.Name] = append(byName[t.Name], t)
		p.state = append(p.state, "review|"+t.ID+"|"+t.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	seen := map[string]bool{}
	for _, r := range b.ReviewSchedules {
		it := Item{Section: SecReviewSchedules, Name: r.Name}
		if seen[r.Name] {
			it.Action = Manual
			it.Notes = append(it.Notes, "the bundle lists this name more than once")
			p.Items = append(p.Items, it)
			continue
		}
		seen[r.Name] = true
		curs := byName[strings.TrimSpace(r.Name)]
		if len(curs) > 1 {
			it.Action = Manual
			it.Notes = append(it.Notes, "several schedules here share this name: rename them so the import can tell which one to change")
			p.Items = append(p.Items, it)
			continue
		}
		var cur *store.ReviewTemplate
		if len(curs) == 1 {
			cur = curs[0]
		}
		cand := reviewCandidate(r, cur)
		if cur == nil && cand.CloseOut == "escalate" {
			it.Action = Manual
			it.Notes = append(it.Notes, "it escalates to a reviewer, who is a person: create the schedule here and choose one")
			p.Items = append(p.Items, it)
			continue
		}
		if err := reviews.ValidateTemplate(tx, cand); err != nil {
			it.Action = Manual
			it.Notes = append(it.Notes, errNote(err))
			p.Items = append(p.Items, it)
			continue
		}
		if cur == nil {
			it.Action = Add
			it.Notes = append(it.Notes, "added paused with no first run: set one to start it")
		} else {
			it.Fields = reviewDiff(cur, r)
			it.Action = Unchanged
			if len(it.Fields) > 0 {
				it.Action = Change
				it.Notes = append(it.Notes, "its first run, state, reviewer and role scope here are kept")
			}
		}
		p.Items = append(p.Items, it)
	}
	return nil
}

func planAlertRules(tx *store.TenantTx, b *Bundle, p *Plan) error {
	if b.AlertRules == nil {
		return nil
	}
	eff, err := alerts.EffectiveRules(tx)
	if err != nil {
		return err
	}
	byID := map[string]alerts.Effective{}
	for _, e := range eff {
		byID[e.ID] = e
		p.state = append(p.state, fmt.Sprintf("alert|%s|%t|%s|%d|%d", e.ID, e.Enabled, e.Severity, e.Threshold, int(e.Window/time.Minute)))
	}
	seen := map[string]bool{}
	for _, r := range b.AlertRules {
		it := Item{Section: SecAlertRules, Name: r.ID}
		cur, ok := byID[r.ID]
		switch {
		case seen[r.ID]:
			it.Action = Manual
			it.Notes = append(it.Notes, "the bundle lists this rule more than once")
		case !ok:
			it.Action = Manual
			it.Notes = append(it.Notes, "this Tessera has no such alert rule")
		default:
			if err := alerts.CheckRule(r.ID, alerts.RuleSpec{Enabled: r.Enabled, Severity: r.Severity, Threshold: r.Threshold,
				WindowMinutes: r.WindowMinutes}); err != nil {
				it.Action = Manual
				it.Notes = append(it.Notes, errNote(err))
				break
			}
			add := func(name string, same bool) {
				if !same {
					it.Fields = append(it.Fields, name)
				}
			}
			add("enabled", cur.Enabled == r.Enabled)
			add("severity", cur.Severity == r.Severity)
			add("threshold", cur.Threshold == r.Threshold)
			add("window_minutes", int(cur.Window/time.Minute) == r.WindowMinutes)
			it.Action = Unchanged
			if len(it.Fields) > 0 {
				it.Action = Change
				if alerts.Loosens(cur, alerts.RuleSpec{Enabled: r.Enabled, Severity: r.Severity, Threshold: r.Threshold,
					WindowMinutes: r.WindowMinutes}) {
					it.Notes = append(it.Notes, "this loosens detection: it fires less often or not at all")
					if alerts.IsSecurityRule(r.ID) {
						// a security rule is loosened by two admins, not by a file (issue #521)
						it.Action = Manual
						it.Notes = append(it.Notes, "loosening a security rule takes two admins: request an "+"alerts.rule.loosen change under Admin > Change requests")
					}
				}
			}
		}
		seen[r.ID] = true
		p.Items = append(p.Items, it)
	}
	return nil
}

func sinkSpec(s SiemSink) siem.SinkSpec {
	return siem.SinkSpec{Name: s.Name, Kind: s.Kind, Format: s.Format, Target: s.Target, Flavor: s.Flavor, CAPEM: s.CAPEM,
		IncludeHTTP: s.IncludeHTTP}
}

func planSiemSinks(tx *store.TenantTx, b *Bundle, p *Plan, target Target) error {
	if b.SiemSinks == nil {
		return nil
	}
	sinks, err := tx.SiemSinks()
	if err != nil {
		return err
	}
	byName := map[string]*store.SiemSink{}
	for _, k := range sinks {
		if _, dup := byName[k.Name]; !dup {
			byName[k.Name] = k
		}
		p.state = append(p.state, "siem|"+k.ID+"|"+k.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	seen := map[string]bool{}
	for _, s := range b.SiemSinks {
		it := Item{Section: SecSiemSinks, Name: s.Name}
		spec, err := siem.CheckSink(sinkSpec(s), !target.Prod)
		if err != nil || seen[s.Name] {
			it.Action = Manual
			if seen[s.Name] {
				it.Notes = append(it.Notes, "the bundle lists this name more than once")
			} else {
				it.Notes = append(it.Notes, errNote(err))
			}
			p.Items = append(p.Items, it)
			continue
		}
		seen[s.Name] = true
		cur, ok := byName[spec.Name]
		if !ok {
			it.Action = Add
			it.Notes = append(it.Notes, "added disabled, without its token: it sends nothing until you set the token and enable it")
			p.Items = append(p.Items, it)
			continue
		}
		add := func(name string, same bool) {
			if !same {
				it.Fields = append(it.Fields, name)
			}
		}
		curCA := ""
		if cur.CAPEM != nil {
			curCA = *cur.CAPEM
		}
		add("kind", cur.Kind == spec.Kind)
		add("format", cur.Format == spec.Format)
		add("target", cur.Target == spec.Target)
		add("flavor", cur.Flavor == spec.Flavor)
		add("ca_pem", curCA == spec.CAPEM)
		add("include_http", cur.IncludeHTTP == spec.IncludeHTTP)
		it.Action = Unchanged
		if len(it.Fields) > 0 {
			it.Action = Manual
			it.Notes = append(it.Notes, "where audit events are sent is not changed by an import: edit the sink under Log streaming")
		}
		p.Items = append(p.Items, it)
	}
	return nil
}

// ------------------------------------------------------------------- apply

func applyCatalog(tx *store.TenantTx, it Item, b *Bundle, hash, actor string, actorUser *string, now time.Time) error {
	for _, c := range b.CatalogItems {
		if catalogName(c) != it.Name {
			continue
		}
		g, err := tx.GroupByXID(c.System, c.ExternalID)
		if err != nil {
			return err
		}
		id := uuid.NewString()
		var owner *int64
		if cur, err := tx.CatalogItemForGroup(g.ID); err == nil {
			id, owner = cur.ID, cur.OwnerIdentityID
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := requests.CheckItem(tx, g, catalogSpec(c, owner)); err != nil {
			return err
		}
		row := &store.CatalogItem{ID: id, GroupID: g.ID, Requestable: c.Requestable, Description: strings.TrimSpace(c.Description),
			OwnerIdentityID: owner, Risk: c.Risk, EligibleTypes: c.EligibleTypes, EligibleDepartments: c.EligibleDepartments,
			DefaultHours: c.DefaultHours, MaxHours: c.MaxHours, UpdatedBy: actorUser, UpdatedAt: now}
		if err := tx.PutCatalogItem(row); err != nil {
			return err
		}
		pops := sortedCopy(c.Populations)
		pops = slices.Compact(pops)
		if err := tx.SetCatalogPopulations(id, pops); err != nil {
			return err
		}
		return tx.Audit(now, actor, "catalog.item.put", ojson.Object{{Key: "catalog_item_id", Value: id},
			{Key: "group_id", Value: g.ID}, {Key: "group", Value: g.System + ":" + g.Name}, {Key: "requestable", Value: c.Requestable},
			{Key: "risk", Value: c.Risk}, {Key: "populations", Value: pops}, {Key: "imported_from_bundle", Value: hash}})
	}
	return nil
}

func applyReviewSchedule(tx *store.TenantTx, it Item, b *Bundle, hash, actor string, actorUser *string, now time.Time) error {
	for _, r := range b.ReviewSchedules {
		if r.Name != it.Name {
			continue
		}
		ts, err := tx.ReviewTemplates()
		if err != nil {
			return err
		}
		var cur *store.ReviewTemplate
		for _, t := range ts {
			if t.Name == strings.TrimSpace(r.Name) {
				cur = t
			}
		}
		t := reviewCandidate(r, cur)
		t.UpdatedAt = now
		if err := reviews.ValidateTemplate(tx, t); err != nil {
			return err
		}
		if cur == nil {
			t.ID, t.CreatedAt, t.CreatedBy = uuid.NewString(), now, actorUser
			err = tx.InsertReviewTemplate(t)
		} else {
			err = tx.UpdateReviewTemplate(t)
		}
		if err != nil {
			return err
		}
		next := ""
		if t.NextRunAt != nil {
			next = t.NextRunAt.UTC().Format(time.RFC3339)
		}
		return tx.Audit(now, actor, "review.schedule.put", ojson.Object{{Key: "schedule_id", Value: t.ID}, {Key: "name", Value: t.Name},
			{Key: "recurrence", Value: t.Recurrence}, {Key: "next_run_at", Value: next}, {Key: "close_out", Value: t.CloseOut},
			{Key: "enabled", Value: t.Enabled}, {Key: "imported_from_bundle", Value: hash}})
	}
	return nil
}

func applyAlertRule(tx *store.TenantTx, it Item, b *Bundle, hash, actor string, actorUser *string, now time.Time) error {
	for _, r := range b.AlertRules {
		if r.ID != it.Name {
			continue
		}
		if err := alerts.CheckRule(r.ID, alerts.RuleSpec{Enabled: r.Enabled, Severity: r.Severity, Threshold: r.Threshold,
			WindowMinutes: r.WindowMinutes}); err != nil {
			return err
		}
		if err := tx.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: r.ID, Enabled: r.Enabled, Severity: r.Severity,
			Threshold: r.Threshold, WindowMinutes: r.WindowMinutes, UpdatedBy: actorUser, UpdatedAt: now}); err != nil {
			return err
		}
		return tx.Audit(now, actor, "alert.rule.updated", ojson.Object{{Key: "rule", Value: r.ID}, {Key: "enabled", Value: r.Enabled},
			{Key: "severity", Value: r.Severity}, {Key: "threshold", Value: r.Threshold}, {Key: "window_minutes", Value: r.WindowMinutes},
			{Key: "imported_from_bundle", Value: hash}})
	}
	return nil
}

func applySiemSink(tx *store.TenantTx, it Item, b *Bundle, target Target, hash, actor string, actorUser *string, now time.Time) error {
	for _, s := range b.SiemSinks {
		if s.Name != it.Name {
			continue
		}
		by := siem.Actor{Display: actor}
		if actorUser != nil {
			by.UserID = *actorUser
		}
		_, err := siem.ImportSink(tx, sinkSpec(s), !target.Prod, by, hash, now)
		return err
	}
	return nil
}
