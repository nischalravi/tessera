package store

import (
	"database/sql"
	"time"
)

// Scheduled access reviews (schema/0281_review_schedules.sql, issue #166).

// ReviewTemplate is a recurring campaign definition.
type ReviewTemplate struct {
	ID                   string
	Name                 string
	System               *string // nil: every system
	PrivilegedOnly       bool
	UnusedDays           int
	DurationDays         int
	ReminderDays         int
	CloseOut             string // revoke | escalate
	EscalationIdentityID *int64
	EscalationDays       int
	Recurrence           string // once | quarterly | semiannual | annual
	NextRunAt            *time.Time
	Enabled              bool
	CreatedBy            *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// ReviewLaunch is one run of a template.
type ReviewLaunch struct {
	ID          string
	TemplateID  string
	PeriodKey   string
	CampaignID  int64
	LaunchedAt  time.Time
	DueAt       time.Time
	RemindedAt  *time.Time
	EscalatedAt *time.Time
	ClosedAt    *time.Time
	Revoked     int
}

const templateCols = `t.id, t.name, t.system, t.privileged_only, t.unused_days, t.duration_days, t.reminder_days, t.close_out,
	t.escalation_identity_id, t.escalation_days, t.recurrence, t.next_run_at, t.enabled, t.created_by, t.created_at, t.updated_at`

const launchCols = `l.id, l.template_id, l.period_key, l.campaign_id, l.launched_at, l.due_at, l.reminded_at, l.escalated_at,
	l.closed_at, l.revoked`

var (
	templatesList = tq("review_templates.list", `
		SELECT `+templateCols+` FROM review_templates t WHERE t.tenant_id = @tenant ORDER BY t.name, t.id`)
	templatesGet = tq("review_templates.get", `
		SELECT `+templateCols+` FROM review_templates t WHERE t.tenant_id = @tenant AND t.id = @id`)
	templatesDue = tq("review_templates.due", `
		SELECT `+templateCols+` FROM review_templates t WHERE t.tenant_id = @tenant AND t.enabled = 1
			AND t.next_run_at IS NOT NULL AND t.next_run_at <= @now ORDER BY t.next_run_at, t.id`)
	templatesCountDue = tq("review_templates.count_due", `
		SELECT count(t.id) FROM review_templates t WHERE t.tenant_id = @tenant AND t.enabled = 1
			AND t.next_run_at IS NOT NULL AND t.next_run_at <= @now`)
	templatesInsert = tq("review_templates.insert", `
		INSERT INTO review_templates (id, tenant_id, name, system, privileged_only, unused_days, duration_days, reminder_days,
			close_out, escalation_identity_id, escalation_days, recurrence, next_run_at, enabled, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @system, @privileged_only, @unused_days, @duration_days, @reminder_days, @close_out,
			@escalation_identity_id, @escalation_days, @recurrence, @next_run_at, @enabled, @created_by, @created_at, @updated_at)`)
	templatesUpdate = tq("review_templates.update", `
		UPDATE review_templates SET name = @name, system = @system, privileged_only = @privileged_only,
			unused_days = @unused_days, duration_days = @duration_days, reminder_days = @reminder_days, close_out = @close_out,
			escalation_identity_id = @escalation_identity_id, escalation_days = @escalation_days, recurrence = @recurrence,
			next_run_at = @next_run_at, enabled = @enabled, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)
	templatesAdvance = tq("review_templates.advance", `
		UPDATE review_templates SET next_run_at = @next WHERE tenant_id = @tenant AND id = @id AND next_run_at = @from`)

	launchesInsert = tq("review_launches.insert", `
		INSERT INTO review_launches (id, tenant_id, template_id, period_key, campaign_id, launched_at, due_at)
		VALUES (@id, @tenant, @template_id, @period_key, @campaign_id, @launched_at, @due_at)`)
	launchesList = tq("review_launches.list", `
		SELECT `+launchCols+` FROM review_launches l WHERE l.tenant_id = @tenant
			AND (@template = '' OR l.template_id = @template) ORDER BY l.launched_at DESC, l.id`)
	launchesOpen = tq("review_launches.open", `
		SELECT `+launchCols+` FROM review_launches l WHERE l.tenant_id = @tenant AND l.closed_at IS NULL
		ORDER BY l.due_at, l.id`)
	launchesForPeriod = tq("review_launches.for_period", `
		SELECT count(l.id) FROM review_launches l WHERE l.tenant_id = @tenant AND l.template_id = @template
			AND l.period_key = @period`)
	launchesSave = tq("review_launches.save", `
		UPDATE review_launches SET due_at = @due_at, reminded_at = @reminded_at, escalated_at = @escalated_at,
			closed_at = @closed_at, revoked = @revoked WHERE tenant_id = @tenant AND id = @id`)

	itemsSetReviewer = tq("review_items.set_reviewer", `
		UPDATE review_items SET reviewer_id = @reviewer WHERE tenant_id = @tenant AND id = @id AND decision IS NULL`)
)

func scanTemplate(s scanner) (*ReviewTemplate, error) {
	var t ReviewTemplate
	var system, by sql.NullString
	var esc sql.NullInt64
	var priv, enabled int
	var next, created, updated nullTime
	if err := s.Scan(&t.ID, &t.Name, &system, &priv, &t.UnusedDays, &t.DurationDays, &t.ReminderDays, &t.CloseOut, &esc,
		&t.EscalationDays, &t.Recurrence, &next, &enabled, &by, &created, &updated); err != nil {
		return nil, err
	}
	t.System, t.PrivilegedOnly, t.EscalationIdentityID, t.Enabled, t.CreatedBy = strp(system), priv != 0, intp(esc), enabled != 0, strp(by)
	var err error
	if t.NextRunAt, err = next.ptr(); err != nil {
		return nil, err
	}
	if t.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	t.UpdatedAt, err = updated.val()
	return &t, err
}

func scanLaunch(s scanner) (*ReviewLaunch, error) {
	var l ReviewLaunch
	var launched, due, reminded, escalated, closed nullTime
	if err := s.Scan(&l.ID, &l.TemplateID, &l.PeriodKey, &l.CampaignID, &launched, &due, &reminded, &escalated, &closed, &l.Revoked); err != nil {
		return nil, err
	}
	var err error
	if l.LaunchedAt, err = launched.val(); err != nil {
		return nil, err
	}
	if l.DueAt, err = due.val(); err != nil {
		return nil, err
	}
	if l.RemindedAt, err = reminded.ptr(); err != nil {
		return nil, err
	}
	if l.EscalatedAt, err = escalated.ptr(); err != nil {
		return nil, err
	}
	l.ClosedAt, err = closed.ptr()
	return &l, err
}

func templateArgs(t *ReviewTemplate) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", t.ID), sql.Named("name", t.Name), sql.Named("system", SP(t.System)),
		sql.Named("privileged_only", B(t.PrivilegedOnly)), sql.Named("unused_days", t.UnusedDays),
		sql.Named("duration_days", t.DurationDays), sql.Named("reminder_days", t.ReminderDays), sql.Named("close_out", t.CloseOut),
		sql.Named("escalation_identity_id", IP(t.EscalationIdentityID)), sql.Named("escalation_days", t.EscalationDays),
		sql.Named("recurrence", t.Recurrence), sql.Named("next_run_at", TP(t.NextRunAt)), sql.Named("enabled", B(t.Enabled)),
		sql.Named("updated_at", T(t.UpdatedAt))}
}

// ReviewTemplates lists the templates by name.
func (tx *TenantTx) ReviewTemplates() ([]*ReviewTemplate, error) {
	return collect(tx, scanTemplate, templatesList)
}

// ReviewTemplate returns one template, or ErrNotFound.
func (tx *TenantTx) ReviewTemplate(id string) (*ReviewTemplate, error) {
	return one(tx, scanTemplate, templatesGet, sql.Named("id", id))
}

// DueReviewTemplates lists enabled templates whose next run is at or before now.
func (tx *TenantTx) DueReviewTemplates(now time.Time) ([]*ReviewTemplate, error) {
	return collect(tx, scanTemplate, templatesDue, sql.Named("now", T(now)))
}

// CountDueReviewTemplates counts DueReviewTemplates.
func (tx *TenantTx) CountDueReviewTemplates(now time.Time) (int, error) {
	return tx.count(templatesCountDue, sql.Named("now", T(now)))
}

// InsertReviewTemplate stores a new template.
func (tx *TenantTx) InsertReviewTemplate(t *ReviewTemplate) error {
	args := append(templateArgs(t), sql.Named("created_by", SP(t.CreatedBy)), sql.Named("created_at", T(t.CreatedAt)))
	_, err := tx.exec(templatesInsert, args...)
	return err
}

// UpdateReviewTemplate replaces a template's settings; ErrNotFound if unknown.
func (tx *TenantTx) UpdateReviewTemplate(t *ReviewTemplate) error {
	res, err := tx.exec(templatesUpdate, templateArgs(t)...)
	return rowsOne(res, err)
}

// AdvanceReviewTemplate moves a template's next run from from to next (nil:
// no further run); ErrNotFound if it was no longer at from (another
// scheduler got there first).
func (tx *TenantTx) AdvanceReviewTemplate(id string, from time.Time, next *time.Time) error {
	res, err := tx.exec(templatesAdvance, sql.Named("id", id), sql.Named("from", T(from)), sql.Named("next", TP(next)))
	return rowsOne(res, err)
}

// InsertReviewLaunch records a run.
func (tx *TenantTx) InsertReviewLaunch(l *ReviewLaunch) error {
	_, err := tx.exec(launchesInsert, sql.Named("id", l.ID), sql.Named("template_id", l.TemplateID),
		sql.Named("period_key", l.PeriodKey), sql.Named("campaign_id", l.CampaignID), sql.Named("launched_at", T(l.LaunchedAt)),
		sql.Named("due_at", T(l.DueAt)))
	return err
}

// ReviewLaunches lists runs, newest first ("" for every template).
func (tx *TenantTx) ReviewLaunches(templateID string) ([]*ReviewLaunch, error) {
	return collect(tx, scanLaunch, launchesList, sql.Named("template", templateID))
}

// OpenReviewLaunches lists runs not yet closed, by due time.
func (tx *TenantTx) OpenReviewLaunches() ([]*ReviewLaunch, error) {
	return collect(tx, scanLaunch, launchesOpen)
}

// ReviewPeriodLaunched reports whether a template already ran for a period.
func (tx *TenantTx) ReviewPeriodLaunched(templateID, period string) (bool, error) {
	n, err := tx.count(launchesForPeriod, sql.Named("template", templateID), sql.Named("period", period))
	return n > 0, err
}

// SaveReviewLaunch stores a run's progress.
func (tx *TenantTx) SaveReviewLaunch(l *ReviewLaunch) error {
	res, err := tx.exec(launchesSave, sql.Named("id", l.ID), sql.Named("due_at", T(l.DueAt)),
		sql.Named("reminded_at", TP(l.RemindedAt)), sql.Named("escalated_at", TP(l.EscalatedAt)),
		sql.Named("closed_at", TP(l.ClosedAt)), sql.Named("revoked", l.Revoked))
	return rowsOne(res, err)
}

// SetItemReviewer reassigns an undecided review item.
func (tx *TenantTx) SetItemReviewer(itemID, reviewerID int64) error {
	res, err := tx.exec(itemsSetReviewer, sql.Named("id", itemID), sql.Named("reviewer", reviewerID))
	return rowsOne(res, err)
}

func rowsOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
