package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Group attestation, deprovisioning, Inbox and report repository
// (schema/0292_group_attestation.sql, issue #57, GR-14). The rules live in
// internal/groups/{inbox,attest,deprov,reports}; this file is only their
// statements, all bound to the transaction's tenant.

func nstr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// column lists shared by statements (they must be constants)
const (
	attestItemCols = `i.id, i.tenant_id, i.campaign_id, i.group_id, i.identity_id, i.how, i.review_item_id, i.apply_state,
		i.apply_detail, i.applied_at`
	deprovItemCols = `d.id, d.tenant_id, d.identity_id, d.folder_id, d.task_id, d.status, d.mode, d.detail, d.opened_at, d.due_at,
		d.resolved_at, d.resolved_by, d.reason`
	reportRunCols = `u.id, u.tenant_id, u.report_id, u.ran_at, u.ran_by, u.trigger_type, u.status, u.format, u.row_count, u.truncated, u.sha256,
		u.content, u.error`
)

func limitOf(n int) int {
	if n < 1 || n > 1000 {
		return 1000
	}
	return n
}

// ---------------------------------------------------------------- Inbox

const grpTaskCols = `t.id, t.tenant_id, t.kind, t.title, t.detail, t.object_type, t.object_id, t.subject_identity_id,
	t.assignee_identity_id, t.status, t.dedupe_key, t.due_at, t.created_at, t.closed_at, t.closed_by`

var (
	grpTaskInsert = tq("grp_inbox_tasks.insert", `
		INSERT INTO grp_inbox_tasks (id, tenant_id, kind, title, detail, object_type, object_id, subject_identity_id,
			assignee_identity_id, status, dedupe_key, due_at, created_at)
		VALUES (@id, @tenant, @kind, @title, @detail, @object_type, @object_id, @subject, @assignee, 'open', @dedupe_key,
			@due_at, @created_at)`)
	grpTaskGet = tq("grp_inbox_tasks.get", `SELECT `+grpTaskCols+` FROM grp_inbox_tasks t WHERE t.tenant_id = @tenant AND t.id = @id`)
	grpTaskKey = tq("grp_inbox_tasks.open_by_key", `SELECT `+grpTaskCols+` FROM grp_inbox_tasks t
		WHERE t.tenant_id = @tenant AND t.status = 'open' AND t.dedupe_key = @dedupe_key`)
	grpTaskList = tq("grp_inbox_tasks.list", `SELECT `+grpTaskCols+` FROM grp_inbox_tasks t
		WHERE t.tenant_id = @tenant AND (@status = '' OR t.status = @status) AND (@kind = '' OR t.kind = @kind)
		  AND (@object_type = '' OR (t.object_type = @object_type AND t.object_id = @object_id))
		ORDER BY t.created_at, t.id LIMIT @limit OFFSET @offset`)
	grpTaskClose = tq("grp_inbox_tasks.close", `UPDATE grp_inbox_tasks SET status = @status, closed_at = @closed_at, closed_by = @closed_by
		WHERE tenant_id = @tenant AND id = @id AND status = 'open'`)
)

func scanGrpTask(s scanner) (*GrpTask, error) {
	var t GrpTask
	var tenant, created string
	var subj, asg sql.NullInt64
	var key, due, closed, by sql.NullString
	if err := s.Scan(&t.ID, &tenant, &t.Kind, &t.Title, &t.Detail, &t.ObjectType, &t.ObjectID, &subj, &asg, &t.Status, &key, &due,
		&created, &closed, &by); err != nil {
		return nil, err
	}
	var err error
	if t.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	t.Subject, t.Assignee, t.DedupeKey, t.ClosedBy = intp(subj), intp(asg), strp(key), strp(by)
	if t.DueAt, err = rtp(due); err != nil {
		return nil, err
	}
	if t.ClosedAt, err = rtp(closed); err != nil {
		return nil, err
	}
	t.CreatedAt, err = ParseRT(created)
	return &t, err
}

// InsertGrpTask adds an open task (a zero ID gets a fresh one). A second open
// task with the same DedupeKey is a unique-index error: GrpOpenTaskByKey first.
func (tx *TenantTx) InsertGrpTask(t *GrpTask) error {
	if err := tx.own(t.TenantID); err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.Detail == "" {
		t.Detail = "{}"
	}
	_, err := tx.exec(grpTaskInsert, sql.Named("id", t.ID), sql.Named("kind", t.Kind), sql.Named("title", t.Title),
		sql.Named("detail", t.Detail), sql.Named("object_type", t.ObjectType), sql.Named("object_id", t.ObjectID),
		sql.Named("subject", IP(t.Subject)), sql.Named("assignee", IP(t.Assignee)), sql.Named("dedupe_key", SP(t.DedupeKey)),
		sql.Named("due_at", RTP(t.DueAt)), sql.Named("created_at", RT(t.CreatedAt)))
	if err == nil {
		t.TenantID, t.Status = tx.tenant, TaskOpen
	}
	return err
}

// GrpTask returns one task or ErrNotFound.
func (tx *TenantTx) GrpTask(id string) (*GrpTask, error) {
	return one(tx, scanGrpTask, grpTaskGet, sql.Named("id", id))
}

// GrpOpenTaskByKey returns the open task with the dedupe key, or ErrNotFound.
func (tx *TenantTx) GrpOpenTaskByKey(key string) (*GrpTask, error) {
	return one(tx, scanGrpTask, grpTaskKey, sql.Named("dedupe_key", key))
}

// GrpTasks lists tasks, oldest first.
func (tx *TenantTx) GrpTasks(f GrpTaskFilter) ([]*GrpTask, error) {
	return collect(tx, scanGrpTask, grpTaskList, sql.Named("status", f.Status), sql.Named("kind", f.Kind),
		sql.Named("object_type", f.ObjectType), sql.Named("object_id", f.ObjectID), sql.Named("limit", limitOf(f.Limit)),
		sql.Named("offset", f.Offset))
}

// CloseGrpTask closes an open task as done or dismissed (ErrNotFound if this
// tenant has no such open task).
func (tx *TenantTx) CloseGrpTask(id, status string, at time.Time, by string) error {
	return tx.execOne(grpTaskClose, sql.Named("id", id), sql.Named("status", status), sql.Named("closed_at", RT(at)),
		sql.Named("closed_by", nstr(by)))
}

// ---------------------------------------------------------------- attestation settings

const attestSetCols = `s.tenant_id, s.owner_type, s.owner_id, s.interval_days, s.window_days, s.reviewer_type, s.reviewer_group_id,
	s.reminder_days, s.overdue_action, s.enabled, s.updated_by, s.updated_at`

var (
	attestSetGet = tq("grp_attest_settings.get", `SELECT `+attestSetCols+` FROM grp_attest_settings s
		WHERE s.tenant_id = @tenant AND s.owner_type = @owner_type AND s.owner_id = @owner_id`)
	attestSetEnabled = tq("grp_attest_settings.enabled", `SELECT `+attestSetCols+` FROM grp_attest_settings s
		WHERE s.tenant_id = @tenant AND s.enabled = 1 ORDER BY s.owner_type, s.owner_id`)
	attestSetSave = tq("grp_attest_settings.save", `
		INSERT INTO grp_attest_settings (tenant_id, owner_type, owner_id, interval_days, window_days, reviewer_type,
			reviewer_group_id, reminder_days, overdue_action, enabled, updated_by, updated_at)
		VALUES (@tenant, @owner_type, @owner_id, @interval_days, @window_days, @reviewer_type, @reviewer_group_id,
			@reminder_days, @overdue_action, @enabled, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, owner_type, owner_id) DO UPDATE SET interval_days = excluded.interval_days,
			window_days = excluded.window_days, reviewer_type = excluded.reviewer_type,
			reviewer_group_id = excluded.reviewer_group_id, reminder_days = excluded.reminder_days,
			overdue_action = excluded.overdue_action, enabled = excluded.enabled, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
	attestSetDelete = tq("grp_attest_settings.delete", `DELETE FROM grp_attest_settings
		WHERE tenant_id = @tenant AND owner_type = @owner_type AND owner_id = @owner_id`)
)

func scanAttestSettings(s scanner) (*GrpAttestSettings, error) {
	var v GrpAttestSettings
	var tenant, at string
	var rg sql.NullString
	var enabled int
	if err := s.Scan(&tenant, &v.OwnerType, &v.OwnerID, &v.IntervalDays, &v.WindowDays, &v.ReviewerType, &rg, &v.ReminderDays,
		&v.OverdueAction, &enabled, &v.UpdatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	if v.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	if rg.Valid {
		g := GroupID(rg.String)
		v.ReviewerGroup = &g
	}
	v.Enabled = enabled == 1
	v.UpdatedAt, err = ParseRT(at)
	return &v, err
}

// GrpAttestSettingsOf returns a folder's or group's own attestation settings, or ErrNotFound.
func (tx *TenantTx) GrpAttestSettingsOf(ownerType, ownerID string) (*GrpAttestSettings, error) {
	return one(tx, scanAttestSettings, attestSetGet, sql.Named("owner_type", ownerType), sql.Named("owner_id", ownerID))
}

// GrpAttestSettingsEnabled lists every enabled setting of the tenant.
func (tx *TenantTx) GrpAttestSettingsEnabled() ([]*GrpAttestSettings, error) {
	return collect(tx, scanAttestSettings, attestSetEnabled)
}

// SetGrpAttestSettings creates or replaces an owner's settings.
func (tx *TenantTx) SetGrpAttestSettings(v *GrpAttestSettings) error {
	if err := tx.own(v.TenantID); err != nil {
		return err
	}
	var rg any
	if v.ReviewerGroup != nil {
		rg = string(*v.ReviewerGroup)
	}
	_, err := tx.exec(attestSetSave, sql.Named("owner_type", v.OwnerType), sql.Named("owner_id", v.OwnerID),
		sql.Named("interval_days", v.IntervalDays), sql.Named("window_days", v.WindowDays),
		sql.Named("reviewer_type", v.ReviewerType), sql.Named("reviewer_group_id", rg), sql.Named("reminder_days", v.ReminderDays),
		sql.Named("overdue_action", v.OverdueAction), sql.Named("enabled", B(v.Enabled)), sql.Named("updated_by", v.UpdatedBy),
		sql.Named("updated_at", RT(v.UpdatedAt)))
	if err == nil {
		v.TenantID = tx.tenant
	}
	return err
}

// DeleteGrpAttestSettings removes an owner's settings and reports whether there were any.
func (tx *TenantTx) DeleteGrpAttestSettings(ownerType, ownerID string) (bool, error) {
	res, err := tx.exec(attestSetDelete, sql.Named("owner_type", ownerType), sql.Named("owner_id", ownerID))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---------------------------------------------------------------- attestation campaigns and items

const attestCampCols = `c.id, c.tenant_id, c.group_id, c.kind, c.review_campaign_id, c.status, c.started_at, c.due_at, c.closed_at,
	c.overdue_action, c.reviewer_type, c.reviewer_group_id, c.reminder_days, c.acts_as, c.population_count, c.population_hash,
	c.reminders_sent, c.last_reminder_at, c.started_by, c.rule_id`

var (
	attestCampInsert = tq("grp_attest_campaigns.insert", `
		INSERT INTO grp_attest_campaigns (id, tenant_id, group_id, kind, review_campaign_id, status, started_at, due_at,
			overdue_action, reviewer_type, reviewer_group_id, reminder_days, acts_as, population_count, population_hash,
			started_by, rule_id)
		VALUES (@id, @tenant, @group_id, @kind, @review_campaign_id, 'open', @started_at, @due_at, @overdue_action,
			@reviewer_type, @reviewer_group_id, @reminder_days, @acts_as, @population_count, @population_hash,
			@started_by, @rule_id)`)
	attestCampGet  = tq("grp_attest_campaigns.get", `SELECT `+attestCampCols+` FROM grp_attest_campaigns c WHERE c.tenant_id = @tenant AND c.id = @id`)
	attestCampList = tq("grp_attest_campaigns.list", `SELECT `+attestCampCols+` FROM grp_attest_campaigns c
		WHERE c.tenant_id = @tenant AND (@group_id = '' OR c.group_id = @group_id) AND (@status = '' OR c.status = @status)
		ORDER BY c.started_at DESC, c.id LIMIT @limit OFFSET @offset`)
	attestCampSave = tq("grp_attest_campaigns.save", `UPDATE grp_attest_campaigns SET status = @status, closed_at = @closed_at,
		reminders_sent = @reminders_sent, last_reminder_at = @last_reminder_at WHERE tenant_id = @tenant AND id = @id`)

	attestItemInsert = tq("grp_attest_items.insert", `
		INSERT INTO grp_attest_items (id, tenant_id, campaign_id, group_id, identity_id, how, review_item_id)
		VALUES (@id, @tenant, @campaign_id, @group_id, @identity_id, @how, @review_item_id)`)
	attestItemGet     = tq("grp_attest_items.get", `SELECT `+attestItemCols+` FROM grp_attest_items i WHERE i.tenant_id = @tenant AND i.id = @id`)
	attestItemByRev   = tq("grp_attest_items.by_review_item", `SELECT `+attestItemCols+` FROM grp_attest_items i WHERE i.tenant_id = @tenant AND i.review_item_id = @review_item_id`)
	attestItemsOf     = tq("grp_attest_items.of_campaign", `SELECT `+attestItemCols+` FROM grp_attest_items i WHERE i.tenant_id = @tenant AND i.campaign_id = @campaign_id ORDER BY i.identity_id`)
	attestItemApplied = tq("grp_attest_items.set_applied", `UPDATE grp_attest_items SET apply_state = @apply_state, apply_detail = @apply_detail,
		applied_at = @applied_at WHERE tenant_id = @tenant AND id = @id`)
)

func scanAttestCampaign(s scanner) (*GrpAttestCampaign, error) {
	var c GrpAttestCampaign
	var tenant, started, due string
	var rc sql.NullInt64
	var closed, rg, last, by, rule sql.NullString
	if err := s.Scan(&c.ID, &tenant, &c.GroupID, &c.Kind, &rc, &c.Status, &started, &due, &closed, &c.OverdueAction, &c.ReviewerType,
		&rg, &c.ReminderDays, &c.ActsAs, &c.PopulationCount, &c.PopulationHash, &c.RemindersSent, &last, &by, &rule); err != nil {
		return nil, err
	}
	var err error
	if c.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	c.ReviewCampaign, c.StartedBy, c.RuleID = intp(rc), strp(by), strp(rule)
	if rg.Valid {
		g := GroupID(rg.String)
		c.ReviewerGroup = &g
	}
	if c.StartedAt, err = ParseRT(started); err != nil {
		return nil, err
	}
	if c.DueAt, err = ParseRT(due); err != nil {
		return nil, err
	}
	if c.ClosedAt, err = rtp(closed); err != nil {
		return nil, err
	}
	c.LastReminderAt, err = rtp(last)
	return &c, err
}

// InsertGrpAttestCampaign adds an open campaign (a zero ID gets a fresh one).
func (tx *TenantTx) InsertGrpAttestCampaign(c *GrpAttestCampaign) error {
	if err := tx.own(c.TenantID); err != nil {
		return err
	}
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	var rg any
	if c.ReviewerGroup != nil {
		rg = string(*c.ReviewerGroup)
	}
	_, err := tx.exec(attestCampInsert, sql.Named("id", c.ID), sql.Named("group_id", string(c.GroupID)), sql.Named("kind", c.Kind),
		sql.Named("review_campaign_id", IP(c.ReviewCampaign)), sql.Named("started_at", RT(c.StartedAt)), sql.Named("due_at", RT(c.DueAt)),
		sql.Named("overdue_action", c.OverdueAction), sql.Named("reviewer_type", c.ReviewerType), sql.Named("reviewer_group_id", rg),
		sql.Named("reminder_days", c.ReminderDays), sql.Named("acts_as", c.ActsAs), sql.Named("population_count", c.PopulationCount),
		sql.Named("population_hash", c.PopulationHash), sql.Named("started_by", SP(c.StartedBy)), sql.Named("rule_id", SP(c.RuleID)))
	if err == nil {
		c.TenantID, c.Status = tx.tenant, AttestOpen
	}
	return err
}

// GrpAttestCampaign returns one campaign or ErrNotFound.
func (tx *TenantTx) GrpAttestCampaign(id string) (*GrpAttestCampaign, error) {
	return one(tx, scanAttestCampaign, attestCampGet, sql.Named("id", id))
}

// GrpAttestCampaigns lists campaigns, newest first.
func (tx *TenantTx) GrpAttestCampaigns(f GrpAttestFilter) ([]*GrpAttestCampaign, error) {
	return collect(tx, scanAttestCampaign, attestCampList, sql.Named("group_id", string(f.Group)), sql.Named("status", f.Status),
		sql.Named("limit", limitOf(f.Limit)), sql.Named("offset", f.Offset))
}

// SaveGrpAttestCampaign stores what changes after the start: status, close time and reminders.
func (tx *TenantTx) SaveGrpAttestCampaign(c *GrpAttestCampaign) error {
	return tx.execOne(attestCampSave, sql.Named("id", c.ID), sql.Named("status", c.Status), sql.Named("closed_at", RTP(c.ClosedAt)),
		sql.Named("reminders_sent", c.RemindersSent), sql.Named("last_reminder_at", RTP(c.LastReminderAt)))
}

func scanAttestItem(s scanner) (*GrpAttestItem, error) {
	var i GrpAttestItem
	var tenant string
	var rev sql.NullInt64
	var at sql.NullString
	if err := s.Scan(&i.ID, &tenant, &i.CampaignID, &i.GroupID, &i.Identity, &i.How, &rev, &i.ApplyState, &i.ApplyDetail, &at); err != nil {
		return nil, err
	}
	var err error
	if i.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	i.ReviewItem = intp(rev)
	i.AppliedAt, err = rtp(at)
	return &i, err
}

// InsertGrpAttestItem adds one identity of a campaign's population.
func (tx *TenantTx) InsertGrpAttestItem(i *GrpAttestItem) error {
	if err := tx.own(i.TenantID); err != nil {
		return err
	}
	if i.ID == "" {
		i.ID = uuid.NewString()
	}
	_, err := tx.exec(attestItemInsert, sql.Named("id", i.ID), sql.Named("campaign_id", i.CampaignID),
		sql.Named("group_id", string(i.GroupID)), sql.Named("identity_id", i.Identity), sql.Named("how", i.How),
		sql.Named("review_item_id", IP(i.ReviewItem)))
	if err == nil {
		i.TenantID, i.ApplyState = tx.tenant, ApplyPending
	}
	return err
}

// GrpAttestItem returns one item or ErrNotFound.
func (tx *TenantTx) GrpAttestItem(id string) (*GrpAttestItem, error) {
	return one(tx, scanAttestItem, attestItemGet, sql.Named("id", id))
}

// GrpAttestItemByReview returns the item behind a review item, or ErrNotFound.
func (tx *TenantTx) GrpAttestItemByReview(reviewItem int64) (*GrpAttestItem, error) {
	return one(tx, scanAttestItem, attestItemByRev, sql.Named("review_item_id", reviewItem))
}

// GrpAttestItems lists a campaign's population by identity id.
func (tx *TenantTx) GrpAttestItems(campaign string) ([]*GrpAttestItem, error) {
	return collect(tx, scanAttestItem, attestItemsOf, sql.Named("campaign_id", campaign))
}

// SetGrpAttestItemApplied records what became of an item's decision.
func (tx *TenantTx) SetGrpAttestItemApplied(id, state, detail string, at time.Time) error {
	return tx.execOne(attestItemApplied, sql.Named("id", id), sql.Named("apply_state", state), sql.Named("apply_detail", detail),
		sql.Named("applied_at", RT(at)))
}

// ---------------------------------------------------------------- deprovisioning

var (
	deprovSetGet = tq("grp_deprov_settings.get", `SELECT s.affiliations, s.veto_enabled, s.updated_at, s.updated_by
		FROM grp_deprov_settings s WHERE s.tenant_id = @tenant`)
	deprovSetSave = tq("grp_deprov_settings.save", `
		INSERT INTO grp_deprov_settings (tenant_id, affiliations, veto_enabled, updated_at, updated_by)
		VALUES (@tenant, @affiliations, @veto_enabled, @updated_at, @updated_by)
		ON CONFLICT (tenant_id) DO UPDATE SET affiliations = excluded.affiliations, veto_enabled = excluded.veto_enabled,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`)

	deprovFolderGet = tq("grp_deprov_folders.get", `SELECT f.folder_id, f.mode, f.days, f.updated_by, f.updated_at
		FROM grp_deprov_folders f WHERE f.tenant_id = @tenant AND f.folder_id = @folder_id`)
	deprovFolderSave = tq("grp_deprov_folders.save", `
		INSERT INTO grp_deprov_folders (tenant_id, folder_id, mode, days, updated_by, updated_at)
		VALUES (@tenant, @folder_id, @mode, @days, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, folder_id) DO UPDATE SET mode = excluded.mode, days = excluded.days,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	deprovFolderDelete = tq("grp_deprov_folders.delete", `DELETE FROM grp_deprov_folders WHERE tenant_id = @tenant AND folder_id = @folder_id`)

	deprovMarkGet = tq("grp_deprovisioned.get", `SELECT m.identity_id, m.since, m.reason FROM grp_deprovisioned m
		WHERE m.tenant_id = @tenant AND m.identity_id = @identity_id`)
	deprovMarkSet = tq("grp_deprovisioned.set", `
		INSERT INTO grp_deprovisioned (tenant_id, identity_id, since, reason) VALUES (@tenant, @identity_id, @since, @reason)
		ON CONFLICT (tenant_id, identity_id) DO NOTHING`)
	deprovMarkClear = tq("grp_deprovisioned.clear", `DELETE FROM grp_deprovisioned WHERE tenant_id = @tenant AND identity_id = @identity_id`)

	deprovItemInsert = tq("grp_deprov_items.insert", `
		INSERT INTO grp_deprov_items (id, tenant_id, identity_id, folder_id, task_id, status, mode, detail, opened_at, due_at)
		VALUES (@id, @tenant, @identity_id, @folder_id, @task_id, 'open', @mode, @detail, @opened_at, @due_at)`)
	deprovItemGet  = tq("grp_deprov_items.get", `SELECT `+deprovItemCols+` FROM grp_deprov_items d WHERE d.tenant_id = @tenant AND d.id = @id`)
	deprovItemList = tq("grp_deprov_items.list", `SELECT `+deprovItemCols+` FROM grp_deprov_items d
		WHERE d.tenant_id = @tenant AND (@status = '' OR d.status = @status) AND (@folder_id = '' OR d.folder_id = @folder_id)
		  AND (@identity_id = 0 OR d.identity_id = @identity_id)
		ORDER BY d.opened_at, d.id LIMIT @limit OFFSET @offset`)
	deprovItemResolve = tq("grp_deprov_items.resolve", `UPDATE grp_deprov_items SET status = @status, resolved_at = @resolved_at,
		resolved_by = @resolved_by, reason = @reason WHERE tenant_id = @tenant AND id = @id AND status = 'open'`)

	// identities that are no longer active and still hold a direct membership in a live group
	deprovInactiveHolders = tq("grp_dm.inactive_holders", `SELECT DISTINCT d.member_identity_id FROM grp_direct_memberships d
		JOIN identities i ON i.tenant_id = @tenant AND i.id = d.member_identity_id
		JOIN grp_groups g ON g.tenant_id = @tenant AND g.id = d.group_id
		WHERE d.tenant_id = @tenant AND d.member_type = 'identity' AND i.status <> 'active' AND g.status <> 'deleted'
		ORDER BY d.member_identity_id`)
)

// GrpDeprovSettings returns the tenant's deprovisioning settings, or ErrNotFound
// while it has never saved any (no affiliations: nothing is deprovisioned).
func (tx *TenantTx) GrpDeprovSettings() (*GrpDeprovSettings, error) {
	return one(tx, func(s scanner) (*GrpDeprovSettings, error) {
		var v GrpDeprovSettings
		var veto int
		var at string
		var by sql.NullString
		if err := s.Scan(&v.Affiliations, &veto, &at, &by); err != nil {
			return nil, err
		}
		v.VetoEnabled, v.UpdatedBy = veto == 1, strp(by)
		var err error
		v.UpdatedAt, err = ParseRT(at)
		return &v, err
	}, deprovSetGet)
}

// SetGrpDeprovSettings stores the tenant's deprovisioning settings.
func (tx *TenantTx) SetGrpDeprovSettings(v *GrpDeprovSettings) error {
	_, err := tx.exec(deprovSetSave, sql.Named("affiliations", v.Affiliations), sql.Named("veto_enabled", B(v.VetoEnabled)),
		sql.Named("updated_at", RT(v.UpdatedAt)), sql.Named("updated_by", SP(v.UpdatedBy)))
	return err
}

// GrpDeprovFolder returns a folder's own deprovisioning mode, or ErrNotFound.
func (tx *TenantTx) GrpDeprovFolder(folder FolderID) (*GrpDeprovFolder, error) {
	return one(tx, func(s scanner) (*GrpDeprovFolder, error) {
		var v GrpDeprovFolder
		var at string
		if err := s.Scan(&v.FolderID, &v.Mode, &v.Days, &v.UpdatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		v.UpdatedAt, err = ParseRT(at)
		return &v, err
	}, deprovFolderGet, sql.Named("folder_id", string(folder)))
}

// SetGrpDeprovFolder stores a folder's deprovisioning mode.
func (tx *TenantTx) SetGrpDeprovFolder(v *GrpDeprovFolder) error {
	_, err := tx.exec(deprovFolderSave, sql.Named("folder_id", string(v.FolderID)), sql.Named("mode", v.Mode), sql.Named("days", v.Days),
		sql.Named("updated_by", v.UpdatedBy), sql.Named("updated_at", RT(v.UpdatedAt)))
	return err
}

// DeleteGrpDeprovFolder removes a folder's own mode (it inherits again) and reports whether it had one.
func (tx *TenantTx) DeleteGrpDeprovFolder(folder FolderID) (bool, error) {
	res, err := tx.exec(deprovFolderDelete, sql.Named("folder_id", string(folder)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// GrpDeprovMark returns the mark of a deprovisioned identity, or ErrNotFound.
func (tx *TenantTx) GrpDeprovMark(identity int64) (*GrpDeprovMark, error) {
	return one(tx, func(s scanner) (*GrpDeprovMark, error) {
		var m GrpDeprovMark
		var since string
		if err := s.Scan(&m.Identity, &since, &m.Reason); err != nil {
			return nil, err
		}
		var err error
		m.Since, err = ParseRT(since)
		return &m, err
	}, deprovMarkGet, sql.Named("identity_id", identity))
}

// SetGrpDeprovMark marks an identity deprovisioned (the first mark stands).
func (tx *TenantTx) SetGrpDeprovMark(m GrpDeprovMark) error {
	_, err := tx.exec(deprovMarkSet, sql.Named("identity_id", m.Identity), sql.Named("since", RT(m.Since)), sql.Named("reason", m.Reason))
	return err
}

// ClearGrpDeprovMark removes the mark and reports whether there was one.
func (tx *TenantTx) ClearGrpDeprovMark(identity int64) (bool, error) {
	res, err := tx.exec(deprovMarkClear, sql.Named("identity_id", identity))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func scanDeprovItem(s scanner) (*GrpDeprovItem, error) {
	var d GrpDeprovItem
	var tenant, opened string
	var task, due, resolved, by sql.NullString
	if err := s.Scan(&d.ID, &tenant, &d.Identity, &d.FolderID, &task, &d.Status, &d.Mode, &d.Detail, &opened, &due, &resolved, &by,
		&d.Reason); err != nil {
		return nil, err
	}
	var err error
	if d.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	d.TaskID, d.ResolvedBy = strp(task), strp(by)
	if d.OpenedAt, err = ParseRT(opened); err != nil {
		return nil, err
	}
	if d.DueAt, err = rtp(due); err != nil {
		return nil, err
	}
	d.ResolvedAt, err = rtp(resolved)
	return &d, err
}

// InsertGrpDeprovItem adds open work for an identity in a folder (a zero ID
// gets a fresh one). A second open item for the pair is a unique-index error.
func (tx *TenantTx) InsertGrpDeprovItem(d *GrpDeprovItem) error {
	if err := tx.own(d.TenantID); err != nil {
		return err
	}
	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	if d.Detail == "" {
		d.Detail = "{}"
	}
	_, err := tx.exec(deprovItemInsert, sql.Named("id", d.ID), sql.Named("identity_id", d.Identity),
		sql.Named("folder_id", string(d.FolderID)), sql.Named("task_id", SP(d.TaskID)), sql.Named("mode", d.Mode),
		sql.Named("detail", d.Detail), sql.Named("opened_at", RT(d.OpenedAt)), sql.Named("due_at", RTP(d.DueAt)))
	if err == nil {
		d.TenantID, d.Status = tx.tenant, DeprovOpen
	}
	return err
}

// GrpDeprovItem returns one item or ErrNotFound.
func (tx *TenantTx) GrpDeprovItem(id string) (*GrpDeprovItem, error) {
	return one(tx, scanDeprovItem, deprovItemGet, sql.Named("id", id))
}

// GrpDeprovItems lists items, oldest first.
func (tx *TenantTx) GrpDeprovItems(f GrpDeprovFilter) ([]*GrpDeprovItem, error) {
	return collect(tx, scanDeprovItem, deprovItemList, sql.Named("status", f.Status), sql.Named("folder_id", string(f.FolderID)),
		sql.Named("identity_id", f.Identity), sql.Named("limit", limitOf(f.Limit)), sql.Named("offset", f.Offset))
}

// ResolveGrpDeprovItem closes an open item as removed or dismissed (ErrNotFound if it is not open).
func (tx *TenantTx) ResolveGrpDeprovItem(id, status, by, reason string, at time.Time) error {
	return tx.execOne(deprovItemResolve, sql.Named("id", id), sql.Named("status", status), sql.Named("resolved_at", RT(at)),
		sql.Named("resolved_by", nstr(by)), sql.Named("reason", reason))
}

// GrpInactiveHolders lists the identities that are no longer active and still
// hold a direct membership in a group that is not deleted.
func (tx *TenantTx) GrpInactiveHolders() ([]int64, error) {
	rows, err := collect(tx, func(s scanner) (*int64, error) {
		var id int64
		return &id, s.Scan(&id)
	}, deprovInactiveHolders)
	out := make([]int64, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	return out, err
}

// ---------------------------------------------------------------- reports

const reportCols = `r.id, r.tenant_id, r.name, r.kind, r.params, r.format, r.schedule, r.delivery, r.next_run_at, r.last_run_at,
	r.created_by, r.created_at, r.updated_at`

var (
	reportInsert = tq("grp_reports.insert", `
		INSERT INTO grp_reports (id, tenant_id, name, kind, params, format, schedule, delivery, next_run_at, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @kind, @params, @format, @schedule, @delivery, @next_run_at, @created_by, @created_at, @updated_at)`)
	reportGet  = tq("grp_reports.get", `SELECT `+reportCols+` FROM grp_reports r WHERE r.tenant_id = @tenant AND r.id = @id`)
	reportList = tq("grp_reports.list", `SELECT `+reportCols+` FROM grp_reports r
		WHERE r.tenant_id = @tenant AND (@created_by = '' OR r.created_by = @created_by) ORDER BY r.created_at, r.id`)
	reportDue = tq("grp_reports.due", `SELECT `+reportCols+` FROM grp_reports r
		WHERE r.tenant_id = @tenant AND r.next_run_at IS NOT NULL AND r.next_run_at <= @now ORDER BY r.next_run_at, r.id LIMIT @limit`)
	reportSave = tq("grp_reports.save", `UPDATE grp_reports SET name = @name, params = @params, format = @format, schedule = @schedule,
		delivery = @delivery, next_run_at = @next_run_at, last_run_at = @last_run_at, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)
	reportRunsDelete = tq("grp_report_runs.delete_of_report", `DELETE FROM grp_report_runs WHERE tenant_id = @tenant AND report_id = @id`)
	reportDelete     = tq("grp_reports.delete", `DELETE FROM grp_reports WHERE tenant_id = @tenant AND id = @id`)

	reportRunInsert = tq("grp_report_runs.insert", `
		INSERT INTO grp_report_runs (id, tenant_id, report_id, ran_at, ran_by, trigger_type, status, format, row_count, truncated, sha256, content, error)
		VALUES (@id, @tenant, @report_id, @ran_at, @ran_by, @trigger_type, @status, @format, @row_count, @truncated, @sha256, @content, @error)`)
	reportRunGet  = tq("grp_report_runs.get", `SELECT `+reportRunCols+` FROM grp_report_runs u WHERE u.tenant_id = @tenant AND u.id = @id`)
	reportRunList = tq("grp_report_runs.list", `SELECT `+reportRunCols+` FROM grp_report_runs u
		WHERE u.tenant_id = @tenant AND u.report_id = @report_id ORDER BY u.ran_at DESC, u.id LIMIT @limit`)
	reportRunDelete = tq("grp_report_runs.delete", `DELETE FROM grp_report_runs WHERE tenant_id = @tenant AND id = @id`)
)

func scanReport(s scanner) (*GrpReport, error) {
	var r GrpReport
	var tenant, created, updated string
	var next, last sql.NullString
	if err := s.Scan(&r.ID, &tenant, &r.Name, &r.Kind, &r.Params, &r.Format, &r.Schedule, &r.Delivery, &next, &last, &r.CreatedBy,
		&created, &updated); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	if r.NextRunAt, err = rtp(next); err != nil {
		return nil, err
	}
	if r.LastRunAt, err = rtp(last); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = ParseRT(updated)
	return &r, err
}

// InsertGrpReport adds a saved report (a zero ID gets a fresh one).
func (tx *TenantTx) InsertGrpReport(r *GrpReport) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := tx.exec(reportInsert, sql.Named("id", r.ID), sql.Named("name", r.Name), sql.Named("kind", r.Kind),
		sql.Named("params", r.Params), sql.Named("format", r.Format), sql.Named("schedule", r.Schedule),
		sql.Named("delivery", r.Delivery), sql.Named("next_run_at", RTP(r.NextRunAt)), sql.Named("created_by", r.CreatedBy),
		sql.Named("created_at", RT(r.CreatedAt)), sql.Named("updated_at", RT(r.UpdatedAt)))
	if err == nil {
		r.TenantID = tx.tenant
	}
	return err
}

// GrpReport returns one saved report or ErrNotFound.
func (tx *TenantTx) GrpReport(id string) (*GrpReport, error) {
	return one(tx, scanReport, reportGet, sql.Named("id", id))
}

// GrpReports lists saved reports, oldest first; createdBy "" lists all.
func (tx *TenantTx) GrpReports(createdBy string) ([]*GrpReport, error) {
	return collect(tx, scanReport, reportList, sql.Named("created_by", createdBy))
}

// GrpReportsDue lists the scheduled reports whose next run is at or before now.
func (tx *TenantTx) GrpReportsDue(now time.Time, limit int) ([]*GrpReport, error) {
	return collect(tx, scanReport, reportDue, sql.Named("now", RT(now)), sql.Named("limit", limitOf(limit)))
}

// SaveGrpReport stores what an update may change (ErrNotFound if this tenant has no such report).
func (tx *TenantTx) SaveGrpReport(r *GrpReport) error {
	return tx.execOne(reportSave, sql.Named("id", r.ID), sql.Named("name", r.Name), sql.Named("params", r.Params),
		sql.Named("format", r.Format), sql.Named("schedule", r.Schedule), sql.Named("delivery", r.Delivery),
		sql.Named("next_run_at", RTP(r.NextRunAt)), sql.Named("last_run_at", RTP(r.LastRunAt)), sql.Named("updated_at", RT(r.UpdatedAt)))
}

// DeleteGrpReport removes a report and its runs (ErrNotFound if this tenant has no such report).
func (tx *TenantTx) DeleteGrpReport(id string) error {
	if _, err := tx.exec(reportRunsDelete, sql.Named("id", id)); err != nil {
		return err
	}
	return tx.execOne(reportDelete, sql.Named("id", id))
}

func scanReportRun(s scanner) (*GrpReportRun, error) {
	var r GrpReportRun
	var tenant, at string
	var trunc int
	if err := s.Scan(&r.ID, &tenant, &r.ReportID, &at, &r.RanBy, &r.Trigger, &r.Status, &r.Format, &r.RowCount, &trunc, &r.SHA256,
		&r.Content, &r.Error); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	r.Truncated = trunc == 1
	r.RanAt, err = ParseRT(at)
	return &r, err
}

// InsertGrpReportRun stores the output of a run (a zero ID gets a fresh one).
func (tx *TenantTx) InsertGrpReportRun(r *GrpReportRun) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := tx.exec(reportRunInsert, sql.Named("id", r.ID), sql.Named("report_id", r.ReportID), sql.Named("ran_at", RT(r.RanAt)),
		sql.Named("ran_by", r.RanBy), sql.Named("trigger_type", r.Trigger), sql.Named("status", r.Status), sql.Named("format", r.Format),
		sql.Named("row_count", r.RowCount), sql.Named("truncated", B(r.Truncated)), sql.Named("sha256", r.SHA256),
		sql.Named("content", r.Content), sql.Named("error", r.Error))
	if err == nil {
		r.TenantID = tx.tenant
	}
	return err
}

// GrpReportRun returns one run or ErrNotFound.
func (tx *TenantTx) GrpReportRun(id string) (*GrpReportRun, error) {
	return one(tx, scanReportRun, reportRunGet, sql.Named("id", id))
}

// GrpReportRuns lists a report's runs, newest first.
func (tx *TenantTx) GrpReportRuns(report string, limit int) ([]*GrpReportRun, error) {
	return collect(tx, scanReportRun, reportRunList, sql.Named("report_id", report), sql.Named("limit", limitOf(limit)))
}

// PruneGrpReportRuns keeps a report's newest keep runs and deletes the rest.
func (tx *TenantTx) PruneGrpReportRuns(report string, keep int) (int64, error) {
	runs, err := tx.GrpReportRuns(report, 1000)
	if err != nil || len(runs) <= keep {
		return 0, err
	}
	var n int64
	for _, r := range runs[keep:] { // newest first
		if _, err := tx.exec(reportRunDelete, sql.Named("id", r.ID)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
