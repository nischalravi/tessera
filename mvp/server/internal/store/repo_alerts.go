package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Alerting (schema/0209_alerts.sql, issue #168).

// AlertRuleSetting is a tenant's override of a built-in rule.
type AlertRuleSetting struct {
	RuleID        string
	Enabled       bool
	Severity      string
	Threshold     int
	WindowMinutes int
	UpdatedBy     *string
	UpdatedAt     time.Time
}

// Alert is one raised alert; repeats of the same rule and key bump it.
type Alert struct {
	ID             string
	RuleID         string
	DedupKey       string
	Severity       string
	Title          string
	Detail         json.RawMessage
	Status         string // open | acknowledged | resolved
	Count          int
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	LastEventSeq   *int64
	AssigneeUserID *string
	AcknowledgedBy *string
	AcknowledgedAt *time.Time
	ResolvedBy     *string
	ResolvedAt     *time.Time
	Resolution     *string
}

// AlertChannel is an email or webhook destination.
type AlertChannel struct {
	ID           string
	Name         string
	Kind         string // email | webhook
	Target       string // addresses, or the webhook URL
	SecretSealed []byte // webhook signing secret, sealed
	MinSeverity  string
	Enabled      bool
	CreatedBy    *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AlertDelivery is one alert's delivery to one channel.
type AlertDelivery struct {
	ID            string
	AlertID       string
	ChannelID     string
	Reason        string // raised | test
	Status        string // pending | sent | failed
	Attempts      int
	NextAttemptAt time.Time
	LastError     *string
	SentAt        *time.Time
	CreatedAt     time.Time
}

// AlertFilter selects alerts; empty fields match everything.
type AlertFilter struct {
	Status   string // open | acknowledged | resolved | live (open or acknowledged)
	Severity string
	RuleID   string
	Limit    int // <= 0: 500
}

const alertCols = `a.id, a.rule_id, a.dedup_key, a.severity, a.title, a.detail, a.status, a.count, a.first_seen_at, a.last_seen_at,
	a.last_event_seq, a.assignee_user_id, a.acknowledged_by, a.acknowledged_at, a.resolved_by, a.resolved_at, a.resolution`

const channelCols = `c.id, c.name, c.kind, c.target, c.secret_sealed, c.min_severity, c.enabled, c.created_by, c.created_at, c.updated_at`

const deliveryCols = `d.id, d.alert_id, d.channel_id, d.reason, d.status, d.attempts, d.next_attempt_at, d.last_error, d.sent_at, d.created_at`

var (
	alertRuleSettingsList = tq("alert_rule_settings.list", `
		SELECT s.rule_id, s.enabled, s.severity, s.threshold, s.window_minutes, s.updated_by, s.updated_at
		FROM alert_rule_settings s WHERE s.tenant_id = @tenant ORDER BY s.rule_id`)
	alertRuleSettingsPut = tq("alert_rule_settings.put", `
		INSERT INTO alert_rule_settings (tenant_id, rule_id, enabled, severity, threshold, window_minutes, updated_by, updated_at)
		VALUES (@tenant, @rule_id, @enabled, @severity, @threshold, @window_minutes, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, rule_id) DO UPDATE SET enabled = excluded.enabled, severity = excluded.severity,
			threshold = excluded.threshold, window_minutes = excluded.window_minutes, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)

	alertsList = tq("alerts.list", `
		SELECT `+alertCols+` FROM alerts a WHERE a.tenant_id = @tenant
			AND (@status = '' OR a.status = @status OR (@status = 'live' AND a.status <> 'resolved'))
			AND (@severity = '' OR a.severity = @severity) AND (@rule = '' OR a.rule_id = @rule)
		ORDER BY a.last_seen_at DESC, a.id LIMIT @limit`)
	alertsGet = tq("alerts.get", `
		SELECT `+alertCols+` FROM alerts a WHERE a.tenant_id = @tenant AND a.id = @id`)
	alertsLive = tq("alerts.live", `
		SELECT `+alertCols+` FROM alerts a WHERE a.tenant_id = @tenant AND a.rule_id = @rule AND a.dedup_key = @key
			AND a.status <> 'resolved'`)
	alertsLiveOfRule = tq("alerts.live_of_rule", `
		SELECT `+alertCols+` FROM alerts a WHERE a.tenant_id = @tenant AND a.rule_id = @rule AND a.status <> 'resolved'
		ORDER BY a.dedup_key`)
	alertsCounts = tq("alerts.counts", `
		SELECT a.status, a.severity, count(a.id) FROM alerts a WHERE a.tenant_id = @tenant AND a.status <> 'resolved'
		GROUP BY a.status, a.severity`)
	alertsInsert = tq("alerts.insert", `
		INSERT INTO alerts (id, tenant_id, rule_id, dedup_key, severity, title, detail, status, count, first_seen_at, last_seen_at,
			last_event_seq)
		VALUES (@id, @tenant, @rule_id, @dedup_key, @severity, @title, @detail, 'open', @count, @first_seen_at, @last_seen_at,
			@last_event_seq)`)
	alertsBump = tq("alerts.bump", `
		UPDATE alerts SET count = count + @n, last_seen_at = @last_seen_at, last_event_seq = coalesce(@last_event_seq, last_event_seq),
			title = @title, detail = @detail, severity = @severity
		WHERE tenant_id = @tenant AND id = @id`)
	alertsSaveState = tq("alerts.save_state", `
		UPDATE alerts SET status = @status, assignee_user_id = @assignee, acknowledged_by = @acknowledged_by,
			acknowledged_at = @acknowledged_at, resolved_by = @resolved_by, resolved_at = @resolved_at, resolution = @resolution
		WHERE tenant_id = @tenant AND id = @id`)

	alertChannelsList = tq("alert_channels.list", `
		SELECT `+channelCols+` FROM alert_channels c WHERE c.tenant_id = @tenant ORDER BY c.name, c.id`)
	alertChannelsGet = tq("alert_channels.get", `
		SELECT `+channelCols+` FROM alert_channels c WHERE c.tenant_id = @tenant AND c.id = @id`)
	alertChannelsInsert = tq("alert_channels.insert", `
		INSERT INTO alert_channels (id, tenant_id, name, kind, target, secret_sealed, min_severity, enabled, created_by, created_at,
			updated_at)
		VALUES (@id, @tenant, @name, @kind, @target, @secret, @min_severity, @enabled, @created_by, @created_at, @updated_at)`)
	alertChannelsUpdate = tq("alert_channels.update", `
		UPDATE alert_channels SET name = @name, target = @target, secret_sealed = @secret, min_severity = @min_severity,
			enabled = @enabled, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id`)

	alertDeliveriesInsert = tq("alert_deliveries.insert", `
		INSERT INTO alert_deliveries (id, tenant_id, alert_id, channel_id, reason, status, attempts, next_attempt_at, created_at)
		VALUES (@id, @tenant, @alert_id, @channel_id, @reason, 'pending', 0, @next_attempt_at, @created_at)`)
	alertDeliveriesDue = tq("alert_deliveries.due", `
		SELECT `+deliveryCols+` FROM alert_deliveries d WHERE d.tenant_id = @tenant AND d.status = 'pending'
			AND d.next_attempt_at <= @now ORDER BY d.next_attempt_at, d.id LIMIT @limit`)
	alertDeliveriesOf = tq("alert_deliveries.of_alert", `
		SELECT `+deliveryCols+` FROM alert_deliveries d WHERE d.tenant_id = @tenant AND d.alert_id = @alert_id
		ORDER BY d.created_at, d.id`)
	alertDeliveriesGet = tq("alert_deliveries.get", `
		SELECT `+deliveryCols+` FROM alert_deliveries d WHERE d.tenant_id = @tenant AND d.id = @id`)
	alertDeliveriesSave = tq("alert_deliveries.save", `
		UPDATE alert_deliveries SET status = @status, attempts = @attempts, next_attempt_at = @next_attempt_at,
			last_error = @last_error, sent_at = @sent_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)

	alertCursorGet = tq("alert_cursors.get", `
		SELECT c.last_seq FROM alert_cursors c WHERE c.tenant_id = @tenant`)
	alertCursorSet = tq("alert_cursors.set", `
		INSERT INTO alert_cursors (tenant_id, last_seq, updated_at) VALUES (@tenant, @seq, @now)
		ON CONFLICT (tenant_id) DO UPDATE SET last_seq = excluded.last_seq, updated_at = excluded.updated_at`)

	auditFailedAnchors = tq("audit_checkpoints.failed_anchors", `
		SELECT count(c.id) FROM audit_checkpoints c WHERE c.tenant_id = @tenant AND c.anchor_status = 'failed'`)
)

// AlertRuleSettings lists the tenant's rule overrides.
func (tx *TenantTx) AlertRuleSettings() ([]*AlertRuleSetting, error) {
	return collect(tx, func(s scanner) (*AlertRuleSetting, error) {
		var r AlertRuleSetting
		var by sql.NullString
		var at nullTime
		if err := s.Scan(&r.RuleID, &r.Enabled, &r.Severity, &r.Threshold, &r.WindowMinutes, &by, &at); err != nil {
			return nil, err
		}
		r.UpdatedBy = strp(by)
		var err error
		r.UpdatedAt, err = at.val()
		return &r, err
	}, alertRuleSettingsList)
}

// PutAlertRuleSetting stores a rule override.
func (tx *TenantTx) PutAlertRuleSetting(r *AlertRuleSetting) error {
	_, err := tx.exec(alertRuleSettingsPut, sql.Named("rule_id", r.RuleID), sql.Named("enabled", B(r.Enabled)),
		sql.Named("severity", r.Severity), sql.Named("threshold", r.Threshold), sql.Named("window_minutes", r.WindowMinutes),
		sql.Named("updated_by", SP(r.UpdatedBy)), sql.Named("updated_at", T(r.UpdatedAt)))
	return err
}

func scanAlert(s scanner) (*Alert, error) {
	var a Alert
	var detail string
	var seq sql.NullInt64
	var assignee, ackBy, resBy, resolution sql.NullString
	var first, last, ackAt, resAt nullTime
	if err := s.Scan(&a.ID, &a.RuleID, &a.DedupKey, &a.Severity, &a.Title, &detail, &a.Status, &a.Count, &first, &last, &seq,
		&assignee, &ackBy, &ackAt, &resBy, &resAt, &resolution); err != nil {
		return nil, err
	}
	a.Detail = json.RawMessage(detail)
	a.LastEventSeq, a.AssigneeUserID, a.AcknowledgedBy, a.ResolvedBy, a.Resolution = intp(seq), strp(assignee), strp(ackBy),
		strp(resBy), strp(resolution)
	var err error
	if a.FirstSeenAt, err = first.val(); err != nil {
		return nil, err
	}
	if a.LastSeenAt, err = last.val(); err != nil {
		return nil, err
	}
	if a.AcknowledgedAt, err = ackAt.ptr(); err != nil {
		return nil, err
	}
	a.ResolvedAt, err = resAt.ptr()
	return &a, err
}

func detailText(d json.RawMessage) string {
	if len(d) == 0 {
		return "{}"
	}
	return string(d)
}

// Alerts lists alerts, newest activity first.
func (tx *TenantTx) Alerts(f AlertFilter) ([]*Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	return collect(tx, scanAlert, alertsList, sql.Named("status", f.Status), sql.Named("severity", f.Severity),
		sql.Named("rule", f.RuleID), sql.Named("limit", f.Limit))
}

// Alert returns one alert, or ErrNotFound.
func (tx *TenantTx) Alert(id string) (*Alert, error) {
	return one(tx, scanAlert, alertsGet, sql.Named("id", id))
}

// LiveAlert returns the open or acknowledged alert of a rule and key, or ErrNotFound.
func (tx *TenantTx) LiveAlert(ruleID, key string) (*Alert, error) {
	return one(tx, scanAlert, alertsLive, sql.Named("rule", ruleID), sql.Named("key", key))
}

// LiveAlertsOfRule lists a rule's open and acknowledged alerts.
func (tx *TenantTx) LiveAlertsOfRule(ruleID string) ([]*Alert, error) {
	return collect(tx, scanAlert, alertsLiveOfRule, sql.Named("rule", ruleID))
}

// AlertCounts counts live alerts by status and severity: counts[status][severity].
func (tx *TenantTx) AlertCounts() (map[string]map[string]int, error) {
	rows, err := tx.query(alertsCounts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var st, sev string
		var n int
		if err := rows.Scan(&st, &sev, &n); err != nil {
			return nil, err
		}
		if out[st] == nil {
			out[st] = map[string]int{}
		}
		out[st][sev] = n
	}
	return out, rows.Err()
}

// InsertAlert raises a new alert (status open).
func (tx *TenantTx) InsertAlert(a *Alert) error {
	_, err := tx.exec(alertsInsert, sql.Named("id", a.ID), sql.Named("rule_id", a.RuleID), sql.Named("dedup_key", a.DedupKey),
		sql.Named("severity", a.Severity), sql.Named("title", a.Title), sql.Named("detail", detailText(a.Detail)),
		sql.Named("count", a.Count), sql.Named("first_seen_at", T(a.FirstSeenAt)), sql.Named("last_seen_at", T(a.LastSeenAt)),
		sql.Named("last_event_seq", IP(a.LastEventSeq)))
	return err
}

// BumpAlert records n more occurrences of a live alert.
func (tx *TenantTx) BumpAlert(id string, n int, at time.Time, seq *int64, severity, title string, detail json.RawMessage) error {
	return tx.execOne(alertsBump, sql.Named("id", id), sql.Named("n", n), sql.Named("last_seen_at", T(at)),
		sql.Named("last_event_seq", IP(seq)), sql.Named("severity", severity), sql.Named("title", title),
		sql.Named("detail", detailText(detail)))
}

// SaveAlertState writes an alert's status, assignee, acknowledgement and resolution.
func (tx *TenantTx) SaveAlertState(a *Alert) error {
	return tx.execOne(alertsSaveState, sql.Named("id", a.ID), sql.Named("status", a.Status),
		sql.Named("assignee", SP(a.AssigneeUserID)), sql.Named("acknowledged_by", SP(a.AcknowledgedBy)),
		sql.Named("acknowledged_at", TP(a.AcknowledgedAt)), sql.Named("resolved_by", SP(a.ResolvedBy)),
		sql.Named("resolved_at", TP(a.ResolvedAt)), sql.Named("resolution", SP(a.Resolution)))
}

func scanChannel(s scanner) (*AlertChannel, error) {
	var c AlertChannel
	var by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&c.ID, &c.Name, &c.Kind, &c.Target, &c.SecretSealed, &c.MinSeverity, &c.Enabled, &by, &created,
		&updated); err != nil {
		return nil, err
	}
	c.CreatedBy = strp(by)
	var err error
	if c.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = updated.val()
	return &c, err
}

// AlertChannels lists the delivery channels.
func (tx *TenantTx) AlertChannels() ([]*AlertChannel, error) {
	return collect(tx, scanChannel, alertChannelsList)
}

// AlertChannel returns one channel, or ErrNotFound.
func (tx *TenantTx) AlertChannel(id string) (*AlertChannel, error) {
	return one(tx, scanChannel, alertChannelsGet, sql.Named("id", id))
}

// InsertAlertChannel adds a channel.
func (tx *TenantTx) InsertAlertChannel(c *AlertChannel) error {
	_, err := tx.exec(alertChannelsInsert, sql.Named("id", c.ID), sql.Named("name", c.Name), sql.Named("kind", c.Kind),
		sql.Named("target", c.Target), sql.Named("secret", c.SecretSealed), sql.Named("min_severity", c.MinSeverity),
		sql.Named("enabled", B(c.Enabled)), sql.Named("created_by", SP(c.CreatedBy)), sql.Named("created_at", T(c.CreatedAt)),
		sql.Named("updated_at", T(c.UpdatedAt)))
	return err
}

// UpdateAlertChannel replaces a channel's settings (its kind is fixed).
func (tx *TenantTx) UpdateAlertChannel(c *AlertChannel) error {
	return tx.execOne(alertChannelsUpdate, sql.Named("id", c.ID), sql.Named("name", c.Name), sql.Named("target", c.Target),
		sql.Named("secret", c.SecretSealed), sql.Named("min_severity", c.MinSeverity), sql.Named("enabled", B(c.Enabled)),
		sql.Named("updated_at", T(c.UpdatedAt)))
}

func scanDelivery(s scanner) (*AlertDelivery, error) {
	var d AlertDelivery
	var lastErr sql.NullString
	var next, sent, created nullTime
	if err := s.Scan(&d.ID, &d.AlertID, &d.ChannelID, &d.Reason, &d.Status, &d.Attempts, &next, &lastErr, &sent,
		&created); err != nil {
		return nil, err
	}
	d.LastError = strp(lastErr)
	var err error
	if d.NextAttemptAt, err = next.val(); err != nil {
		return nil, err
	}
	if d.SentAt, err = sent.ptr(); err != nil {
		return nil, err
	}
	d.CreatedAt, err = created.val()
	return &d, err
}

// InsertAlertDelivery queues a delivery (status pending).
func (tx *TenantTx) InsertAlertDelivery(d *AlertDelivery) error {
	_, err := tx.exec(alertDeliveriesInsert, sql.Named("id", d.ID), sql.Named("alert_id", d.AlertID),
		sql.Named("channel_id", d.ChannelID), sql.Named("reason", d.Reason), sql.Named("next_attempt_at", T(d.NextAttemptAt)),
		sql.Named("created_at", T(d.CreatedAt)))
	return err
}

// DueAlertDeliveries lists pending deliveries whose next attempt is due.
func (tx *TenantTx) DueAlertDeliveries(now time.Time, limit int) ([]*AlertDelivery, error) {
	return collect(tx, scanDelivery, alertDeliveriesDue, sql.Named("now", T(now)), sql.Named("limit", limit))
}

// AlertDeliveries lists an alert's deliveries.
func (tx *TenantTx) AlertDeliveries(alertID string) ([]*AlertDelivery, error) {
	return collect(tx, scanDelivery, alertDeliveriesOf, sql.Named("alert_id", alertID))
}

// AlertDelivery returns one delivery, or ErrNotFound.
func (tx *TenantTx) AlertDelivery(id string) (*AlertDelivery, error) {
	return one(tx, scanDelivery, alertDeliveriesGet, sql.Named("id", id))
}

// SaveAlertDelivery records an attempt on a pending delivery. It returns
// ErrNotFound when the delivery is no longer pending (another worker got it).
func (tx *TenantTx) SaveAlertDelivery(d *AlertDelivery) error {
	return tx.execOne(alertDeliveriesSave, sql.Named("id", d.ID), sql.Named("status", d.Status), sql.Named("attempts", d.Attempts),
		sql.Named("next_attempt_at", T(d.NextAttemptAt)), sql.Named("last_error", SP(d.LastError)),
		sql.Named("sent_at", TP(d.SentAt)))
}

// AlertCursor is the last audit seq the alert engine has read; ok is false
// before the engine first ran for the tenant.
func (tx *TenantTx) AlertCursor() (seq int64, ok bool, err error) {
	err = tx.queryRow(alertCursorGet).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return seq, err == nil, err
}

// SetAlertCursor moves the cursor.
func (tx *TenantTx) SetAlertCursor(seq int64, now time.Time) error {
	_, err := tx.exec(alertCursorSet, sql.Named("seq", seq), sql.Named("now", T(now)))
	return err
}

// FailedAuditAnchors counts the tenant's checkpoints whose anchoring failed.
func (tx *TenantTx) FailedAuditAnchors() (int, error) {
	var n int
	err := tx.queryRow(auditFailedAnchors).Scan(&n)
	return n, err
}
