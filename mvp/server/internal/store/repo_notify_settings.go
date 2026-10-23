package store

import (
	"database/sql"
	"errors"
	"time"
)

// Tenant notification settings (schema 0760 to 0764): the tenant's own SMTP relay, its chat webhook, the wording of
// notification emails, reminder and escalation timings, and the addresses email is no longer sent to. Secrets
// (relay password, webhook URL) are stored sealed by the caller; nothing here opens them.

// MailRelayRow is the tenant's SMTP relay.
type MailRelayRow struct {
	Enabled        bool
	Host           string
	Port           int
	TLS            string
	Username       string
	PasswordSealed []byte // nil: no password
	From           string
	LastTestAt     *time.Time
	LastTestResult string
	Version        int
	UpdatedBy      string
	UpdatedAt      time.Time
}

// ChatWebhookRow is the tenant's chat webhook.
type ChatWebhookRow struct {
	Provider      string // slack | teams
	Enabled       bool
	WebhookSealed []byte
	WebhookHost   string
	Kinds         string // JSON list
	CursorAt      string // opaque: the created_at (store format) of the last notification looked at
	CursorID      string
	CursorKey     string // the event last posted
	FailCount     int
	LastError     string
	LastPostAt    *time.Time
	Version       int
	UpdatedBy     string
	UpdatedAt     time.Time
}

// NotificationTemplateRow is a tenant's wording for one kind.
type NotificationTemplateRow struct {
	Kind      string
	Subject   string
	Body      string
	UpdatedBy string
	UpdatedAt time.Time
}

// NotificationPolicyRow is a tenant's reminder cadence and escalation timings.
type NotificationPolicyRow struct {
	ReviewRemindAfterDays int
	ReviewRemindEveryDays int
	RequestWarnHours      int
	JITWarnMinutes        int
	EscalateAfterHours    int
	Version               int
	UpdatedBy             string
	UpdatedAt             time.Time
}

// EmailSuppressionRow is an address email is not sent to.
type EmailSuppressionRow struct {
	Address   string
	Reason    string // hard_bounce | manual
	Note      string
	MessageID string
	CreatedBy string
	CreatedAt time.Time
}

const (
	SuppressHardBounce = "hard_bounce"
	SuppressManual     = "manual"
)

var (
	mailRelayGet = tq("tenant_mail_relay.get", `
		SELECT r.enabled, r.host, r.port, r.tls, r.username, r.password_sealed, r.from_address, r.last_test_at, r.last_test_outcome,
			r.version, r.updated_by, r.updated_at
		FROM tenant_mail_relay r WHERE r.tenant_id = @tenant`)
	mailRelayPut = tq("tenant_mail_relay.put", `
		INSERT INTO tenant_mail_relay (tenant_id, enabled, host, port, tls, username, password_sealed, from_address, version,
			updated_by, updated_at)
		VALUES (@tenant, @enabled, @host, @port, @tls, @username, @password_sealed, @from_address, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, host = excluded.host, port = excluded.port,
			tls = excluded.tls, username = excluded.username, password_sealed = excluded.password_sealed,
			from_address = excluded.from_address, version = tenant_mail_relay.version + 1, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
	mailRelayDelete = tq("tenant_mail_relay.delete", `DELETE FROM tenant_mail_relay WHERE tenant_id = @tenant`)
	mailRelayTest   = tq("tenant_mail_relay.test_result", `
		UPDATE tenant_mail_relay SET last_test_at = @at, last_test_outcome = @outcome WHERE tenant_id = @tenant`)

	chatWebhookGet = tq("tenant_chat_webhook.get", `
		SELECT c.provider, c.enabled, c.webhook_sealed, c.webhook_host, c.kinds, c.cursor_at, c.cursor_id, c.cursor_key,
			c.fail_count, c.last_error, c.last_post_at, c.version, c.updated_by, c.updated_at
		FROM tenant_chat_webhook c WHERE c.tenant_id = @tenant`)
	chatWebhookPut = tq("tenant_chat_webhook.put", `
		INSERT INTO tenant_chat_webhook (tenant_id, provider, enabled, webhook_sealed, webhook_host, kinds, cursor_at, cursor_id,
			cursor_key, fail_count, last_error, version, updated_by, updated_at)
		VALUES (@tenant, @provider, @enabled, @webhook_sealed, @webhook_host, @kinds, @cursor_at, '', '', 0, '', 1, @updated_by,
			@updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET provider = excluded.provider, enabled = excluded.enabled,
			webhook_sealed = excluded.webhook_sealed, webhook_host = excluded.webhook_host, kinds = excluded.kinds,
			cursor_at = CASE WHEN tenant_chat_webhook.enabled = 0 AND excluded.enabled = 1 THEN excluded.cursor_at
				ELSE tenant_chat_webhook.cursor_at END,
			cursor_id = CASE WHEN tenant_chat_webhook.enabled = 0 AND excluded.enabled = 1 THEN '' ELSE tenant_chat_webhook.cursor_id END,
			cursor_key = CASE WHEN tenant_chat_webhook.enabled = 0 AND excluded.enabled = 1 THEN '' ELSE tenant_chat_webhook.cursor_key END,
			fail_count = 0, last_error = '', version = tenant_chat_webhook.version + 1, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
	chatWebhookDelete   = tq("tenant_chat_webhook.delete", `DELETE FROM tenant_chat_webhook WHERE tenant_id = @tenant`)
	chatWebhookProgress = tq("tenant_chat_webhook.progress", `
		UPDATE tenant_chat_webhook SET cursor_at = @cursor_at, cursor_id = @cursor_id, cursor_key = @cursor_key,
			fail_count = @fail_count, last_error = @last_error, last_post_at = COALESCE(@last_post_at, last_post_at)
		WHERE tenant_id = @tenant`)
	notificationsAfter = tq("notifications.after_cursor", `
		SELECT `+notificationCols+` FROM notifications n WHERE n.tenant_id = @tenant
			AND (n.created_at > @at OR (n.created_at = @at AND n.id > @id)) AND n.created_at <= @until
		ORDER BY n.created_at, n.id LIMIT @limit`)

	notifTemplatesList = tq("notification_templates.list", `
		SELECT t.kind, t.subject_tpl, t.body_tpl, t.updated_by, t.updated_at FROM notification_templates t
		WHERE t.tenant_id = @tenant ORDER BY t.kind`)
	notifTemplatesPut = tq("notification_templates.put", `
		INSERT INTO notification_templates (tenant_id, kind, subject_tpl, body_tpl, updated_by, updated_at)
		VALUES (@tenant, @kind, @subject_tpl, @body_tpl, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, kind) DO UPDATE SET subject_tpl = excluded.subject_tpl, body_tpl = excluded.body_tpl,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	notifTemplatesDelete = tq("notification_templates.delete", `
		DELETE FROM notification_templates WHERE tenant_id = @tenant AND kind = @kind`)

	notifPolicyGet = tq("notification_policy.get", `
		SELECT p.review_remind_after_days, p.review_remind_every_days, p.request_warn_hours, p.jit_warn_minutes,
			p.escalate_after_hours, p.version, p.updated_by, p.updated_at
		FROM notification_policy p WHERE p.tenant_id = @tenant`)
	notifPolicyPut = tq("notification_policy.put", `
		INSERT INTO notification_policy (tenant_id, review_remind_after_days, review_remind_every_days, request_warn_hours,
			jit_warn_minutes, escalate_after_hours, version, updated_by, updated_at)
		VALUES (@tenant, @after, @every, @request_warn, @jit_warn, @escalate, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET review_remind_after_days = excluded.review_remind_after_days,
			review_remind_every_days = excluded.review_remind_every_days, request_warn_hours = excluded.request_warn_hours,
			jit_warn_minutes = excluded.jit_warn_minutes, escalate_after_hours = excluded.escalate_after_hours,
			version = notification_policy.version + 1, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)

	emailSuppressionsList = tq("email_suppressions.list", `
		SELECT s.address, s.reason, s.note, s.message_id, s.created_by, s.created_at FROM email_suppressions s
		WHERE s.tenant_id = @tenant ORDER BY s.created_at DESC, s.address`)
	emailSuppressionsGet = tq("email_suppressions.get", `
		SELECT s.address, s.reason, s.note, s.message_id, s.created_by, s.created_at FROM email_suppressions s
		WHERE s.tenant_id = @tenant AND s.address = @address`)
	emailSuppressionsPut = tq("email_suppressions.put", `
		INSERT INTO email_suppressions (tenant_id, address, reason, note, message_id, created_by, created_at)
		VALUES (@tenant, @address, @reason, @note, @message_id, @created_by, @created_at)
		ON CONFLICT (tenant_id, address) DO NOTHING`)
	emailSuppressionsDelete = tq("email_suppressions.delete", `
		DELETE FROM email_suppressions WHERE tenant_id = @tenant AND address = @address`)
	notificationDeliveryOf = tq("notifications.delivery_of", `
		SELECT n.delivery FROM notifications n WHERE n.tenant_id = @tenant AND n.id = @id`)
	emailByQueueID = tq("email_messages.by_queue_id", `
		SELECT `+emailCols+` FROM email_messages m WHERE m.tenant_id = @tenant AND m.queue_id = @queue_id
		ORDER BY m.updated_at DESC LIMIT 1`)
)

// MailRelay returns the tenant's relay; ErrNotFound if it has none.
func (tx *TenantTx) MailRelay() (*MailRelayRow, error) {
	return one(tx, func(s scanner) (*MailRelayRow, error) {
		var r MailRelayRow
		var en int
		var sealed []byte
		var testAt nullTime
		var at string
		if err := s.Scan(&en, &r.Host, &r.Port, &r.TLS, &r.Username, &sealed, &r.From, &testAt, &r.LastTestResult, &r.Version,
			&r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		r.Enabled, r.PasswordSealed = en == 1, sealed
		var err error
		if r.LastTestAt, err = testAt.ptr(); err != nil {
			return nil, err
		}
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, mailRelayGet)
}

// PutMailRelay replaces the tenant's relay and moves the version on. PasswordSealed is stored as given.
func (tx *TenantTx) PutMailRelay(r *MailRelayRow, now time.Time) error {
	var sealed any
	if len(r.PasswordSealed) > 0 {
		sealed = r.PasswordSealed
	}
	_, err := tx.exec(mailRelayPut, sql.Named("enabled", B(r.Enabled)), sql.Named("host", r.Host), sql.Named("port", r.Port),
		sql.Named("tls", r.TLS), sql.Named("username", r.Username), sql.Named("password_sealed", sealed),
		sql.Named("from_address", r.From), sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// DeleteMailRelay removes the tenant's relay (ErrNotFound if there is none).
func (tx *TenantTx) DeleteMailRelay() error { return affected(tx.exec(mailRelayDelete)) }

// SetMailRelayTest records the outcome of the last test message (no credential ever).
func (tx *TenantTx) SetMailRelayTest(at time.Time, outcome string) error {
	return affected(tx.exec(mailRelayTest, sql.Named("at", T(at)), sql.Named("outcome", outcome)))
}

// ChatWebhook returns the tenant's chat webhook; ErrNotFound if it has none.
func (tx *TenantTx) ChatWebhook() (*ChatWebhookRow, error) {
	return one(tx, func(s scanner) (*ChatWebhookRow, error) {
		var c ChatWebhookRow
		var en int
		var post nullTime
		var at string
		if err := s.Scan(&c.Provider, &en, &c.WebhookSealed, &c.WebhookHost, &c.Kinds, &c.CursorAt, &c.CursorID, &c.CursorKey,
			&c.FailCount, &c.LastError, &post, &c.Version, &c.UpdatedBy, &at); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		var err error
		if c.LastPostAt, err = post.ptr(); err != nil {
			return nil, err
		}
		c.UpdatedAt, err = ParseRT(at)
		return &c, err
	}, chatWebhookGet)
}

// PutChatWebhook replaces the tenant's chat webhook and moves the version on. Turning it on starts the cursor at now, so
// history is not replayed.
func (tx *TenantTx) PutChatWebhook(c *ChatWebhookRow, now time.Time) error {
	_, err := tx.exec(chatWebhookPut, sql.Named("provider", c.Provider), sql.Named("enabled", B(c.Enabled)),
		sql.Named("webhook_sealed", c.WebhookSealed), sql.Named("webhook_host", c.WebhookHost), sql.Named("kinds", c.Kinds),
		sql.Named("cursor_at", T(now)), sql.Named("updated_by", c.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// DeleteChatWebhook removes the tenant's chat webhook (ErrNotFound if there is none).
func (tx *TenantTx) DeleteChatWebhook() error { return affected(tx.exec(chatWebhookDelete)) }

// SetChatProgress moves the posting cursor and records the retry state.
func (tx *TenantTx) SetChatProgress(c *ChatWebhookRow) error {
	var post any
	if c.LastPostAt != nil {
		post = T(*c.LastPostAt)
	}
	return affected(tx.exec(chatWebhookProgress, sql.Named("cursor_at", c.CursorAt), sql.Named("cursor_id", c.CursorID),
		sql.Named("cursor_key", c.CursorKey), sql.Named("fail_count", c.FailCount), sql.Named("last_error", c.LastError),
		sql.Named("last_post_at", post)))
}

// NotificationsAfter lists notifications created after the cursor (at, id) and no later than until, oldest first. The caller
// keeps until a little behind the clock, so a row written at the cursor's own instant by a transaction that was still open
// is not passed over.
func (tx *TenantTx) NotificationsAfter(at, id string, until time.Time, limit int) ([]*Notification, error) {
	return collect(tx, scanNotification, notificationsAfter, sql.Named("at", at), sql.Named("id", id), sql.Named("until", T(until)),
		sql.Named("limit", limit))
}

// NotificationTemplates lists the tenant's wording, by kind.
func (tx *TenantTx) NotificationTemplates() ([]*NotificationTemplateRow, error) {
	return collect(tx, func(s scanner) (*NotificationTemplateRow, error) {
		var t NotificationTemplateRow
		var at string
		if err := s.Scan(&t.Kind, &t.Subject, &t.Body, &t.UpdatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		t.UpdatedAt, err = ParseRT(at)
		return &t, err
	}, notifTemplatesList)
}

// PutNotificationTemplate saves the wording of one kind.
func (tx *TenantTx) PutNotificationTemplate(t *NotificationTemplateRow, now time.Time) error {
	_, err := tx.exec(notifTemplatesPut, sql.Named("kind", t.Kind), sql.Named("subject_tpl", t.Subject), sql.Named("body_tpl", t.Body),
		sql.Named("updated_by", t.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// DeleteNotificationTemplate returns a kind to the producer's wording (ErrNotFound if it had none).
func (tx *TenantTx) DeleteNotificationTemplate(kind string) error {
	return affected(tx.exec(notifTemplatesDelete, sql.Named("kind", kind)))
}

// NotificationPolicy returns the tenant's timings; ErrNotFound if it never saved any.
func (tx *TenantTx) NotificationPolicy() (*NotificationPolicyRow, error) {
	return one(tx, func(s scanner) (*NotificationPolicyRow, error) {
		var p NotificationPolicyRow
		var at string
		if err := s.Scan(&p.ReviewRemindAfterDays, &p.ReviewRemindEveryDays, &p.RequestWarnHours, &p.JITWarnMinutes,
			&p.EscalateAfterHours, &p.Version, &p.UpdatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		p.UpdatedAt, err = ParseRT(at)
		return &p, err
	}, notifPolicyGet)
}

// PutNotificationPolicy replaces the tenant's timings and moves the version on.
func (tx *TenantTx) PutNotificationPolicy(p *NotificationPolicyRow, now time.Time) error {
	_, err := tx.exec(notifPolicyPut, sql.Named("after", p.ReviewRemindAfterDays), sql.Named("every", p.ReviewRemindEveryDays),
		sql.Named("request_warn", p.RequestWarnHours), sql.Named("jit_warn", p.JITWarnMinutes),
		sql.Named("escalate", p.EscalateAfterHours), sql.Named("updated_by", p.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

func scanSuppression(s scanner) (*EmailSuppressionRow, error) {
	var r EmailSuppressionRow
	var at string
	if err := s.Scan(&r.Address, &r.Reason, &r.Note, &r.MessageID, &r.CreatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	r.CreatedAt, err = ParseRT(at)
	return &r, err
}

// EmailSuppressions lists the suppressed addresses, newest first.
func (tx *TenantTx) EmailSuppressions() ([]*EmailSuppressionRow, error) {
	return collect(tx, scanSuppression, emailSuppressionsList)
}

// EmailSuppression returns one suppressed address (lower case), or ErrNotFound.
func (tx *TenantTx) EmailSuppression(address string) (*EmailSuppressionRow, error) {
	return one(tx, scanSuppression, emailSuppressionsGet, sql.Named("address", address))
}

// PutEmailSuppression suppresses an address; it reports whether it was new (an address already suppressed keeps its
// first reason).
func (tx *TenantTx) PutEmailSuppression(r *EmailSuppressionRow, now time.Time) (bool, error) {
	res, err := tx.exec(emailSuppressionsPut, sql.Named("address", r.Address), sql.Named("reason", r.Reason), sql.Named("note", r.Note),
		sql.Named("message_id", r.MessageID), sql.Named("created_by", r.CreatedBy), sql.Named("created_at", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteEmailSuppression lifts a suppression (ErrNotFound if the address was not suppressed).
func (tx *TenantTx) DeleteEmailSuppression(address string) error {
	return affected(tx.exec(emailSuppressionsDelete, sql.Named("address", address)))
}

// EmailMessageByQueueID returns the newest message the relay gave this queue id, or ErrNotFound.
func (tx *TenantTx) EmailMessageByQueueID(queueID string) (*EmailMessage, error) {
	return one(tx, scanEmail, emailByQueueID, sql.Named("queue_id", queueID))
}

// NotificationDeliveryOf returns the email delivery state of one notification, or ErrNotFound.
func (tx *TenantTx) NotificationDeliveryOf(id string) (string, error) {
	var d string
	if err := tx.queryRow(notificationDeliveryOf, sql.Named("id", id)).Scan(&d); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	return d, nil
}
