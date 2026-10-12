package store

import (
	"database/sql"
	"time"
)

// Notifications (schema/0223_notifications.sql, issue #189): the per-tenant
// outbox and in-app inbox, and each user's preferences.

// Delivery states of a notification's email side.
const (
	DeliveryNone     = "none"     // no email wanted
	DeliveryPending  = "pending"  // to send (or to retry at NextAttemptAt)
	DeliveryDigest   = "digest"   // waits for the daily digest
	DeliveryDigested = "digested" // was included in a digest
	DeliverySent     = "sent"
	DeliverySkipped  = "skipped" // email is not configured, or no address
	DeliveryDead     = "dead"    // a dead letter
)

// Notification is one message to one recipient.
type Notification struct {
	ID            string
	UserID        *string // the platform user whose inbox shows it
	IdentityID    *int64  // an identity with no sign-in, reached by email
	Email         *string // the address at the time it was written
	Kind          string
	Subject       string
	Body          string
	Link          string // an app path such as /access/requests
	DedupeKey     string
	InApp         bool
	CreatedAt     time.Time
	ReadAt        *time.Time
	Delivery      string
	Attempts      int
	NextAttemptAt *time.Time
	LastError     *string
	SentAt        *time.Time
}

// NotificationPref is a user's channel for one kind (off, in_app, email, both, digest).
type NotificationPref struct {
	Kind      string
	Channel   string
	UpdatedAt time.Time
}

// UserRole is an active user's unexpired role assignment.
type UserRole struct {
	UserID string
	Role   string
}

// ReviewerLoad is a campaign reviewer's items and how many are still open.
type ReviewerLoad struct {
	ReviewerID int64
	Items      int
	Open       int
}

const notificationCols = `n.id, n.user_id, n.identity_id, n.recipient_email, n.kind, n.subject, n.body, n.link,
	n.dedupe_key, n.in_app, n.created_at, n.read_at, n.delivery, n.attempts, n.next_attempt_at, n.last_error, n.sent_at`

var (
	notificationsInsert = tq("notifications.insert", `
		INSERT INTO notifications (id, tenant_id, user_id, identity_id, recipient_email, kind, subject, body, link,
			dedupe_key, in_app, created_at, delivery, attempts, next_attempt_at)
		VALUES (@id, @tenant, @user_id, @identity_id, @email, @kind, @subject, @body, @link, @dedupe_key, @in_app,
			@created_at, @delivery, 0, @next_attempt_at)
		ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`)
	notificationsExists = tq("notifications.exists", `
		SELECT count(n.id) FROM notifications n WHERE n.tenant_id = @tenant AND n.dedupe_key = @dedupe_key`)
	notificationsInbox = tq("notifications.inbox", `
		SELECT `+notificationCols+` FROM notifications n WHERE n.tenant_id = @tenant AND n.user_id = @user AND n.in_app = 1
			AND (@unread = 0 OR n.read_at IS NULL) ORDER BY n.created_at DESC, n.id LIMIT @limit`)
	notificationsUnread = tq("notifications.count_unread", `
		SELECT count(n.id) FROM notifications n WHERE n.tenant_id = @tenant AND n.user_id = @user AND n.in_app = 1
			AND n.read_at IS NULL`)
	notificationsRead = tq("notifications.mark_read", `
		UPDATE notifications SET read_at = @at WHERE tenant_id = @tenant AND user_id = @user AND in_app = 1
			AND id = @id AND read_at IS NULL`)
	notificationsReadAll = tq("notifications.mark_all_read", `
		UPDATE notifications SET read_at = @at WHERE tenant_id = @tenant AND user_id = @user AND in_app = 1
			AND read_at IS NULL`)
	notificationsDue = tq("notifications.due", `
		SELECT `+notificationCols+` FROM notifications n WHERE n.tenant_id = @tenant AND n.delivery = 'pending'
			AND n.next_attempt_at <= @now ORDER BY n.next_attempt_at, n.id LIMIT @limit`)
	notificationsClaim = tq("notifications.claim", `
		UPDATE notifications SET attempts = attempts + 1, next_attempt_at = @lease
		WHERE tenant_id = @tenant AND id = @id AND delivery = 'pending' AND attempts = @attempts`)
	notificationsFinish = tq("notifications.finish", `
		UPDATE notifications SET delivery = @delivery, next_attempt_at = @next_attempt_at, last_error = @last_error,
			sent_at = @sent_at
		WHERE tenant_id = @tenant AND id = @id AND delivery = 'pending' AND attempts = @attempts`)
	notificationsDigestWaiting = tq("notifications.digest_waiting", `
		SELECT `+notificationCols+` FROM notifications n WHERE n.tenant_id = @tenant AND n.delivery = 'digest'
		ORDER BY n.recipient_email, n.user_id, n.created_at, n.id`)
	notificationsDigested = tq("notifications.mark_digested", `
		UPDATE notifications SET delivery = 'digested' WHERE tenant_id = @tenant AND id = @id AND delivery = 'digest'`)
	notificationsCountDelivery = tq("notifications.count_delivery", `
		SELECT count(n.id) FROM notifications n WHERE n.tenant_id = @tenant AND n.delivery = @delivery`)

	notificationPrefsList = tq("notification_prefs.list", `
		SELECT p.kind, p.channel, p.updated_at FROM notification_prefs p WHERE p.tenant_id = @tenant AND p.user_id = @user
		ORDER BY p.kind`)
	notificationPrefsPut = tq("notification_prefs.put", `
		INSERT INTO notification_prefs (tenant_id, user_id, kind, channel, updated_at)
		VALUES (@tenant, @user, @kind, @channel, @updated_at)
		ON CONFLICT (tenant_id, user_id, kind) DO UPDATE SET channel = excluded.channel, updated_at = excluded.updated_at`)

	userRolesActive = tq("role_assignments.active_user_roles", `
		SELECT u.id, r.role FROM platform_users u JOIN role_assignments r ON r.user_id = u.id AND r.tenant_id = @tenant
		WHERE u.tenant_id = @tenant AND u.status = 'active' AND (r.expires_at IS NULL OR r.expires_at > @now)
		ORDER BY u.id, r.role`)
	reviewerLoads = tq("review_items.reviewer_loads", `
		SELECT ri.reviewer_id, count(ri.id), sum(CASE WHEN ri.decision IS NULL THEN 1 ELSE 0 END) FROM review_items ri
		WHERE ri.tenant_id = @tenant AND ri.campaign_id = @campaign_id AND ri.reviewer_id IS NOT NULL
		GROUP BY ri.reviewer_id ORDER BY ri.reviewer_id`)
	jitExpiring = tq("access_requests.expiring", `
		SELECT `+requestCols+` FROM access_requests r WHERE r.tenant_id = @tenant AND r.status = 'approved'
			AND r.expires_at > @from AND r.expires_at <= @to ORDER BY r.id`)
	linesExpiring = tq("access_request_lines.expiring", `
		SELECT `+lineCols+` FROM access_request_lines l WHERE l.tenant_id = @tenant AND l.status = 'approved'
			AND l.expires_at > @from AND l.expires_at <= @to ORDER BY l.expires_at, l.id`)
)

func scanNotification(s scanner) (*Notification, error) {
	var n Notification
	var user, email, lastErr sql.NullString
	var ident sql.NullInt64
	var inApp int
	var created, read, next, sent nullTime
	if err := s.Scan(&n.ID, &user, &ident, &email, &n.Kind, &n.Subject, &n.Body, &n.Link, &n.DedupeKey, &inApp, &created,
		&read, &n.Delivery, &n.Attempts, &next, &lastErr, &sent); err != nil {
		return nil, err
	}
	n.UserID, n.IdentityID, n.Email, n.LastError, n.InApp = strp(user), intp(ident), strp(email), strp(lastErr), inApp != 0
	var err error
	if n.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if n.ReadAt, err = read.ptr(); err != nil {
		return nil, err
	}
	if n.NextAttemptAt, err = next.ptr(); err != nil {
		return nil, err
	}
	n.SentAt, err = sent.ptr()
	return &n, err
}

// InsertNotification writes a notification unless one with the same
// DedupeKey exists (idempotency); it reports whether it wrote one. A
// notification with email to send starts due at NextAttemptAt.
func (tx *TenantTx) InsertNotification(n *Notification) (bool, error) {
	res, err := tx.exec(notificationsInsert, sql.Named("id", n.ID), sql.Named("user_id", SP(n.UserID)),
		sql.Named("identity_id", IP(n.IdentityID)), sql.Named("email", SP(n.Email)), sql.Named("kind", n.Kind),
		sql.Named("subject", n.Subject), sql.Named("body", n.Body), sql.Named("link", n.Link),
		sql.Named("dedupe_key", n.DedupeKey), sql.Named("in_app", B(n.InApp)), sql.Named("created_at", T(n.CreatedAt)),
		sql.Named("delivery", n.Delivery), sql.Named("next_attempt_at", TP(n.NextAttemptAt)))
	if err != nil {
		return false, err
	}
	c, err := res.RowsAffected()
	return c > 0, err
}

// HasNotification reports whether a notification with this dedupe key exists.
func (tx *TenantTx) HasNotification(dedupeKey string) (bool, error) {
	n, err := tx.count(notificationsExists, sql.Named("dedupe_key", dedupeKey))
	return n > 0, err
}

// Notifications returns a user's inbox, newest first.
func (tx *TenantTx) Notifications(user string, unreadOnly bool, limit int) ([]*Notification, error) {
	if limit <= 0 {
		limit = -1
	}
	return collect(tx, scanNotification, notificationsInbox, sql.Named("user", user), sql.Named("unread", B(unreadOnly)),
		sql.Named("limit", limit))
}

// CountUnreadNotifications counts a user's unread inbox entries.
func (tx *TenantTx) CountUnreadNotifications(user string) (int, error) {
	return tx.count(notificationsUnread, sql.Named("user", user))
}

// MarkNotificationsRead marks the user's own unread entries among ids read
// and returns how many it changed; other users' ids are ignored.
func (tx *TenantTx) MarkNotificationsRead(user string, ids []string, at time.Time) (int, error) {
	changed := 0
	for _, id := range ids {
		res, err := tx.exec(notificationsRead, sql.Named("user", user), sql.Named("id", id), sql.Named("at", T(at)))
		if err != nil {
			return changed, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return changed, err
		}
		changed += int(n)
	}
	return changed, nil
}

// MarkAllNotificationsRead marks every unread entry of the user read.
func (tx *TenantTx) MarkAllNotificationsRead(user string, at time.Time) (int, error) {
	res, err := tx.exec(notificationsReadAll, sql.Named("user", user), sql.Named("at", T(at)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DueNotifications returns up to limit notifications whose email is due at now.
func (tx *TenantTx) DueNotifications(now time.Time, limit int) ([]*Notification, error) {
	return collect(tx, scanNotification, notificationsDue, sql.Named("now", T(now)), sql.Named("limit", limit))
}

// ClaimNotification takes a due notification for one send attempt: it counts
// the attempt and pushes next_attempt_at to lease, so a crash retries after
// the lease and a second dispatcher does not send it too. attempts is the
// count the caller read; ErrNotFound if it changed or the row is no longer pending.
func (tx *TenantTx) ClaimNotification(id string, attempts int, lease time.Time) error {
	return affected(tx.exec(notificationsClaim, sql.Named("id", id), sql.Named("attempts", attempts), sql.Named("lease", T(lease))))
}

// FinishNotification records the outcome of attempt number attempts (the
// count after the claim): delivery sent, skipped, dead, or pending with the
// next retry time. ErrNotFound if it is no longer that attempt.
func (tx *TenantTx) FinishNotification(id string, attempts int, delivery string, next *time.Time, lastErr *string,
	sent *time.Time) error {
	return affected(tx.exec(notificationsFinish, sql.Named("id", id), sql.Named("attempts", attempts),
		sql.Named("delivery", delivery), sql.Named("next_attempt_at", TP(next)), sql.Named("last_error", SP(lastErr)),
		sql.Named("sent_at", TP(sent))))
}

// DigestWaiting returns the notifications waiting for the daily digest,
// grouped by recipient.
func (tx *TenantTx) DigestWaiting() ([]*Notification, error) {
	return collect(tx, scanNotification, notificationsDigestWaiting)
}

// MarkDigested moves a waiting notification to digested.
func (tx *TenantTx) MarkDigested(id string) error {
	return affected(tx.exec(notificationsDigested, sql.Named("id", id)))
}

// CountNotificationsDelivery counts notifications in a delivery state (for
// example dead letters).
func (tx *TenantTx) CountNotificationsDelivery(delivery string) (int, error) {
	return tx.count(notificationsCountDelivery, sql.Named("delivery", delivery))
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// NotificationPrefs returns a user's saved channels, by kind.
func (tx *TenantTx) NotificationPrefs(user string) ([]*NotificationPref, error) {
	return collect(tx, func(s scanner) (*NotificationPref, error) {
		var p NotificationPref
		var at nullTime
		if err := s.Scan(&p.Kind, &p.Channel, &at); err != nil {
			return nil, err
		}
		var err error
		p.UpdatedAt, err = at.val()
		return &p, err
	}, notificationPrefsList, sql.Named("user", user))
}

// PutNotificationPref sets a user's channel for a kind.
func (tx *TenantTx) PutNotificationPref(user, kind, channel string, at time.Time) error {
	_, err := tx.exec(notificationPrefsPut, sql.Named("user", user), sql.Named("kind", kind), sql.Named("channel", channel),
		sql.Named("updated_at", T(at)))
	return err
}

// ActiveUserRoles lists the roles of every active user, expired assignments left out.
func (tx *TenantTx) ActiveUserRoles(now time.Time) ([]UserRole, error) {
	rows, err := tx.query(userRolesActive, sql.Named("now", RT(now)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []UserRole
	for rows.Next() {
		var u UserRole
		if err := rows.Scan(&u.UserID, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ReviewerLoads lists each reviewer of a campaign with their item counts.
func (tx *TenantTx) ReviewerLoads(campaignID int64) ([]ReviewerLoad, error) {
	rows, err := tx.query(reviewerLoads, sql.Named("campaign_id", campaignID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ReviewerLoad
	for rows.Next() {
		var l ReviewerLoad
		if err := rows.Scan(&l.ReviewerID, &l.Items, &l.Open); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// JITExpiringBetween returns approved JIT requests whose access ends after from and by to.
func (tx *TenantTx) JITExpiringBetween(from, to time.Time) ([]*AccessRequest, error) {
	return collect(tx, scanRequest, jitExpiring, sql.Named("from", T(from)), sql.Named("to", T(to)))
}

// RequestLinesExpiringBetween returns approved request lines whose access ends after from and by to.
func (tx *TenantTx) RequestLinesExpiringBetween(from, to time.Time) ([]*RequestLine, error) {
	return collect(tx, scanLine, linesExpiring, sql.Named("from", T(from)), sql.Named("to", T(to)))
}
