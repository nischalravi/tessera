package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// The email delivery log (schema/0224_email_messages.sql, issue #189).

// Email message statuses. EmailBounced is reserved for bounce processing.
const (
	EmailQueued   = "queued"
	EmailSending  = "sending"
	EmailAccepted = "accepted" // accepted by the relay, not delivered to the inbox
	EmailDeferred = "deferred" // 4xx: retried with backoff
	EmailRejected = "rejected" // 5xx: not retried
	EmailFailed   = "failed"   // network or TLS error: retried with backoff
	EmailBounced  = "bounced"
)

// EmailMessage is one email and what happened to it.
type EmailMessage struct {
	ID             string
	NotificationID string
	Kind           string
	Recipient      string
	Subject        string
	MailFrom       *string
	RcptTo         *string
	Status         string
	QueueID        *string
	AttemptCount   int
	Attempts       json.RawMessage // a JSON array of attempts
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EmailFilter selects messages; zero fields match everything.
type EmailFilter struct {
	Status    string
	Kind      string
	Recipient string // a case-insensitive part of the address
	Limit     int
}

const emailCols = `m.id, m.notification_id, m.kind, m.recipient, m.subject, m.mail_from, m.rcpt_to, m.status, m.queue_id,
	m.attempt_count, m.attempts, m.created_at, m.updated_at`

var (
	emailInsert = tq("email_messages.insert", `
		INSERT INTO email_messages (id, tenant_id, notification_id, kind, recipient, subject, status, attempts, created_at, updated_at)
		VALUES (@id, @tenant, @notification_id, @kind, @recipient, @subject, 'queued', '[]', @at, @at)
		ON CONFLICT (tenant_id, notification_id) DO NOTHING`)
	emailList = tq("email_messages.list", `
		SELECT `+emailCols+` FROM email_messages m WHERE m.tenant_id = @tenant
			AND (@status = '' OR m.status = @status) AND (@kind = '' OR m.kind = @kind)
			AND (@recipient = '' OR instr(lower(m.recipient), lower(@recipient)) > 0)
		ORDER BY m.updated_at DESC, m.id LIMIT @limit`)
	emailGet = tq("email_messages.get", `
		SELECT `+emailCols+` FROM email_messages m WHERE m.tenant_id = @tenant AND m.id = @id`)
	emailByNotification = tq("email_messages.by_notification", `
		SELECT `+emailCols+` FROM email_messages m WHERE m.tenant_id = @tenant AND m.notification_id = @notification_id`)
	emailSave = tq("email_messages.save", `
		UPDATE email_messages SET status = @status, mail_from = @mail_from, rcpt_to = @rcpt_to, queue_id = @queue_id,
			attempt_count = @attempt_count, attempts = @attempts, updated_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	notificationsRequeue = tq("notifications.requeue", `
		UPDATE notifications SET delivery = 'pending', next_attempt_at = @at, last_error = NULL
		WHERE tenant_id = @tenant AND id = @id AND delivery IN ('pending','dead')`)
)

func scanEmail(s scanner) (*EmailMessage, error) {
	var m EmailMessage
	var from, rcpt, queue sql.NullString
	var attempts string
	var created, updated nullTime
	if err := s.Scan(&m.ID, &m.NotificationID, &m.Kind, &m.Recipient, &m.Subject, &from, &rcpt, &m.Status, &queue,
		&m.AttemptCount, &attempts, &created, &updated); err != nil {
		return nil, err
	}
	m.MailFrom, m.RcptTo, m.QueueID, m.Attempts = strp(from), strp(rcpt), strp(queue), json.RawMessage(attempts)
	var err error
	if m.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	m.UpdatedAt, err = updated.val()
	return &m, err
}

// EnsureEmailMessage creates the message record of a notification (queued)
// unless it exists.
func (tx *TenantTx) EnsureEmailMessage(m *EmailMessage) error {
	_, err := tx.exec(emailInsert, sql.Named("id", m.ID), sql.Named("notification_id", m.NotificationID),
		sql.Named("kind", m.Kind), sql.Named("recipient", m.Recipient), sql.Named("subject", m.Subject),
		sql.Named("at", T(m.CreatedAt)))
	return err
}

// EmailMessages lists messages, most recently updated first.
func (tx *TenantTx) EmailMessages(f EmailFilter) ([]*EmailMessage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = -1
	}
	return collect(tx, scanEmail, emailList, sql.Named("status", f.Status), sql.Named("kind", f.Kind),
		sql.Named("recipient", f.Recipient), sql.Named("limit", limit))
}

// EmailMessage returns one message, or ErrNotFound.
func (tx *TenantTx) EmailMessage(id string) (*EmailMessage, error) {
	return one(tx, scanEmail, emailGet, sql.Named("id", id))
}

// EmailMessageForNotification returns a notification's message, or ErrNotFound.
func (tx *TenantTx) EmailMessageForNotification(notificationID string) (*EmailMessage, error) {
	return one(tx, scanEmail, emailByNotification, sql.Named("notification_id", notificationID))
}

// SaveEmailMessage writes a message's status, envelope, queue id and attempts.
func (tx *TenantTx) SaveEmailMessage(m *EmailMessage) error {
	attempts := string(m.Attempts)
	if attempts == "" {
		attempts = "[]"
	}
	return affected(tx.exec(emailSave, sql.Named("id", m.ID), sql.Named("status", m.Status), sql.Named("mail_from", SP(m.MailFrom)),
		sql.Named("rcpt_to", SP(m.RcptTo)), sql.Named("queue_id", SP(m.QueueID)), sql.Named("attempt_count", m.AttemptCount),
		sql.Named("attempts", attempts), sql.Named("at", T(m.UpdatedAt))))
}

// RequeueNotification makes a pending or dead-lettered notification due at
// at (a manual retry); ErrNotFound if it is neither.
func (tx *TenantTx) RequeueNotification(id string, at time.Time) error {
	return affected(tx.exec(notificationsRequeue, sql.Named("id", id), sql.Named("at", T(at))))
}
