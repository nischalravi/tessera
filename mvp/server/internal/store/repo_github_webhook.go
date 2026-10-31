package store

import (
	"database/sql"
	"errors"
	"time"
)

// The GitHub webhook secret and the deliveries handled (schema/0963_github_webhook.sql, issue #771). Every statement
// binds the tenant.

// GitHubWebhookSecret is a tenant's sealed webhook secret. SecretEnc is never returned by the API.
type GitHubWebhookSecret struct {
	SecretEnc []byte
	SetAt     time.Time
	SetBy     string
}

var (
	ghHookSecretGet = tq("github_webhook_secrets.get", `
		SELECT s.secret_enc, s.set_at, s.set_by FROM github_webhook_secrets s WHERE s.tenant_id = @tenant`)
	ghHookSecretPut = tq("github_webhook_secrets.put", `
		INSERT INTO github_webhook_secrets (tenant_id, secret_enc, set_at, set_by) VALUES (@tenant, @secret_enc, @set_at, @set_by)
		ON CONFLICT (tenant_id) DO UPDATE SET secret_enc = excluded.secret_enc, set_at = excluded.set_at, set_by = excluded.set_by`)
	ghHookSecretDel = tq("github_webhook_secrets.delete", `
		DELETE FROM github_webhook_secrets WHERE tenant_id = @tenant`)
	ghHookDelivPrune = tq("github_webhook_deliveries.prune", `
		DELETE FROM github_webhook_deliveries WHERE tenant_id = @tenant AND expires_at <= @now`)
	ghHookDelivIns = tq("github_webhook_deliveries.insert", `
		INSERT INTO github_webhook_deliveries (tenant_id, delivery_id, expires_at) VALUES (@tenant, @delivery_id, @until)
		ON CONFLICT (tenant_id, delivery_id) DO NOTHING`)
	ghHookDelivDel = tq("github_webhook_deliveries.delete", `
		DELETE FROM github_webhook_deliveries WHERE tenant_id = @tenant AND delivery_id = @delivery_id`)
)

// GitHubWebhookSecret returns the tenant's sealed secret, or nil when it has none.
func (tx *TenantTx) GitHubWebhookSecret() (*GitHubWebhookSecret, error) {
	s, err := one(tx, func(r scanner) (*GitHubWebhookSecret, error) {
		var s GitHubWebhookSecret
		var at string
		if err := r.Scan(&s.SecretEnc, &at, &s.SetBy); err != nil {
			return nil, err
		}
		var err error
		s.SetAt, err = ParseRT(at)
		return &s, err
	}, ghHookSecretGet)
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return s, err
}

// PutGitHubWebhookSecret replaces the tenant's sealed secret.
func (tx *TenantTx) PutGitHubWebhookSecret(enc []byte, by string, now time.Time) error {
	_, err := tx.exec(ghHookSecretPut, sql.Named("secret_enc", enc), sql.Named("set_at", RT(now)), sql.Named("set_by", by))
	return err
}

// DeleteGitHubWebhookSecret removes the tenant's secret; the receiver then refuses every delivery.
func (tx *TenantTx) DeleteGitHubWebhookSecret() error {
	_, err := tx.exec(ghHookSecretDel)
	return err
}

// RecordGitHubDelivery records an X-GitHub-Delivery id until `until`, and reports false when it was already recorded and
// has not expired (a replay). The insert is atomic, so two concurrent copies cannot both get true. Expired rows are
// pruned first.
func (tx *TenantTx) RecordGitHubDelivery(id string, until, now time.Time) (bool, error) {
	if _, err := tx.exec(ghHookDelivPrune, sql.Named("now", RT(now))); err != nil {
		return false, err
	}
	res, err := tx.exec(ghHookDelivIns, sql.Named("delivery_id", id), sql.Named("until", RT(until)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ForgetGitHubDelivery drops a delivery id so GitHub's redelivery of it is handled (a delivery that could not be
// processed for a reason that may pass).
func (tx *TenantTx) ForgetGitHubDelivery(id string) error {
	_, err := tx.exec(ghHookDelivDel, sql.Named("delivery_id", id))
	return err
}
