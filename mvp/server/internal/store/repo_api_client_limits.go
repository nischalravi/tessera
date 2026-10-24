package store

import (
	"database/sql"
	"time"
)

// Per-client API rate limit overrides (schema/0913_api_client_limits.sql, issue #587).

// APIClientLimit is a machine client's token bucket: Burst requests at once,
// refilled at PerMinute requests a minute.
type APIClientLimit struct {
	ClientID  string
	Burst     int
	PerMinute int
	UpdatedAt time.Time
}

var (
	clientLimitGet = tq("api_client_limits.get", `
		SELECT client_id, burst, per_minute, updated_at FROM api_client_limits WHERE tenant_id = @tenant AND client_id = @client_id`)
	clientLimitSet = tq("api_client_limits.set", `
		INSERT INTO api_client_limits (tenant_id, client_id, burst, per_minute, updated_at)
		VALUES (@tenant, @client_id, @burst, @per_minute, @at)
		ON CONFLICT (tenant_id, client_id) DO UPDATE SET burst = excluded.burst, per_minute = excluded.per_minute,
			updated_at = excluded.updated_at`)
	clientLimitClear = tq("api_client_limits.clear", `
		DELETE FROM api_client_limits WHERE tenant_id = @tenant AND client_id = @client_id`)
)

func scanClientLimit(s scanner) (*APIClientLimit, error) {
	var l APIClientLimit
	var at string
	if err := s.Scan(&l.ClientID, &l.Burst, &l.PerMinute, &at); err != nil {
		return nil, err
	}
	var err error
	l.UpdatedAt, err = ParseRT(at)
	return &l, err
}

// APIClientLimit returns the client's override (ErrNotFound when it has none).
func (tx *TenantTx) APIClientLimit(clientID string) (*APIClientLimit, error) {
	return one(tx, scanClientLimit, clientLimitGet, sql.Named("client_id", clientID))
}

// SetAPIClientLimit stores the client's override. A client of another tenant, or none, is a foreign key error.
func (tx *TenantTx) SetAPIClientLimit(clientID string, burst, perMinute int, at time.Time) error {
	_, err := tx.exec(clientLimitSet, sql.Named("client_id", clientID), sql.Named("burst", burst),
		sql.Named("per_minute", perMinute), sql.Named("at", RT(at)))
	return crossTenant(err)
}

// ClearAPIClientLimit removes the client's override, so the tenant default applies again.
func (tx *TenantTx) ClearAPIClientLimit(clientID string) error {
	_, err := tx.exec(clientLimitClear, sql.Named("client_id", clientID))
	return err
}
