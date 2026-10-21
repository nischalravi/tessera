package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Per-user preferences (schema/0494_user_preferences.sql, issue #298). One row
// per user; ErrNotFound means the user never saved any.

// UserPreferencesRow is the stored form of prefs.Preferences. An empty value means "the default".
type UserPreferencesRow struct {
	TimeZone    string
	DateFormat  string
	Locale      string
	LandingPage string
	UpdatedAt   time.Time
}

var (
	userPrefsGet = tq("user_preferences.get", `
		SELECT p.time_zone, p.date_format, p.locale, p.landing_page, p.updated_at
		FROM user_preferences p WHERE p.tenant_id = @tenant AND p.user_id = @user`)
	userPrefsPut = tq("user_preferences.put", `
		INSERT INTO user_preferences (tenant_id, user_id, time_zone, date_format, locale, landing_page, updated_at)
		VALUES (@tenant, @user, @time_zone, @date_format, @locale, @landing_page, @updated_at)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET time_zone = excluded.time_zone, date_format = excluded.date_format,
			locale = excluded.locale, landing_page = excluded.landing_page, updated_at = excluded.updated_at`)
)

// UserPreferences returns one user's saved preferences; ErrNotFound if there are none.
func (tx *TenantTx) UserPreferences(user uuid.UUID) (*UserPreferencesRow, error) {
	return one(tx, func(s scanner) (*UserPreferencesRow, error) {
		var r UserPreferencesRow
		var at string
		if err := s.Scan(&r.TimeZone, &r.DateFormat, &r.Locale, &r.LandingPage, &at); err != nil {
			return nil, err
		}
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, userPrefsGet, sql.Named("user", user.String()))
}

// PutUserPreferences replaces one user's preferences.
func (tx *TenantTx) PutUserPreferences(user uuid.UUID, r *UserPreferencesRow, now time.Time) error {
	_, err := tx.exec(userPrefsPut, sql.Named("user", user.String()), sql.Named("time_zone", r.TimeZone),
		sql.Named("date_format", r.DateFormat), sql.Named("locale", r.Locale), sql.Named("landing_page", r.LandingPage),
		sql.Named("updated_at", RT(now)))
	return err
}
