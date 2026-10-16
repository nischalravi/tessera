package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// MFA posture (schema/0255_mfa_posture.sql). Strengths are the values of
// mfa.Strength; the store keeps them as plain strings.

// AuthMethod is one registered authentication method of an account.
type AuthMethod struct {
	AccountID  int64
	ExternalID string
	System     string
	Strength   string
	Kind       string
	Label      string
	EnrolledAt *time.Time
	ObservedAt time.Time
}

// AuthMethodSource records whether a system's methods could be read.
type AuthMethodSource struct {
	System    string
	Status    string // ok | unavailable
	Detail    string
	UpdatedAt time.Time
}

// AccountAuthSignals are what an app or data platform reports about how an
// account signs in. A nil flag is unknown.
type AccountAuthSignals struct {
	AccountID        int64
	HasLocalPassword *bool
	MFAEnabled       *bool
	SSOEnforced      *bool
	ObservedAt       time.Time
}

// MFASnapshot is one day's coverage of one group of identities.
type MFASnapshot struct {
	Date              string // YYYY-MM-DD
	Dimension         string // all | department | privileged_group
	GroupKey          string
	Total             int
	PhishingResistant int
	PushNumberMatch   int
	Push              int
	OTP               int
	SMSVoice          int
	NoMFA             int
	Unknown           int
	PasskeyEnrolled   int
}

const (
	authMethodCols = `m.account_id, m.external_id, m.system, m.strength, m.kind, m.label, m.enrolled_at, m.observed_at`
	snapshotCols   = `s.snapshot_date, s.dimension, s.group_key, s.total, s.phishing_resistant, s.push_number_match, s.push,
		s.otp, s.sms_voice, s.no_mfa, s.unknown, s.passkey_enrolled`
)

var (
	authMethodsList = tq("auth_methods.list", `
		SELECT `+authMethodCols+` FROM auth_methods m WHERE m.tenant_id = @tenant
		ORDER BY m.account_id, m.external_id`)
	authMethodsDeleteSystem = tq("auth_methods.delete_system", `
		DELETE FROM auth_methods WHERE tenant_id = @tenant AND system = @system`)
	authMethodsInsert = tq("auth_methods.insert", `
		INSERT INTO auth_methods (tenant_id, account_id, external_id, system, strength, kind, label, enrolled_at, observed_at)
		VALUES (@tenant, @account_id, @external_id, @system, @strength, @kind, @label, @enrolled_at, @observed_at)
		ON CONFLICT (tenant_id, account_id, external_id) DO UPDATE SET system = excluded.system,
			strength = excluded.strength, kind = excluded.kind, label = excluded.label,
			enrolled_at = excluded.enrolled_at, observed_at = excluded.observed_at`)

	authSourcesList = tq("auth_method_sources.list", `
		SELECT s.system, s.status, s.detail, s.updated_at FROM auth_method_sources s WHERE s.tenant_id = @tenant
		ORDER BY s.system`)
	authSourcesPut = tq("auth_method_sources.put", `
		INSERT INTO auth_method_sources (tenant_id, system, status, detail, updated_at)
		VALUES (@tenant, @system, @status, @detail, @updated_at)
		ON CONFLICT (tenant_id, system) DO UPDATE SET status = excluded.status, detail = excluded.detail,
			updated_at = excluded.updated_at`)

	authSignalsList = tq("account_auth_signals.list", `
		SELECT g.account_id, g.has_local_password, g.mfa_enabled, g.sso_enforced, g.observed_at
		FROM account_auth_signals g WHERE g.tenant_id = @tenant ORDER BY g.account_id`)
	authSignalsPut = tq("account_auth_signals.put", `
		INSERT INTO account_auth_signals (tenant_id, account_id, has_local_password, mfa_enabled, sso_enforced, observed_at)
		VALUES (@tenant, @account_id, @has_local_password, @mfa_enabled, @sso_enforced, @observed_at)
		ON CONFLICT (tenant_id, account_id) DO UPDATE SET has_local_password = excluded.has_local_password,
			mfa_enabled = excluded.mfa_enabled, sso_enforced = excluded.sso_enforced, observed_at = excluded.observed_at`)

	snapshotsList = tq("mfa_posture_snapshots.list", `
		SELECT `+snapshotCols+` FROM mfa_posture_snapshots s
		WHERE s.tenant_id = @tenant AND s.snapshot_date >= @since
		ORDER BY s.snapshot_date, s.dimension, s.group_key`)
	snapshotsPut = tq("mfa_posture_snapshots.put", `
		INSERT INTO mfa_posture_snapshots (tenant_id, snapshot_date, dimension, group_key, total, phishing_resistant,
			push_number_match, push, otp, sms_voice, no_mfa, unknown, passkey_enrolled)
		VALUES (@tenant, @date, @dimension, @group_key, @total, @phishing_resistant, @push_number_match, @push,
			@otp, @sms_voice, @no_mfa, @unknown, @passkey_enrolled)
		ON CONFLICT (tenant_id, snapshot_date, dimension, group_key) DO UPDATE SET total = excluded.total,
			phishing_resistant = excluded.phishing_resistant, push_number_match = excluded.push_number_match,
			push = excluded.push, otp = excluded.otp, sms_voice = excluded.sms_voice, no_mfa = excluded.no_mfa,
			unknown = excluded.unknown, passkey_enrolled = excluded.passkey_enrolled`)
)

func scanAuthMethod(s scanner) (*AuthMethod, error) {
	var m AuthMethod
	var enrolled nullTime
	var observed string
	if err := s.Scan(&m.AccountID, &m.ExternalID, &m.System, &m.Strength, &m.Kind, &m.Label, &enrolled, &observed); err != nil {
		return nil, err
	}
	var err error
	if m.EnrolledAt, err = enrolled.ptr(); err != nil {
		return nil, err
	}
	m.ObservedAt, err = timeutil.ParseDB(observed)
	return &m, err
}

func scanAuthSource(s scanner) (*AuthMethodSource, error) {
	var v AuthMethodSource
	var at string
	if err := s.Scan(&v.System, &v.Status, &v.Detail, &at); err != nil {
		return nil, err
	}
	var err error
	v.UpdatedAt, err = timeutil.ParseDB(at)
	return &v, err
}

func scanAuthSignals(s scanner) (*AccountAuthSignals, error) {
	var g AccountAuthSignals
	var pw, mfa, sso sql.NullInt64
	var at string
	if err := s.Scan(&g.AccountID, &pw, &mfa, &sso, &at); err != nil {
		return nil, err
	}
	flag := func(n sql.NullInt64) *bool {
		if !n.Valid {
			return nil
		}
		b := n.Int64 != 0
		return &b
	}
	g.HasLocalPassword, g.MFAEnabled, g.SSOEnforced = flag(pw), flag(mfa), flag(sso)
	var err error
	g.ObservedAt, err = timeutil.ParseDB(at)
	return &g, err
}

func scanSnapshot(s scanner) (*MFASnapshot, error) {
	var v MFASnapshot
	err := s.Scan(&v.Date, &v.Dimension, &v.GroupKey, &v.Total, &v.PhishingResistant, &v.PushNumberMatch, &v.Push,
		&v.OTP, &v.SMSVoice, &v.NoMFA, &v.Unknown, &v.PasskeyEnrolled)
	return &v, err
}

// nullableBool stores a tri-state flag (NULL for unknown).
func nullableBool(b *bool) any {
	if b == nil {
		return nil
	}
	return B(*b)
}

// AuthMethods returns every registered method of the tenant's accounts.
func (tx *TenantTx) AuthMethods() ([]*AuthMethod, error) {
	return collect(tx, scanAuthMethod, authMethodsList)
}

// ReplaceAuthMethods makes rows the complete set of methods of one system:
// the methods the system no longer reports (a removed key, a deleted factor)
// disappear.
func (tx *TenantTx) ReplaceAuthMethods(system string, rows []AuthMethod) error {
	if _, err := tx.exec(authMethodsDeleteSystem, sql.Named("system", system)); err != nil {
		return err
	}
	for _, m := range rows {
		if _, err := tx.exec(authMethodsInsert, sql.Named("account_id", m.AccountID), sql.Named("external_id", m.ExternalID),
			sql.Named("system", system), sql.Named("strength", m.Strength), sql.Named("kind", m.Kind),
			sql.Named("label", m.Label), sql.Named("enrolled_at", TP(m.EnrolledAt)), sql.Named("observed_at", T(m.ObservedAt))); err != nil {
			return err
		}
	}
	return nil
}

// AuthMethodSources lists, per system, whether its methods could be read.
func (tx *TenantTx) AuthMethodSources() ([]*AuthMethodSource, error) {
	return collect(tx, scanAuthSource, authSourcesList)
}

// PutAuthMethodSource records the outcome of reading a system's methods.
func (tx *TenantTx) PutAuthMethodSource(v AuthMethodSource) error {
	_, err := tx.exec(authSourcesPut, sql.Named("system", v.System), sql.Named("status", v.Status),
		sql.Named("detail", v.Detail), sql.Named("updated_at", T(v.UpdatedAt)))
	return err
}

// AccountAuthSignalRows lists what apps report about how accounts sign in.
func (tx *TenantTx) AccountAuthSignalRows() ([]*AccountAuthSignals, error) {
	return collect(tx, scanAuthSignals, authSignalsList)
}

// PutAccountAuthSignals stores (or replaces) one account's sign-in facts.
func (tx *TenantTx) PutAccountAuthSignals(g AccountAuthSignals) error {
	_, err := tx.exec(authSignalsPut, sql.Named("account_id", g.AccountID),
		sql.Named("has_local_password", nullableBool(g.HasLocalPassword)), sql.Named("mfa_enabled", nullableBool(g.MFAEnabled)),
		sql.Named("sso_enforced", nullableBool(g.SSOEnforced)), sql.Named("observed_at", T(g.ObservedAt)))
	return err
}

// MFASnapshots returns the daily snapshots from date since (YYYY-MM-DD) on.
func (tx *TenantTx) MFASnapshots(since string) ([]*MFASnapshot, error) {
	return collect(tx, scanSnapshot, snapshotsList, sql.Named("since", since))
}

// PutMFASnapshot stores (or replaces) one day's row for a group.
func (tx *TenantTx) PutMFASnapshot(v MFASnapshot) error {
	_, err := tx.exec(snapshotsPut, sql.Named("date", v.Date), sql.Named("dimension", v.Dimension),
		sql.Named("group_key", v.GroupKey), sql.Named("total", v.Total), sql.Named("phishing_resistant", v.PhishingResistant),
		sql.Named("push_number_match", v.PushNumberMatch), sql.Named("push", v.Push), sql.Named("otp", v.OTP),
		sql.Named("sms_voice", v.SMSVoice), sql.Named("no_mfa", v.NoMFA), sql.Named("unknown", v.Unknown),
		sql.Named("passkey_enrolled", v.PasskeyEnrolled))
	return err
}
