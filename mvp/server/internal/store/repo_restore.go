package store

import (
	"database/sql"
	"time"
)

// Credential invalidation after a restore (issue #171). A backup is a copy of
// the database at one moment: sessions, login transactions, bootstrap codes
// and access-token signing keys that were revoked, consumed or rotated after
// that moment come back valid with it, and the restored database cannot
// remember the later revocation. InvalidateCredentials is the one hook that
// closes that gap before the restored database serves a request.

// CredentialsInvalidated counts what InvalidateCredentials changed in a tenant.
type CredentialsInvalidated struct {
	Sessions          int64 `json:"sessions"`
	LoginTransactions int64 `json:"login_transactions"`
	Invitations       int64 `json:"bootstrap_invitations"`
	SigningKeys       int64 `json:"signing_keys"`
}

var (
	credsRevokeSessions = tq("restore.revoke_sessions", `
		UPDATE sessions SET status = 'revoked', revoked_at = @at, revoked_reason = @reason
		WHERE tenant_id = @tenant AND status = 'active'`)
	credsDeleteTxns = tq("restore.delete_login_transactions", `
		DELETE FROM login_transactions WHERE tenant_id = @tenant`)
	// consumed invitations are history; an unconsumed code is a live credential
	credsDeleteInvitations = tq("restore.delete_invitations", `
		DELETE FROM bootstrap_invitations WHERE tenant_id = @tenant AND consumed_at IS NULL`)
	// access tokens and AWS federation tokens are verified against the tenant's published access_token and aws_federation
	// keys; revoking them all makes every token signed before the restore fail
	// (EnsureKeys mints fresh ones at the next start). idp_client_auth keys are
	// registered with the IdP and are left alone.
	credsRevokeKeys = tq("restore.revoke_signing_keys", `
		UPDATE tenant_signing_keys SET status = 'revoked', retired_at = COALESCE(retired_at, @at)
		WHERE tenant_id = @tenant AND purpose IN ('access_token', 'aws_federation') AND status IN ('next', 'active', 'retired')`)
)

// InvalidateCredentials revokes every active session of this tenant, drops
// its pending login transactions and unconsumed bootstrap invitations, and
// revokes its access-token signing keys. Run it on a restored database
// before it serves.
func (tx *TenantTx) InvalidateCredentials(reason string, at time.Time) (CredentialsInvalidated, error) {
	var out CredentialsInvalidated
	for _, s := range []struct {
		st   tstmt
		n    *int64
		args []sql.NamedArg
	}{
		{credsRevokeSessions, &out.Sessions, []sql.NamedArg{sql.Named("at", RT(at)), sql.Named("reason", reason)}},
		{credsDeleteTxns, &out.LoginTransactions, nil},
		{credsDeleteInvitations, &out.Invitations, nil},
		{credsRevokeKeys, &out.SigningKeys, []sql.NamedArg{sql.Named("at", RT(at))}},
	} {
		res, err := tx.exec(s.st, s.args...)
		if err != nil {
			return out, err
		}
		if *s.n, err = res.RowsAffected(); err != nil {
			return out, err
		}
	}
	return out, nil
}
