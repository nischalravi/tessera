package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Containment's local sessions and the shared Deny policy lease
// (schema/0208_containment_policy.sql).

const (
	DenialPending = "pending" // written to the ledger, not yet verified in the policy
	DenialActive  = "active"  // written to the policy and read back
)

var (
	// A platform user is linked to an identity by platform_users.identity_id, or
	// by a sign-in through an IdP connection whose (profile = system, subject)
	// is the external id of one of the identity's accounts.
	usersByIdentity = tq("platform_users.by_identity", `
		SELECT u.id FROM platform_users u
		WHERE u.tenant_id = @tenant AND (u.identity_id = @identity_id OR EXISTS (
			SELECT 1 FROM external_logins l
			JOIN idp_connections c ON c.tenant_id = l.tenant_id AND c.id = l.idp_connection_id
			JOIN accounts a ON a.tenant_id = l.tenant_id AND a.system = c.profile AND a.external_id = l.subject
			WHERE l.tenant_id = @tenant AND c.tenant_id = @tenant AND a.tenant_id = @tenant
				AND l.user_id = u.id AND a.identity_id = @identity_id))
		ORDER BY u.created_at, u.rowid`)
	leaseAcquire = tq("containment_policy_leases.acquire", `
		INSERT INTO containment_policy_leases (tenant_id, policy_id, holder, expires_at)
		VALUES (@tenant, @policy_id, @holder, @expires_at)
		ON CONFLICT (tenant_id, policy_id) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
		WHERE containment_policy_leases.expires_at <= @now OR containment_policy_leases.holder = excluded.holder`)
	leaseRelease = tq("containment_policy_leases.release", `
		DELETE FROM containment_policy_leases WHERE tenant_id = @tenant AND policy_id = @policy_id AND holder = @holder`)
	denialMark = tq("containment_policy_denials.mark", `
		INSERT INTO containment_policy_denials (tenant_id, policy_id, user_id, state, updated_at)
		VALUES (@tenant, @policy_id, @user_id, @state, @now)
		ON CONFLICT (tenant_id, policy_id, user_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`)
	denialList = tq("containment_policy_denials.list", `
		SELECT d.user_id FROM containment_policy_denials d
		WHERE d.tenant_id = @tenant AND d.policy_id = @policy_id AND d.updated_at >= @since
		ORDER BY d.updated_at, d.user_id`)
	denialPrune = tq("containment_policy_denials.prune", `
		DELETE FROM containment_policy_denials WHERE tenant_id = @tenant AND policy_id = @policy_id AND updated_at < @since`)
)

// PlatformUserIDsForIdentity lists the ids of the platform users (every status)
// linked to an identity of this tenant.
func (tx *TenantTx) PlatformUserIDsForIdentity(identityID int64) ([]uuid.UUID, error) {
	ids, err := collect(tx, func(s scanner) (*uuid.UUID, error) {
		var raw string
		if err := s.Scan(&raw); err != nil {
			return nil, err
		}
		id, err := uuid.Parse(raw)
		return &id, err
	}, usersByIdentity, sql.Named("identity_id", identityID))
	out := make([]uuid.UUID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// AcquirePolicyLease takes the lease on a policy for holder until expires. It
// reports false when another holder has an unexpired lease. Taking a lease the
// holder already has extends it.
func (tx *TenantTx) AcquirePolicyLease(policyID, holder string, now, expires time.Time) (bool, error) {
	res, err := tx.exec(leaseAcquire, sql.Named("policy_id", policyID), sql.Named("holder", holder),
		sql.Named("expires_at", RT(expires)), sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReleasePolicyLease drops holder's lease on a policy (a no-op if it is not the holder's).
func (tx *TenantTx) ReleasePolicyLease(policyID, holder string) error {
	_, err := tx.exec(leaseRelease, sql.Named("policy_id", policyID), sql.Named("holder", holder))
	return err
}

// MarkPolicyDenial records that Tessera holds userID in the policy, in state
// DenialPending or DenialActive.
func (tx *TenantTx) MarkPolicyDenial(policyID, userID, state string, now time.Time) error {
	_, err := tx.exec(denialMark, sql.Named("policy_id", policyID), sql.Named("user_id", userID),
		sql.Named("state", state), sql.Named("now", RT(now)))
	return err
}

// PolicyDenials lists the user ids Tessera holds in a policy that were
// recorded at or after since.
func (tx *TenantTx) PolicyDenials(policyID string, since time.Time) ([]string, error) {
	ids, err := collect(tx, func(s scanner) (*string, error) {
		var id string
		err := s.Scan(&id)
		return &id, err
	}, denialList, sql.Named("policy_id", policyID), sql.Named("since", RT(since)))
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// PrunePolicyDenials forgets the entries recorded before since.
func (tx *TenantTx) PrunePolicyDenials(policyID string, since time.Time) error {
	_, err := tx.exec(denialPrune, sql.Named("policy_id", policyID), sql.Named("since", RT(since)))
	return err
}
