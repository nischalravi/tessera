package store

import (
	"database/sql"
	"time"
)

// Deleting a connection (issue #963). The connection must already be retired; the readiness service checks
// that and the usage below, then DeleteConnection removes the connection and everything that hangs off it,
// including its sealed credentials. Synced objects (accounts, groups, resources, permissions) are never
// removed here: a connection that still owns some is refused, so a delete cannot bypass the deletion guard.

// ConnectionUsage is what still depends on a connection.
type ConnectionUsage struct {
	Accounts, Groups, Resources, Permissions int // synced objects of the connection's system
	PendingOps                               int // provisioning ops not yet finished, and queued or leased agent jobs
	RunningJobs                              int // job runs (sync, validation, ...) in progress
	Loaders, Provisioners, Transmitters      int // group loaders, group provisioners and SSF transmitters that name it
}

// Objects is the number of synced objects the connection owns.
func (u ConnectionUsage) Objects() int { return u.Accounts + u.Groups + u.Resources + u.Permissions }

// Referenced is the number of configured objects that name the connection.
func (u ConnectionUsage) Referenced() int { return u.Loaders + u.Provisioners + u.Transmitters }

var (
	connUseGroups = tq("connections.use_groups", `
		SELECT count(g.id) FROM groups g WHERE g.tenant_id = @tenant AND g.system = @system`)
	connUseResources = tq("connections.use_resources", `
		SELECT count(r.id) FROM resources r WHERE r.tenant_id = @tenant AND r.system = @system`)
	connUsePermissions = tq("connections.use_permissions", `
		SELECT count(p.id) FROM permissions p WHERE p.tenant_id = @tenant AND p.system = @system`)
	connUsePendingOps = tq("connections.use_pending_ops", `
		SELECT (SELECT count(o.id) FROM provisioning_ops o WHERE o.tenant_id = @tenant AND o.connection_id = @id
			AND o.status IN ('queued','sent','pending_verification'))
		     + (SELECT count(j.id) FROM agent_jobs j WHERE j.tenant_id = @tenant AND j.connection_id = @id
			AND j.status IN ('queued','leased'))`)
	connUseRunningJobs = tq("connections.use_running_jobs", `
		SELECT count(j.id) FROM job_runs j WHERE j.tenant_id = @tenant AND j.connection_id = @id AND j.status = 'running'`)
	connUseLoaders = tq("connections.use_loaders", `
		SELECT count(l.id) FROM grp_loaders l WHERE l.tenant_id = @tenant AND l.connection_id = @id`)
	connUseProvisioners = tq("connections.use_provisioners", `
		SELECT count(p.id) FROM grp_provisioners p WHERE p.tenant_id = @tenant AND p.connection_id = @id`)
	connUseTransmitters = tq("connections.use_transmitters", `
		SELECT count(t.id) FROM ssf_transmitters t WHERE t.tenant_id = @tenant AND t.connection_id = @id`)
)

// ConnectionUsage counts what still depends on connection id, whose system is system.
func (tx *TenantTx) ConnectionUsage(id, system string) (ConnectionUsage, error) {
	var u ConnectionUsage
	byID, bySystem := sql.Named("id", id), sql.Named("system", system)
	for _, q := range []struct {
		dst *int
		s   tstmt
		arg sql.NamedArg
	}{
		{&u.Groups, connUseGroups, bySystem}, {&u.Resources, connUseResources, bySystem},
		{&u.Permissions, connUsePermissions, bySystem}, {&u.PendingOps, connUsePendingOps, byID},
		{&u.RunningJobs, connUseRunningJobs, byID}, {&u.Loaders, connUseLoaders, byID},
		{&u.Provisioners, connUseProvisioners, byID}, {&u.Transmitters, connUseTransmitters, byID},
	} {
		n, err := tx.count(q.s, q.arg)
		if err != nil {
			return u, err
		}
		*q.dst = n
	}
	var err error
	u.Accounts, err = tx.count(accountsCountInSystem, bySystem)
	return u, err
}

// runsOf and revsOf select the check runs and revisions of connection @id.
const (
	revsOf = `SELECT v.id FROM connection_revisions v WHERE v.tenant_id = @tenant AND v.connection_id = @id`
	runsOf = `SELECT k.id FROM readiness_check_runs k WHERE k.tenant_id = @tenant AND k.revision_id IN (` + revsOf + `)`
	opsOf  = `SELECT o.id FROM provisioning_ops o WHERE o.tenant_id = @tenant AND o.connection_id = @id`
)

// connDeleteSteps run in order: children before parents. The sealed credentials go with their rows
// (connection_credentials, provisioning_targets.credential_enc); a certificate row stays as evidence but
// loses its sealed key and its link to the connection; job history stays, unlinked.
var (
	connStep_del_stg_identities       = tq("connections.del_stg_identities", `DELETE FROM stg_identities WHERE stg_identities.tenant_id = @tenant AND run_id IN (`+runsOf+`)`)
	connStep_del_stg_accounts         = tq("connections.del_stg_accounts", `DELETE FROM stg_accounts WHERE stg_accounts.tenant_id = @tenant AND run_id IN (`+runsOf+`)`)
	connStep_del_stg_groups           = tq("connections.del_stg_groups", `DELETE FROM stg_groups WHERE stg_groups.tenant_id = @tenant AND run_id IN (`+runsOf+`)`)
	connStep_del_stg_memberships      = tq("connections.del_stg_memberships", `DELETE FROM stg_memberships WHERE stg_memberships.tenant_id = @tenant AND run_id IN (`+runsOf+`)`)
	connStep_del_stg_attr_stats       = tq("connections.del_stg_attr_stats", `DELETE FROM stg_attr_stats WHERE stg_attr_stats.tenant_id = @tenant AND run_id IN (`+runsOf+`)`)
	connStep_del_check_results        = tq("connections.del_check_results", `DELETE FROM readiness_check_results WHERE readiness_check_results.tenant_id = @tenant AND run_id IN (`+runsOf+`)`)
	connStep_del_recon_findings       = tq("connections.del_recon_findings", `DELETE FROM recon_findings WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_recon_runs           = tq("connections.del_recon_runs", `DELETE FROM recon_runs WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_attestations         = tq("connections.del_attestations", `DELETE FROM readiness_attestations WHERE readiness_attestations.tenant_id = @tenant AND revision_id IN (`+revsOf+`)`)
	connStep_del_item_states          = tq("connections.del_item_states", `DELETE FROM readiness_item_states WHERE readiness_item_states.tenant_id = @tenant AND revision_id IN (`+revsOf+`)`)
	connStep_del_live_attestations    = tq("connections.del_live_attestations", `DELETE FROM readiness_live_attestations WHERE readiness_live_attestations.tenant_id = @tenant AND revision_id IN (`+revsOf+`)`)
	connStep_del_baselines            = tq("connections.del_baselines", `DELETE FROM readiness_baselines WHERE readiness_baselines.tenant_id = @tenant AND revision_id IN (`+revsOf+`)`)
	connStep_del_skips                = tq("connections.del_skips", `DELETE FROM readiness_skips WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_scores               = tq("connections.del_scores", `DELETE FROM readiness_scores WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_activation_requests  = tq("connections.del_activation_requests", `DELETE FROM connection_activation_requests WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_check_runs           = tq("connections.del_check_runs", `DELETE FROM readiness_check_runs WHERE readiness_check_runs.tenant_id = @tenant AND revision_id IN (`+revsOf+`)`)
	connStep_clear_active_revision    = tq("connections.clear_active_revision", `UPDATE connections SET active_revision_id = NULL WHERE tenant_id = @tenant AND id = @id`)
	connStep_del_revisions            = tq("connections.del_revisions", `DELETE FROM connection_revisions WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_overlays             = tq("connections.del_overlays", `DELETE FROM readiness_overlays WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_agent_jobs           = tq("connections.del_agent_jobs", `DELETE FROM agent_jobs WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_unlink_bundle_account_op = tq("connections.unlink_bundle_account_op", `UPDATE guest_bundle_items SET account_op_id = NULL WHERE guest_bundle_items.tenant_id = @tenant AND account_op_id IN (`+opsOf+`)`)
	connStep_unlink_bundle_grant_op   = tq("connections.unlink_bundle_grant_op", `UPDATE guest_bundle_items SET grant_op_id = NULL WHERE guest_bundle_items.tenant_id = @tenant AND grant_op_id IN (`+opsOf+`)`)
	connStep_unlink_bundle_remove_op  = tq("connections.unlink_bundle_remove_op", `UPDATE guest_bundle_items SET remove_op_id = NULL WHERE guest_bundle_items.tenant_id = @tenant AND remove_op_id IN (`+opsOf+`)`)
	connStep_del_prov_findings        = tq("connections.del_prov_findings", `DELETE FROM provisioning_findings WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_prov_ops             = tq("connections.del_prov_ops", `DELETE FROM provisioning_ops WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_prov_targets         = tq("connections.del_prov_targets", `DELETE FROM provisioning_targets WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_credentials          = tq("connections.del_credentials", `DELETE FROM connection_credentials WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_limits               = tq("connections.del_limits", `DELETE FROM connection_limits WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_worker_states        = tq("connections.del_worker_states", `DELETE FROM worker_target_states WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_del_containment_retries  = tq("connections.del_containment_retries", `DELETE FROM containment_retries WHERE tenant_id = @tenant AND connection_id = @id`)
	connStep_unlink_job_runs          = tq("connections.unlink_job_runs", `UPDATE job_runs SET connection_id = NULL WHERE tenant_id = @tenant AND connection_id = @id`)
)

var connDeleteSteps = []tstmt{
	connStep_del_stg_identities,
	connStep_del_stg_accounts,
	connStep_del_stg_groups,
	connStep_del_stg_memberships,
	connStep_del_stg_attr_stats,
	connStep_del_check_results,
	connStep_del_recon_findings,
	connStep_del_recon_runs,
	connStep_del_attestations,
	connStep_del_item_states,
	connStep_del_live_attestations,
	connStep_del_baselines,
	connStep_del_skips,
	connStep_del_scores,
	connStep_del_activation_requests,
	connStep_del_check_runs,
	connStep_clear_active_revision,
	connStep_del_revisions,
	connStep_del_overlays,
	connStep_del_agent_jobs,
	connStep_unlink_bundle_account_op,
	connStep_unlink_bundle_grant_op,
	connStep_unlink_bundle_remove_op,
	connStep_del_prov_findings,
	connStep_del_prov_ops,
	connStep_del_prov_targets,
	connStep_del_credentials,
	connStep_del_limits,
	connStep_del_worker_states,
	connStep_del_containment_retries,
	connStep_unlink_job_runs,
}

var (
	connRetireCerts = tq("connections.retire_certs", `
		UPDATE tenant_certificates SET status = 'retired', retired_at = COALESCE(retired_at, @now), key_sealed = NULL, connection_id = NULL
		WHERE tenant_id = @tenant AND connection_id = @id`)
	connDelete = tq("connections.delete", `DELETE FROM connections WHERE tenant_id = @tenant AND id = @id`)
)

// DeleteConnection removes connection id and its dependent rows (see connDeleteSteps); ErrNotFound if this
// tenant has no such connection. The caller has checked ConnectionUsage.
func (tx *TenantTx) DeleteConnection(id string, now time.Time) error {
	byID := sql.Named("id", id)
	for _, st := range connDeleteSteps {
		if _, err := tx.exec(st, byID); err != nil {
			return err
		}
	}
	if _, err := tx.exec(connRetireCerts, byID, sql.Named("now", RT(now))); err != nil {
		return err
	}
	return tx.execOne(connDelete, byID)
}
