package store

import (
	"database/sql"
)

// Policy group repository (schema/0289_group_policy.sql, issue #52, GR-9). The
// rules live in internal/groups/policygroups; this file is only its statements,
// all bound to the transaction's tenant.

const policySourceCols = `s.tenant_id, s.group_id, s.origin, s.path, s.commit_sha, s.cedar, s.cedar_sha256, s.allow_node,
	s.deny_node, s.compiled_sha256, s.applied_at, s.applied_by`

const policyNodeCols = `n.tenant_id, n.node_hash, n.kind, n.attr, n.value, n.group_id, n.created_at`

var (
	policySourceUpsert = tq("grp_policy_sources.upsert", `
		INSERT INTO grp_policy_sources (tenant_id, group_id, origin, path, commit_sha, cedar, cedar_sha256, allow_node, deny_node,
			compiled_sha256, applied_at, applied_by)
		VALUES (@tenant, @group_id, @origin, @path, @commit_sha, @cedar, @cedar_sha256, @allow_node, @deny_node,
			@compiled_sha256, @applied_at, @applied_by)
		ON CONFLICT (tenant_id, group_id) DO UPDATE SET origin = excluded.origin, path = excluded.path,
			commit_sha = excluded.commit_sha, cedar = excluded.cedar, cedar_sha256 = excluded.cedar_sha256,
			allow_node = excluded.allow_node, deny_node = excluded.deny_node, compiled_sha256 = excluded.compiled_sha256,
			applied_at = excluded.applied_at, applied_by = excluded.applied_by`)
	policySourceGet = tq("grp_policy_sources.get", `SELECT `+policySourceCols+` FROM grp_policy_sources s
		WHERE s.tenant_id = @tenant AND s.group_id = @group_id`)
	policySourceByPath = tq("grp_policy_sources.by_path", `SELECT `+policySourceCols+` FROM grp_policy_sources s
		WHERE s.tenant_id = @tenant AND s.origin = 'repo' AND s.path = @path`)
	policySourceList = tq("grp_policy_sources.list", `SELECT `+policySourceCols+` FROM grp_policy_sources s
		WHERE s.tenant_id = @tenant AND (@origin = '' OR s.origin = @origin) ORDER BY s.group_id`)
	policySourceDelete = tq("grp_policy_sources.delete", `DELETE FROM grp_policy_sources WHERE tenant_id = @tenant AND group_id = @group_id`)

	groupSetPolicy = tq("grp_groups.set_policy", `UPDATE grp_groups SET definition = 'policy', composite_op = NULL,
		policy_ref = @policy_ref, managed_by = @managed_by, version = version + 1
		WHERE tenant_id = @tenant AND id = @id`)

	policyNodeInsert = tq("grp_policy_nodes.insert", `
		INSERT INTO grp_policy_nodes (tenant_id, node_hash, kind, attr, value, group_id, created_at)
		VALUES (@tenant, @node_hash, @kind, @attr, @value, @group_id, @created_at)`)
	policyNodeGet = tq("grp_policy_nodes.get", `SELECT `+policyNodeCols+` FROM grp_policy_nodes n
		WHERE n.tenant_id = @tenant AND n.node_hash = @node_hash`)
	policyNodeByGroup = tq("grp_policy_nodes.by_group", `SELECT `+policyNodeCols+` FROM grp_policy_nodes n
		WHERE n.tenant_id = @tenant AND n.group_id = @group_id`)
	policyNodeList = tq("grp_policy_nodes.list", `SELECT `+policyNodeCols+` FROM grp_policy_nodes n
		WHERE n.tenant_id = @tenant AND (@kind = '' OR n.kind = @kind) ORDER BY n.node_hash`)
	policyNodeUnused = tq("grp_policy_nodes.unused", `SELECT `+policyNodeCols+` FROM grp_policy_nodes n
		WHERE n.tenant_id = @tenant AND n.kind <> 'empty'
		  AND NOT EXISTS (SELECT 1 FROM grp_policy_uses u WHERE u.tenant_id = @tenant AND u.node_hash = n.node_hash)
		ORDER BY n.node_hash`)
	policyNodeDelete = tq("grp_policy_nodes.delete", `DELETE FROM grp_policy_nodes WHERE tenant_id = @tenant AND node_hash = @node_hash`)

	policyUseInsert = tq("grp_policy_uses.insert", `INSERT INTO grp_policy_uses (tenant_id, policy_group_id, node_hash)
		VALUES (@tenant, @policy_group_id, @node_hash)`)
	policyUsesDelete = tq("grp_policy_uses.delete_of", `DELETE FROM grp_policy_uses WHERE tenant_id = @tenant AND policy_group_id = @policy_group_id`)
	policyUsesOf     = tq("grp_policy_uses.of", `SELECT u.node_hash FROM grp_policy_uses u
		WHERE u.tenant_id = @tenant AND u.policy_group_id = @policy_group_id ORDER BY u.node_hash`)
	policyUsedBy = tq("grp_policy_uses.used_by", `SELECT count(*) FROM grp_policy_uses u
		WHERE u.tenant_id = @tenant AND u.node_hash = @node_hash`)
)

func scanGrpPolicySource(s scanner) (*GrpPolicySource, error) {
	var p GrpPolicySource
	var tenant, applied string
	var by sql.NullString
	if err := s.Scan(&tenant, &p.GroupID, &p.Origin, &p.Path, &p.CommitSHA, &p.Cedar, &p.CedarSHA256, &p.AllowNode, &p.DenyNode,
		&p.CompiledSHA256, &applied, &by); err != nil {
		return nil, err
	}
	var err error
	if p.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	p.AppliedBy = strp(by)
	p.AppliedAt, err = ParseRT(applied)
	return &p, err
}

func scanGrpPolicyNode(s scanner) (*GrpPolicyNode, error) {
	var n GrpPolicyNode
	var tenant, created string
	if err := s.Scan(&tenant, &n.Hash, &n.Kind, &n.Attr, &n.Value, &n.GroupID, &created); err != nil {
		return nil, err
	}
	var err error
	if n.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	n.CreatedAt, err = ParseRT(created)
	return &n, err
}

// SetGrpPolicySource inserts or replaces the source of a policy group.
func (tx *TenantTx) SetGrpPolicySource(p *GrpPolicySource) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(policySourceUpsert, sql.Named("group_id", string(p.GroupID)), sql.Named("origin", p.Origin),
		sql.Named("path", p.Path), sql.Named("commit_sha", p.CommitSHA), sql.Named("cedar", p.Cedar),
		sql.Named("cedar_sha256", p.CedarSHA256), sql.Named("allow_node", p.AllowNode), sql.Named("deny_node", p.DenyNode),
		sql.Named("compiled_sha256", p.CompiledSHA256), sql.Named("applied_at", RT(p.AppliedAt)), sql.Named("applied_by", SP(p.AppliedBy)))
	if err == nil {
		p.TenantID = tx.tenant
	}
	return err
}

// GrpPolicySource returns a policy group's source or ErrNotFound.
func (tx *TenantTx) GrpPolicySource(group GroupID) (*GrpPolicySource, error) {
	return one(tx, scanGrpPolicySource, policySourceGet, sql.Named("group_id", string(group)))
}

// GrpPolicySourceByPath returns the repository source at a path or ErrNotFound.
func (tx *TenantTx) GrpPolicySourceByPath(path string) (*GrpPolicySource, error) {
	return one(tx, scanGrpPolicySource, policySourceByPath, sql.Named("path", path))
}

// GrpPolicySources lists the sources of an origin ("" for all), by group id.
func (tx *TenantTx) GrpPolicySources(origin string) ([]*GrpPolicySource, error) {
	return collect(tx, scanGrpPolicySource, policySourceList, sql.Named("origin", origin))
}

// DeleteGrpPolicySource removes a policy group's source (ErrNotFound if none).
func (tx *TenantTx) DeleteGrpPolicySource(group GroupID) error {
	res, err := tx.exec(policySourceDelete, sql.Named("group_id", string(group)))
	return rowsOrNotFound(res, err)
}

// SetGrpGroupPolicy makes a group a policy group (definition policy, no
// composite operator) with its policy_ref JSON and writer, and bumps its version.
func (tx *TenantTx) SetGrpGroupPolicy(id GroupID, managedBy ManagedBy, policyRef string) error {
	res, err := tx.exec(groupSetPolicy, sql.Named("id", string(id)), sql.Named("policy_ref", policyRef),
		sql.Named("managed_by", string(managedBy)))
	return rowsOrNotFound(res, err)
}

// InsertGrpPolicyNode adds a compiled node.
func (tx *TenantTx) InsertGrpPolicyNode(n *GrpPolicyNode) error {
	if err := tx.own(n.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(policyNodeInsert, sql.Named("node_hash", n.Hash), sql.Named("kind", n.Kind), sql.Named("attr", n.Attr),
		sql.Named("value", n.Value), sql.Named("group_id", string(n.GroupID)), sql.Named("created_at", RT(n.CreatedAt)))
	if err == nil {
		n.TenantID = tx.tenant
	}
	return err
}

// GrpPolicyNode returns a node by hash or ErrNotFound.
func (tx *TenantTx) GrpPolicyNode(hash string) (*GrpPolicyNode, error) {
	return one(tx, scanGrpPolicyNode, policyNodeGet, sql.Named("node_hash", hash))
}

// GrpPolicyNodeOfGroup returns the node a group holds or ErrNotFound.
func (tx *TenantTx) GrpPolicyNodeOfGroup(group GroupID) (*GrpPolicyNode, error) {
	return one(tx, scanGrpPolicyNode, policyNodeByGroup, sql.Named("group_id", string(group)))
}

// GrpPolicyNodes lists the nodes of a kind ("" for all), by hash.
func (tx *TenantTx) GrpPolicyNodes(kind string) ([]*GrpPolicyNode, error) {
	return collect(tx, scanGrpPolicyNode, policyNodeList, sql.Named("kind", kind))
}

// GrpPolicyNodesUnused lists the nodes no policy group reaches (the empty node excepted).
func (tx *TenantTx) GrpPolicyNodesUnused() ([]*GrpPolicyNode, error) {
	return collect(tx, scanGrpPolicyNode, policyNodeUnused)
}

// DeleteGrpPolicyNode removes a node (ErrNotFound if none).
func (tx *TenantTx) DeleteGrpPolicyNode(hash string) error {
	res, err := tx.exec(policyNodeDelete, sql.Named("node_hash", hash))
	return rowsOrNotFound(res, err)
}

// ReplaceGrpPolicyUses sets the nodes a policy group's compiled form reaches.
// Every hash must name an existing node of the tenant.
func (tx *TenantTx) ReplaceGrpPolicyUses(group GroupID, hashes []string) error {
	if _, err := tx.exec(policyUsesDelete, sql.Named("policy_group_id", string(group))); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.exec(policyUseInsert, sql.Named("policy_group_id", string(group)), sql.Named("node_hash", h)); err != nil {
			return err
		}
	}
	return nil
}

// GrpPolicyUsesOf lists the node hashes a policy group reaches.
func (tx *TenantTx) GrpPolicyUsesOf(group GroupID) ([]string, error) {
	hs, err := collect(tx, func(s scanner) (*string, error) {
		var h string
		err := s.Scan(&h)
		return &h, err
	}, policyUsesOf, sql.Named("policy_group_id", string(group)))
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = *h
	}
	return out, err
}

// GrpPolicyUsers is how many policy groups reach a node.
func (tx *TenantTx) GrpPolicyUsers(hash string) (int, error) {
	var n int
	err := tx.queryRow(policyUsedBy, sql.Named("node_hash", hash)).Scan(&n)
	return n, err
}
