package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Membership-engine repository (schema/0280_groups.sql engine section and
// 0284_groups_engine.sql). The rules of the engine live in
// internal/groups/engine; this file is only its statements. All of them are
// bound to the transaction's tenant.
//
// The statements avoid CTEs, UNION and RETURNING (the statement linter in
// sqllint_test.go does not accept them): the engine reads sets in ordered,
// cursor-paged queries and merges them in Go.

const dmCols = `d.id, d.tenant_id, d.group_id, d.list_id, d.member_type, d.member_identity_id, d.member_group_id,
	d.enabled_from, d.disabled_at, d.source, d.source_ref, d.reason, d.created_by, d.created_at`

// dmActive is "this direct row counts at @now": its own dates only (the
// group's status and dates are the engine's concern).
const dmActive = `(d.enabled_from IS NULL OR d.enabled_from <= @now) AND (d.disabled_at IS NULL OR @now < d.disabled_at)`

var (
	// ---- direct memberships
	grpDmGet          = tq("grp_dm.get", `SELECT `+dmCols+` FROM grp_direct_memberships d WHERE d.tenant_id = @tenant AND d.id = @id`)
	grpDmFindIdentity = tq("grp_dm.find_identity", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id
		  AND d.member_type = 'identity' AND d.member_identity_id = @member`)
	grpDmFindGroup = tq("grp_dm.find_group", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id
		  AND d.member_type = 'group' AND d.member_group_id = @member`)
	grpDmList = tq("grp_dm.list", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id
		  AND (@list_id = '' OR d.list_id = @list_id) AND (@member_type = '' OR d.member_type = @member_type)
		ORDER BY d.created_at, d.id LIMIT @limit OFFSET @offset`)
	grpDmCount = tq("grp_dm.count", `SELECT count(*) FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id
		  AND (@list_id = '' OR d.list_id = @list_id) AND (@member_type = '' OR d.member_type = @member_type)`)
	grpDmInsert = tq("grp_dm.insert", `
		INSERT INTO grp_direct_memberships (id, tenant_id, group_id, list_id, member_type, member_identity_id, member_group_id,
			enabled_from, disabled_at, source, source_ref, reason, created_by, created_at)
		VALUES (@id, @tenant, @group_id, @list_id, @member_type, @member_identity_id, @member_group_id,
			@enabled_from, @disabled_at, @source, @source_ref, @reason, @created_by, @created_at)`)
	grpDmSetDates = tq("grp_dm.set_dates", `UPDATE grp_direct_memberships SET enabled_from = @enabled_from, disabled_at = @disabled_at,
		reason = @reason WHERE tenant_id = @tenant AND id = @id`)
	grpDmDelete   = tq("grp_dm.delete", `DELETE FROM grp_direct_memberships WHERE tenant_id = @tenant AND id = @id`)
	grpDmDeleteOf = tq("grp_dm.delete_of", `DELETE FROM grp_direct_memberships WHERE tenant_id = @tenant AND group_id = @group_id`)
	// candidate identities of a group's own direct rows, in id order after a cursor
	grpDmIdentitiesAfter = tq("grp_dm.identities_after", `SELECT d.member_identity_id FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id AND d.member_type = 'identity'
		  AND d.member_identity_id > @after ORDER BY d.member_identity_id LIMIT @limit`)
	// the lists a group has direct rows in
	grpDmLists = tq("grp_dm.lists", `SELECT DISTINCT d.list_id FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id ORDER BY d.list_id`)
	// every group-in-group row's edge, for verification
	grpDmGroupEdges = tq("grp_dm.group_edges", `SELECT DISTINCT d.group_id, d.member_group_id, d.list_id FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.member_type = 'group' ORDER BY d.group_id, d.member_group_id, d.list_id`)
	// support of a basic group: its active direct identity row (0 or 1) plus
	// its active direct group rows whose child contains the identity (design §6.2 I1)
	grpBasicSupport = tq("grp_dm.basic_support", `SELECT
		(SELECT count(*) FROM grp_direct_memberships d
			WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id AND d.member_type = 'identity'
			  AND d.member_identity_id = @identity AND `+dmActive+`)
		+
		(SELECT count(*) FROM grp_direct_memberships d
			JOIN grp_effective e ON e.tenant_id = @tenant AND e.group_id = d.member_group_id AND e.list_id = d.list_id
			  AND e.identity_id = @identity
			WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id AND d.member_type = 'group'
			  AND `+dmActive+`)`)
	// the same, but each group row also needs its child to be a member by its own
	// rows: used by IsMember to ignore rows the time wheel has not yet applied
	grpDmActiveIdentityRow = tq("grp_dm.active_identity_row", `SELECT count(*) FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id AND d.member_type = 'identity'
		  AND d.member_identity_id = @identity AND `+dmActive)
	grpDmActiveGroupRows = tq("grp_dm.active_group_rows", `SELECT d.member_group_id FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id AND d.member_type = 'group'
		  AND `+dmActive+` ORDER BY d.member_group_id`)
	// rows whose enabled_from or disabled_at fell in (@from, @to]: the time wheel's input
	grpDmEnabledIn = tq("grp_dm.enabled_in", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.enabled_from IS NOT NULL AND d.enabled_from > @from AND d.enabled_from <= @to
		ORDER BY d.enabled_from, d.id`)
	grpDmDisabledIn = tq("grp_dm.disabled_in", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.disabled_at IS NOT NULL AND d.disabled_at > @from AND d.disabled_at <= @to
		ORDER BY d.disabled_at, d.id`)
	grpDmNextEnable = tq("grp_dm.next_enable", `SELECT MIN(d.enabled_from) FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.enabled_from IS NOT NULL AND d.enabled_from > @now`)
	grpDmNextDisable = tq("grp_dm.next_disable", `SELECT MIN(d.disabled_at) FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.disabled_at IS NOT NULL AND d.disabled_at > @now`)

	// ---- effective membership
	grpEffSupport = tq("grp_eff.support", `SELECT e.support FROM grp_effective e
		WHERE e.tenant_id = @tenant AND e.group_id = @group_id AND e.list_id = @list_id AND e.identity_id = @identity`)
	grpEffUpsert = tq("grp_eff.upsert", `
		INSERT INTO grp_effective (tenant_id, group_id, list_id, identity_id, support, since)
		VALUES (@tenant, @group_id, @list_id, @identity, @support, @since)
		ON CONFLICT (tenant_id, group_id, list_id, identity_id) DO UPDATE SET support = @support`)
	grpEffDelete = tq("grp_eff.delete", `DELETE FROM grp_effective
		WHERE tenant_id = @tenant AND group_id = @group_id AND list_id = @list_id AND identity_id = @identity`)
	grpEffDeleteGroup = tq("grp_eff.delete_group", `DELETE FROM grp_effective
		WHERE tenant_id = @tenant AND group_id = @group_id`)
	grpEffCount = tq("grp_eff.count", `SELECT count(*) FROM grp_effective e
		WHERE e.tenant_id = @tenant AND e.group_id = @group_id AND (@list_id = '' OR e.list_id = @list_id)`)
	grpEffIdentitiesAfter = tq("grp_eff.identities_after", `SELECT e.identity_id FROM grp_effective e
		WHERE e.tenant_id = @tenant AND e.group_id = @group_id AND e.list_id = @list_id AND e.identity_id > @after
		ORDER BY e.identity_id LIMIT @limit`)
	grpEffList = tq("grp_eff.list", `SELECT e.identity_id, e.support, e.since FROM grp_effective e
		WHERE e.tenant_id = @tenant AND e.group_id = @group_id AND e.list_id = @list_id
		ORDER BY e.identity_id LIMIT @limit OFFSET @offset`)
	// which (group, list) pairs have effective rows at all (verification finds orphans)
	grpEffPairs = tq("grp_eff.pairs", `SELECT DISTINCT e.group_id, e.list_id FROM grp_effective e
		WHERE e.tenant_id = @tenant ORDER BY e.group_id, e.list_id`)
	grpEffGroupsOf = tq("grp_eff.groups_of", `SELECT e.group_id FROM grp_effective e
		WHERE e.tenant_id = @tenant AND e.identity_id = @identity AND e.list_id = @list_id ORDER BY e.group_id`)

	// ---- dependency DAG
	grpDepInsert = tq("grp_deps.insert", `
		INSERT INTO grp_deps (tenant_id, parent_group_id, child_group_id, kind, list_id)
		VALUES (@tenant, @parent, @child, @kind, @list_id)
		ON CONFLICT (tenant_id, parent_group_id, child_group_id, kind, list_id) DO NOTHING`)
	grpDepDelete = tq("grp_deps.delete", `DELETE FROM grp_deps
		WHERE tenant_id = @tenant AND parent_group_id = @parent AND child_group_id = @child AND kind = @kind AND list_id = @list_id`)
	grpDepsOf = tq("grp_deps.of_parent", `SELECT d.parent_group_id, d.child_group_id, d.kind, d.list_id FROM grp_deps d
		WHERE d.tenant_id = @tenant AND d.parent_group_id = @parent ORDER BY d.child_group_id, d.kind, d.list_id`)
	grpDepsAll = tq("grp_deps.all", `SELECT d.parent_group_id, d.child_group_id, d.kind, d.list_id FROM grp_deps d
		WHERE d.tenant_id = @tenant ORDER BY d.parent_group_id, d.child_group_id, d.kind, d.list_id`)
	grpDepParents = tq("grp_deps.parents", `SELECT DISTINCT d.parent_group_id FROM grp_deps d
		WHERE d.tenant_id = @tenant AND d.child_group_id = @child AND d.list_id = @list_id ORDER BY d.parent_group_id`)
	grpDepPairs = tq("grp_deps.pair_count", `SELECT count(*) FROM grp_deps d
		WHERE d.tenant_id = @tenant AND d.parent_group_id = @parent AND d.child_group_id = @child`)
	grpDepChildren = tq("grp_deps.children", `SELECT DISTINCT d.child_group_id FROM grp_deps d
		WHERE d.tenant_id = @tenant AND d.parent_group_id = @parent ORDER BY d.child_group_id`)
	grpDepChildrenInList = tq("grp_deps.children_in_list", `SELECT DISTINCT d.child_group_id FROM grp_deps d
		WHERE d.tenant_id = @tenant AND d.parent_group_id = @parent AND d.list_id = @list_id ORDER BY d.child_group_id`)

	// ---- closure
	grpClosureAncestors = tq("grp_closure.ancestors", `SELECT c.ancestor_id, c.descendant_id, c.paths, c.min_depth FROM grp_closure c
		WHERE c.tenant_id = @tenant AND c.descendant_id = @group_id ORDER BY c.ancestor_id`)
	grpClosureDescendants = tq("grp_closure.descendants", `SELECT c.ancestor_id, c.descendant_id, c.paths, c.min_depth FROM grp_closure c
		WHERE c.tenant_id = @tenant AND c.ancestor_id = @group_id ORDER BY c.descendant_id`)
	grpClosureAll = tq("grp_closure.all", `SELECT c.ancestor_id, c.descendant_id, c.paths, c.min_depth FROM grp_closure c
		WHERE c.tenant_id = @tenant ORDER BY c.ancestor_id, c.descendant_id`)
	grpClosureAncestorCount = tq("grp_closure.ancestor_count", `SELECT count(*) FROM grp_closure c
		WHERE c.tenant_id = @tenant AND c.descendant_id = @group_id`)
	grpClosureGet = tq("grp_closure.get", `SELECT c.ancestor_id, c.descendant_id, c.paths, c.min_depth FROM grp_closure c
		WHERE c.tenant_id = @tenant AND c.ancestor_id = @ancestor AND c.descendant_id = @descendant`)
	grpClosureAdd = tq("grp_closure.add", `
		INSERT INTO grp_closure (tenant_id, ancestor_id, descendant_id, paths, min_depth)
		VALUES (@tenant, @ancestor, @descendant, @paths, @min_depth)
		ON CONFLICT (tenant_id, ancestor_id, descendant_id) DO UPDATE SET paths = grp_closure.paths + @paths, min_depth = CASE WHEN grp_closure.min_depth < @min_depth THEN grp_closure.min_depth ELSE @min_depth END`)
	grpClosureSub = tq("grp_closure.sub", `UPDATE grp_closure SET paths = paths - @paths
		WHERE tenant_id = @tenant AND ancestor_id = @ancestor AND descendant_id = @descendant`)
	grpClosureSetDepth = tq("grp_closure.set_depth", `UPDATE grp_closure SET min_depth = @min_depth
		WHERE tenant_id = @tenant AND ancestor_id = @ancestor AND descendant_id = @descendant`)
	grpClosureDrop = tq("grp_closure.drop_empty", `DELETE FROM grp_closure
		WHERE tenant_id = @tenant AND ancestor_id = @ancestor AND descendant_id = @descendant AND paths <= 0`)
	grpClosureDelete = tq("grp_closure.delete", `DELETE FROM grp_closure
		WHERE tenant_id = @tenant AND ancestor_id = @ancestor AND descendant_id = @descendant`)

	// ---- levels
	grpLevelGet = tq("grp_levels.get", `SELECT l.level FROM grp_levels l WHERE l.tenant_id = @tenant AND l.group_id = @group_id`)
	grpLevelSet = tq("grp_levels.set", `
		INSERT INTO grp_levels (tenant_id, group_id, level) VALUES (@tenant, @group_id, @level)
		ON CONFLICT (tenant_id, group_id) DO UPDATE SET level = @level`)
	grpLevelsAll = tq("grp_levels.all", `SELECT l.group_id, l.level FROM grp_levels l WHERE l.tenant_id = @tenant ORDER BY l.group_id`)
	// the highest level among a group's children, -1 when it has none
	grpLevelOfChildren = tq("grp_levels.children_max", `SELECT COALESCE(MAX(COALESCE(l.level, 0)), -1) FROM grp_deps d
		LEFT JOIN grp_levels l ON l.tenant_id = @tenant AND l.group_id = d.child_group_id
		WHERE d.tenant_id = @tenant AND d.parent_group_id = @group_id`)

	// ---- composite factors and group definition
	grpFactorsOf = tq("grp_factors.of", `SELECT f.factor_group_id FROM grp_composite_factors f
		WHERE f.tenant_id = @tenant AND f.group_id = @group_id ORDER BY f.position`)
	grpFactorsAll = tq("grp_factors.all", `SELECT f.group_id, f.factor_group_id FROM grp_composite_factors f
		WHERE f.tenant_id = @tenant ORDER BY f.group_id, f.position`)
	grpFactorInsert = tq("grp_factors.insert", `INSERT INTO grp_composite_factors (tenant_id, group_id, position, factor_group_id)
		VALUES (@tenant, @group_id, @position, @factor)`)
	grpFactorsDelete      = tq("grp_factors.delete", `DELETE FROM grp_composite_factors WHERE tenant_id = @tenant AND group_id = @group_id`)
	grpGroupSetDefinition = tq("grp_groups.set_definition", `UPDATE grp_groups SET definition = @definition, composite_op = @composite_op,
		version = version + 1 WHERE tenant_id = @tenant AND id = @id`)
	grpGroupAddEffective = tq("grp_groups.add_effective", `UPDATE grp_groups SET effective_count = effective_count + @delta,
		effective_version = effective_version + 1 WHERE tenant_id = @tenant AND id = @id`)
	grpGroupSetEffectiveCount = tq("grp_groups.set_effective_count", `UPDATE grp_groups SET effective_count = @count
		WHERE tenant_id = @tenant AND id = @id`)
	grpGroupSetRecompute = tq("grp_groups.set_recompute", `UPDATE grp_groups SET recompute_state = @state
		WHERE tenant_id = @tenant AND id = @id`)
	grpGroupsAll       = tq("grp_groups.all", `SELECT `+grpGroupCols+` FROM grp_groups g WHERE g.tenant_id = @tenant ORDER BY g.id`)
	grpGroupsEnabledIn = tq("grp_groups.enabled_in", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.enabled_from IS NOT NULL AND g.enabled_from > @from AND g.enabled_from <= @to ORDER BY g.id`)
	grpGroupsDisabledIn = tq("grp_groups.disabled_in", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.disabled_at IS NOT NULL AND g.disabled_at > @from AND g.disabled_at <= @to ORDER BY g.id`)
	grpGroupNextEnable = tq("grp_groups.next_enable", `SELECT MIN(g.enabled_from) FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.enabled_from IS NOT NULL AND g.enabled_from > @now`)
	grpGroupNextDisable = tq("grp_groups.next_disable", `SELECT MIN(g.disabled_at) FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.disabled_at IS NOT NULL AND g.disabled_at > @now`)
	// the members of a group's children, by their cached counts: the work estimate of a recompute
	grpChildEffectiveSum = tq("grp_groups.child_effective_sum", `SELECT COALESCE(SUM(c.effective_count), 0) FROM grp_deps d
		JOIN grp_groups c ON c.tenant_id = @tenant AND c.id = d.child_group_id
		WHERE d.tenant_id = @tenant AND d.parent_group_id = @group_id`)

	// ---- engine queue and state
	grpStateEnsure = tq("grp_state.ensure", `INSERT INTO grp_engine_state (tenant_id, next_seq) VALUES (@tenant, 1)
		ON CONFLICT (tenant_id) DO NOTHING`)
	grpStateGet         = tq("grp_state.get", `SELECT s.next_seq, s.wheel_at, s.verified_at FROM grp_engine_state s WHERE s.tenant_id = @tenant`)
	grpStateBump        = tq("grp_state.bump", `UPDATE grp_engine_state SET next_seq = next_seq + 1 WHERE tenant_id = @tenant`)
	grpStateSetWheel    = tq("grp_state.set_wheel", `UPDATE grp_engine_state SET wheel_at = @at WHERE tenant_id = @tenant`)
	grpStateSetVerified = tq("grp_state.set_verified", `UPDATE grp_engine_state SET verified_at = @at WHERE tenant_id = @tenant`)
	grpQueueInsert      = tq("grp_queue.insert", `INSERT INTO grp_engine_queue (tenant_id, seq, kind, payload, enqueued_at)
		VALUES (@tenant, @seq, @kind, @payload, @enqueued_at)`)
	grpQueueFirst = tq("grp_queue.first", `SELECT q.seq, q.kind, q.payload, q.enqueued_at FROM grp_engine_queue q
		WHERE q.tenant_id = @tenant ORDER BY q.seq LIMIT 1`)
	grpQueueGet = tq("grp_queue.get", `SELECT q.seq, q.kind, q.payload, q.enqueued_at FROM grp_engine_queue q
		WHERE q.tenant_id = @tenant AND q.seq = @seq`)
	grpQueueSetPayload = tq("grp_queue.set_payload", `UPDATE grp_engine_queue SET payload = @payload WHERE tenant_id = @tenant AND seq = @seq`)
	grpQueueDelete     = tq("grp_queue.delete", `DELETE FROM grp_engine_queue WHERE tenant_id = @tenant AND seq = @seq`)
	grpQueueCount      = tq("grp_queue.count", `SELECT count(*) FROM grp_engine_queue q WHERE q.tenant_id = @tenant`)
	// the payload is JSON text; the group is matched in Go (json_extract is SQLite-only)
	grpQueuePayloads = tq("grp_queue.payloads", `SELECT q.payload FROM grp_engine_queue q WHERE q.tenant_id = @tenant`)
)

func scanGrpDirect(s scanner) (*DirectMembership, error) {
	var m DirectMembership
	var tenant, typ, created string
	var ident sql.NullInt64
	var grp, from, to, ref, reason, by sql.NullString
	if err := s.Scan(&m.ID, &tenant, &m.GroupID, &m.ListID, &typ, &ident, &grp, &from, &to, &m.Source, &ref, &reason, &by, &created); err != nil {
		return nil, err
	}
	var err error
	if m.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	m.MemberType, m.MemberIdentity = MemberType(typ), intp(ident)
	if grp.Valid {
		g := GroupID(grp.String)
		m.MemberGroup = &g
	}
	m.SourceRef, m.Reason, m.CreatedBy = strp(ref), strp(reason), strp(by)
	if m.EnabledFrom, err = rtp(from); err != nil {
		return nil, err
	}
	if m.DisabledAt, err = rtp(to); err != nil {
		return nil, err
	}
	m.CreatedAt, err = ParseRT(created)
	return &m, err
}

func scanGrpDep(s scanner) (*GrpDep, error) {
	var d GrpDep
	var kind string
	err := s.Scan(&d.Parent, &d.Child, &kind, &d.List)
	d.Kind = DepKind(kind)
	return &d, err
}

func scanGrpClosure(s scanner) (*GrpClosureRow, error) {
	var c GrpClosureRow
	err := s.Scan(&c.Ancestor, &c.Descendant, &c.Paths, &c.MinDepth)
	return &c, err
}

func scanGroupID(s scanner) (*GroupID, error) {
	var g GroupID
	err := s.Scan(&g)
	return &g, err
}

func scanInt64(s scanner) (*int64, error) {
	var n int64
	err := s.Scan(&n)
	return &n, err
}

func scanEngineJob(s scanner) (*EngineJob, error) {
	var j EngineJob
	var at string
	if err := s.Scan(&j.Seq, &j.Kind, &j.Payload, &at); err != nil {
		return nil, err
	}
	var err error
	j.EnqueuedAt, err = ParseRT(at)
	return &j, err
}

// ---------------------------------------------------------------- direct memberships

// GrpDirectMembership returns a direct membership row or ErrNotFound.
func (tx *TenantTx) GrpDirectMembership(id string) (*DirectMembership, error) {
	return one(tx, scanGrpDirect, grpDmGet, sql.Named("id", id))
}

// GrpDirectFind finds the row naming member (an identity id for MemberIdentity,
// a group id for MemberGroup) in a group's list, or ErrNotFound.
func (tx *TenantTx) GrpDirectFind(group GroupID, list ListID, typ MemberType, member string) (*DirectMembership, error) {
	s := grpDmFindIdentity
	var arg any = member
	if typ == MemberGroup {
		s = grpDmFindGroup
	} else {
		n, err := strconv.ParseInt(member, 10, 64)
		if err != nil {
			return nil, ErrNotFound
		}
		arg = n
	}
	return one(tx, scanGrpDirect, s, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)), sql.Named("member", arg))
}

// GrpDirect lists a group's direct memberships, oldest first; a zero Limit
// means 100.
func (tx *TenantTx) GrpDirect(f GrpDirectFilter) ([]*DirectMembership, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	return collect(tx, scanGrpDirect, grpDmList, sql.Named("group_id", string(f.Group)), sql.Named("list_id", string(f.List)),
		sql.Named("member_type", string(f.MemberType)), sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))
}

// GrpDirectCount counts a group's direct memberships (Group is required).
func (tx *TenantTx) GrpDirectCount(f GrpDirectFilter) (int, error) {
	return tx.count(grpDmCount, sql.Named("group_id", string(f.Group)), sql.Named("list_id", string(f.List)),
		sql.Named("member_type", string(f.MemberType)))
}

// InsertGrpDirect inserts m, assigning its id (when empty). m.TenantID must be
// zero or the transaction's tenant.
func (tx *TenantTx) InsertGrpDirect(m *DirectMembership) error {
	if err := tx.own(m.TenantID); err != nil {
		return err
	}
	if m.ID == "" {
		m.ID = uuid.NewString()
	}
	var ident, grp any
	if m.MemberIdentity != nil {
		ident = *m.MemberIdentity
	}
	if m.MemberGroup != nil {
		grp = string(*m.MemberGroup)
	}
	m.TenantID = tx.tenant
	_, err := tx.exec(grpDmInsert, sql.Named("id", m.ID), sql.Named("group_id", string(m.GroupID)), sql.Named("list_id", string(m.ListID)),
		sql.Named("member_type", string(m.MemberType)), sql.Named("member_identity_id", ident), sql.Named("member_group_id", grp),
		sql.Named("enabled_from", RTP(m.EnabledFrom)), sql.Named("disabled_at", RTP(m.DisabledAt)), sql.Named("source", m.Source),
		sql.Named("source_ref", SP(m.SourceRef)), sql.Named("reason", SP(m.Reason)), sql.Named("created_by", SP(m.CreatedBy)),
		sql.Named("created_at", RT(m.CreatedAt)))
	return err
}

// SetGrpDirectDates changes a row's dates and reason.
func (tx *TenantTx) SetGrpDirectDates(m *DirectMembership) error {
	res, err := tx.exec(grpDmSetDates, sql.Named("id", m.ID), sql.Named("enabled_from", RTP(m.EnabledFrom)),
		sql.Named("disabled_at", RTP(m.DisabledAt)), sql.Named("reason", SP(m.Reason)))
	return rowsOrNotFound(res, err)
}

// DeleteGrpDirect removes a direct membership row.
func (tx *TenantTx) DeleteGrpDirect(id string) error {
	res, err := tx.exec(grpDmDelete, sql.Named("id", id))
	return rowsOrNotFound(res, err)
}

// DeleteGrpDirectOf removes every direct row of a group and returns how many.
func (tx *TenantTx) DeleteGrpDirectOf(group GroupID) (int64, error) {
	res, err := tx.exec(grpDmDeleteOf, sql.Named("group_id", string(group)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GrpDirectIdentitiesAfter lists up to limit identity ids with a direct row in
// the group's list, above the cursor, ascending.
func (tx *TenantTx) GrpDirectIdentitiesAfter(group GroupID, list ListID, after int64, limit int) ([]int64, error) {
	return ints(tx, grpDmIdentitiesAfter, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("after", after), sql.Named("limit", limit))
}

// GrpDirectLists lists the lists a group has direct rows in.
func (tx *TenantTx) GrpDirectLists(group GroupID) ([]ListID, error) {
	ids, err := collect(tx, scanGroupID, grpDmLists, sql.Named("group_id", string(group)))
	out := make([]ListID, len(ids))
	for i, id := range ids {
		out[i] = ListID(*id)
	}
	return out, err
}

// GrpDirectGroupEdges lists the distinct (parent, child, list) of every
// group-in-group direct row: the nest edges the dependency DAG must hold.
func (tx *TenantTx) GrpDirectGroupEdges() ([]GrpDep, error) {
	rows, err := tx.query(grpDmGroupEdges)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrpDep
	for rows.Next() {
		d := GrpDep{Kind: DepNest}
		if err := rows.Scan(&d.Parent, &d.Child, &d.List); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GrpBasicSupport computes, from the stored rows, the support a basic group
// should have for an identity at now (design §6.2 invariant I1): its active
// direct identity row plus its active direct group rows whose child is
// effective for the identity. The child's effective rows must be current.
func (tx *TenantTx) GrpBasicSupport(group GroupID, list ListID, identity int64, now time.Time) (int32, error) {
	var n int32
	err := tx.queryRow(grpBasicSupport, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("identity", identity), sql.Named("now", RT(now))).Scan(&n)
	return n, err
}

// GrpDirectIdentityActive reports whether the group has a direct identity row
// for the identity that counts at now.
func (tx *TenantTx) GrpDirectIdentityActive(group GroupID, list ListID, identity int64, now time.Time) (bool, error) {
	n, err := tx.count(grpDmActiveIdentityRow, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("identity", identity), sql.Named("now", RT(now)))
	return n > 0, err
}

// GrpDirectActiveChildren lists the groups the group has an active direct
// group row for at now.
func (tx *TenantTx) GrpDirectActiveChildren(group GroupID, list ListID, now time.Time) ([]GroupID, error) {
	ids, err := collect(tx, scanGroupID, grpDmActiveGroupRows, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("now", RT(now)))
	out := make([]GroupID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// GrpDirectEnabledIn lists the rows whose enabled_from lies in (from, to].
func (tx *TenantTx) GrpDirectEnabledIn(from, to time.Time) ([]*DirectMembership, error) {
	return collect(tx, scanGrpDirect, grpDmEnabledIn, sql.Named("from", RT(from)), sql.Named("to", RT(to)))
}

// GrpDirectDisabledIn lists the rows whose disabled_at lies in (from, to].
func (tx *TenantTx) GrpDirectDisabledIn(from, to time.Time) ([]*DirectMembership, error) {
	return collect(tx, scanGrpDirect, grpDmDisabledIn, sql.Named("from", RT(from)), sql.Named("to", RT(to)))
}

// GrpNextBoundary returns the earliest enabled_from or disabled_at after now
// on any direct row or group, or nil: when the time wheel next has work.
func (tx *TenantTx) GrpNextBoundary(now time.Time) (*time.Time, error) {
	var best *time.Time
	for _, s := range []tstmt{grpDmNextEnable, grpDmNextDisable, grpGroupNextEnable, grpGroupNextDisable} {
		var v sql.NullString
		if err := tx.queryRow(s, sql.Named("now", RT(now))).Scan(&v); err != nil {
			return nil, err
		}
		t, err := rtp(v)
		if err != nil {
			return nil, err
		}
		if t != nil && (best == nil || t.Before(*best)) {
			best = t
		}
	}
	return best, nil
}

// ---------------------------------------------------------------- effective membership

// GrpEffectiveSupport returns the support of an effective row, 0 when there is none.
func (tx *TenantTx) GrpEffectiveSupport(group GroupID, list ListID, identity int64) (int32, error) {
	var n int32
	err := tx.queryRow(grpEffSupport, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("identity", identity)).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// SetGrpEffective writes an effective row with the given support (> 0). A row
// that exists keeps its since.
func (tx *TenantTx) SetGrpEffective(group GroupID, list ListID, identity int64, support int32, since time.Time) error {
	_, err := tx.exec(grpEffUpsert, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("identity", identity), sql.Named("support", support), sql.Named("since", RT(since)))
	return err
}

// DeleteGrpEffective removes an effective row if there is one.
func (tx *TenantTx) DeleteGrpEffective(group GroupID, list ListID, identity int64) error {
	_, err := tx.exec(grpEffDelete, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)), sql.Named("identity", identity))
	return err
}

// DeleteGrpEffectiveOf removes every effective row of a group (any list).
func (tx *TenantTx) DeleteGrpEffectiveOf(group GroupID) error {
	_, err := tx.exec(grpEffDeleteGroup, sql.Named("group_id", string(group)))
	return err
}

// GrpEffectiveCount counts a group's effective rows; an empty list counts every list.
func (tx *TenantTx) GrpEffectiveCount(group GroupID, list ListID) (int, error) {
	return tx.count(grpEffCount, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)))
}

// GrpEffectiveIdentitiesAfter lists up to limit effective identity ids above
// the cursor, ascending.
func (tx *TenantTx) GrpEffectiveIdentitiesAfter(group GroupID, list ListID, after int64, limit int) ([]int64, error) {
	return ints(tx, grpEffIdentitiesAfter, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("after", after), sql.Named("limit", limit))
}

// GrpEffectiveList pages a group's effective members by identity id.
func (tx *TenantTx) GrpEffectiveList(group GroupID, list ListID, limit, offset int) ([]GrpEffectiveRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := tx.query(grpEffList, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("limit", limit), sql.Named("offset", offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrpEffectiveRow
	for rows.Next() {
		var r GrpEffectiveRow
		var since string
		if err := rows.Scan(&r.Identity, &r.Support, &since); err != nil {
			return nil, err
		}
		if r.Since, err = ParseRT(since); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GrpEffectivePairs lists every (group, list) that has effective rows.
func (tx *TenantTx) GrpEffectivePairs() ([]GrpDep, error) {
	rows, err := tx.query(grpEffPairs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrpDep
	for rows.Next() {
		var d GrpDep
		if err := rows.Scan(&d.Parent, &d.List); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GrpEffectiveGroupsOf lists the groups an identity is effectively in, in the list.
func (tx *TenantTx) GrpEffectiveGroupsOf(identity int64, list ListID) ([]GroupID, error) {
	ids, err := collect(tx, scanGroupID, grpEffGroupsOf, sql.Named("identity", identity), sql.Named("list_id", string(list)))
	out := make([]GroupID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// ---------------------------------------------------------------- dependency DAG

// InsertGrpDep adds an edge to the dependency DAG (a no-op if it exists).
func (tx *TenantTx) InsertGrpDep(d GrpDep) error {
	_, err := tx.exec(grpDepInsert, sql.Named("parent", string(d.Parent)), sql.Named("child", string(d.Child)),
		sql.Named("kind", string(d.Kind)), sql.Named("list_id", string(d.List)))
	return err
}

// DeleteGrpDep removes an edge of the dependency DAG.
func (tx *TenantTx) DeleteGrpDep(d GrpDep) error {
	_, err := tx.exec(grpDepDelete, sql.Named("parent", string(d.Parent)), sql.Named("child", string(d.Child)),
		sql.Named("kind", string(d.Kind)), sql.Named("list_id", string(d.List)))
	return err
}

// GrpDepsOf lists the edges that feed a parent group.
func (tx *TenantTx) GrpDepsOf(parent GroupID) ([]GrpDep, error) {
	return derefs(collect(tx, scanGrpDep, grpDepsOf, sql.Named("parent", string(parent))))
}

// GrpDepsAll lists every edge of the tenant's dependency DAG.
func (tx *TenantTx) GrpDepsAll() ([]GrpDep, error) {
	return derefs(collect(tx, scanGrpDep, grpDepsAll))
}

// GrpDepParents lists the distinct groups a child group feeds in a list.
func (tx *TenantTx) GrpDepParents(child GroupID, list ListID) ([]GroupID, error) {
	ids, err := collect(tx, scanGroupID, grpDepParents, sql.Named("child", string(child)), sql.Named("list_id", string(list)))
	out := make([]GroupID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// GrpDepPairCount counts the edges (any kind or list) between a parent and a child.
func (tx *TenantTx) GrpDepPairCount(parent, child GroupID) (int, error) {
	return tx.count(grpDepPairs, sql.Named("parent", string(parent)), sql.Named("child", string(child)))
}

// GrpDepChildren lists the distinct child groups of a parent, in one list or
// (empty list) in any.
func (tx *TenantTx) GrpDepChildren(parent GroupID, list ListID) ([]GroupID, error) {
	var ids []*GroupID
	var err error
	if list == "" {
		ids, err = collect(tx, scanGroupID, grpDepChildren, sql.Named("parent", string(parent)))
	} else {
		ids, err = collect(tx, scanGroupID, grpDepChildrenInList, sql.Named("parent", string(parent)), sql.Named("list_id", string(list)))
	}
	out := make([]GroupID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// ---------------------------------------------------------------- closure and levels

// GrpClosureAncestors lists the groups that depend on the group (not itself).
func (tx *TenantTx) GrpClosureAncestors(group GroupID) ([]GrpClosureRow, error) {
	return derefs(collect(tx, scanGrpClosure, grpClosureAncestors, sql.Named("group_id", string(group))))
}

// GrpClosureDescendants lists the groups the group depends on (not itself).
func (tx *TenantTx) GrpClosureDescendants(group GroupID) ([]GrpClosureRow, error) {
	return derefs(collect(tx, scanGrpClosure, grpClosureDescendants, sql.Named("group_id", string(group))))
}

// GrpClosureAll lists the whole closure of the tenant.
func (tx *TenantTx) GrpClosureAll() ([]GrpClosureRow, error) {
	return derefs(collect(tx, scanGrpClosure, grpClosureAll))
}

// GrpClosureAncestorCount counts the groups that depend on the group.
func (tx *TenantTx) GrpClosureAncestorCount(group GroupID) (int, error) {
	return tx.count(grpClosureAncestorCount, sql.Named("group_id", string(group)))
}

// GrpClosureGet returns one closure row or ErrNotFound.
func (tx *TenantTx) GrpClosureGet(ancestor, descendant GroupID) (*GrpClosureRow, error) {
	return one(tx, scanGrpClosure, grpClosureGet, sql.Named("ancestor", string(ancestor)), sql.Named("descendant", string(descendant)))
}

// AddGrpClosure adds paths to a closure row, creating it, and keeps the
// shorter of the two min depths.
func (tx *TenantTx) AddGrpClosure(ancestor, descendant GroupID, paths int64, minDepth int) error {
	_, err := tx.exec(grpClosureAdd, sql.Named("ancestor", string(ancestor)), sql.Named("descendant", string(descendant)),
		sql.Named("paths", paths), sql.Named("min_depth", minDepth))
	return err
}

// SubGrpClosure removes paths from a closure row and deletes it when none is left.
func (tx *TenantTx) SubGrpClosure(ancestor, descendant GroupID, paths int64) error {
	a, d := sql.Named("ancestor", string(ancestor)), sql.Named("descendant", string(descendant))
	if _, err := tx.exec(grpClosureSub, a, d, sql.Named("paths", paths)); err != nil {
		return err
	}
	_, err := tx.exec(grpClosureDrop, a, d)
	return err
}

// SetGrpClosureDepth sets a closure row's min depth.
func (tx *TenantTx) SetGrpClosureDepth(ancestor, descendant GroupID, minDepth int) error {
	_, err := tx.exec(grpClosureSetDepth, sql.Named("ancestor", string(ancestor)), sql.Named("descendant", string(descendant)),
		sql.Named("min_depth", minDepth))
	return err
}

// DeleteGrpClosure removes a closure row outright (verification repairs).
func (tx *TenantTx) DeleteGrpClosure(ancestor, descendant GroupID) error {
	_, err := tx.exec(grpClosureDelete, sql.Named("ancestor", string(ancestor)), sql.Named("descendant", string(descendant)))
	return err
}

// GrpLevel returns a group's level; a group without a row is a leaf (0).
func (tx *TenantTx) GrpLevel(group GroupID) (int, error) {
	var n int
	err := tx.queryRow(grpLevelGet, sql.Named("group_id", string(group))).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// SetGrpLevel stores a group's level.
func (tx *TenantTx) SetGrpLevel(group GroupID, level int) error {
	_, err := tx.exec(grpLevelSet, sql.Named("group_id", string(group)), sql.Named("level", level))
	return err
}

// GrpLevels lists every stored level.
func (tx *TenantTx) GrpLevels() ([]GrpLevel, error) {
	rows, err := tx.query(grpLevelsAll)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrpLevel
	for rows.Next() {
		var l GrpLevel
		if err := rows.Scan(&l.Group, &l.Level); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GrpMaxChildLevel returns the highest level among a group's children, or -1
// when it has none.
func (tx *TenantTx) GrpMaxChildLevel(group GroupID) (int, error) {
	var n int
	err := tx.queryRow(grpLevelOfChildren, sql.Named("group_id", string(group))).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- composites and group state

// GrpFactors lists a composite's factors in position order.
func (tx *TenantTx) GrpFactors(group GroupID) ([]GroupID, error) {
	ids, err := collect(tx, scanGroupID, grpFactorsOf, sql.Named("group_id", string(group)))
	out := make([]GroupID, len(ids))
	for i, id := range ids {
		out[i] = *id
	}
	return out, err
}

// GrpFactorsAll lists every (composite, factor) pair of the tenant.
func (tx *TenantTx) GrpFactorsAll() ([]GrpDep, error) {
	rows, err := tx.query(grpFactorsAll)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrpDep
	for rows.Next() {
		d := GrpDep{Kind: DepFactor}
		if err := rows.Scan(&d.Parent, &d.Child); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetGrpFactors replaces a composite's factor list.
func (tx *TenantTx) SetGrpFactors(group GroupID, factors []GroupID) error {
	if _, err := tx.exec(grpFactorsDelete, sql.Named("group_id", string(group))); err != nil {
		return err
	}
	for i, f := range factors {
		if _, err := tx.exec(grpFactorInsert, sql.Named("group_id", string(group)), sql.Named("position", i),
			sql.Named("factor", string(f))); err != nil {
			return err
		}
	}
	return nil
}

// SetGrpGroupDefinition changes a group's definition and composite operator
// (nil for a basic group) and bumps its version.
func (tx *TenantTx) SetGrpGroupDefinition(id GroupID, def Definition, op *CompositeOp) error {
	var o any
	if op != nil {
		o = string(*op)
	}
	res, err := tx.exec(grpGroupSetDefinition, sql.Named("id", string(id)), sql.Named("definition", string(def)), sql.Named("composite_op", o))
	return rowsOrNotFound(res, err)
}

// AddGrpEffectiveCount adds delta to a group's cached member count and bumps
// its effective_version (clients use it to see that the membership changed).
func (tx *TenantTx) AddGrpEffectiveCount(id GroupID, delta int64) error {
	res, err := tx.exec(grpGroupAddEffective, sql.Named("id", string(id)), sql.Named("delta", delta))
	return rowsOrNotFound(res, err)
}

// SetGrpEffectiveCount overwrites a group's cached member count (verification).
func (tx *TenantTx) SetGrpEffectiveCount(id GroupID, n int64) error {
	res, err := tx.exec(grpGroupSetEffectiveCount, sql.Named("id", string(id)), sql.Named("count", n))
	return rowsOrNotFound(res, err)
}

// SetGrpRecomputeState sets a group's recompute_state (clean, pending, failed).
func (tx *TenantTx) SetGrpRecomputeState(id GroupID, state string) error {
	res, err := tx.exec(grpGroupSetRecompute, sql.Named("id", string(id)), sql.Named("state", state))
	return rowsOrNotFound(res, err)
}

// GrpGroupsAll lists every group of the tenant (any status).
func (tx *TenantTx) GrpGroupsAll() ([]*NativeGroup, error) {
	return collect(tx, scanGrpGroup, grpGroupsAll)
}

// GrpGroupsEnabledIn lists the groups whose enabled_from lies in (from, to].
func (tx *TenantTx) GrpGroupsEnabledIn(from, to time.Time) ([]*NativeGroup, error) {
	return collect(tx, scanGrpGroup, grpGroupsEnabledIn, sql.Named("from", RT(from)), sql.Named("to", RT(to)))
}

// GrpGroupsDisabledIn lists the groups whose disabled_at lies in (from, to].
func (tx *TenantTx) GrpGroupsDisabledIn(from, to time.Time) ([]*NativeGroup, error) {
	return collect(tx, scanGrpGroup, grpGroupsDisabledIn, sql.Named("from", RT(from)), sql.Named("to", RT(to)))
}

// GrpChildEffectiveSum is the sum of the cached member counts of a group's children.
func (tx *TenantTx) GrpChildEffectiveSum(group GroupID) (int64, error) {
	var n int64
	err := tx.queryRow(grpChildEffectiveSum, sql.Named("group_id", string(group))).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- engine queue and state

func (tx *TenantTx) ensureEngineState() error {
	_, err := tx.exec(grpStateEnsure)
	return err
}

// GrpEngineState returns the tenant's engine state, creating it on first use.
func (tx *TenantTx) GrpEngineState() (*EngineState, error) {
	if tx.readOnly {
		return tx.readEngineState()
	}
	if err := tx.ensureEngineState(); err != nil {
		return nil, err
	}
	return tx.readEngineState()
}

func (tx *TenantTx) readEngineState() (*EngineState, error) {
	var st EngineState
	var wheel, verified sql.NullString
	err := tx.queryRow(grpStateGet).Scan(&st.NextSeq, &wheel, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return &EngineState{NextSeq: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	if st.WheelAt, err = rtp(wheel); err != nil {
		return nil, err
	}
	st.VerifiedAt, err = rtp(verified)
	return &st, err
}

// SetGrpWheelAt records when the time wheel last ran.
func (tx *TenantTx) SetGrpWheelAt(at time.Time) error {
	if err := tx.ensureEngineState(); err != nil {
		return err
	}
	_, err := tx.exec(grpStateSetWheel, sql.Named("at", RT(at)))
	return err
}

// SetGrpVerifiedAt records when the tenant was last verified.
func (tx *TenantTx) SetGrpVerifiedAt(at time.Time) error {
	if err := tx.ensureEngineState(); err != nil {
		return err
	}
	_, err := tx.exec(grpStateSetVerified, sql.Named("at", RT(at)))
	return err
}

// EnqueueGrpJob appends a job to the tenant's engine queue and returns its
// sequence number, which is the operation id. Numbers are never reused.
func (tx *TenantTx) EnqueueGrpJob(kind, payload string, now time.Time) (int64, error) {
	st, err := tx.GrpEngineState()
	if err != nil {
		return 0, err
	}
	if _, err := tx.exec(grpQueueInsert, sql.Named("seq", st.NextSeq), sql.Named("kind", kind), sql.Named("payload", payload),
		sql.Named("enqueued_at", RT(now))); err != nil {
		return 0, err
	}
	if _, err := tx.exec(grpStateBump); err != nil {
		return 0, err
	}
	return st.NextSeq, nil
}

// GrpFirstJob returns the oldest queued job or ErrNotFound.
func (tx *TenantTx) GrpFirstJob() (*EngineJob, error) { return one(tx, scanEngineJob, grpQueueFirst) }

// GrpJob returns a queued job by sequence number or ErrNotFound.
func (tx *TenantTx) GrpJob(seq int64) (*EngineJob, error) {
	return one(tx, scanEngineJob, grpQueueGet, sql.Named("seq", seq))
}

// SetGrpJobPayload replaces a queued job's payload (its progress).
func (tx *TenantTx) SetGrpJobPayload(seq int64, payload string) error {
	res, err := tx.exec(grpQueueSetPayload, sql.Named("seq", seq), sql.Named("payload", payload))
	return rowsOrNotFound(res, err)
}

// DeleteGrpJob removes a finished job.
func (tx *TenantTx) DeleteGrpJob(seq int64) error {
	res, err := tx.exec(grpQueueDelete, sql.Named("seq", seq))
	return rowsOrNotFound(res, err)
}

// GrpQueueLen counts the queued jobs.
func (tx *TenantTx) GrpQueueLen() (int, error) { return tx.count(grpQueueCount) }

// GrpQueuedFor counts the queued jobs on a group.
func (tx *TenantTx) GrpQueuedFor(group GroupID) (int, error) {
	rows, err := tx.query(grpQueuePayloads)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return 0, err
		}
		var p struct {
			Group string `json:"group"`
		}
		if json.Unmarshal([]byte(payload), &p) == nil && p.Group == string(group) {
			n++
		}
	}
	return n, rows.Err()
}

// GrpOpState says whether an operation id is still queued, finished or was
// never issued.
func (tx *TenantTx) GrpOpState(seq int64) (string, error) {
	if _, err := tx.GrpJob(seq); err == nil {
		return OpPending, nil
	} else if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	st, err := tx.GrpEngineState()
	if err != nil {
		return "", err
	}
	if seq >= 1 && seq < st.NextSeq {
		return OpDone, nil
	}
	return OpUnknown, nil
}

// ---------------------------------------------------------------- helpers

func ints(tx *TenantTx, s tstmt, args ...sql.NamedArg) ([]int64, error) {
	ns, err := collect(tx, scanInt64, s, args...)
	out := make([]int64, len(ns))
	for i, n := range ns {
		out[i] = *n
	}
	return out, err
}

func derefs[T any](ps []*T, err error) ([]T, error) {
	out := make([]T, len(ps))
	for i, p := range ps {
		out[i] = *p
	}
	return out, err
}
