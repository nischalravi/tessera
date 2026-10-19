package store

import (
	"database/sql"
	"errors"
	"time"
)

// Deployment-readiness connections and revisions. Every statement is
// tenant-scoped (tq) and linted like the rest of the store.

func isUnique(err error) bool {
	return isUniqueViolation(err)
}

const connCols = `c.id, c.tenant_id, c.name, c.connector_type, c.system, c.role, c.active_revision_id, c.health,
	c.technical_owner_id, c.business_owner, c.agent_id, c.created_at, c.updated_at, c.retired_at`

var (
	connectionsInsert = tq("connections.insert", `
		INSERT INTO connections (id, tenant_id, name, connector_type, system, role, health, technical_owner_id,
			business_owner, created_at, updated_at)
		VALUES (@id, @tenant, @name, @connector_type, @system, @role, 'none', @technical_owner_id, @business_owner,
			@created_at, @updated_at)`)
	connectionsGet = tq("connections.get", `
		SELECT `+connCols+` FROM connections c WHERE c.tenant_id = @tenant AND c.id = @id`)
	connectionsList = tq("connections.list", `
		SELECT `+connCols+` FROM connections c WHERE c.tenant_id = @tenant ORDER BY c.created_at, c.rowid`)
	connectionsSetOwners = tq("connections.set_owners", `
		UPDATE connections SET technical_owner_id = @technical_owner_id, business_owner = @business_owner,
			updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	connectionsSetLive = tq("connections.set_live", `
		UPDATE connections SET active_revision_id = @revision_id, health = @health, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	connectionsRetire = tq("connections.retire", `
		UPDATE connections SET retired_at = @now, health = 'none', updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
)

func scanConnection(s scanner) (*Connection, error) {
	var c Connection
	var tid string
	var active, tech, biz, agent, retired sql.NullString
	var created, updated string
	if err := s.Scan(&c.ID, &tid, &c.Name, &c.ConnectorType, &c.System, &c.Role, &active, &c.Health,
		&tech, &biz, &agent, &created, &updated, &retired); err != nil {
		return nil, err
	}
	var err error
	if c.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	c.ActiveRevisionID, c.TechnicalOwner, c.BusinessOwner, c.AgentID = strp(active), strp(tech), strp(biz), strp(agent)
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if c.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	c.RetiredAt, err = rtp(retired)
	return &c, err
}

// InsertConnection adds a connection; ErrDuplicate when the name or system is
// taken in this tenant.
func (tx *TenantTx) InsertConnection(x *Connection) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(connectionsInsert, sql.Named("id", x.ID), sql.Named("name", x.Name),
		sql.Named("connector_type", x.ConnectorType), sql.Named("system", x.System), sql.Named("role", x.Role),
		sql.Named("technical_owner_id", SP(x.TechnicalOwner)), sql.Named("business_owner", SP(x.BusinessOwner)),
		sql.Named("created_at", RT(x.CreatedAt)), sql.Named("updated_at", RT(x.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// Connection returns one connection or ErrNotFound.
func (tx *TenantTx) Connection(id string) (*Connection, error) {
	return one(tx, scanConnection, connectionsGet, sql.Named("id", id))
}

// Connections lists the tenant's connections, oldest first.
func (tx *TenantTx) Connections() ([]*Connection, error) {
	return collect(tx, scanConnection, connectionsList)
}

// UpdateConnectionOwners records the owners named in the revision config.
func (tx *TenantTx) UpdateConnectionOwners(id string, tech, biz *string, now time.Time) error {
	_, err := tx.exec(connectionsSetOwners, sql.Named("technical_owner_id", SP(tech)), sql.Named("business_owner", SP(biz)),
		sql.Named("now", RT(now)), sql.Named("id", id))
	return err
}

// SetConnectionLive points the connection at its live revision (nil for none) and sets its health.
func (tx *TenantTx) SetConnectionLive(id string, revisionID *string, health string, now time.Time) error {
	_, err := tx.exec(connectionsSetLive, sql.Named("revision_id", SP(revisionID)), sql.Named("health", health),
		sql.Named("now", RT(now)), sql.Named("id", id))
	return err
}

// MarkConnectionRetired stamps retired_at.
func (tx *TenantTx) MarkConnectionRetired(id string, now time.Time) error {
	_, err := tx.exec(connectionsRetire, sql.Named("now", RT(now)), sql.Named("id", id))
	return err
}

// ---------------------------------------------------------------- revisions

const revCols = `r.id, r.tenant_id, r.connection_id, r.rev, r.state, r.template_id, r.template_version, r.overlay_version,
	r.config, r.secret_ref, r.secret_version, r.config_hash, r.evidence_seq, r.write_mode, r.expected_counts,
	r.gate_report, r.activated_at, r.activated_by, r.created_by, r.created_at, r.updated_at`

var (
	revisionsInsert = tq("connection_revisions.insert", `
		INSERT INTO connection_revisions (id, tenant_id, connection_id, rev, state, template_id, template_version,
			overlay_version, config, secret_ref, secret_version, config_hash, write_mode, expected_counts, created_by,
			created_at, updated_at)
		VALUES (@id, @tenant, @connection_id, @rev, 'draft', @template_id, @template_version, @overlay_version, @config,
			@secret_ref, @secret_version, @config_hash, @write_mode, @expected_counts, @created_by, @created_at,
			@updated_at)`)
	revisionsGet = tq("connection_revisions.get", `
		SELECT `+revCols+` FROM connection_revisions r WHERE r.tenant_id = @tenant AND r.id = @id`)
	revisionsOfConnection = tq("connection_revisions.of_connection", `
		SELECT `+revCols+` FROM connection_revisions r
		WHERE r.tenant_id = @tenant AND r.connection_id = @connection_id ORDER BY r.rev DESC`)
	revisionsSetConfig = tq("connection_revisions.set_config", `
		UPDATE connection_revisions SET config = @config, config_hash = @config_hash, write_mode = @write_mode,
			expected_counts = @expected_counts, evidence_seq = evidence_seq + 1, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	revisionsSetSecret = tq("connection_revisions.set_secret", `
		UPDATE connection_revisions SET secret_ref = @secret_ref, secret_version = @secret_version,
			config_hash = @config_hash, evidence_seq = evidence_seq + 1, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	revisionsBumpEvidence = tq("connection_revisions.bump_evidence", `
		UPDATE connection_revisions SET evidence_seq = evidence_seq + 1, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	revisionsSetState = tq("connection_revisions.set_state", `
		UPDATE connection_revisions SET state = @to, gate_report = COALESCE(@gate_report, gate_report),
			activated_at = COALESCE(@activated_at, activated_at), activated_by = COALESCE(@activated_by, activated_by),
			updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND state = @from AND config_hash = @config_hash
			AND evidence_seq = @evidence_seq`)
)

func scanRevision(s scanner) (*ConnectionRevision, error) {
	var r ConnectionRevision
	var tid string
	var ref, ver, counts, gate, actAt, actBy sql.NullString
	var created, updated string
	if err := s.Scan(&r.ID, &tid, &r.ConnectionID, &r.Rev, &r.State, &r.TemplateID, &r.TemplateVersion,
		&r.OverlayVersion, &r.Config, &ref, &ver, &r.ConfigHash, &r.EvidenceSeq, &r.WriteMode, &counts, &gate,
		&actAt, &actBy, &r.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	r.SecretRef, r.SecretVersion, r.ExpectedCounts, r.GateReport, r.ActivatedBy = strp(ref), strp(ver), strp(counts), strp(gate), strp(actBy)
	if r.ActivatedAt, err = rtp(actAt); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = ParseRT(updated)
	return &r, err
}

// InsertRevision adds a revision. A new revision always starts in draft.
func (tx *TenantTx) InsertRevision(r *ConnectionRevision) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(revisionsInsert, sql.Named("id", r.ID), sql.Named("connection_id", r.ConnectionID),
		sql.Named("rev", r.Rev), sql.Named("template_id", r.TemplateID), sql.Named("template_version", r.TemplateVersion),
		sql.Named("overlay_version", r.OverlayVersion), sql.Named("config", r.Config), sql.Named("secret_ref", SP(r.SecretRef)),
		sql.Named("secret_version", SP(r.SecretVersion)), sql.Named("config_hash", r.ConfigHash),
		sql.Named("write_mode", r.WriteMode), sql.Named("expected_counts", SP(r.ExpectedCounts)),
		sql.Named("created_by", r.CreatedBy), sql.Named("created_at", RT(r.CreatedAt)), sql.Named("updated_at", RT(r.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// Revision returns one revision or ErrNotFound.
func (tx *TenantTx) Revision(id string) (*ConnectionRevision, error) {
	return one(tx, scanRevision, revisionsGet, sql.Named("id", id))
}

// Revisions lists a connection's revisions, newest first.
func (tx *TenantTx) Revisions(connectionID string) ([]*ConnectionRevision, error) {
	return collect(tx, scanRevision, revisionsOfConnection, sql.Named("connection_id", connectionID))
}

// UpdateRevisionConfig stores a new config, its hash and bumps the evidence sequence.
func (tx *TenantTx) UpdateRevisionConfig(id, config, configHash, writeMode string, expectedCounts *string, now time.Time) error {
	_, err := tx.exec(revisionsSetConfig, sql.Named("config", config), sql.Named("config_hash", configHash),
		sql.Named("write_mode", writeMode), sql.Named("expected_counts", SP(expectedCounts)), sql.Named("now", RT(now)),
		sql.Named("id", id))
	return err
}

// UpdateRevisionSecret stores a credential reference (never the secret) and the new config hash.
func (tx *TenantTx) UpdateRevisionSecret(id string, ref, version, configHash string, now time.Time) error {
	_, err := tx.exec(revisionsSetSecret, sql.Named("secret_ref", ref), sql.Named("secret_version", version),
		sql.Named("config_hash", configHash), sql.Named("now", RT(now)), sql.Named("id", id))
	return err
}

// BumpEvidence records that evidence a gate reads changed (attestation,
// skip, run, finding acceptance), so a concurrent activation's CAS fails.
func (tx *TenantTx) BumpEvidence(id string, now time.Time) error {
	_, err := tx.exec(revisionsBumpEvidence, sql.Named("now", RT(now)), sql.Named("id", id))
	return err
}

// StateChange is a compare-and-set state write.
type StateChange struct {
	RevisionID  string
	From, To    string
	ConfigHash  string // expected current config hash
	EvidenceSeq int64  // expected current evidence sequence
	GateReport  *string
	ActivatedBy *string
	Now         time.Time
}

// SetRevisionState is the only way a revision's state changes. Only package
// internal/readiness may call it (TestOnlyReadinessWritesConnectionState).
// It returns ErrStateConflict unless the revision is still in ch.From with
// the expected config hash and evidence sequence (and belongs to this tenant).
func (tx *TenantTx) SetRevisionState(ch StateChange) error {
	var activatedAt any
	if ch.To == StateActive && ch.ActivatedBy != nil {
		activatedAt = RT(ch.Now)
	}
	res, err := tx.exec(revisionsSetState, sql.Named("to", ch.To), sql.Named("gate_report", SP(ch.GateReport)),
		sql.Named("activated_at", activatedAt), sql.Named("activated_by", SP(ch.ActivatedBy)), sql.Named("now", RT(ch.Now)),
		sql.Named("id", ch.RevisionID), sql.Named("from", ch.From), sql.Named("config_hash", ch.ConfigHash),
		sql.Named("evidence_seq", ch.EvidenceSeq))
	if isUnique(err) {
		return ErrStateConflict // a second live or pending revision
	}
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrStateConflict
	}
	return nil
}

// ---------------------------------------------------------------- evidence

var (
	attestationsUpsert = tq("readiness_attestations.upsert", `
		INSERT INTO readiness_attestations (tenant_id, revision_id, item_id, actor_id, note, item_hash, config_hash,
			attested_at)
		VALUES (@tenant, @revision_id, @item_id, @actor_id, @note, @item_hash, @config_hash, @attested_at)
		ON CONFLICT (tenant_id, revision_id, item_id) DO UPDATE SET actor_id = excluded.actor_id, note = excluded.note,
			item_hash = excluded.item_hash, config_hash = excluded.config_hash, attested_at = excluded.attested_at`)
	attestationsOfRevision = tq("readiness_attestations.of_revision", `
		SELECT a.revision_id, a.item_id, a.actor_id, a.note, a.item_hash, a.config_hash, a.attested_at
		FROM readiness_attestations a WHERE a.tenant_id = @tenant AND a.revision_id = @revision_id`)
	skipsUpsert = tq("readiness_skips.upsert", `
		INSERT INTO readiness_skips (tenant_id, revision_id, connection_id, item_id, level, actor_id, reason, review_by,
			template_version, skipped_at)
		VALUES (@tenant, @revision_id, @connection_id, @item_id, @level, @actor_id, @reason, @review_by,
			@template_version, @skipped_at)
		ON CONFLICT (tenant_id, revision_id, item_id) DO UPDATE SET actor_id = excluded.actor_id, reason = excluded.reason,
			review_by = excluded.review_by, template_version = excluded.template_version, skipped_at = excluded.skipped_at`)
	skipsDelete = tq("readiness_skips.delete", `
		DELETE FROM readiness_skips WHERE tenant_id = @tenant AND revision_id = @revision_id AND item_id = @item_id`)
	skipsOfRevision = tq("readiness_skips.of_revision", `
		SELECT `+skipCols+` FROM readiness_skips k WHERE k.tenant_id = @tenant AND k.revision_id = @revision_id`)
	skipsAll = tq("readiness_skips.list", `
		SELECT `+skipCols+` FROM readiness_skips k WHERE k.tenant_id = @tenant ORDER BY k.skipped_at DESC, k.rowid DESC`)
	itemStatesDelete = tq("readiness_item_states.delete_revision", `
		DELETE FROM readiness_item_states WHERE tenant_id = @tenant AND revision_id = @revision_id`)
	itemStatesInsert = tq("readiness_item_states.insert", `
		INSERT INTO readiness_item_states (tenant_id, revision_id, item_id, level, status, source, actor_id, note,
			review_by, check_run_id, config_hash, updated_at)
		VALUES (@tenant, @revision_id, @item_id, @level, @status, @source, @actor_id, @note, @review_by, @check_run_id,
			@config_hash, @updated_at)`)
	itemStatesOfRevision = tq("readiness_item_states.of_revision", `
		SELECT s.revision_id, s.item_id, s.level, s.status, s.source, s.actor_id, s.note, s.review_by, s.check_run_id,
			s.config_hash, s.updated_at
		FROM readiness_item_states s WHERE s.tenant_id = @tenant AND s.revision_id = @revision_id ORDER BY s.item_id`)
)

// UpsertAttestation records (or replaces) an attestation.
func (tx *TenantTx) UpsertAttestation(a *Attestation) error {
	_, err := tx.exec(attestationsUpsert, sql.Named("revision_id", a.RevisionID), sql.Named("item_id", a.ItemID),
		sql.Named("actor_id", a.ActorID), sql.Named("note", a.Note), sql.Named("item_hash", a.ItemHash),
		sql.Named("config_hash", a.ConfigHash), sql.Named("attested_at", RT(a.AttestedAt)))
	return err
}

// Attestations returns a revision's attestations by item id.
func (tx *TenantTx) Attestations(revisionID string) (map[string]*Attestation, error) {
	list, err := collect(tx, func(s scanner) (*Attestation, error) {
		var a Attestation
		var at string
		if err := s.Scan(&a.RevisionID, &a.ItemID, &a.ActorID, &a.Note, &a.ItemHash, &a.ConfigHash, &at); err != nil {
			return nil, err
		}
		var err error
		a.AttestedAt, err = ParseRT(at)
		return &a, err
	}, attestationsOfRevision, sql.Named("revision_id", revisionID))
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Attestation, len(list))
	for _, a := range list {
		out[a.ItemID] = a
	}
	return out, nil
}

// UpsertSkip records (or replaces) a skip.
func (tx *TenantTx) UpsertSkip(s *Skip) error {
	_, err := tx.exec(skipsUpsert, sql.Named("revision_id", s.RevisionID), sql.Named("connection_id", s.ConnectionID),
		sql.Named("item_id", s.ItemID), sql.Named("level", s.Level), sql.Named("actor_id", s.ActorID),
		sql.Named("reason", s.Reason), sql.Named("review_by", RT(s.ReviewBy)), sql.Named("template_version", s.TemplateVersion),
		sql.Named("skipped_at", RT(s.SkippedAt)))
	return err
}

// DeleteSkip removes a skip; it reports whether one existed.
func (tx *TenantTx) DeleteSkip(revisionID, itemID string) (bool, error) {
	res, err := tx.exec(skipsDelete, sql.Named("revision_id", revisionID), sql.Named("item_id", itemID))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func scanSkip(s scanner) (*Skip, error) {
	var k Skip
	var review, at string
	if err := s.Scan(&k.RevisionID, &k.ConnectionID, &k.ItemID, &k.Level, &k.ActorID, &k.Reason, &review,
		&k.TemplateVersion, &at); err != nil {
		return nil, err
	}
	var err error
	if k.ReviewBy, err = ParseRT(review); err != nil {
		return nil, err
	}
	k.SkippedAt, err = ParseRT(at)
	return &k, err
}

const skipCols = "k.revision_id, k.connection_id, k.item_id, k.level, k.actor_id, k.reason, k.review_by, k.template_version, k.skipped_at"

// Skips returns a revision's skips by item id.
func (tx *TenantTx) Skips(revisionID string) (map[string]*Skip, error) {
	list, err := collect(tx, scanSkip, skipsOfRevision, sql.Named("revision_id", revisionID))
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Skip, len(list))
	for _, k := range list {
		out[k.ItemID] = k
	}
	return out, nil
}

// AllSkips lists every skip in the tenant, newest first.
func (tx *TenantTx) AllSkips() ([]*Skip, error) { return collect(tx, scanSkip, skipsAll) }

// ReplaceItemStates stores the latest evaluation of a revision's checklist.
func (tx *TenantTx) ReplaceItemStates(revisionID string, states []*ItemState) error {
	if _, err := tx.exec(itemStatesDelete, sql.Named("revision_id", revisionID)); err != nil {
		return err
	}
	for _, s := range states {
		if _, err := tx.exec(itemStatesInsert, sql.Named("revision_id", revisionID), sql.Named("item_id", s.ItemID),
			sql.Named("level", s.Level), sql.Named("status", s.Status), sql.Named("source", s.Source),
			sql.Named("actor_id", SP(s.ActorID)), sql.Named("note", SP(s.Note)), sql.Named("review_by", RTP(s.ReviewBy)),
			sql.Named("check_run_id", SP(s.CheckRunID)), sql.Named("config_hash", s.ConfigHash),
			sql.Named("updated_at", RT(s.UpdatedAt))); err != nil {
			return err
		}
	}
	return nil
}

// ItemStates returns the stored evaluation of a revision.
func (tx *TenantTx) ItemStates(revisionID string) ([]*ItemState, error) {
	return collect(tx, func(s scanner) (*ItemState, error) {
		var st ItemState
		var actor, note, review, run sql.NullString
		var at string
		if err := s.Scan(&st.RevisionID, &st.ItemID, &st.Level, &st.Status, &st.Source, &actor, &note, &review, &run,
			&st.ConfigHash, &at); err != nil {
			return nil, err
		}
		st.ActorID, st.Note, st.CheckRunID = strp(actor), strp(note), strp(run)
		var err error
		if st.ReviewBy, err = rtp(review); err != nil {
			return nil, err
		}
		st.UpdatedAt, err = ParseRT(at)
		return &st, err
	}, itemStatesOfRevision, sql.Named("revision_id", revisionID))
}

// ---------------------------------------------------------------- overlays

// The checklist templates are global (embedded in the binary, never in the
// database); overlays are the tenant's own additions to them.

var (
	overlaysLatest = tq("readiness_overlays.latest", `
		SELECT o.id, o.connector_type, o.connection_id, o.version, o.body, o.updated_by, o.updated_at
		FROM readiness_overlays o
		WHERE o.tenant_id = @tenant AND o.connector_type = @connector_type AND o.connection_id IS NULL
		ORDER BY o.version DESC LIMIT 1`)
	overlaysVersion = tq("readiness_overlays.version", `
		SELECT o.id, o.connector_type, o.connection_id, o.version, o.body, o.updated_by, o.updated_at
		FROM readiness_overlays o
		WHERE o.tenant_id = @tenant AND o.connector_type = @connector_type AND o.connection_id IS NULL
			AND o.version = @version`)
	overlaysInsert = tq("readiness_overlays.insert", `
		INSERT INTO readiness_overlays (id, tenant_id, connector_type, connection_id, version, body, updated_by,
			updated_at)
		VALUES (@id, @tenant, @connector_type, NULL, @version, @body, @updated_by, @updated_at)`)
)

func scanOverlay(s scanner) (*OverlayRow, error) {
	var o OverlayRow
	var conn sql.NullString
	var at string
	if err := s.Scan(&o.ID, &o.ConnectorType, &conn, &o.Version, &o.Body, &o.UpdatedBy, &at); err != nil {
		return nil, err
	}
	o.ConnectionID = strp(conn)
	var err error
	o.UpdatedAt, err = ParseRT(at)
	return &o, err
}

// LatestOverlay returns the newest tenant-wide overlay for a template, or nil.
func (tx *TenantTx) LatestOverlay(templateID string) (*OverlayRow, error) {
	o, err := one(tx, scanOverlay, overlaysLatest, sql.Named("connector_type", templateID))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return o, err
}

// OverlayVersion returns a specific overlay version, or ErrNotFound.
func (tx *TenantTx) OverlayVersion(templateID string, version int) (*OverlayRow, error) {
	return one(tx, scanOverlay, overlaysVersion, sql.Named("connector_type", templateID), sql.Named("version", version))
}

// InsertOverlay stores a new overlay version.
func (tx *TenantTx) InsertOverlay(o *OverlayRow) error {
	_, err := tx.exec(overlaysInsert, sql.Named("id", o.ID), sql.Named("connector_type", o.ConnectorType),
		sql.Named("version", o.Version), sql.Named("body", o.Body), sql.Named("updated_by", o.UpdatedBy),
		sql.Named("updated_at", RT(o.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}
