package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Every query below is scoped to the tenant (DefaultTenantID until #5).

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const connCols = `id, tenant_id, name, connector_type, system, role, active_revision_id, health,
	technical_owner_id, business_owner, agent_id, created_at, updated_at, retired_at`

func scanConnection(s scanner) (*Connection, error) {
	var c Connection
	var active, tech, biz, agent, retired sql.NullString
	var created, updated string
	if err := s.Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.System, &c.Role, &active, &c.Health,
		&tech, &biz, &agent, &created, &updated, &retired); err != nil {
		return nil, err
	}
	c.ActiveRevisionID, c.TechnicalOwner, c.BusinessOwner, c.AgentID = strp(active), strp(tech), strp(biz), strp(agent)
	var err error
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if c.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	c.RetiredAt, err = rtp(retired)
	return &c, err
}

// InsertConnection adds a connection; ErrDuplicate when the name or system is taken.
func (c *Conn) InsertConnection(x *Connection) error {
	_, err := c.Exec(`INSERT INTO connections (id, tenant_id, name, connector_type, system, role, health,
		technical_owner_id, business_owner, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'none', ?, ?, ?, ?)`,
		x.ID, DefaultTenantID, x.Name, x.ConnectorType, x.System, x.Role, SP(x.TechnicalOwner), SP(x.BusinessOwner),
		RT(x.CreatedAt), RT(x.UpdatedAt))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// Connection returns one connection or ErrNotFound.
func (c *Conn) Connection(id string) (*Connection, error) {
	return one(c, scanConnection, "SELECT "+connCols+" FROM connections WHERE tenant_id = ? AND id = ?", DefaultTenantID, id)
}

// Connections lists the tenant's connections, oldest first.
func (c *Conn) Connections() ([]*Connection, error) {
	return collect(c, scanConnection, "SELECT "+connCols+" FROM connections WHERE tenant_id = ? ORDER BY created_at, rowid", DefaultTenantID)
}

// UpdateConnectionOwners records the owners named in the revision config.
func (c *Conn) UpdateConnectionOwners(id string, tech, biz *string, now time.Time) error {
	_, err := c.Exec("UPDATE connections SET technical_owner_id = ?, business_owner = ?, updated_at = ? WHERE tenant_id = ? AND id = ?",
		SP(tech), SP(biz), RT(now), DefaultTenantID, id)
	return err
}

// SetConnectionLive points the connection at its live revision (nil for none) and sets its health.
func (c *Conn) SetConnectionLive(id string, revisionID *string, health string, now time.Time) error {
	_, err := c.Exec("UPDATE connections SET active_revision_id = ?, health = ?, updated_at = ? WHERE tenant_id = ? AND id = ?",
		SP(revisionID), health, RT(now), DefaultTenantID, id)
	return err
}

// MarkConnectionRetired stamps retired_at.
func (c *Conn) MarkConnectionRetired(id string, now time.Time) error {
	_, err := c.Exec("UPDATE connections SET retired_at = ?, health = 'none', updated_at = ? WHERE tenant_id = ? AND id = ?",
		RT(now), RT(now), DefaultTenantID, id)
	return err
}

const revCols = `id, tenant_id, connection_id, rev, state, template_id, template_version, overlay_version, config,
	secret_ref, secret_version, config_hash, evidence_seq, write_mode, expected_counts, gate_report, activated_at,
	activated_by, created_by, created_at, updated_at`

func scanRevision(s scanner) (*ConnectionRevision, error) {
	var r ConnectionRevision
	var ref, ver, counts, gate, actAt, actBy sql.NullString
	var created, updated string
	if err := s.Scan(&r.ID, &r.TenantID, &r.ConnectionID, &r.Rev, &r.State, &r.TemplateID, &r.TemplateVersion,
		&r.OverlayVersion, &r.Config, &ref, &ver, &r.ConfigHash, &r.EvidenceSeq, &r.WriteMode, &counts, &gate,
		&actAt, &actBy, &r.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	r.SecretRef, r.SecretVersion, r.ExpectedCounts, r.GateReport, r.ActivatedBy = strp(ref), strp(ver), strp(counts), strp(gate), strp(actBy)
	var err error
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
func (c *Conn) InsertRevision(r *ConnectionRevision) error {
	_, err := c.Exec(`INSERT INTO connection_revisions (id, tenant_id, connection_id, rev, state, template_id,
		template_version, overlay_version, config, secret_ref, secret_version, config_hash, write_mode, expected_counts,
		created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, DefaultTenantID, r.ConnectionID, r.Rev, r.TemplateID, r.TemplateVersion, r.OverlayVersion, r.Config,
		SP(r.SecretRef), SP(r.SecretVersion), r.ConfigHash, r.WriteMode, SP(r.ExpectedCounts), r.CreatedBy,
		RT(r.CreatedAt), RT(r.UpdatedAt))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// Revision returns one revision or ErrNotFound.
func (c *Conn) Revision(id string) (*ConnectionRevision, error) {
	return one(c, scanRevision, "SELECT "+revCols+" FROM connection_revisions WHERE tenant_id = ? AND id = ?", DefaultTenantID, id)
}

// Revisions lists a connection's revisions, newest first.
func (c *Conn) Revisions(connectionID string) ([]*ConnectionRevision, error) {
	return collect(c, scanRevision, "SELECT "+revCols+" FROM connection_revisions WHERE tenant_id = ? AND connection_id = ? ORDER BY rev DESC",
		DefaultTenantID, connectionID)
}

// UpdateRevisionConfig stores a new config, its hash and bumps the evidence sequence.
func (c *Conn) UpdateRevisionConfig(id, config, configHash, writeMode string, expectedCounts *string, now time.Time) error {
	_, err := c.Exec(`UPDATE connection_revisions SET config = ?, config_hash = ?, write_mode = ?, expected_counts = ?,
		evidence_seq = evidence_seq + 1, updated_at = ? WHERE tenant_id = ? AND id = ?`,
		config, configHash, writeMode, SP(expectedCounts), RT(now), DefaultTenantID, id)
	return err
}

// UpdateRevisionSecret stores a credential reference (never the secret) and the new config hash.
func (c *Conn) UpdateRevisionSecret(id string, ref, version, configHash string, now time.Time) error {
	_, err := c.Exec(`UPDATE connection_revisions SET secret_ref = ?, secret_version = ?, config_hash = ?,
		evidence_seq = evidence_seq + 1, updated_at = ? WHERE tenant_id = ? AND id = ?`,
		ref, version, configHash, RT(now), DefaultTenantID, id)
	return err
}

// BumpEvidence records that evidence a gate reads changed (attestation,
// skip, run, finding acceptance), so a concurrent activation's CAS fails.
func (c *Conn) BumpEvidence(id string, now time.Time) error {
	_, err := c.Exec("UPDATE connection_revisions SET evidence_seq = evidence_seq + 1, updated_at = ? WHERE tenant_id = ? AND id = ?",
		RT(now), DefaultTenantID, id)
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
// the expected config hash and evidence sequence.
func (c *Conn) SetRevisionState(ch StateChange) error {
	var activatedAt any
	if ch.To == StateActive && ch.ActivatedBy != nil {
		activatedAt = RT(ch.Now)
	}
	res, err := c.Exec(`UPDATE connection_revisions SET state = ?, gate_report = COALESCE(?, gate_report),
		activated_at = COALESCE(?, activated_at), activated_by = COALESCE(?, activated_by), updated_at = ?
		WHERE tenant_id = ? AND id = ? AND state = ? AND config_hash = ? AND evidence_seq = ?`,
		ch.To, SP(ch.GateReport), activatedAt, SP(ch.ActivatedBy), RT(ch.Now), DefaultTenantID, ch.RevisionID,
		ch.From, ch.ConfigHash, ch.EvidenceSeq)
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

// UpsertAttestation records (or replaces) an attestation.
func (c *Conn) UpsertAttestation(a *Attestation) error {
	_, err := c.Exec(`INSERT INTO readiness_attestations (tenant_id, revision_id, item_id, actor_id, note, item_hash,
		config_hash, attested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, revision_id, item_id) DO UPDATE SET actor_id = excluded.actor_id, note = excluded.note,
		item_hash = excluded.item_hash, config_hash = excluded.config_hash, attested_at = excluded.attested_at`,
		DefaultTenantID, a.RevisionID, a.ItemID, a.ActorID, a.Note, a.ItemHash, a.ConfigHash, RT(a.AttestedAt))
	return err
}

// Attestations returns a revision's attestations by item id.
func (c *Conn) Attestations(revisionID string) (map[string]*Attestation, error) {
	list, err := collect(c, func(s scanner) (*Attestation, error) {
		var a Attestation
		var at string
		if err := s.Scan(&a.RevisionID, &a.ItemID, &a.ActorID, &a.Note, &a.ItemHash, &a.ConfigHash, &at); err != nil {
			return nil, err
		}
		var err error
		a.AttestedAt, err = ParseRT(at)
		return &a, err
	}, `SELECT revision_id, item_id, actor_id, note, item_hash, config_hash, attested_at FROM readiness_attestations
		WHERE tenant_id = ? AND revision_id = ?`, DefaultTenantID, revisionID)
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
func (c *Conn) UpsertSkip(s *Skip) error {
	_, err := c.Exec(`INSERT INTO readiness_skips (tenant_id, revision_id, connection_id, item_id, level, actor_id, reason,
		review_by, template_version, skipped_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, revision_id, item_id) DO UPDATE SET actor_id = excluded.actor_id, reason = excluded.reason,
		review_by = excluded.review_by, template_version = excluded.template_version, skipped_at = excluded.skipped_at`,
		DefaultTenantID, s.RevisionID, s.ConnectionID, s.ItemID, s.Level, s.ActorID, s.Reason, RT(s.ReviewBy),
		s.TemplateVersion, RT(s.SkippedAt))
	return err
}

// DeleteSkip removes a skip; it reports whether one existed.
func (c *Conn) DeleteSkip(revisionID, itemID string) (bool, error) {
	res, err := c.Exec("DELETE FROM readiness_skips WHERE tenant_id = ? AND revision_id = ? AND item_id = ?",
		DefaultTenantID, revisionID, itemID)
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

const skipCols = "revision_id, connection_id, item_id, level, actor_id, reason, review_by, template_version, skipped_at"

// Skips returns a revision's skips by item id.
func (c *Conn) Skips(revisionID string) (map[string]*Skip, error) {
	list, err := collect(c, scanSkip, "SELECT "+skipCols+" FROM readiness_skips WHERE tenant_id = ? AND revision_id = ?",
		DefaultTenantID, revisionID)
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
func (c *Conn) AllSkips() ([]*Skip, error) {
	return collect(c, scanSkip, "SELECT "+skipCols+" FROM readiness_skips WHERE tenant_id = ? ORDER BY skipped_at DESC, rowid DESC",
		DefaultTenantID)
}

// ReplaceItemStates stores the latest evaluation of a revision's checklist.
func (c *Conn) ReplaceItemStates(revisionID string, states []*ItemState) error {
	if _, err := c.Exec("DELETE FROM readiness_item_states WHERE tenant_id = ? AND revision_id = ?", DefaultTenantID, revisionID); err != nil {
		return err
	}
	for _, s := range states {
		if _, err := c.Exec(`INSERT INTO readiness_item_states (tenant_id, revision_id, item_id, level, status, source,
			actor_id, note, review_by, check_run_id, config_hash, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			DefaultTenantID, revisionID, s.ItemID, s.Level, s.Status, s.Source, SP(s.ActorID), SP(s.Note),
			RTP(s.ReviewBy), SP(s.CheckRunID), s.ConfigHash, RT(s.UpdatedAt)); err != nil {
			return err
		}
	}
	return nil
}

// ItemStates returns the stored evaluation of a revision.
func (c *Conn) ItemStates(revisionID string) ([]*ItemState, error) {
	return collect(c, func(s scanner) (*ItemState, error) {
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
	}, `SELECT revision_id, item_id, level, status, source, actor_id, note, review_by, check_run_id, config_hash, updated_at
		FROM readiness_item_states WHERE tenant_id = ? AND revision_id = ? ORDER BY item_id`, DefaultTenantID, revisionID)
}

// ---------------------------------------------------------------- overlays

// LatestOverlay returns the newest tenant-wide overlay for a template, or nil.
func (c *Conn) LatestOverlay(templateID string) (*OverlayRow, error) {
	o, err := one(c, func(s scanner) (*OverlayRow, error) {
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
	}, `SELECT id, connector_type, connection_id, version, body, updated_by, updated_at FROM readiness_overlays
		WHERE tenant_id = ? AND connector_type = ? AND connection_id IS NULL ORDER BY version DESC LIMIT 1`,
		DefaultTenantID, templateID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return o, err
}

// OverlayVersion returns a specific overlay version, or ErrNotFound.
func (c *Conn) OverlayVersion(templateID string, version int) (*OverlayRow, error) {
	return one(c, func(s scanner) (*OverlayRow, error) {
		var o OverlayRow
		var at string
		if err := s.Scan(&o.ID, &o.ConnectorType, &o.Version, &o.Body, &o.UpdatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		o.UpdatedAt, err = ParseRT(at)
		return &o, err
	}, `SELECT id, connector_type, version, body, updated_by, updated_at FROM readiness_overlays
		WHERE tenant_id = ? AND connector_type = ? AND connection_id IS NULL AND version = ?`,
		DefaultTenantID, templateID, version)
}

// InsertOverlay stores a new overlay version.
func (c *Conn) InsertOverlay(o *OverlayRow) error {
	_, err := c.Exec(`INSERT INTO readiness_overlays (id, tenant_id, connector_type, connection_id, version, body,
		updated_by, updated_at) VALUES (?, ?, ?, NULL, ?, ?, ?, ?)`,
		o.ID, DefaultTenantID, o.ConnectorType, o.Version, o.Body, o.UpdatedBy, RT(o.UpdatedAt))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}
