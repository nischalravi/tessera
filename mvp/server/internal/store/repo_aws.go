package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// AWS evaluator persistence (schema/0319_aws_snapshots.sql). Every statement
// is tenant-scoped (tq) and linted like the rest of the store. The snapshot
// tables are append-only: there is no UPDATE or DELETE of a snapshot row.

const awsConnCols = `c.id, c.tenant_id, c.name, c.config, c.external_id, c.credentials_enc, c.status, c.last_snapshot_id,
	c.last_run_at, c.last_error, c.created_by, c.created_at, c.updated_at`

var (
	awsConnInsert = tq("aws_connectors.insert", `
		INSERT INTO aws_connectors (id, tenant_id, name, config, external_id, credentials_enc, status, created_by,
			created_at, updated_at)
		VALUES (@id, @tenant, @name, @config, @external_id, @credentials_enc, 'idle', @created_by, @created_at, @updated_at)`)
	awsConnGet = tq("aws_connectors.get", `
		SELECT `+awsConnCols+` FROM aws_connectors c WHERE c.tenant_id = @tenant AND c.id = @id`)
	awsConnList = tq("aws_connectors.list", `
		SELECT `+awsConnCols+` FROM aws_connectors c WHERE c.tenant_id = @tenant ORDER BY c.created_at, c.id`)
	awsConnDelete = tq("aws_connectors.delete", `
		DELETE FROM aws_connectors WHERE tenant_id = @tenant AND id = @id`)
	awsConnRun = tq("aws_connectors.run", `
		UPDATE aws_connectors SET status = @status, last_snapshot_id = @last_snapshot_id, last_run_at = @now,
			last_error = @last_error, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)

	awsSnapInsert = tq("aws_snapshots.insert", `
		INSERT INTO aws_snapshots (tenant_id, id, taken_at, org_id, account_ids, catalog_version, source, connector_id)
		VALUES (@tenant, @id, @taken_at, @org_id, @account_ids, @catalog_version, @source, @connector_id)
		ON CONFLICT (tenant_id, id) DO NOTHING`)
	awsSnapGet = tq("aws_snapshots.get", `
		SELECT s.id, s.taken_at, s.org_id, s.account_ids, s.catalog_version, s.source, s.connector_id
		FROM aws_snapshots s WHERE s.tenant_id = @tenant AND s.id = @id`)
	awsSnapList = tq("aws_snapshots.list", `
		SELECT s.id, s.taken_at, s.org_id, s.account_ids, s.catalog_version, s.source, s.connector_id
		FROM aws_snapshots s WHERE s.tenant_id = @tenant ORDER BY s.taken_at DESC, s.id LIMIT @limit`)

	awsDocInsert = tq("aws_policy_documents.insert", `
		INSERT INTO aws_policy_documents (tenant_id, id, kind, source_arn, version_id, raw_json, normalized, fetched_at)
		VALUES (@tenant, @id, @kind, @source_arn, @version_id, @raw_json, @normalized, @fetched_at)
		ON CONFLICT (tenant_id, id) DO NOTHING`)
	awsDocGet = tq("aws_policy_documents.get", `
		SELECT d.id, d.kind, d.source_arn, d.version_id, d.raw_json, d.normalized, d.fetched_at
		FROM aws_policy_documents d WHERE d.tenant_id = @tenant AND d.id = @id`)
	awsDocsBySource = tq("aws_policy_documents.by_source", `
		SELECT d.id, d.kind, d.source_arn, d.version_id, d.raw_json, d.normalized, d.fetched_at
		FROM aws_policy_documents d WHERE d.tenant_id = @tenant AND d.source_arn = @source_arn ORDER BY d.fetched_at, d.id`)

	awsAttachInsert = tq("aws_policy_attachments.insert", `
		INSERT INTO aws_policy_attachments (tenant_id, snapshot_id, policy_id, target_arn, attachment_type, via)
		VALUES (@tenant, @snapshot_id, @policy_id, @target_arn, @attachment_type, @via)`)
	awsAttachList = tq("aws_policy_attachments.list", `
		SELECT a.snapshot_id, a.policy_id, a.target_arn, a.attachment_type, a.via
		FROM aws_policy_attachments a WHERE a.tenant_id = @tenant AND a.snapshot_id = @snapshot_id ORDER BY a.id`)
	awsAttachByTarget = tq("aws_policy_attachments.by_target", `
		SELECT a.snapshot_id, a.policy_id, a.target_arn, a.attachment_type, a.via
		FROM aws_policy_attachments a WHERE a.tenant_id = @tenant AND a.target_arn = @target_arn ORDER BY a.id`)

	awsOrgInsert = tq("aws_org_nodes.insert", `
		INSERT INTO aws_org_nodes (tenant_id, snapshot_id, id, kind, parent_id, name)
		VALUES (@tenant, @snapshot_id, @id, @kind, @parent_id, @name)`)
	awsOrgList = tq("aws_org_nodes.list", `
		SELECT n.snapshot_id, n.id, n.kind, n.parent_id, n.name
		FROM aws_org_nodes n WHERE n.tenant_id = @tenant AND n.snapshot_id = @snapshot_id ORDER BY n.id`)

	awsEntityInsert = tq("aws_snapshot_entities.insert", `
		INSERT INTO aws_snapshot_entities (tenant_id, snapshot_id, kind, key, body)
		VALUES (@tenant, @snapshot_id, @kind, @key, @body)`)
	awsEntityList = tq("aws_snapshot_entities.list", `
		SELECT e.snapshot_id, e.kind, e.key, e.body
		FROM aws_snapshot_entities e WHERE e.tenant_id = @tenant AND e.snapshot_id = @snapshot_id AND e.kind = @kind
		ORDER BY e.key`)

	awsFindingInsert = tq("aws_collection_findings.insert", `
		INSERT INTO aws_collection_findings (tenant_id, snapshot_id, kind, source_arn, policy_kind, code, detail, scope)
		VALUES (@tenant, @snapshot_id, @kind, @source_arn, @policy_kind, @code, @detail, @scope)`)
	awsFindingList = tq("aws_collection_findings.list", `
		SELECT f.snapshot_id, f.kind, f.source_arn, f.policy_kind, f.code, f.detail, f.scope
		FROM aws_collection_findings f WHERE f.tenant_id = @tenant AND f.snapshot_id = @snapshot_id ORDER BY f.id`)

	awsTrustInsert = tq("aws_trust_edges.insert", `
		INSERT INTO aws_trust_edges (tenant_id, snapshot_id, from_arn, to_role_arn, mechanism, outcome, residual, explanation_id)
		VALUES (@tenant, @snapshot_id, @from_arn, @to_role_arn, @mechanism, @outcome, @residual, @explanation_id)`)
	awsTrustList = tq("aws_trust_edges.list", `
		SELECT t.snapshot_id, t.from_arn, t.to_role_arn, t.mechanism, t.outcome, t.residual, t.explanation_id
		FROM aws_trust_edges t WHERE t.tenant_id = @tenant AND t.snapshot_id = @snapshot_id ORDER BY t.id`)

	awsEffInsert = tq("aws_effective_permissions.insert", `
		INSERT INTO aws_effective_permissions (tenant_id, snapshot_id, principal_arn, action_atom, resource_atom, outcome,
			residual, fidelity, explanation_id, engine_version, catalog_version)
		VALUES (@tenant, @snapshot_id, @principal_arn, @action_atom, @resource_atom, @outcome, @residual, @fidelity,
			@explanation_id, @engine_version, @catalog_version)`)
	awsEffByPrincipal = tq("aws_effective_permissions.by_principal", `
		SELECT e.snapshot_id, e.principal_arn, e.action_atom, e.resource_atom, e.outcome, e.residual, e.fidelity,
			e.explanation_id, e.engine_version, e.catalog_version
		FROM aws_effective_permissions e
		WHERE e.tenant_id = @tenant AND e.snapshot_id = @snapshot_id AND e.principal_arn = @principal_arn
		ORDER BY e.action_atom, e.resource_atom, e.id`)

	awsExplInsert = tq("aws_explanations.insert", `
		INSERT INTO aws_explanations (tenant_id, id, trace) VALUES (@tenant, @id, @trace)
		ON CONFLICT (tenant_id, id) DO NOTHING`)
	awsExplGet = tq("aws_explanations.get", `
		SELECT x.id, x.trace FROM aws_explanations x WHERE x.tenant_id = @tenant AND x.id = @id`)
)

// awsNull stores "" as NULL.
func awsNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func awsJSONList(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func awsJSONOrEmptyObject(b json.RawMessage) string {
	if len(b) == 0 {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------- connectors

func scanAWSConnector(s scanner) (*AWSConnector, error) {
	var c AWSConnector
	var tid, cfg, created, updated string
	var last, runAt sql.NullString
	if err := s.Scan(&c.ID, &tid, &c.Name, &cfg, &c.ExternalID, &c.CredentialsEnc, &c.Status, &last, &runAt, &c.LastError,
		&c.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if c.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	c.Config = json.RawMessage(cfg)
	if last.Valid {
		c.LastSnapshotID = last.String
	}
	if c.LastRunAt, err = rtp(runAt); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = ParseRT(updated)
	return &c, err
}

// InsertAWSConnector adds a connector; ErrDuplicate when the name is taken in
// this tenant.
func (tx *TenantTx) InsertAWSConnector(c *AWSConnector) error {
	if err := tx.own(c.TenantID); err != nil {
		return err
	}
	enc := c.CredentialsEnc
	if enc == nil {
		enc = []byte{} // federated connector: nothing secret to store; the column is NOT NULL
	}
	_, err := tx.exec(awsConnInsert, sql.Named("id", c.ID), sql.Named("name", c.Name),
		sql.Named("config", awsJSONOrEmptyObject(c.Config)), sql.Named("external_id", c.ExternalID),
		sql.Named("credentials_enc", enc), sql.Named("created_by", c.CreatedBy),
		sql.Named("created_at", RT(c.CreatedAt)), sql.Named("updated_at", RT(c.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// AWSConnector returns one connector, or ErrNotFound.
func (tx *TenantTx) AWSConnector(id string) (*AWSConnector, error) {
	return one(tx, scanAWSConnector, awsConnGet, sql.Named("id", id))
}

// AWSConnectors lists the tenant's connectors, oldest first.
func (tx *TenantTx) AWSConnectors() ([]*AWSConnector, error) {
	return collect(tx, scanAWSConnector, awsConnList)
}

// DeleteAWSConnector removes a connector (and with it its sealed credentials);
// ErrNotFound when there is no such connector in this tenant. Snapshots it
// collected stay.
func (tx *TenantTx) DeleteAWSConnector(id string) error {
	return tx.affectOne(awsConnDelete, sql.Named("id", id))
}

// SetAWSConnectorRun records the outcome of a collection run.
func (tx *TenantTx) SetAWSConnectorRun(id, status, snapshotID, lastError string, now time.Time) error {
	return tx.affectOne(awsConnRun, sql.Named("id", id), sql.Named("status", status),
		sql.Named("last_snapshot_id", awsNull(snapshotID)), sql.Named("last_error", lastError), sql.Named("now", RT(now)))
}

// affectOne runs a statement that must change exactly the row it names.
func (tx *TenantTx) affectOne(s tstmt, args ...sql.NamedArg) error {
	res, err := tx.exec(s, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- snapshots

func scanAWSSnapshot(s scanner) (*AWSSnapshot, error) {
	var x AWSSnapshot
	var taken, accounts string
	var org, conn sql.NullString
	if err := s.Scan(&x.ID, &taken, &org, &accounts, &x.CatalogVersion, &x.Source, &conn); err != nil {
		return nil, err
	}
	var err error
	if x.TakenAt, err = ParseRT(taken); err != nil {
		return nil, err
	}
	x.OrgID, x.ConnectorID = org.String, conn.String
	if err := json.Unmarshal([]byte(accounts), &x.AccountIDs); err != nil {
		return nil, err
	}
	return &x, nil
}

// PutAWSSnapshot adds a snapshot header. The id is a content hash, so putting
// the same snapshot again is a no-op: it reports created = false and the
// caller must not add its rows a second time.
func (tx *TenantTx) PutAWSSnapshot(x *AWSSnapshot) (created bool, err error) {
	accounts, err := awsJSONList(x.AccountIDs)
	if err != nil {
		return false, err
	}
	res, err := tx.exec(awsSnapInsert, sql.Named("id", x.ID), sql.Named("taken_at", RT(x.TakenAt)),
		sql.Named("org_id", awsNull(x.OrgID)), sql.Named("account_ids", accounts),
		sql.Named("catalog_version", x.CatalogVersion), sql.Named("source", x.Source),
		sql.Named("connector_id", awsNull(x.ConnectorID)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// AWSSnapshot returns one snapshot header, or ErrNotFound.
func (tx *TenantTx) AWSSnapshot(id string) (*AWSSnapshot, error) {
	return one(tx, scanAWSSnapshot, awsSnapGet, sql.Named("id", id))
}

// AWSSnapshots lists the newest snapshots first (limit <= 0: 100).
func (tx *TenantTx) AWSSnapshots(limit int) ([]*AWSSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	return collect(tx, scanAWSSnapshot, awsSnapList, sql.Named("limit", limit))
}

// ---------------------------------------------------------------- policy documents

func scanAWSPolicyDocument(s scanner) (*AWSPolicyDocument, error) {
	var d AWSPolicyDocument
	var ver sql.NullString
	var norm, fetched string
	if err := s.Scan(&d.ID, &d.Kind, &d.SourceARN, &ver, &d.RawJSON, &norm, &fetched); err != nil {
		return nil, err
	}
	d.VersionID, d.Normalized = ver.String, json.RawMessage(norm)
	var err error
	d.FetchedAt, err = ParseRT(fetched)
	return &d, err
}

// PutAWSPolicyDocument stores a document by content id; a document already
// stored for this tenant is left as it is (documents are immutable).
func (tx *TenantTx) PutAWSPolicyDocument(d *AWSPolicyDocument) error {
	_, err := tx.exec(awsDocInsert, sql.Named("id", d.ID), sql.Named("kind", d.Kind), sql.Named("source_arn", d.SourceARN),
		sql.Named("version_id", awsNull(d.VersionID)), sql.Named("raw_json", d.RawJSON),
		sql.Named("normalized", awsJSONOrEmptyObject(d.Normalized)), sql.Named("fetched_at", RT(d.FetchedAt)))
	return err
}

// AWSPolicyDocument returns one document, or ErrNotFound.
func (tx *TenantTx) AWSPolicyDocument(id string) (*AWSPolicyDocument, error) {
	return one(tx, scanAWSPolicyDocument, awsDocGet, sql.Named("id", id))
}

// AWSPolicyDocumentsBySource lists every stored version of the policy with
// this source ARN, oldest first.
func (tx *TenantTx) AWSPolicyDocumentsBySource(sourceARN string) ([]*AWSPolicyDocument, error) {
	return collect(tx, scanAWSPolicyDocument, awsDocsBySource, sql.Named("source_arn", sourceARN))
}

// ---------------------------------------------------------------- attachments

func scanAWSAttachment(s scanner) (*AWSAttachment, error) {
	var a AWSAttachment
	var via string
	if err := s.Scan(&a.SnapshotID, &a.PolicyID, &a.TargetARN, &a.AttachmentType, &via); err != nil {
		return nil, err
	}
	return &a, json.Unmarshal([]byte(via), &a.Via)
}

// AddAWSAttachment links a policy document to a target in a snapshot.
func (tx *TenantTx) AddAWSAttachment(a *AWSAttachment) error {
	via, err := awsJSONList(a.Via)
	if err != nil {
		return err
	}
	_, err = tx.exec(awsAttachInsert, sql.Named("snapshot_id", a.SnapshotID), sql.Named("policy_id", a.PolicyID),
		sql.Named("target_arn", a.TargetARN), sql.Named("attachment_type", a.AttachmentType), sql.Named("via", via))
	return err
}

// AWSAttachments lists a snapshot's attachments in insertion order.
func (tx *TenantTx) AWSAttachments(snapshotID string) ([]*AWSAttachment, error) {
	return collect(tx, scanAWSAttachment, awsAttachList, sql.Named("snapshot_id", snapshotID))
}

// AWSAttachmentsByTarget lists the attachments to one target in every snapshot.
func (tx *TenantTx) AWSAttachmentsByTarget(targetARN string) ([]*AWSAttachment, error) {
	return collect(tx, scanAWSAttachment, awsAttachByTarget, sql.Named("target_arn", targetARN))
}

// ---------------------------------------------------------------- org nodes

func scanAWSOrgNode(s scanner) (*AWSOrgNode, error) {
	var n AWSOrgNode
	var parent sql.NullString
	if err := s.Scan(&n.SnapshotID, &n.ID, &n.Kind, &parent, &n.Name); err != nil {
		return nil, err
	}
	n.ParentID = parent.String
	return &n, nil
}

// AddAWSOrgNode adds a node of a snapshot's organization tree.
func (tx *TenantTx) AddAWSOrgNode(n *AWSOrgNode) error {
	_, err := tx.exec(awsOrgInsert, sql.Named("snapshot_id", n.SnapshotID), sql.Named("id", n.ID),
		sql.Named("kind", n.Kind), sql.Named("parent_id", awsNull(n.ParentID)), sql.Named("name", n.Name))
	return err
}

// AWSOrgNodes lists a snapshot's organization nodes by id.
func (tx *TenantTx) AWSOrgNodes(snapshotID string) ([]*AWSOrgNode, error) {
	return collect(tx, scanAWSOrgNode, awsOrgList, sql.Named("snapshot_id", snapshotID))
}

// ---------------------------------------------------------------- entities

func scanAWSEntity(s scanner) (*AWSEntity, error) {
	var e AWSEntity
	var body string
	if err := s.Scan(&e.SnapshotID, &e.Kind, &e.Key, &body); err != nil {
		return nil, err
	}
	e.Body = json.RawMessage(body)
	return &e, nil
}

// AddAWSEntity adds one JSON-encoded entity of a snapshot.
func (tx *TenantTx) AddAWSEntity(e *AWSEntity) error {
	_, err := tx.exec(awsEntityInsert, sql.Named("snapshot_id", e.SnapshotID), sql.Named("kind", e.Kind),
		sql.Named("key", e.Key), sql.Named("body", awsJSONOrEmptyObject(e.Body)))
	return err
}

// AWSEntities lists a snapshot's entities of one kind by key.
func (tx *TenantTx) AWSEntities(snapshotID, kind string) ([]*AWSEntity, error) {
	return collect(tx, scanAWSEntity, awsEntityList, sql.Named("snapshot_id", snapshotID), sql.Named("kind", kind))
}

// ---------------------------------------------------------------- findings

func scanAWSFinding(s scanner) (*AWSFinding, error) {
	var f AWSFinding
	var scope string
	if err := s.Scan(&f.SnapshotID, &f.Kind, &f.SourceARN, &f.PolicyKind, &f.Code, &f.Detail, &scope); err != nil {
		return nil, err
	}
	f.Scope = json.RawMessage(scope)
	return &f, nil
}

// AddAWSFinding records something collection could not take at face value.
func (tx *TenantTx) AddAWSFinding(f *AWSFinding) error {
	_, err := tx.exec(awsFindingInsert, sql.Named("snapshot_id", f.SnapshotID), sql.Named("kind", f.Kind),
		sql.Named("source_arn", f.SourceARN), sql.Named("policy_kind", f.PolicyKind), sql.Named("code", f.Code),
		sql.Named("detail", f.Detail), sql.Named("scope", awsJSONOrEmptyObject(f.Scope)))
	return err
}

// AWSFindings lists a snapshot's collection findings in insertion order.
func (tx *TenantTx) AWSFindings(snapshotID string) ([]*AWSFinding, error) {
	return collect(tx, scanAWSFinding, awsFindingList, sql.Named("snapshot_id", snapshotID))
}

// ---------------------------------------------------------------- trust edges, effective permissions, explanations

func scanAWSTrustEdge(s scanner) (*AWSTrustEdge, error) {
	var e AWSTrustEdge
	var residual string
	if err := s.Scan(&e.SnapshotID, &e.FromARN, &e.ToRoleARN, &e.Mechanism, &e.Outcome, &residual, &e.ExplanationID); err != nil {
		return nil, err
	}
	e.Residual = json.RawMessage(residual)
	return &e, nil
}

// AddAWSTrustEdge adds a materialized trust edge to a snapshot.
func (tx *TenantTx) AddAWSTrustEdge(e *AWSTrustEdge) error {
	_, err := tx.exec(awsTrustInsert, sql.Named("snapshot_id", e.SnapshotID), sql.Named("from_arn", e.FromARN),
		sql.Named("to_role_arn", e.ToRoleARN), sql.Named("mechanism", e.Mechanism), sql.Named("outcome", e.Outcome),
		sql.Named("residual", awsJSONOrEmptyObject(e.Residual)), sql.Named("explanation_id", e.ExplanationID))
	return err
}

// AWSTrustEdges lists a snapshot's trust edges in insertion order.
func (tx *TenantTx) AWSTrustEdges(snapshotID string) ([]*AWSTrustEdge, error) {
	return collect(tx, scanAWSTrustEdge, awsTrustList, sql.Named("snapshot_id", snapshotID))
}

func scanAWSEffective(s scanner) (*AWSEffective, error) {
	var e AWSEffective
	var residual sql.NullString
	if err := s.Scan(&e.SnapshotID, &e.PrincipalARN, &e.ActionAtom, &e.ResourceAtom, &e.Outcome, &residual, &e.Fidelity,
		&e.ExplanationID, &e.EngineVersion, &e.CatalogVersion); err != nil {
		return nil, err
	}
	if residual.Valid {
		e.Residual = json.RawMessage(residual.String)
	}
	return &e, nil
}

// AddAWSEffective adds one materialized effective-permission cell.
func (tx *TenantTx) AddAWSEffective(e *AWSEffective) error {
	var residual any
	if len(e.Residual) > 0 {
		residual = string(e.Residual)
	}
	_, err := tx.exec(awsEffInsert, sql.Named("snapshot_id", e.SnapshotID), sql.Named("principal_arn", e.PrincipalARN),
		sql.Named("action_atom", e.ActionAtom), sql.Named("resource_atom", e.ResourceAtom), sql.Named("outcome", e.Outcome),
		sql.Named("residual", residual), sql.Named("fidelity", e.Fidelity), sql.Named("explanation_id", e.ExplanationID),
		sql.Named("engine_version", e.EngineVersion), sql.Named("catalog_version", e.CatalogVersion))
	return err
}

// ListAWSEffectiveByPrincipal lists one principal's cells in a snapshot.
func (tx *TenantTx) ListAWSEffectiveByPrincipal(snapshotID, principalARN string) ([]*AWSEffective, error) {
	return collect(tx, scanAWSEffective, awsEffByPrincipal, sql.Named("snapshot_id", snapshotID),
		sql.Named("principal_arn", principalARN))
}

// PutAWSExplanation stores a trace by content id; an id already stored for
// this tenant is left as it is.
func (tx *TenantTx) PutAWSExplanation(x *AWSExplanation) error {
	_, err := tx.exec(awsExplInsert, sql.Named("id", x.ID), sql.Named("trace", awsJSONOrEmptyObject(x.Trace)))
	return err
}

// AWSExplanation returns one trace, or ErrNotFound.
func (tx *TenantTx) AWSExplanation(id string) (*AWSExplanation, error) {
	x, err := one(tx, func(s scanner) (*AWSExplanation, error) {
		var x AWSExplanation
		var trace string
		if err := s.Scan(&x.ID, &trace); err != nil {
			return nil, err
		}
		x.Trace = json.RawMessage(trace)
		return &x, nil
	}, awsExplGet, sql.Named("id", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return x, err
}
