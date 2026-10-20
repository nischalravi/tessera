package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// ---------------------------------------------------------------- evidence packs

// EvidencePack is a generated framework evidence pack (schema/0261). Content
// is the ZIP; it is empty in the rows EvidencePacks lists.
type EvidencePack struct {
	ID             string
	TenantID       tenancy.ID
	Framework      string
	PeriodFrom     time.Time
	PeriodTo       time.Time
	GeneratedAt    time.Time
	GeneratedBy    string
	ManifestSHA256 string
	Manifest       json.RawMessage
	SizeBytes      int64
	Content        []byte
}

const packMetaCols = `p.id, p.tenant_id, p.framework, p.period_from, p.period_to, p.generated_at, p.generated_by,
	p.manifest_sha256, p.manifest, p.size_bytes`

var (
	packsList = tq("evidence_packs.list", `
		SELECT `+packMetaCols+` FROM evidence_packs p WHERE p.tenant_id = @tenant ORDER BY p.generated_at DESC, p.id`)
	packsGet = tq("evidence_packs.get", `
		SELECT `+packMetaCols+`, p.content FROM evidence_packs p WHERE p.tenant_id = @tenant AND p.id = @id`)
	packsInsert = tq("evidence_packs.insert", `
		INSERT INTO evidence_packs (id, tenant_id, framework, period_from, period_to, generated_at, generated_by,
			manifest_sha256, manifest, size_bytes, content)
		VALUES (@id, @tenant, @framework, @period_from, @period_to, @generated_at, @generated_by, @manifest_sha256,
			@manifest, @size_bytes, @content)`)
)

func scanPackMeta(s scanner, content *[]byte) (*EvidencePack, error) {
	var p EvidencePack
	var tid, from, to, at, manifest string
	dest := []any{&p.ID, &tid, &p.Framework, &from, &to, &at, &p.GeneratedBy, &p.ManifestSHA256, &manifest, &p.SizeBytes}
	if content != nil {
		dest = append(dest, content)
	}
	if err := s.Scan(dest...); err != nil {
		return nil, err
	}
	var err error
	if p.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		dst *time.Time
		src string
	}{{&p.PeriodFrom, from}, {&p.PeriodTo, to}, {&p.GeneratedAt, at}} {
		if *f.dst, err = timeutil.ParseDB(f.src); err != nil {
			return nil, err
		}
	}
	p.Manifest = json.RawMessage(manifest)
	if content != nil {
		p.Content = *content
	}
	return &p, nil
}

// EvidencePacks lists the tenant's packs without their content, newest first.
func (tx *TenantTx) EvidencePacks() ([]*EvidencePack, error) {
	return collect(tx, func(s scanner) (*EvidencePack, error) { return scanPackMeta(s, nil) }, packsList)
}

// EvidencePack returns one pack with its content, or ErrNotFound.
func (tx *TenantTx) EvidencePack(id string) (*EvidencePack, error) {
	return one(tx, func(s scanner) (*EvidencePack, error) {
		var content []byte
		return scanPackMeta(s, &content)
	}, packsGet, sql.Named("id", id))
}

// InsertEvidencePack stores a generated pack. The caller appends the ledger
// event in the same transaction.
func (tx *TenantTx) InsertEvidencePack(p *EvidencePack) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(packsInsert, sql.Named("id", p.ID), sql.Named("framework", p.Framework),
		sql.Named("period_from", T(p.PeriodFrom)), sql.Named("period_to", T(p.PeriodTo)),
		sql.Named("generated_at", T(p.GeneratedAt)), sql.Named("generated_by", p.GeneratedBy),
		sql.Named("manifest_sha256", p.ManifestSHA256), sql.Named("manifest", string(p.Manifest)),
		sql.Named("size_bytes", p.SizeBytes), sql.Named("content", p.Content))
	return err
}
