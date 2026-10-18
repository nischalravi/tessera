package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// The audit routes (design §16.1). Like every route they are served for the
// dev default tenant without authentication until PR5, which adds audit.read
// and audit.verify.
func (s *Server) registerAuditRoutes() {
	G := http.MethodGet
	s.handle(G, "/api/audit", read, need(auth.PermAuditRead), s.auditLog)
	s.handle(G, "/api/audit/events/{event_id}/proof", read, need(auth.PermAuditRead), s.auditProof)
	s.handle(G, "/api/audit/checkpoints", read, need(auth.PermAuditRead), s.auditCheckpoints)
	s.handle(G, "/api/audit/keys", noTenant, need(auth.PermAuditRead), s.auditKeys)
	s.handle(http.MethodPost, "/api/audit/verify", phased, need(auth.PermAuditVerify), s.auditVerify)
	s.handle(G, "/api/audit/export", phased, need(auth.PermAuditRead), s.auditExport).stream = true
}

const maxFilterLen = 200

func (p *params) queryFilter(name string) string {
	v := p.queryOptStr(name)
	if v == nil {
		return ""
	}
	if len(*v) > maxFilterLen {
		p.errs = append(p.errs, verr{Type: "string_too_long", Loc: []any{"query", name},
			Msg: fmt.Sprintf("String should have at most %d characters", maxFilterLen), Input: *v,
			Ctx: ojson.Object{{Key: "max_length", Value: maxFilterLen}}})
		return ""
	}
	return *v
}

func (p *params) queryTime(name string) time.Time {
	v := p.queryOptStr(name)
	if v == nil {
		return time.Time{}
	}
	t, err := timeutil.ParseISO(*v)
	if err != nil || t.IsZero() {
		p.errs = append(p.errs, verr{Type: "datetime_from_date_parsing", Loc: []any{"query", name},
			Msg: "Input should be a valid datetime", Input: *v})
		return time.Time{}
	}
	return t
}

// auditActorLabel is the legacy "actor" string of an event.
func auditActorLabel(e *store.AuditEvent) string {
	switch {
	case e.ActorDisplay != nil:
		return *e.ActorDisplay
	case e.ActorID != nil:
		return *e.ActorID
	}
	return e.ActorType
}

func rawOrNull(r json.RawMessage) any {
	if len(r) == 0 {
		return nil
	}
	return r
}

// auditRow is one /api/audit row: the original fields (id, at, actor,
// action, detail) followed by the ledger's. id is the event's seq, which
// keeps the original integer id and newest-first ordering.
func auditRow(e *store.AuditEvent) ojson.Object {
	var target any
	if e.TargetType != nil || e.TargetID != nil {
		target = ojson.Object{{Key: "type", Value: e.TargetType}, {Key: "id", Value: e.TargetID}}
	}
	return ojson.Object{
		{Key: "id", Value: e.Seq}, {Key: "at", Value: timeutil.ISO(e.OccurredAt)},
		{Key: "actor", Value: auditActorLabel(e)}, {Key: "action", Value: e.Action}, {Key: "detail", Value: e.Detail},
		{Key: "event_id", Value: e.ID.String()}, {Key: "seq", Value: e.Seq}, {Key: "actor_type", Value: e.ActorType},
		{Key: "actor_id", Value: e.ActorID}, {Key: "outcome", Value: e.Outcome}, {Key: "target", Value: target},
		{Key: "request_id", Value: e.RequestID}, {Key: "authn", Value: rawOrNull(e.Authn)},
		{Key: "http", Value: rawOrNull(e.HTTP)}, {Key: "hash", Value: e.Hash}, {Key: "prev_hash", Value: e.PrevHash},
	}
}

// MaxAuditLimit caps GET /api/audit's limit; larger values are clamped to
// it. Page further with before_seq, or use GET /api/audit/export.
const MaxAuditLimit = 1000

// GET /api/audit: newest first. Domain events by default; include_http=true
// (or action=http.request) adds the per-request events. limit defaults to
// 100, is clamped to MaxAuditLimit, and must not be negative (422); 0 returns
// no rows.
func (s *Server) auditLog(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	limit := min(p.queryInt("limit", 100, i64(0), nil), MaxAuditLimit)
	f := store.AuditFilter{Limit: int(limit)}
	if b := p.queryOptInt("before_seq"); b != nil {
		f.BeforeSeq = *b
	}
	f.Action, f.ActorID = p.queryFilter("action"), p.queryFilter("actor_id")
	f.TargetType, f.TargetID = p.queryFilter("target_type"), p.queryFilter("target_id")
	f.From, f.To = p.queryTime("from"), p.queryTime("to")
	if b := p.queryOptBool("include_http"); b != nil {
		f.IncludeHTTP = *b
	}
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if f.Limit == 0 {
		return []ojson.Object{}, nil // the store reads limit 0 as "no limit"
	}
	rows, err := store.TxFrom(r.Context()).AuditEvents(f)
	if err != nil {
		return nil, err
	}
	out := make([]ojson.Object, 0, len(rows))
	for _, e := range rows {
		out = append(out, auditRow(e))
	}
	return out, nil
}

func checkpointRow(c *store.AuditCheckpoint) ojson.Object {
	var anchoredAt any
	if c.AnchoredAt != nil {
		anchoredAt = c.AnchoredAt.UTC().Format(audit.TimeLayout)
	}
	return ojson.Object{{Key: "id", Value: c.ID.String()}, {Key: "seq", Value: c.Seq}, {Key: "head_hash", Value: c.HeadHash},
		{Key: "created_at", Value: c.CreatedAt.UTC().Format(audit.TimeLayout)}, {Key: "jws", Value: c.JWS},
		{Key: "anchor_status", Value: c.AnchorStatus}, {Key: "anchor_ref", Value: c.AnchorRef}, {Key: "anchored_at", Value: anchoredAt}}
}

var errAuditEventNotFound = errStatus(http.StatusNotFound, "Audit event not found")

// GET /api/audit/events/{event_id}/proof: the event in its hashed form, its
// neighbours' hashes and the checkpoint that covers it, so an auditor can
// check one entry offline (with GET /api/audit/export for the events up to
// the checkpoint and GET /api/audit/keys for the signing key).
func (s *Server) auditProof(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := uuid.Parse(p.path["event_id"])
	if err != nil {
		return nil, errAuditEventNotFound
	}
	tx := store.TxFrom(r.Context())
	e, err := tx.AuditEvent(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errAuditEventNotFound // also for another tenant's event
	}
	if err != nil {
		return nil, err
	}
	rec, err := audit.ExportRecord(e)
	if err != nil {
		return nil, err
	}
	neighbour := func(seq int64) (any, error) {
		n, err := tx.AuditEventBySeq(seq)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return ojson.Object{{Key: "seq", Value: n.Seq}, {Key: "hash", Value: n.Hash}, {Key: "prev_hash", Value: n.PrevHash}}, nil
	}
	prev, err := neighbour(e.Seq - 1)
	if err != nil {
		return nil, err
	}
	next, err := neighbour(e.Seq + 1)
	if err != nil {
		return nil, err
	}
	var ck any
	var between int64
	c, err := tx.CoveringAuditCheckpoint(e.Seq)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	default:
		ck = checkpointRow(c)
		between = c.Seq - e.Seq
	}
	return ojson.Object{
		{Key: "event", Value: rec}, {Key: "previous", Value: prev}, {Key: "next", Value: next},
		{Key: "checkpoint", Value: ck}, {Key: "events_to_checkpoint", Value: between},
		{Key: "hash_algorithm", Value: `sha256("tessera-audit-v1" || 0x00 || RFC8785(event without "hash"))`},
		{Key: "genesis", Value: audit.Genesis(tx.Tenant())},
	}, nil
}

// GET /api/audit/checkpoints?from_seq=
func (s *Server) auditCheckpoints(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	from := p.queryInt("from_seq", 0, i64(0), nil)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	cks, err := store.TxFrom(r.Context()).AuditCheckpoints(from, 0)
	if err != nil {
		return nil, err
	}
	out := make([]ojson.Object, 0, len(cks))
	for _, c := range cks {
		out = append(out, checkpointRow(c))
	}
	return out, nil
}

// GET /api/audit/keys: the platform public keys that sign checkpoints
// (retired ones included, revoked ones never), as a JWKS.
func (s *Server) auditKeys(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var out any
	err := s.store.InSystem(r.Context(), "GET /api/audit/keys", func(sys *store.SystemTx) error {
		set, err := keys.PlatformJWKS(sys, s.log)
		out = set
		return err
	})
	return out, err
}

// verifyBody is the optional body of POST /api/audit/verify.
type verifyBody struct {
	FromSeq *int64 `json:"from_seq"`
	ToSeq   *int64 `json:"to_seq"`
}

func decodeVerifyBody(r *http.Request) (verifyBody, error) {
	var b verifyBody
	v, present, err := readBody(r)
	if err != nil || !present {
		return b, err
	}
	raw, err := ojson.Marshal(v)
	if err != nil {
		return b, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, &validationError{[]verr{{Type: "model_attributes_type", Loc: []any{"body"},
			Msg: "Input should be an object with integer from_seq and to_seq", Input: v}}}
	}
	for name, x := range map[string]*int64{"from_seq": b.FromSeq, "to_seq": b.ToSeq} {
		if x != nil && *x < 0 {
			return b, &validationError{[]verr{{Type: "greater_than_equal", Loc: []any{"body", name},
				Msg: "Input should be greater than or equal to 0", Input: *x, Ctx: ojson.Object{{Key: "ge", Value: 0}}}}}
		}
	}
	return b, nil
}

// anchors loads the configured anchor source for verification: nil when
// there is none (or it is the S3 stub, which nothing can be read from yet).
func (s *Server) anchors() (*audit.AnchorSet, error) {
	if !strings.HasPrefix(s.cfg.AuditAnchor, "file://") {
		return nil, nil
	}
	path, err := audit.FilePath(s.cfg.AuditAnchor)
	if err != nil {
		return nil, err
	}
	set, err := audit.ReadAnchors(path)
	if errors.Is(err, os.ErrNotExist) {
		return audit.ParseAnchors(strings.NewReader(""))
	}
	return set, err
}

func (s *Server) tenantSlug(ctx context.Context, t tenancy.ID) string {
	var slug string
	_ = s.store.InSystem(ctx, "audit: tenant slug", func(sys *store.SystemTx) error {
		ts, err := sys.Tenants()
		for _, x := range ts {
			if x.ID == t {
				slug = x.Slug
			}
		}
		return err
	})
	return slug
}

// POST /api/audit/verify {from_seq?, to_seq?}: verifies the tenant's chain,
// checkpoints and anchors and records audit.verify.run.
func (s *Server) auditVerify(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, err := decodeVerifyBody(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	pub, err := audit.PlatformPublicKeys(ctx, s.store)
	if err != nil {
		return nil, err
	}
	anchors, err := s.anchors()
	if err != nil {
		return nil, err
	}
	opts := audit.VerifyOptions{Keys: pub, Anchors: anchors, Now: time.Now().UTC()}
	if body.FromSeq != nil {
		opts.FromSeq = *body.FromSeq
	}
	if body.ToSeq != nil {
		opts.ToSeq = *body.ToSeq
	}
	slug := s.tenantSlug(ctx, p.scope.Tenant)
	var rep audit.Report
	err = p.scope.Write(ctx, func(tx *store.TenantTx) error {
		var err error
		if rep, err = audit.Verify(tx, slug, opts); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, "audit.verify.run", ojson.Object{
			{Key: "from_seq", Value: opts.FromSeq}, {Key: "to_seq", Value: opts.ToSeq},
			{Key: "result", Value: rep.Result}, {Key: "exit_code", Value: rep.ExitCode},
			{Key: "events", Value: rep.Events}, {Key: "checkpoints", Value: rep.Checkpoints},
			{Key: "anchored", Value: rep.Anchored}, {Key: "anchors_checked", Value: anchors != nil}},
			audit.At(s.clock()))
		return err
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// GET /api/audit/export?from_seq=&to_seq=: NDJSON, one hashed record per
// line, streamed in pages (audit.Export) with chunked writes, so memory stays
// bounded whatever the chain's length. The route bypasses the handler
// timeout and runs under StreamTimeout (default 15 min); a longer export is
// split with from_seq/to_seq. Its http.request event is written before the
// first byte (503 if that fails); an audit.export event records how it ended
// (outcome error if the stream was cut short).
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	from := p.queryInt("from_seq", 1, i64(0), nil)
	to := p.queryInt("to_seq", 0, i64(0), nil)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	ctx := r.Context()
	if err := audit.StartStream(r); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, ojson.Object{{Key: "error", Value: "audit_unavailable"},
			{Key: "request_id", Value: audit.RequestID(ctx)}})
		return nil, nil
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="tessera-audit.ndjson"`)
	w.WriteHeader(http.StatusOK)
	n, exportErr := audit.Export(ctx, s.store, p.scope.Tenant, from, to, w)
	outcome := store.OutcomeSuccess
	if exportErr != nil {
		outcome = store.OutcomeError
		s.log.Error("audit export failed", "err", exportErr, "request_id", audit.RequestID(ctx))
	}
	if err := p.scope.Write(context.WithoutCancel(ctx), func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, "audit.export", ojson.Object{{Key: "from_seq", Value: from},
			{Key: "to_seq", Value: to}, {Key: "events", Value: n}}, audit.Outcome(outcome), audit.At(s.clock()))
		return err
	}); err != nil {
		s.log.Error("audit export event failed", "critical", true, "err", err, "request_id", audit.RequestID(ctx))
	}
	return nil, nil
}
