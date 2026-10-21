package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/retention"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Log retention and the archive (issue #298).
//
//	GET  /api/admin/retention                                 the retention of each class, defaults, floors, and whether archiving is on
//	GET  /api/admin/archive/segments?class=&status=&limit=    the archive catalogue, newest first
//	POST /api/admin/archive/segments/{segment_id}/verify      read the segment back and check it (chain hashes for audit)
//	GET  /api/admin/archive/segments/{segment_id}/export      the segment's records as NDJSON, after checking them; step-up
//
// Retention is changed through the admin change requests
// (POST /api/admin/change-requests, type retention.update: two admins, a
// step-up each, audited in the transaction that applies it), not here.

// archiveEvery is how often each tenant's archival job runs.
const archiveEvery = 6 * time.Hour

// maxArchiveAttempts: a failing run is retried once; the next window tries again anyway.
const maxArchiveAttempts = 2

func (s *Server) registerArchiveRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/admin/retention", read, need(auth.PermAdminRead), s.getRetention)
	s.handle(G, "/api/admin/archive/segments", read, need(auth.PermAuditRead), s.listArchive)
	s.handle(P, "/api/admin/archive/segments/{segment_id}/verify", phased, need(auth.PermAuditVerify), s.verifyArchiveSegment)
	s.handle(G, "/api/admin/archive/segments/{segment_id}/export", phased, needStepUp(auth.PermAuditRead, auth.StepUpAdmin),
		s.exportArchiveSegment).stream = true
}

// queueArchive is the queue handler of the archival job.
func (s *Server) queueArchive(ctx context.Context, j queue.Job) (any, error) {
	if !s.archive.Enabled() {
		return nil, nil
	}
	res, err := s.archive.RunTenant(ctx, j.Tenant)
	if res.Total() == 0 && err == nil {
		return nil, nil // nothing was due: no job run
	}
	return res, err
}

// archiveSource is the verifier's view of the archive: nil when archiving is off.
func (s *Server) archiveSource() audit.ArchiveSource {
	if s.archive.Enabled() {
		return s.archive
	}
	return nil
}

type retentionView struct {
	Archive  archiveStatus       `json:"archive"`
	Settings []retention.Setting `json:"settings"`
}

type archiveStatus struct {
	Enabled bool `json:"enabled"`
	// Location is local or remote ("" when archiving is not configured).
	Location string `json:"location"`
	// EverySeconds is how often the archival job runs.
	EverySeconds int64 `json:"every_seconds"`
}

func (s *Server) archiveStatus() archiveStatus {
	st := archiveStatus{EverySeconds: int64(archiveEvery / time.Second)}
	if s.archive.Enabled() {
		st.Enabled, st.Location = true, s.archive.Store.Location()
	}
	return st
}

func (s *Server) getRetention(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	ss, err := retention.Effective(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return retentionView{Archive: s.archiveStatus(), Settings: ss}, nil
}

type segmentView struct {
	ID         string  `json:"id"`
	Class      string  `json:"class"`
	Status     string  `json:"status"`
	Count      int64   `json:"count"`
	SeqFrom    int64   `json:"seq_from,omitempty"`
	SeqTo      int64   `json:"seq_to,omitempty"`
	RangeFrom  string  `json:"range_from"`
	RangeTo    string  `json:"range_to"`
	FirstHash  string  `json:"first_hash,omitempty"`
	LastHash   string  `json:"last_hash,omitempty"`
	SHA256     string  `json:"sha256"`
	Size       int64   `json:"size_bytes"`
	Location   string  `json:"location"`
	CreatedAt  string  `json:"created_at"`
	VerifiedAt *string `json:"verified_at"`
	PurgedAt   *string `json:"purged_at"`
}

func viewSegment(g *store.ArchiveSegment) segmentView {
	return segmentView{ID: g.ID, Class: g.Class, Status: g.Status, Count: g.Count, SeqFrom: g.SeqFrom, SeqTo: g.SeqTo,
		RangeFrom: g.RangeFrom, RangeTo: g.RangeTo, FirstHash: g.FirstHash, LastHash: g.LastHash, SHA256: g.SHA256, Size: g.Size,
		Location: g.Location, CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339), VerifiedAt: isoPtr(g.VerifiedAt), PurgedAt: isoPtr(g.PurgedAt)}
}

var segmentStatuses = []string{store.SegmentWritten, store.SegmentVerified, store.SegmentPurged, store.SegmentFailed}

func (s *Server) listArchive(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	class, _ := p.query("class")
	status, _ := p.query("status")
	if class != "" && !slices.Contains(store.ArchiveClasses, class) {
		return nil, badRequest("invalid_class", "class must be one of "+joinComma(store.ArchiveClasses))
	}
	if status != "" && !slices.Contains(segmentStatuses, status) {
		return nil, badRequest("invalid_status", "status must be one of "+joinComma(segmentStatuses))
	}
	limit := 200
	if l, _ := p.query("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		limit = n
	}
	gs, err := store.TxFrom(r.Context()).ArchiveSegments(store.ArchiveSegmentFilter{Class: class, Status: status, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]segmentView, 0, len(gs))
	for _, g := range gs {
		out = append(out, viewSegment(g))
	}
	return ojson.Object{{Key: "archive", Value: s.archiveStatus()}, {Key: "segments", Value: out}}, nil
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// segment loads the segment named in the path, 404 for another tenant's or an unknown one.
func (s *Server) segment(tx *store.TenantTx, p *params) (*store.ArchiveSegment, error) {
	id := p.path["segment_id"]
	if !idRE.MatchString(id) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	g, err := tx.ArchiveSegment(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	return g, err
}

func (s *Server) needArchive() error {
	if !s.archive.Enabled() {
		return &httpError{http.StatusServiceUnavailable, "archiving is not configured on this server (TESSERA_ARCHIVE_DIR or TESSERA_ARCHIVE_URL, and a KEK)"}
	}
	return nil
}

// POST .../verify reads the segment back from the archive store and checks it.
// A segment that fails is the answer (ok false, the problem), not an error.
func (s *Server) verifyArchiveSegment(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := s.needArchive(); err != nil {
		return nil, err
	}
	ctx := r.Context()
	var out archive.SegmentCheck
	err := p.scope.Write(ctx, func(tx *store.TenantTx) error {
		g, err := s.segment(tx, p)
		if err != nil {
			return err
		}
		if g.Status == store.SegmentFailed {
			return &httpError{http.StatusConflict, "this segment failed verification when it was written and was given up; its records were archived again in a newer segment"}
		}
		if out, err = s.archive.Verify(ctx, p.scope.Tenant, g); err != nil {
			return err
		}
		outcome := store.OutcomeSuccess
		if !out.OK {
			outcome = store.OutcomeFailure
		}
		_, err = audit.Record(ctx, tx, "archive.segment.checked", ojson.Object{{Key: "segment_id", Value: g.ID}, {Key: "class", Value: g.Class},
			{Key: "ok", Value: out.OK}, {Key: "records", Value: out.Records}}, audit.At(s.clock()), audit.Outcome(outcome),
			audit.Target(audit.TargetArchiveSegment, g.ID))
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GET .../export streams the segment's records as NDJSON after checking them:
// the read-only restore. Its http.request event is written before the first
// byte (503 if that fails); archive.segment.exported records how it ended.
func (s *Server) exportArchiveSegment(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := s.needArchive(); err != nil {
		return nil, err
	}
	ctx := r.Context()
	var g *store.ArchiveSegment
	if err := p.scope.Read(ctx, func(tx *store.TenantTx) error {
		var err error
		g, err = s.segment(tx, p)
		return err
	}); err != nil {
		return nil, err
	}
	if g.Status == store.SegmentFailed {
		return nil, &httpError{http.StatusConflict, "this segment failed verification when it was written and was given up"}
	}
	// check before the first byte: a segment that does not verify is an error response, not a cut-off stream
	if chk, err := s.archive.Verify(ctx, p.scope.Tenant, g); err != nil {
		return nil, err
	} else if !chk.OK {
		return nil, &httpError{http.StatusConflict, "the archived segment does not verify: " + chk.Problem}
	}
	if err := audit.StartStream(r); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, ojson.Object{{Key: "error", Value: "audit_unavailable"},
			{Key: "request_id", Value: audit.RequestID(ctx)}})
		return nil, nil
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="tessera-archive-`+g.Class+`-`+g.ID+`.ndjson"`)
	w.WriteHeader(http.StatusOK)
	n, exportErr := s.archive.Export(ctx, p.scope.Tenant, g, w)
	outcome := store.OutcomeSuccess
	if exportErr != nil {
		outcome = store.OutcomeError
		s.log.Error("archive export failed", "err", exportErr, "request_id", audit.RequestID(ctx))
	}
	if err := p.scope.Write(context.WithoutCancel(ctx), func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, "archive.segment.exported", ojson.Object{{Key: "segment_id", Value: g.ID}, {Key: "class", Value: g.Class},
			{Key: "records", Value: n}}, audit.Outcome(outcome), audit.At(s.clock()), audit.Target(audit.TargetArchiveSegment, g.ID))
		return err
	}); err != nil {
		s.log.Error("archive export event failed", "critical", true, "err", err, "request_id", audit.RequestID(ctx))
	}
	return nil, nil
}

// archiveJobKind is the queue kind of the archival job.
const archiveJobKind = jobs.ArchiveSweep
