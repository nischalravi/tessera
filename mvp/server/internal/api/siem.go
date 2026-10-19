package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SIEM streaming (issue #169):
//
//	GET  /api/siem/sinks                              sinks with their health and lag
//	POST /api/siem/sinks                              add a sink
//	PUT  /api/siem/sinks/{sink_id}                    change a sink
//	POST /api/siem/sinks/{sink_id}/rewind {seq}       replay from seq+1 (0: everything)
//	POST /api/siem/sinks/{sink_id}/test               send one test event now
//	GET  /api/siem/sinks/{sink_id}/dead-letters       batches the destination rejected

func (s *Server) registerSiemRoutes() {
	readS, configure := need(auth.PermSiemRead), need(auth.PermSiemConfigure)
	configureStepUp := needStepUp(auth.PermSiemConfigure, auth.StepUpPolicy)
	s.handle(http.MethodGet, "/api/siem/sinks", read, readS, s.listSiemSinks)
	s.handle(http.MethodPost, "/api/siem/sinks", write, configureStepUp, s.createSiemSink)
	s.handle(http.MethodPut, "/api/siem/sinks/{sink_id}", write, configureStepUp, s.updateSiemSink)
	s.handle(http.MethodPost, "/api/siem/sinks/{sink_id}/rewind", write, configure, s.rewindSiemSink)
	s.handle(http.MethodPost, "/api/siem/sinks/{sink_id}/test", phased, configure, s.rd(s.testSiemSink))
	s.handle(http.MethodGet, "/api/siem/sinks/{sink_id}/dead-letters", read, readS, s.siemDeadLetters)
}

func siemErr(err error) error {
	var se *siem.Error
	if errors.As(err, &se) {
		return &readiness.Error{Status: se.Status, Code: se.Code, Msg: se.Msg}
	}
	return err
}

var errSinkNotFound = &readiness.Error{Status: http.StatusNotFound, Code: "sink_not_found", Msg: "sink not found"}

func siemActor(r *http.Request) (siem.Actor, error) {
	pr := principal(r)
	if pr.UserID == nil {
		return siem.Actor{}, &readiness.Error{Status: http.StatusForbidden, Code: "user_required", Msg: "only a signed-in user can do this"}
	}
	return siem.Actor{UserID: pr.UserID.String(), Display: pr.Display}, nil
}

type sinkView struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Kind            string      `json:"kind"`
	Format          string      `json:"format"`
	Target          string      `json:"target"` // webhook URLs without their query
	Flavor          string      `json:"flavor"`
	HasCA           bool        `json:"has_ca"`
	HasToken        bool        `json:"has_token"`
	IncludeHTTP     bool        `json:"include_http"`
	Enabled         bool        `json:"enabled"`
	CursorSeq       int64       `json:"cursor_seq"`
	HeadSeq         int64       `json:"head_seq"`
	Health          siem.Health `json:"health"`
	Attempts        int         `json:"attempts"`
	NextAttemptAt   *time.Time  `json:"next_attempt_at"`
	LastError       *string     `json:"last_error"`
	LastSuccessAt   *time.Time  `json:"last_success_at"`
	DeliveredCount  int64       `json:"delivered_count"`
	DeadLetterCount int64       `json:"dead_letter_count"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

func redactSinkTarget(k *store.SiemSink) string {
	if k.Kind != "webhook" {
		return k.Target
	}
	u, err := url.Parse(k.Target)
	if err != nil {
		return "(invalid URL)"
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

func sinkViewOf(tx *store.TenantTx, k *store.SiemSink, head int64) (sinkView, error) {
	pending, err := tx.SiemPending(k.CursorSeq, k.IncludeHTTP)
	if err != nil {
		return sinkView{}, err
	}
	return sinkView{ID: k.ID, Name: k.Name, Kind: k.Kind, Format: k.Format, Target: redactSinkTarget(k), Flavor: k.Flavor,
		HasCA: k.CAPEM != nil, HasToken: len(k.SecretSealed) > 0, IncludeHTTP: k.IncludeHTTP, Enabled: k.Enabled, CursorSeq: k.CursorSeq,
		HeadSeq: head, Health: siem.HealthOf(k, pending), Attempts: k.Attempts, NextAttemptAt: k.NextAttemptAt, LastError: k.LastError,
		LastSuccessAt: k.LastSuccessAt, DeliveredCount: k.DeliveredCount, DeadLetterCount: k.DeadLetterCount, CreatedAt: k.CreatedAt,
		UpdatedAt: k.UpdatedAt}, nil
}

func ledgerHead(tx *store.TenantTx) (int64, error) {
	h, err := tx.AuditHead()
	return h.LastSeq, err
}

func (s *Server) listSiemSinks(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	ks, err := tx.SiemSinks()
	if err != nil {
		return nil, err
	}
	head, err := ledgerHead(tx)
	if err != nil {
		return nil, err
	}
	out := make([]sinkView, 0, len(ks))
	for _, k := range ks {
		v, err := sinkViewOf(tx, k, head)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

type sinkBody struct {
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	Format      string  `json:"format"`
	Target      *string `json:"target"` // omitted on update: keep
	Flavor      string  `json:"flavor"`
	CAPEM       *string `json:"ca_pem"` // omitted on update: keep
	Token       *string `json:"token"`  // omitted: keep; "": clear
	IncludeHTTP bool    `json:"include_http"`
	Enabled     *bool   `json:"enabled"`
	Start       string  `json:"start"` // creation only: now | beginning
}

func (b sinkBody) spec(cur *store.SiemSink) siem.SinkSpec {
	sp := siem.SinkSpec{Name: b.Name, Kind: b.Kind, Format: b.Format, Flavor: b.Flavor, Token: b.Token, IncludeHTTP: b.IncludeHTTP,
		Enabled: b.Enabled == nil || *b.Enabled, Start: b.Start}
	if b.Target != nil {
		sp.Target = *b.Target
	} else if cur != nil {
		sp.Target = cur.Target
	}
	if b.CAPEM != nil {
		sp.CAPEM = *b.CAPEM
	} else if cur != nil && cur.CAPEM != nil {
		sp.CAPEM = *cur.CAPEM
	}
	if cur != nil {
		if sp.Format == "" {
			sp.Format = cur.Format
		}
		if sp.Flavor == "" {
			sp.Flavor = cur.Flavor
		}
	}
	return sp
}

func (s *Server) siemSealer() *seal.Sealer {
	if s.cfg.Siem == nil {
		return nil
	}
	return s.cfg.Siem.Sealer
}

func (s *Server) createSiemSink(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := siemActor(r)
	if err != nil {
		return nil, err
	}
	var b sinkBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	k, err := siem.CreateSink(tx, s.siemSealer(), b.spec(nil), s.cfg.Env == config.Dev, by, s.clock().UTC())
	if err != nil {
		return nil, siemErr(err)
	}
	head, err := ledgerHead(tx)
	if err != nil {
		return nil, err
	}
	v, err := sinkViewOf(tx, k, head)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, v}, nil
}

func (s *Server) updateSiemSink(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	by, err := siemActor(r)
	if err != nil {
		return nil, err
	}
	var b sinkBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	cur, err := tx.SiemSink(p.path["sink_id"])
	if errors.Is(err, store.ErrNotFound) {
		return nil, errSinkNotFound
	} else if err != nil {
		return nil, err
	}
	k, err := siem.UpdateSink(tx, s.siemSealer(), cur.ID, b.spec(cur), s.cfg.Env == config.Dev, by, s.clock().UTC())
	if err != nil {
		return nil, siemErr(err)
	}
	head, err := ledgerHead(tx)
	if err != nil {
		return nil, err
	}
	return sinkViewOf(tx, k, head)
}

func (s *Server) rewindSiemSink(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	by, err := siemActor(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		Seq *int64 `json:"seq"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.Seq == nil {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_seq", Msg: "give seq (0 replays everything)"}
	}
	tx := store.TxFrom(r.Context())
	k, err := siem.Rewind(tx, p.path["sink_id"], *b.Seq, by, s.clock().UTC())
	if err != nil {
		return nil, siemErr(err)
	}
	head, err := ledgerHead(tx)
	if err != nil {
		return nil, err
	}
	return sinkViewOf(tx, k, head)
}

// testSiemSink sends one synthetic event outside any transaction, then
// records the result.
func (s *Server) testSiemSink(r *http.Request, p *params) (int, any, error) {
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	svc := s.cfg.Siem
	if svc == nil {
		return 0, nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "siem_unavailable", Msg: "SIEM streaming is not configured"}
	}
	var k *store.SiemSink
	if err := p.scope.Read(r.Context(), func(tx *store.TenantTx) error {
		var err error
		k, err = tx.SiemSink(p.path["sink_id"])
		return err
	}); errors.Is(err, store.ErrNotFound) {
		return 0, nil, errSinkNotFound
	} else if err != nil {
		return 0, nil, err
	}
	slug := p.scope.Tenant.String()
	if ts, err := s.store.ActiveTenants(r.Context()); err == nil {
		for _, t := range ts {
			if t.ID == p.scope.Tenant {
				slug = t.Slug
			}
		}
	}
	sendErr := svc.TestSink(r.Context(), p.scope.Tenant, slug, k)
	result := map[string]any{"ok": sendErr == nil}
	if sendErr != nil {
		result["error"] = sendErr.Error()
	}
	now := s.clock().UTC()
	err := p.scope.Write(r.Context(), func(tx *store.TenantTx) error {
		det := ojson.Object{{Key: "sink_id", Value: k.ID}, {Key: "sink", Value: k.Name}, {Key: "ok", Value: sendErr == nil}}
		if sendErr != nil {
			det = append(det, ojson.KV{Key: "error", Value: sendErr.Error()})
		}
		return tx.Audit(now, principal(r).Display, "siem.sink.tested", det)
	})
	return http.StatusOK, result, err
}

type deadLetterView struct {
	ID        string    `json:"id"`
	FromSeq   int64     `json:"from_seq"`
	ToSeq     int64     `json:"to_seq"`
	Events    int       `json:"events"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) siemDeadLetters(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	if _, err := tx.SiemSink(p.path["sink_id"]); errors.Is(err, store.ErrNotFound) {
		return nil, errSinkNotFound
	} else if err != nil {
		return nil, err
	}
	ds, err := tx.SiemDeadLetters(p.path["sink_id"])
	if err != nil {
		return nil, err
	}
	out := make([]deadLetterView, 0, len(ds))
	for _, d := range ds {
		out = append(out, deadLetterView{d.ID, d.FromSeq, d.ToSeq, d.Events, d.Error, d.CreatedAt})
	}
	return out, nil
}
