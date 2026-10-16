package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events/sinks"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group event sinks (issue #61, GR-18; design docs/design/groups-grouper-parity.md
// §10.1). A sink streams the group change events to AWS SQS, AWS SNS, RabbitMQ
// or Kafka as CloudEvents 1.0 JSON (internal/groups/events/sinks). Every route
// needs groups.admin, which only tenant_admin holds until GR-4. Credentials are
// sealed on write and never returned: a sink shows "credentials_set" only.
//
//	GET    /api/groups/event-sinks                                          every sink with its health and lag
//	POST   /api/groups/event-sinks                                          {name, kind, config, credentials, event_types, enabled, from}
//	GET    /api/groups/event-sinks/{id}
//	PATCH  /api/groups/event-sinks/{id}                                     {name, enabled, config, credentials, event_types}
//	DELETE /api/groups/event-sinks/{id}
//	GET    /api/groups/event-sinks/{id}/dead-letters?status=&limit=         events that could not be delivered (default status dead)
//	POST   /api/groups/event-sinks/{id}/dead-letters/{seq}/redeliver        send it again on the next pass (out of order)
//	POST   /api/groups/event-sinks/{id}/dead-letters/{seq}/discard          give up on it
//
// "from" is "now" (the default) or "start" (every event still in the outbox).
// A change to config or credentials replaces it whole and clears the retry state.
// The routes are registered before the {id} routes of groups_folders.go, which
// would otherwise match "event-sinks".
func (s *Server) registerGroupsSinkRoutes() {
	G, P, PA, D := http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete
	perm := need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/event-sinks", read, perm, s.rd(s.listGrpSinks))
	s.handle(P, "/api/groups/event-sinks", write, perm, s.rd(s.createGrpSink))
	s.handle(G, "/api/groups/event-sinks/{id}", read, perm, s.rd(s.getGrpSink))
	s.handle(PA, "/api/groups/event-sinks/{id}", write, perm, s.rd(s.patchGrpSink))
	s.handle(D, "/api/groups/event-sinks/{id}", write, perm, s.rd(s.deleteGrpSink))
	s.handle(G, "/api/groups/event-sinks/{id}/dead-letters", read, perm, s.rd(s.listGrpDeadLetters))
	s.handle(P, "/api/groups/event-sinks/{id}/dead-letters/{seq}/redeliver", write, perm, s.rd(s.redeliverGrpDeadLetter))
	s.handle(P, "/api/groups/event-sinks/{id}/dead-letters/{seq}/discard", write, perm, s.rd(s.discardGrpDeadLetter))
}

func (s *Server) sinkService() *sinks.Service {
	return &sinks.Service{Sealer: s.cfg.Sealer, AllowInsecure: s.cfg.Env == config.Dev}
}

// sinkErr maps the sinks package's refusals to API errors.
func sinkErr(err error) error {
	var se *sinks.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		return grpNotFound("sink or dead letter")
	case errors.As(err, &se):
		status := map[string]int{"invalid": http.StatusUnprocessableEntity, "conflict": http.StatusConflict,
			"unavailable": http.StatusServiceUnavailable}[se.Kind]
		return &readiness.Error{Status: status, Code: se.Code, Msg: se.Msg}
	}
	return err
}

type sinkView struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Kind             string          `json:"kind"`
	Enabled          bool            `json:"enabled"`
	Config           json.RawMessage `json:"config"`
	EventTypes       []string        `json:"event_types"`
	CredentialsSet   bool            `json:"credentials_set"`
	State            string          `json:"state"`
	Attempts         int             `json:"attempts"`
	NextAttemptAt    *string         `json:"next_attempt_at"`
	LastError        string          `json:"last_error"`
	LastDeliveredSeq int64           `json:"last_delivered_seq"`
	LastDeliveredAt  *string         `json:"last_delivered_at"`
	DeliveredCount   int64           `json:"delivered_count"`
	Cursor           int64           `json:"cursor"`
	Lag              int64           `json:"lag"`
	DeadLetters      int64           `json:"dead_letters"`
	CreatedBy        string          `json:"created_by"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

func sinkViewOf(tx *store.TenantTx, k *store.GrpSink) (sinkView, error) {
	cur, err := tx.GrpCursor(sinks.Consumer(k.ID))
	if err != nil {
		return sinkView{}, err
	}
	lag, err := events.Lag(tx, sinks.Consumer(k.ID))
	if err != nil {
		return sinkView{}, err
	}
	dead, err := tx.CountGrpDeadLetters(k.ID, store.DeadLetterDead)
	if err != nil {
		return sinkView{}, err
	}
	types := k.EventTypes
	if types == nil {
		types = []string{}
	}
	return sinkView{ID: k.ID, Name: k.Name, Kind: k.Kind, Enabled: k.Enabled, Config: k.Config, EventTypes: types,
		CredentialsSet: len(k.SecretEnc) > 0, State: k.State, Attempts: k.Attempts, NextAttemptAt: rtPtr(k.NextAttemptAt),
		LastError: k.LastError, LastDeliveredSeq: k.LastDeliveredSeq, LastDeliveredAt: rtPtr(k.LastDeliveredAt),
		DeliveredCount: k.DeliveredCount, Cursor: cur, Lag: lag, DeadLetters: dead, CreatedBy: k.CreatedBy,
		CreatedAt: store.RT(k.CreatedAt), UpdatedAt: store.RT(k.UpdatedAt)}, nil
}

func (s *Server) listGrpSinks(r *http.Request, _ *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	all, err := tx.GrpSinks()
	if err != nil {
		return 0, nil, err
	}
	items := make([]sinkView, 0, len(all))
	for _, k := range all {
		v, err := sinkViewOf(tx, k)
		if err != nil {
			return 0, nil, err
		}
		items = append(items, v)
	}
	return http.StatusOK, map[string]any{"items": items, "kinds": sinks.Kinds(), "max_sinks": sinks.MaxSinks,
		"allow_insecure": s.cfg.Env == config.Dev}, nil
}

func (s *Server) getGrpSink(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "sink")
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	k, err := tx.GrpSink(id)
	if err != nil {
		return 0, nil, sinkErr(err)
	}
	v, err := sinkViewOf(tx, k)
	return http.StatusOK, v, err
}

func (s *Server) createGrpSink(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Name        string            `json:"name"`
		Kind        string            `json:"kind"`
		Config      sinks.Config      `json:"config"`
		Credentials sinks.Credentials `json:"credentials"`
		EventTypes  []string          `json:"event_types"`
		Enabled     *bool             `json:"enabled"`
		From        string            `json:"from"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out sinkView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		k, err := s.sinkService().Create(c, sinks.CreateInput{Name: in.Name, Kind: in.Kind, Config: in.Config, Creds: in.Credentials,
			EventTypes: in.EventTypes, Enabled: in.Enabled == nil || *in.Enabled, From: in.From}, actor(r), now)
		if err != nil {
			return err
		}
		out, err = sinkViewOf(c, k)
		return err
	})
	if err != nil {
		return 0, nil, sinkErr(err)
	}
	return http.StatusCreated, out, nil
}

func (s *Server) patchGrpSink(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "sink")
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Name        *string            `json:"name"`
		Enabled     *bool              `json:"enabled"`
		Config      *sinks.Config      `json:"config"`
		Credentials *sinks.Credentials `json:"credentials"`
		EventTypes  *[]string          `json:"event_types"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out sinkView
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		k, err := s.sinkService().Update(c, id, sinks.UpdateInput{Name: in.Name, Enabled: in.Enabled, Config: in.Config,
			Creds: in.Credentials, EventTypes: in.EventTypes}, actor(r), now)
		if err != nil {
			return err
		}
		out, err = sinkViewOf(c, k)
		return err
	})
	if err != nil {
		return 0, nil, sinkErr(err)
	}
	return http.StatusOK, out, nil
}

func (s *Server) deleteGrpSink(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "sink")
	if err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		return s.sinkService().Delete(c, id, actor(r), now)
	})
	if err != nil {
		return 0, nil, sinkErr(err)
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

type deadLetterView struct {
	Seq       int64           `json:"seq"`
	EventType string          `json:"event_type"`
	ObjectID  string          `json:"object_id"`
	Attempts  int             `json:"attempts"`
	LastError string          `json:"last_error"`
	Status    string          `json:"status"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

func (s *Server) listGrpDeadLetters(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "sink")
	if err != nil {
		return 0, nil, err
	}
	limit, _, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	status := store.DeadLetterDead
	if v, ok := p.query("status"); ok {
		switch v {
		case store.DeadLetterDead, store.DeadLetterRequeued, store.DeadLetterDelivered, store.DeadLetterDiscarded, "all":
			status = v
		default:
			return 0, nil, badRequest("invalid_status", "status is dead, requeued, delivered, discarded or all")
		}
	}
	tx := store.TxFrom(r.Context())
	if _, err := tx.GrpSink(id); err != nil {
		return 0, nil, sinkErr(err)
	}
	filter := status
	if status == "all" {
		filter = ""
	}
	rows, err := tx.GrpDeadLetters(id, filter, limit)
	if err != nil {
		return 0, nil, err
	}
	items := make([]deadLetterView, 0, len(rows))
	for _, d := range rows {
		items = append(items, deadLetterView{Seq: d.Seq, EventType: d.EventType, ObjectID: d.ObjectID, Attempts: d.Attempts,
			LastError: d.LastError, Status: d.Status, Payload: json.RawMessage(d.Payload), CreatedAt: store.RT(d.CreatedAt),
			UpdatedAt: store.RT(d.UpdatedAt)})
	}
	return http.StatusOK, map[string]any{"items": items, "status": status, "limit": limit}, nil
}

func deadLetterSeq(p *params) (int64, error) {
	n, err := strconv.ParseInt(p.path["seq"], 10, 64)
	if err != nil || n < 1 {
		return 0, grpNotFound("dead letter")
	}
	return n, nil
}

func (s *Server) redeliverGrpDeadLetter(r *http.Request, p *params) (int, any, error) {
	return s.deadLetterAction(r, p, func(svc *sinks.Service, c *store.TenantTx, id string, seq int64, now time.Time) error {
		return svc.Requeue(c, id, seq, actor(r), now)
	}, "requeued")
}

func (s *Server) discardGrpDeadLetter(r *http.Request, p *params) (int, any, error) {
	return s.deadLetterAction(r, p, func(svc *sinks.Service, c *store.TenantTx, id string, seq int64, now time.Time) error {
		return svc.Discard(c, id, seq, actor(r), now)
	}, "discarded")
}

func (s *Server) deadLetterAction(r *http.Request, p *params, do func(*sinks.Service, *store.TenantTx, string, int64, time.Time) error, status string) (int, any, error) {
	id, err := grpPathID(p, "sink")
	if err != nil {
		return 0, nil, err
	}
	seq, err := deadLetterSeq(p)
	if err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error { return do(s.sinkService(), c, id, seq, now) })
	if err != nil {
		return 0, nil, sinkErr(err)
	}
	return http.StatusOK, map[string]any{"sink_id": id, "seq": seq, "status": status}, nil
}
