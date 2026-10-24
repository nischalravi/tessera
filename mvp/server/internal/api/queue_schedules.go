package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Job schedules an admin manages (issue #588), next to the built-in ones:
//
//	GET    /api/queue/schedule-kinds           the kinds an admin may schedule, with their payload
//	POST   /api/queue/schedules                {name, kind, spec, payload, max_attempts}: a new schedule, named custom.<name>
//	DELETE /api/queue/schedules/{name}         removes a custom schedule (a built-in one is paused, never deleted)
//	POST   /api/queue/schedules/{name}/run     queues the schedule's job now (once a minute at most)
//
// List, pause and resume were already there (GET /api/queue/schedules, .../pause, .../resume). Creating,
// deleting and running need jobs.manage and a fresh sign-in and are audited in the same transaction.
// Only the kinds below can be scheduled, each with its payload checked, and a schedule fires at most once
// a minute: connector_sync (a sync of the tenant's connections, incremental or full) and review_tick (launch
// the due review schedules and progress the open campaigns).

const (
	customSchedulePrefix = "custom."
	maxCustomSchedules   = 50
	minScheduleInterval  = time.Minute
	maxScheduleAttempts  = 10
)

var customScheduleNameRE = regexp.MustCompile(`^custom\.[a-z0-9][a-z0-9_.-]{0,60}$`)

// schedulableKind is a job kind an admin may schedule.
type schedulableKind struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Payload says what the payload may hold, for the form.
	Payload string `json:"payload"`
	check   func(raw json.RawMessage) (string, error)
}

func strictPayload(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errors.New("bad payload")
	}
	return nil
}

var schedulableKinds = []schedulableKind{
	{Kind: jobs.ConnectorSync, Label: "Connector sync", Description: "Reads the tenant's connections.",
		Payload: `{"mode": "incremental" | "full"}`,
		check: func(raw json.RawMessage) (string, error) {
			var p struct {
				Mode string `json:"mode"`
			}
			if len(bytes.TrimSpace(raw)) > 0 {
				if err := strictPayload(raw, &p); err != nil {
					return "", badRequest("invalid_payload", "the payload of a sync is {\"mode\": \"incremental\" or \"full\"}")
				}
			}
			if p.Mode == "" {
				p.Mode = "incremental"
			}
			if p.Mode != "incremental" && p.Mode != "full" {
				return "", badRequest("invalid_payload", "mode is incremental or full")
			}
			out, _ := json.Marshal(p)
			return string(out), nil
		}},
	{Kind: jobs.ReviewTick, Label: "Review scheduler", Description: "Launches due review schedules and progresses open campaigns.",
		Payload: `{}`,
		check: func(raw json.RawMessage) (string, error) {
			var p struct{}
			if len(bytes.TrimSpace(raw)) > 0 {
				if err := strictPayload(raw, &p); err != nil {
					return "", badRequest("invalid_payload", "this kind takes no payload")
				}
			}
			return "{}", nil
		}},
}

func (s *Server) registerQueueScheduleRoutes() {
	manage := needStepUp(auth.PermJobsManage, auth.StepUpPolicy)
	s.handle(http.MethodGet, "/api/queue/schedule-kinds", read, need(auth.PermJobsRead), s.listScheduleKinds)
	s.handle(http.MethodPost, "/api/queue/schedules", write, manage, s.createQueueSchedule)
	s.handle(http.MethodDelete, "/api/queue/schedules/{name}", write, manage, s.deleteQueueSchedule)
	s.handle(http.MethodPost, "/api/queue/schedules/{name}/run", write, manage, s.runQueueSchedule)
}

func (s *Server) listScheduleKinds(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	return map[string]any{"kinds": schedulableKinds, "name_prefix": customSchedulePrefix, "min_interval_seconds": int(minScheduleInterval / time.Second)}, nil
}

func (s *Server) createQueueSchedule(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var in struct {
		Name        string          `json:"name"`
		Kind        string          `json:"kind"`
		Spec        string          `json:"spec"`
		Payload     json.RawMessage `json:"payload"`
		MaxAttempts int             `json:"max_attempts"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	if !customScheduleNameRE.MatchString(in.Name) {
		return nil, badRequest("invalid_name", "a schedule name is custom. followed by 1 to 61 lowercase letters, digits, dots, dashes or underscores")
	}
	var kind *schedulableKind
	for i := range schedulableKinds {
		if schedulableKinds[i].Kind == in.Kind {
			kind = &schedulableKinds[i]
		}
	}
	if kind == nil {
		return nil, badRequest("invalid_kind", "this kind cannot be scheduled; see GET /api/queue/schedule-kinds")
	}
	payload, err := kind.check(in.Payload)
	if err != nil {
		return nil, err
	}
	sp, err := queue.ParseSpec(in.Spec)
	if err != nil {
		return nil, badRequest("invalid_spec", "the spec is @every <duration> or five cron fields")
	}
	now := s.clock().UTC()
	if sp.Next(sp.First(now)).Sub(sp.First(now)) < minScheduleInterval {
		return nil, badRequest("interval_too_short", "a schedule runs at most once a minute")
	}
	if in.MaxAttempts == 0 {
		in.MaxAttempts = 3
	}
	if in.MaxAttempts < 1 || in.MaxAttempts > maxScheduleAttempts {
		return nil, badRequest("invalid_max_attempts", "max_attempts is 1 to 10")
	}
	c := store.TxFrom(r.Context())
	existing, err := c.QueueSchedules()
	if err != nil {
		return nil, err
	}
	custom := 0
	for _, e := range existing {
		if e.Name == in.Name {
			return nil, &httpError{http.StatusConflict, "a schedule with this name exists"}
		}
		if strings.HasPrefix(e.Name, customSchedulePrefix) {
			custom++
		}
	}
	if custom >= maxCustomSchedules {
		return nil, badRequest("too_many_schedules", "a tenant has at most 50 custom schedules")
	}
	sched := &store.QueueSchedule{Name: in.Name, Kind: kind.Kind, Payload: payload, Spec: sp.String(), Enabled: true,
		MaxAttempts: in.MaxAttempts, NextRunAt: sp.First(now)}
	if err := c.SetQueueSchedule(sched, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor(r), "queue.schedule_created", ojson.Object{{Key: "schedule", Value: in.Name}, {Key: "kind", Value: kind.Kind},
		{Key: "spec", Value: sched.Spec}, {Key: "payload", Value: payload}, {Key: "max_attempts", Value: in.MaxAttempts}}); err != nil {
		return nil, err
	}
	cur, err := c.QueueSchedule(in.Name)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, viewQueueSchedule(cur)}, nil
}

func (s *Server) deleteQueueSchedule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	name := p.path["name"]
	if !queueScheduleNameRE.MatchString(name) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	if !strings.HasPrefix(name, customSchedulePrefix) {
		return nil, badRequest("built_in_schedule", "a built-in schedule cannot be deleted; pause it instead")
	}
	c := store.TxFrom(r.Context())
	cur, err := c.QueueSchedule(name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	} else if err != nil {
		return nil, err
	}
	if err := c.DeleteQueueSchedule(name); err != nil {
		return nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "queue.schedule_deleted", ojson.Object{{Key: "schedule", Value: name}, {Key: "kind", Value: cur.Kind}}); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": true}, nil
}

func (s *Server) runQueueSchedule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	name := p.path["name"]
	if !queueScheduleNameRE.MatchString(name) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	c := store.TxFrom(r.Context())
	cur, err := c.QueueSchedule(name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	} else if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	key := "run-now:" + name + ":" + now.Format("200601021504")
	created, err := s.queue.EnqueueTx(c, cur.Kind, cur.Payload, key, now, cur.MaxAttempts)
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, &httpError{http.StatusConflict, "this schedule was already run in the last minute"}
	}
	if err := c.Audit(now, actor(r), "queue.schedule_run_now", ojson.Object{{Key: "schedule", Value: name}, {Key: "kind", Value: cur.Kind}}); err != nil {
		return nil, err
	}
	return map[string]any{"queued": true, "kind": cur.Kind}, nil
}
