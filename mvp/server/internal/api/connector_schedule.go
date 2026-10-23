package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// Connector sync schedule and status (Admin > Connections, issue #498):
//
//	GET /api/connectors/sync-status      the schedule, the last sync run, and per connector the record counts and last sync
//	PUT /api/connectors/sync-schedule    {delta_every_minutes, full_every_hours} (0 turns a schedule off)
//
// A delta sync lets each connector resume from its checkpoint; a full sync ignores the checkpoints. Both are schedules of
// the tenant's job queue, so they run as the connector_sync job (shown under Jobs) wherever a worker runs it.
func (s *Server) registerConnectorScheduleRoutes() {
	s.handle(http.MethodGet, "/api/connectors/sync-status", read, need(auth.PermConnectionsRead), s.connectorSyncStatus)
	s.handle(http.MethodPut, "/api/connectors/sync-schedule", write, need(auth.PermConnectionsManage), s.putConnectorSyncSchedule)
}

type syncScheduleView struct {
	DeltaEveryMinutes int     `json:"delta_every_minutes"`
	FullEveryHours    int     `json:"full_every_hours"`
	NextDeltaAt       *string `json:"next_delta_at"`
	NextFullAt        *string `json:"next_full_at"`
	LastDeltaQueuedAt *string `json:"last_delta_queued_at"`
	LastFullQueuedAt  *string `json:"last_full_queued_at"`
}

func syncScheduleOf(sc worker.SyncSchedule) syncScheduleView {
	return syncScheduleView{DeltaEveryMinutes: sc.DeltaMinutes, FullEveryHours: sc.FullHours, NextDeltaAt: timeutil.ISOPtr(sc.NextDelta),
		NextFullAt: timeutil.ISOPtr(sc.NextFull), LastDeltaQueuedAt: timeutil.ISOPtr(sc.LastDelta), LastFullQueuedAt: timeutil.ISOPtr(sc.LastFull)}
}

type syncRunView struct {
	Status     string  `json:"status"`
	Trigger    string  `json:"trigger"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
}

type connectorStatusRow struct {
	System       string  `json:"system"`
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Accounts     int     `json:"accounts"`
	Groups       int     `json:"groups"`
	Resources    int     `json:"resources"`
	Permissions  int     `json:"permissions"`
	LastSyncAt   *string `json:"last_sync_at"`      // the connector's checkpoint: when it last moved; nil for one that keeps none
	LastFullSync *string `json:"last_full_sync_at"` // when it last read everything
}

func (s *Server) connectorSyncStatus(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	sc, err := worker.GetSyncSchedule(c)
	if err != nil {
		return nil, err
	}
	srcs, err := s.sources(c)
	if err != nil {
		return nil, err
	}
	cps, err := c.ConnectorCheckpoints()
	if err != nil {
		return nil, err
	}
	type seen struct{ at, full *time.Time }
	bySystem := map[string]*seen{}
	for _, k := range cps {
		x := bySystem[k.System]
		if x == nil {
			x = &seen{}
			bySystem[k.System] = x
		}
		if at := k.UpdatedAt; x.at == nil || at.After(*x.at) {
			x.at = &at
		}
		if k.FullSyncAt != nil && (x.full == nil || k.FullSyncAt.After(*x.full)) {
			x.full = k.FullSyncAt
		}
	}
	rows := []connectorStatusRow{}
	for _, cn := range srcs {
		n, err := c.CountSystem(cn.system)
		if err != nil {
			return nil, err
		}
		row := connectorStatusRow{System: cn.system, Name: cn.name, Type: cn.typeName, Accounts: n.Accounts, Groups: n.Groups,
			Resources: n.Resources, Permissions: n.Permissions}
		if x := bySystem[cn.system]; x != nil {
			row.LastSyncAt, row.LastFullSync = timeutil.ISOPtr(x.at), timeutil.ISOPtr(x.full)
		}
		rows = append(rows, row)
	}
	var last *syncRunView
	runs, err := c.JobRuns(store.JobRunFilter{Kind: jobs.Sync, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(runs) > 0 {
		j := runs[0]
		last = &syncRunView{Status: j.Status, Trigger: j.Trigger, StartedAt: timeutil.ISO(j.StartedAt), FinishedAt: timeutil.ISOPtr(j.FinishedAt)}
	}
	return map[string]any{"schedule": syncScheduleOf(sc), "last_run": last, "connectors": rows}, nil
}

type syncScheduleBody struct {
	DeltaEveryMinutes int `json:"delta_every_minutes"`
	FullEveryHours    int `json:"full_every_hours"`
}

func (s *Server) putConnectorSyncSchedule(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b syncScheduleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := worker.CheckSyncSchedule(b.DeltaEveryMinutes, b.FullEveryHours); err != nil {
		return nil, badRequest("invalid_schedule", err.Error())
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	if err := worker.SetSyncSchedule(c, now, b.DeltaEveryMinutes, b.FullEveryHours); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor(r), "connectors.schedule_updated", ojson.Object{{Key: "delta_every_minutes", Value: b.DeltaEveryMinutes},
		{Key: "full_every_hours", Value: b.FullEveryHours}}); err != nil {
		return nil, err
	}
	sc, err := worker.GetSyncSchedule(c)
	if err != nil {
		return nil, err
	}
	return syncScheduleOf(sc), nil
}
