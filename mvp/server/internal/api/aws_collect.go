package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The AWS collection job (issue #637, EP-1; docs/design/differentiators-plan.md
// section 1). Collecting a connector reads every account of the estate and can
// outlast a request, so it is a job of the durable queue (kind aws_collect):
//
//	POST /api/aws/connectors/{id}/collect  queue a collection and its evaluation; 202 {run_id, status: "queued"}
//	GET  /api/aws/collection-runs          the runs, newest first (?connector_id=, ?limit=)
//	GET  /api/aws/collection-runs/{id}     one run: poll it for the outcome
//
// A worker runs awsorg.Service.CollectAndMaterialize: it collects, and when the
// estate changed it evaluates the snapshot and brings the graph up to date. A
// scheduled run of the same job (every 6 hours; pause it like any built-in
// schedule) does this for every connector of the tenant. AWS has no change feed
// for GetAccountAuthorizationDetails, so each run reads the estate; the write is
// what is incremental. The snapshot id is the content hash, so an estate that
// has not changed since the run that evaluated it writes no snapshot and no
// event, is not evaluated again, and a scheduled run leaves no run row or job
// run (the connector's last-run time is the only write).
//
// A connector whose config has "usage" also ingests usage in the same job, after
// the estate (issue #644; awsorg.Service.CollectUsage): the org CloudTrail's log
// files since a per-connector cursor, and IAM Access Advisor, into aws_usage_daily.
// A failure of the usage ingest is in the run's result (usage_error) and never
// fails the collection; an unchanged estate with new usage still leaves no run row.
//
// Starting a collection changes what the evaluator answers and costs AWS API
// calls in the customer's account, so it needs connections.manage and a fresh
// sign-in, like creating the connector. Listing runs needs connections.read.
// A connector has at most one queued or running run (409 collection_in_progress).
func (s *Server) registerAWSCollectRoutes() {
	s.handle(http.MethodPost, "/api/aws/connectors/{id}/collect", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.collectAWSConnector))
	s.handle(http.MethodGet, "/api/aws/collection-runs", read, need(auth.PermConnectionsRead), s.rd(s.listAWSCollectionRuns))
	s.handle(http.MethodGet, "/api/aws/collection-runs/{id}", read, need(auth.PermConnectionsRead), s.rd(s.getAWSCollectionRun))
}

const (
	awsCollectActor = "aws.collector"
	// awsCollectEvery is the scheduled collection's interval.
	awsCollectEvery = 6 * time.Hour
	// awsRunStaleAfter: a run still queued or running this long after it was queued lost its worker; it is failed
	// so it stops blocking the connector.
	awsRunStaleAfter = 2 * time.Hour
)

// awsCollector is the service that collects and evaluates: the server's HTTP
// client for AWS and its action catalog. The errors are API refusals (503).
func (s *Server) awsCollector() (*awsorg.Service, error) {
	if s.cfg.AWSHTTP == nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "aws_collector_unavailable",
			Msg: "this server has no outbound client for AWS collections"}
	}
	cat, err := s.awsCatalog()
	if err != nil {
		return nil, err
	}
	cfg := &awsorg.EvalConfig{Index: cat.indexConfig}
	var canonical func(string) (string, bool)
	if v, ok := cat.Cat.(*catalog.EvalView); ok && v.C != nil {
		cfg.Privileged = func(action string) bool { return v.C.AccessLevel(action) == catalog.AccessPermissionsManagement }
		canonical = v.C.CanonicalAction // the usage ingest files only actions the catalog has
	}
	return &awsorg.Service{Sealer: s.cfg.Sealer, Client: &awsorg.Client{HTTP: s.cfg.AWSHTTP, Now: s.clock}, Clock: s.clock,
		CatalogVersion: cat.Cat.Version(), Eval: cfg, Canonical: canonical, AllowStaticKeys: s.cfg.AWSAllowStaticKeys,
		Federation: &awsorg.Federation{DB: s.store, Sealer: s.cfg.Sealer, PublicURL: s.cfg.PublicURL, Clock: s.clock}}, nil
}

type awsCollectPayload struct {
	RunID       string `json:"run_id"`
	ConnectorID string `json:"connector_id"`
}

type awsRunView struct {
	ID          string          `json:"id"`
	ConnectorID string          `json:"connector_id"`
	Trigger     string          `json:"trigger"`
	Status      string          `json:"status"`
	RequestedBy string          `json:"requested_by"`
	QueuedAt    string          `json:"queued_at"`
	StartedAt   *string         `json:"started_at"`
	FinishedAt  *string         `json:"finished_at"`
	SnapshotID  string          `json:"snapshot_id"`
	Changed     bool            `json:"changed"`
	Result      json.RawMessage `json:"result"`
	Error       string          `json:"error"`
}

func awsRunViewOf(r *store.AWSCollectionRun) awsRunView {
	v := awsRunView{ID: r.ID, ConnectorID: r.ConnectorID, Trigger: r.Trigger, Status: r.Status, RequestedBy: r.RequestedBy,
		QueuedAt: store.RT(r.QueuedAt), StartedAt: awsRT(r.StartedAt), FinishedAt: awsRT(r.FinishedAt), SnapshotID: r.SnapshotID,
		Changed: r.Changed, Result: json.RawMessage("null"), Error: r.Error}
	if len(r.Result) > 0 {
		v.Result = r.Result
	}
	return v
}

func (s *Server) collectAWSConnector(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.awsCollector(); err != nil {
		return 0, nil, err
	}
	var run *store.AWSCollectionRun
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		if _, err := c.AWSConnector(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such connector"}
			}
			return err
		}
		if _, err := c.FailStaleAWSCollectionRuns(now.Add(-awsRunStaleAfter), now, "interrupted: the worker running this collection stopped"); err != nil {
			return err
		}
		run = &store.AWSCollectionRun{ID: store.NewID(), ConnectorID: id, Trigger: store.AWSRunManual, Status: store.AWSRunQueued,
			RequestedBy: actor(r), QueuedAt: now}
		if err := c.InsertAWSCollectionRun(run); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				e := &readiness.Error{Status: http.StatusConflict, Code: "collection_in_progress", Msg: "this connector already has a collection queued or running"}
				if cur, gerr := c.ActiveAWSCollectionRun(id); gerr == nil {
					e.Extra = map[string]any{"run_id": cur.ID}
				}
				return e
			}
			return err
		}
		payload, err := json.Marshal(awsCollectPayload{RunID: run.ID, ConnectorID: id})
		if err != nil {
			return err
		}
		// one attempt: a failure is the run's outcome, and the next request or window collects again
		if _, err := s.queue.EnqueueTx(c, jobs.AWSCollect, string(payload), run.ID, now, 1); err != nil {
			return err
		}
		return c.Audit(now, actor(r), "aws.collection.queued", ojson.Object{{Key: "connector_id", Value: id}, {Key: "run_id", Value: run.ID}})
	})
	if err != nil {
		return 0, nil, awsErr(err)
	}
	return http.StatusAccepted, map[string]any{"run_id": run.ID, "connector_id": id, "status": run.Status}, nil
}

func (s *Server) listAWSCollectionRuns(r *http.Request, _ *params) (int, any, error) {
	connector := r.URL.Query().Get("connector_id")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		limit = n
	}
	if connector != "" && !idRE.MatchString(connector) {
		return 0, nil, badRequest("invalid_connector_id", "connector_id is not a connector id")
	}
	runs, err := store.TxFrom(r.Context()).AWSCollectionRuns(connector, limit)
	if err != nil {
		return 0, nil, err
	}
	items := make([]awsRunView, 0, len(runs))
	for _, x := range runs {
		items = append(items, awsRunViewOf(x))
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) getAWSCollectionRun(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	notFound := &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such collection run"}
	if !idRE.MatchString(id) {
		return 0, nil, notFound
	}
	x, err := store.TxFrom(r.Context()).AWSCollectionRun(id)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, notFound
	} else if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, awsRunViewOf(x), nil
}

// ---------------------------------------------------------------- the job

// queueAWSCollect runs the aws_collect job: the collection a request queued
// (payload names its run), or, with no payload, the scheduled one.
func (s *Server) queueAWSCollect(ctx context.Context, j queue.Job) (any, error) {
	ctx = audit.WithSystemActor(ctx, awsCollectActor)
	var p awsCollectPayload
	if strings.TrimSpace(j.Payload) != "" && strings.TrimSpace(j.Payload) != "{}" {
		if err := json.Unmarshal([]byte(j.Payload), &p); err != nil || !idRE.MatchString(p.RunID) || !idRE.MatchString(p.ConnectorID) {
			return nil, queue.Permanent(errors.New("aws_collect: bad payload"))
		}
		return s.awsCollectRequested(ctx, j, p)
	}
	return s.awsCollectScheduled(ctx, j)
}

// awsRunResult is the summary a run keeps: counts, never policy text.
type awsRunResult struct {
	SnapshotID  string `json:"snapshot_id"`
	Changed     bool   `json:"changed"`
	Permissions int    `json:"permissions,omitempty"`
	TrustEdges  int    `json:"trust_edges,omitempty"`
	Pruned      int    `json:"pruned_edges,omitempty"`
	Notes       int    `json:"notes,omitempty"`
	// the usage ingest (issue #644), counts only
	Usage      *awsorg.UsageStats `json:"usage,omitempty"`
	UsageError string             `json:"usage_error,omitempty"`
}

func awsRunResultOf(res *awsorg.CollectResult) awsRunResult {
	out := awsRunResult{SnapshotID: res.SnapshotID, Changed: res.Changed, Usage: res.Usage, UsageError: res.UsageError}
	if m := res.Materialized; m != nil {
		out.Permissions, out.TrustEdges, out.Pruned, out.Notes = m.Cells, m.Trust, m.Pruned, len(m.Notes)
	}
	return out
}

func (s *Server) awsCollectRequested(ctx context.Context, j queue.Job, p awsCollectPayload) (any, error) {
	var run *store.AWSCollectionRun
	err := s.store.InTenant(ctx, j.Tenant, func(c *store.TenantTx) (err error) {
		if run, err = c.AWSCollectionRun(p.RunID); err != nil {
			return err
		}
		return c.StartAWSCollectionRun(p.RunID, s.clock())
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil // it was failed as stale, or never existed: nothing to run
	} else if err != nil {
		return nil, err
	}
	svc, err := s.awsCollector()
	var res *awsorg.CollectResult
	if err == nil {
		res, err = svc.CollectAndMaterialize(ctx, s.store, j.Tenant, p.ConnectorID, run.RequestedBy)
	}
	if err != nil && ctx.Err() != nil {
		return nil, err // shutdown: the queue hands the job back, and the run stays running for the next worker
	}
	rec := context.WithoutCancel(ctx)
	now := s.clock()
	ferr := s.store.InTenant(rec, j.Tenant, func(c *store.TenantTx) error {
		if err != nil {
			msg := jobs.ErrorSummary(err)
			if ferr := c.FinishAWSCollectionRun(p.RunID, store.AWSRunFailed, "", false, nil, msg, now); ferr != nil {
				return ferr
			}
			var refused *readiness.Error
			if errors.As(err, &refused) { // refused before the service ran, so it recorded nothing itself
				return c.Audit(now, run.RequestedBy, "aws.collection.failed", ojson.Object{{Key: "connector_id", Value: p.ConnectorID},
					{Key: "code", Value: refused.Code}})
			}
			return nil
		}
		status := store.AWSRunSucceeded
		if !res.Changed {
			status = store.AWSRunUnchanged
		}
		b, merr := json.Marshal(awsRunResultOf(res))
		if merr != nil {
			return merr
		}
		return c.FinishAWSCollectionRun(p.RunID, status, res.SnapshotID, res.Changed, b, "", now)
	})
	if ferr != nil {
		err = errors.Join(err, ferr)
	}
	if err != nil {
		return nil, queue.Permanent(err)
	}
	return awsRunResultOf(res), nil
}

func (s *Server) awsCollectScheduled(ctx context.Context, j queue.Job) (any, error) {
	var conns []*store.AWSConnector
	now := s.clock()
	if err := s.store.InTenant(ctx, j.Tenant, func(c *store.TenantTx) (err error) {
		if conns, err = c.AWSConnectors(); err != nil || len(conns) == 0 {
			return err
		}
		_, err = c.FailStaleAWSCollectionRuns(now.Add(-awsRunStaleAfter), now, "interrupted: the worker running this collection stopped")
		return err
	}); err != nil || len(conns) == 0 {
		return nil, err
	}
	svc, err := s.awsCollector()
	if err != nil {
		return nil, nil // a server with no AWS client or catalog has nothing to collect with
	}
	var changed, failed int
	var errs []error
	for _, k := range conns {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		busy := false
		if err := s.store.ReadTenant(ctx, j.Tenant, func(c *store.TenantTx) error {
			_, err := c.ActiveAWSCollectionRun(k.ID)
			busy = err == nil
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}); err != nil {
			errs = append(errs, err)
			continue
		}
		if busy {
			continue // a requested collection is on it
		}
		started := s.clock()
		res, err := svc.CollectAndMaterialize(ctx, s.store, j.Tenant, k.ID, awsCollectActor)
		if err == nil && !res.Changed {
			continue // nothing changed: nothing is written
		}
		if err != nil && ctx.Err() != nil {
			return nil, err
		}
		run := &store.AWSCollectionRun{ID: store.NewID(), ConnectorID: k.ID, Trigger: store.AWSRunSchedule, Status: store.AWSRunSucceeded,
			RequestedBy: awsCollectActor, QueuedAt: started, StartedAt: &started}
		fin := s.clock()
		run.FinishedAt = &fin
		if err != nil {
			failed++
			run.Status, run.Error = store.AWSRunFailed, jobs.ErrorSummary(err)
			errs = append(errs, fmt.Errorf("connector %s: %w", k.ID, err))
		} else {
			changed++
			run.SnapshotID, run.Changed = res.SnapshotID, true
			if run.Result, err = json.Marshal(awsRunResultOf(res)); err != nil {
				return nil, err
			}
		}
		if rerr := s.store.InTenant(context.WithoutCancel(ctx), j.Tenant, func(c *store.TenantTx) error { return c.InsertAWSCollectionRun(run) }); rerr != nil {
			errs = append(errs, rerr)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return map[string]int{"connectors": len(conns), "changed": changed, "failed": failed}, err
	}
	if changed == 0 {
		return nil, nil
	}
	return map[string]int{"connectors": len(conns), "changed": changed, "failed": failed}, nil
}
