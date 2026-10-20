package api

import (
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/rotation"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Secret rotation routes (issue #113). New API surface: plain JSON errors
// ({"error": code, "detail": msg}) like the readiness routes. Reading needs
// graph.read, like the NHI views these screens extend. Everything that
// changes rotation (adapters and their credentials, policies, rotate now,
// retry, the vendor-compromised run) needs secrets.rotate (policy_admin) and
// a fresh phishing-resistant sign-in. Planning is a dry run: it reads the
// database, calls no provider and writes nothing.
//
// The sealed adapter credentials never leave the server: no route returns
// them, and a new credential is handed to the customer's vault by the worker
// (rotation.Engine), not by a request.
func (s *Server) registerRotationRoutes() {
	G, P, PUT, DEL := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	rot := needStepUp(auth.PermSecretsRotate, auth.StepUpPolicy)
	s.handle(G, "/api/rotation/openapi.json", noTenant, need(auth.PermAuthenticated), s.rotationOpenAPI)
	s.handle(G, "/api/rotation/overview", read, need(auth.PermGraphRead), s.rd(s.rotOverview))
	s.handle(G, "/api/rotation/adapters", read, need(auth.PermGraphRead), s.rd(s.rotAdapters))
	s.handle(PUT, "/api/rotation/adapters/{name}", write, rot, s.rd(s.rotPutAdapter))
	s.handle(DEL, "/api/rotation/adapters/{name}", write, rot, s.rd(s.rotDeleteAdapter))
	s.handle(G, "/api/rotation/policies", read, need(auth.PermGraphRead), s.rd(s.rotPolicies))
	s.handle(PUT, "/api/rotation/policies", write, rot, s.rd(s.rotPutPolicy))
	s.handle(DEL, "/api/rotation/policies/{id}", write, rot, s.rd(s.rotDeletePolicy))
	// plans are computed data: like what-if analysis they are recorded by
	// their http.request event and fail closed like a read (design §13.4)
	s.handle(P, "/api/rotation/plan", read, need(auth.PermGraphRead), s.rd(s.rotPlan)).answersRead = true
	s.handle(G, "/api/rotation/jobs", read, need(auth.PermGraphRead), s.rd(s.rotJobs))
	s.handle(P, "/api/rotation/jobs", write, rot, s.rd(s.rotStart))
	s.handle(G, "/api/rotation/jobs/{id}", read, need(auth.PermGraphRead), s.rd(s.rotJob))
	s.handle(P, "/api/rotation/jobs/{id}/retry", write, rot, s.rd(s.rotRetry))
	s.handle(P, "/api/rotation/jobs/{id}/cancel", write, rot, s.rd(s.rotCancel))
	s.handle(P, "/api/rotation/bulk/plan", read, need(auth.PermGraphRead), s.rd(s.rotBulkPlan)).answersRead = true
	s.handle(G, "/api/rotation/bulk", read, need(auth.PermGraphRead), s.rd(s.rotBulks))
	s.handle(P, "/api/rotation/bulk", write, rot, s.rd(s.rotBulkExecute))
	s.handle(G, "/api/rotation/bulk/{id}", read, need(auth.PermGraphRead), s.rd(s.rotBulk))
}

// rotErr renders a rotation.Problem as the readiness error shape.
func rotErr(err error) error {
	var p *rotation.Problem
	if errors.As(err, &p) {
		return &readiness.Error{Status: p.Status, Code: p.Code, Msg: p.Msg}
	}
	return err
}

func (s *Server) rotOverview(r *http.Request, _ *params) (int, any, error) {
	out, err := s.rotation.Overview(store.TxFrom(r.Context()), s.clock())
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotAdapters(r *http.Request, _ *params) (int, any, error) {
	out, err := s.rotation.Adapters(store.TxFrom(r.Context()))
	return http.StatusOK, map[string]any{"adapters": out, "types": rotation.AdapterTypes(s.cfg.RotationFake)}, rotErr(err)
}

var adapterNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func (s *Server) rotPutAdapter(r *http.Request, p *params) (int, any, error) {
	name := p.path["name"]
	if !adapterNameRE.MatchString(name) {
		return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such adapter"}
	}
	var in rotation.AdapterInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Name != "" && in.Name != name {
		return 0, nil, badRequest("name_mismatch", "the name in the body must match the name in the path")
	}
	in.Name = name
	var out *rotation.AdapterView
	var created bool
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		out, created, err = s.rotation.PutAdapter(c, in, actor(r), now)
		return err
	})
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return status, out, rotErr(err)
}

func (s *Server) rotDeleteAdapter(r *http.Request, p *params) (int, any, error) {
	name := p.path["name"]
	if !adapterNameRE.MatchString(name) {
		return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such adapter"}
	}
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		a, err := c.RotationAdapterByName(name)
		if errors.Is(err, store.ErrNotFound) {
			return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such adapter"}
		}
		if err != nil {
			return err
		}
		return s.rotation.DeleteAdapter(c, a.ID, actor(r), now)
	})
	return http.StatusOK, map[string]any{"deleted": name}, rotErr(err)
}

func (s *Server) rotPolicies(r *http.Request, _ *params) (int, any, error) {
	out, err := s.rotation.Policies(store.TxFrom(r.Context()))
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotPutPolicy(r *http.Request, _ *params) (int, any, error) {
	var in rotation.PolicyInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *rotation.PolicyView
	var created bool
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		out, created, err = s.rotation.PutPolicy(c, in, actor(r), now)
		return err
	})
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return status, out, rotErr(err)
}

func (s *Server) rotDeletePolicy(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error { return s.rotation.DeletePolicy(c, id, actor(r), now) })
	return http.StatusOK, map[string]any{"deleted": id}, rotErr(err)
}

func (s *Server) rotPlan(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		SecretIDs []int64 `json:"secret_ids"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	if len(in.SecretIDs) > 500 {
		return 0, nil, badRequest("too_many", "plan at most 500 secrets at a time")
	}
	out, err := s.rotation.Plan(store.TxFrom(r.Context()), in.SecretIDs, s.clock())
	if out == nil {
		out = []*rotation.PlanItem{}
	}
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotJobs(r *http.Request, _ *params) (int, any, error) {
	q := r.URL.Query()
	f := store.RotationJobFilter{State: q.Get("state"), BulkID: q.Get("bulk_id"), Limit: 200}
	if f.State != "" && !slices.Contains([]string{store.RotPending, store.RotCreated, store.RotHandedOver, store.RotOldDisabled,
		store.RotVerified, store.RotOldDeleted, store.RotFailed, store.RotCancelled}, f.State) {
		return 0, nil, badRequest("invalid_state", "state is not a rotation job state")
	}
	if f.BulkID != "" && !idRE.MatchString(f.BulkID) {
		return 0, nil, badRequest("invalid_bulk_id", "bulk_id must be a bulk run id")
	}
	if v := q.Get("secret_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return 0, nil, badRequest("invalid_secret_id", "secret_id must be a positive integer")
		}
		f.SecretID = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be from 1 to 500")
		}
		f.Limit = n
	}
	out, err := s.rotation.Jobs(store.TxFrom(r.Context()), f, s.clock())
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotJob(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	out, err := s.rotation.Job(store.TxFrom(r.Context()), id, s.clock())
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotStart(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		SecretID int64 `json:"secret_id"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.SecretID < 1 {
		return 0, nil, badRequest("invalid_secret_id", "secret_id is required")
	}
	var out *rotation.JobView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		out, err = s.rotation.StartRotation(c, in.SecretID, actor(r), now)
		return err
	})
	return http.StatusCreated, out, rotErr(err)
}

func (s *Server) rotRetry(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	var out *rotation.JobView
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		out, err = s.rotation.RetryJob(c, id, actor(r), now)
		return err
	})
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotCancel(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	var out *rotation.JobView
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		out, err = s.rotation.CancelJob(c, id, actor(r), now)
		return err
	})
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotBulkPlan(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		System string `json:"system"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	out, err := s.rotation.BulkPlanFor(store.TxFrom(r.Context()), in.System, s.clock())
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotBulks(r *http.Request, _ *params) (int, any, error) {
	out, err := s.rotation.Bulks(store.TxFrom(r.Context()), s.clock())
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotBulk(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	out, err := s.rotation.Bulk(store.TxFrom(r.Context()), id, s.clock())
	return http.StatusOK, out, rotErr(err)
}

func (s *Server) rotBulkExecute(r *http.Request, _ *params) (int, any, error) {
	var in rotation.BulkInput
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out *rotation.BulkView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		var err error
		out, err = s.rotation.ExecuteBulk(c, in, actor(r), now)
		return err
	})
	return http.StatusCreated, out, rotErr(err)
}
