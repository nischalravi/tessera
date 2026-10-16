package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/reports"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/viz"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group reports and the Groups lens (issue #57, GR-14; design
// docs/design/groups-grouper-parity.md §10.7). Reports come from a fixed
// catalogue (no free SQL). A report shows only what the person it runs for may
// see: the caller for a run by hand, the user who saved it for a scheduled one.
// A saved report, and the output of its runs, belong to the user who saved it
// (a tenant admin may read them); anyone else gets 404.
//
//	GET    /api/groups/reports/catalogue                          the reports and their parameters
//	GET    /api/groups/reports/saved                              your saved reports (a tenant admin sees all)
//	POST   /api/groups/reports/saved                              save one: {name, kind, params, format, schedule, delivery}
//	GET|PUT|DELETE /api/groups/reports/saved/{report_id}
//	POST   /api/groups/reports/saved/{report_id}/run              run it now and keep the output
//	GET    /api/groups/reports/saved/{report_id}/runs             the kept runs (without their output)
//	GET    /api/groups/reports/runs/{run_id}                      one run with its output (CSV or JSON text in "content")
//	POST   /api/groups/reports/run                                {kind, params, format}: run once, keep nothing
//
//	GET /api/groups/{id}/graph[?up=&down=]                        the group's dependency graph, nodes filtered by view (view)
//	GET /api/groups/graph/identity/{identity_id}[?levels=]        a person's group graph, nodes filtered by view
func (s *Server) registerGroupsReportRoutes() {
	G, P, PU, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	canRead, canWrite := need(auth.PermGroupsRead), need(auth.PermGroupsWrite)
	s.handle(G, "/api/groups/reports/catalogue", read, canRead, s.rd(s.reportCatalogue))
	s.handle(G, "/api/groups/reports/saved", read, canRead, s.rd(s.listReports))
	s.handle(P, "/api/groups/reports/saved", write, canWrite, s.rd(s.createReport))
	s.handle(G, "/api/groups/reports/saved/{report_id}", read, canRead, s.rd(s.getReport))
	s.handle(PU, "/api/groups/reports/saved/{report_id}", write, canWrite, s.rd(s.updateReport))
	s.handle(D, "/api/groups/reports/saved/{report_id}", write, canWrite, s.rd(s.deleteReport))
	s.handle(P, "/api/groups/reports/saved/{report_id}/run", write, canWrite, s.rd(s.runReport))
	s.handle(G, "/api/groups/reports/saved/{report_id}/runs", read, canRead, s.rd(s.listRuns))
	s.handle(G, "/api/groups/reports/runs/{run_id}", read, canRead, s.rd(s.getRun))
	s.handle(P, "/api/groups/reports/run", write, canWrite, s.rd(s.adhocReport))
	s.handle(G, "/api/groups/{id}/graph", read, canRead, s.rd(s.groupGraph))
	s.handle(G, "/api/groups/graph/identity/{identity_id}", read, canRead, s.rd(s.personGraph))
}

func (s *Server) reportCatalogue(*http.Request, *params) (int, any, error) {
	return http.StatusOK, map[string]any{"items": reports.Catalogue()}, nil
}

// reportUser is the request's platform user id ("" for a machine client) and
// whether it holds tenant_admin.
func reportUser(r *http.Request) (string, bool) {
	pr := principal(r)
	by := ""
	if pr.UserID != nil {
		by = pr.UserID.String()
	}
	return by, pr.ActiveRoles.Has(auth.RoleTenantAdmin)
}

type reportView struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Params    reports.Params  `json:"params"`
	Format    string          `json:"format"`
	Schedule  string          `json:"schedule"`
	Delivery  string          `json:"delivery"`
	NextRunAt *time.Time      `json:"next_run_at,omitempty"`
	LastRunAt *time.Time      `json:"last_run_at,omitempty"`
	Owner     string          `json:"owner"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Extra     map[string]bool `json:"-"`
}

func viewReport(r *store.GrpReport) (reportView, error) {
	p, err := reports.ParamsOf(r)
	if err != nil {
		return reportView{}, err
	}
	return reportView{ID: r.ID, Name: r.Name, Kind: r.Kind, Params: p, Format: r.Format, Schedule: r.Schedule, Delivery: r.Delivery,
		NextRunAt: r.NextRunAt, LastRunAt: r.LastRunAt, Owner: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}

type reportBody struct {
	Name     string         `json:"name"`
	Kind     string         `json:"kind"`
	Params   reports.Params `json:"params"`
	Format   string         `json:"format"`
	Schedule string         `json:"schedule"`
	Delivery string         `json:"delivery"`
}

func (b reportBody) input() reports.SaveInput {
	return reports.SaveInput{Name: b.Name, Kind: b.Kind, Params: b.Params, Format: b.Format, Schedule: b.Schedule, Delivery: b.Delivery}
}

func (s *Server) saveEnv(r *http.Request, c *store.TenantTx, now time.Time, ck *privs.Checker) reports.SaveEnv {
	by, _ := reportUser(r)
	return reports.SaveEnv{Tx: c, Now: now, By: by, Checker: ck}
}

func (s *Server) listReports(r *http.Request, _ *params) (int, any, error) {
	by, admin := reportUser(r)
	filter := by
	if admin {
		filter = ""
	} else if by == "" {
		return http.StatusOK, map[string]any{"items": []reportView{}}, nil
	}
	rows, err := store.TxFrom(r.Context()).GrpReports(filter)
	if err != nil {
		return 0, nil, err
	}
	items := make([]reportView, 0, len(rows))
	for _, row := range rows {
		v, err := viewReport(row)
		if err != nil {
			return 0, nil, err
		}
		items = append(items, v)
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) createReport(r *http.Request, _ *params) (int, any, error) {
	var in reportBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	var out reportView
	err := grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		row, err := reports.Save(s.saveEnv(r, c, now, ck), in.input())
		if err != nil {
			return err
		}
		out, err = viewReport(row)
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, out, nil
}

func (s *Server) ownReport(r *http.Request, p *params) (*store.GrpReport, error) {
	id, err := pathUUID(p, "report_id", "report")
	if err != nil {
		return nil, err
	}
	by, admin := reportUser(r)
	row, err := reports.Own(store.TxFrom(r.Context()), id, by, admin)
	return row, grpErr(err)
}

func (s *Server) getReport(r *http.Request, p *params) (int, any, error) {
	row, err := s.ownReport(r, p)
	if err != nil {
		return 0, nil, err
	}
	v, err := viewReport(row)
	return http.StatusOK, v, err
}

func (s *Server) updateReport(r *http.Request, p *params) (int, any, error) {
	row, err := s.ownReport(r, p)
	if err != nil {
		return 0, nil, err
	}
	var in reportBody
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Kind != "" && in.Kind != row.Kind {
		return 0, nil, badRequest("invalid_kind", "a saved report's kind does not change: save a new report")
	}
	ck := s.grpChecker(r)
	var out reportView
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		updated, err := reports.Update(s.saveEnv(r, c, now, ck), row, in.input())
		if err != nil {
			return err
		}
		out, err = viewReport(updated)
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (s *Server) deleteReport(r *http.Request, p *params) (int, any, error) {
	row, err := s.ownReport(r, p)
	if err != nil {
		return 0, nil, err
	}
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		return reports.Delete(s.saveEnv(r, c, now, s.grpChecker(r)), row)
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": row.ID, "deleted": true}, nil
}

type runView struct {
	ID        string    `json:"id"`
	ReportID  string    `json:"report_id,omitempty"`
	RanAt     time.Time `json:"ran_at"`
	Trigger   string    `json:"trigger,omitempty"`
	Status    string    `json:"status"`
	Format    string    `json:"format"`
	RowCount  int       `json:"row_count"`
	Truncated bool      `json:"truncated"`
	SHA256    string    `json:"sha256"`
	Error     string    `json:"error,omitempty"`
	Content   *string   `json:"content,omitempty"`
}

func viewRun(x *store.GrpReportRun, withContent bool) runView {
	v := runView{ID: x.ID, ReportID: x.ReportID, RanAt: x.RanAt, Trigger: x.Trigger, Status: x.Status, Format: x.Format, RowCount: x.RowCount,
		Truncated: x.Truncated, SHA256: x.SHA256, Error: x.Error}
	if withContent {
		v.Content = &x.Content
	}
	return v
}

func (s *Server) runReport(r *http.Request, p *params) (int, any, error) {
	row, err := s.ownReport(r, p)
	if err != nil {
		return 0, nil, err
	}
	by, _ := reportUser(r)
	ck := s.grpChecker(r)
	var out runView
	err = grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		run, err := reports.RunSaved(reports.Env{Tx: c, Now: now, Checker: ck, Engine: s.cfg.GroupsEngine}, row, by, "manual")
		if err != nil {
			return err
		}
		out = viewRun(run, true)
		return nil
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func (s *Server) listRuns(r *http.Request, p *params) (int, any, error) {
	row, err := s.ownReport(r, p)
	if err != nil {
		return 0, nil, err
	}
	by, admin := reportUser(r)
	runs, err := store.TxFrom(r.Context()).GrpReportRuns(row.ID, reports.KeepRuns)
	if err != nil {
		return 0, nil, err
	}
	items := make([]runView, 0, len(runs))
	for _, x := range runs {
		if x.RanBy == by || admin { // the output of a run belongs to whom it was made for
			items = append(items, viewRun(x, false))
		}
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) getRun(r *http.Request, p *params) (int, any, error) {
	id, err := pathUUID(p, "run_id", "run")
	if err != nil {
		return 0, nil, err
	}
	by, admin := reportUser(r)
	run, _, err := reports.ReadRun(store.TxFrom(r.Context()), id, by, admin)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, viewRun(run, true), nil
}

func (s *Server) adhocReport(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Kind   string         `json:"kind"`
		Params reports.Params `json:"params"`
		Format string         `json:"format"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.Format == "" {
		in.Format = "csv"
	}
	ck := s.grpChecker(r)
	var out runView
	err := grpErr(s.write(r, func(c *store.TenantTx, now time.Time) error {
		res, err := reports.Run(reports.Env{Tx: c, Now: now, Checker: ck, Engine: s.cfg.GroupsEngine}, in.Kind, in.Params)
		if err != nil {
			return err
		}
		text, err := res.Render(in.Format, now)
		if err != nil {
			return err
		}
		out = runView{ID: "", RanAt: now, Status: "ok", Format: in.Format, RowCount: len(res.Rows), Truncated: res.Truncated, SHA256: reports.Digest(text),
			Content: &text}
		// an export leaves a trace of what was taken, not the data
		_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "groups.report.exported", LegacyActor: "groups", TargetType: "report", TargetID: in.Kind,
			Detail: ojson.Object{{Key: "kind", Value: in.Kind}, {Key: "format", Value: in.Format}, {Key: "rows", Value: len(res.Rows)},
				{Key: "truncated", Value: res.Truncated}, {Key: "sha256", Value: out.SHA256}}})
		return err
	}))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

// ---------------------------------------------------------------- the Groups lens

func levelParam(p *params, name string, def int) (int, error) {
	v, ok := p.query(name)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > viz.MaxLevels {
		return 0, badRequest("invalid_"+name, name+" is 0 to "+strconv.Itoa(viz.MaxLevels))
	}
	return n, nil
}

func (s *Server) groupGraph(r *http.Request, p *params) (int, any, error) {
	ck := s.grpChecker(r)
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	g, err := s.grpGroupFor(r, ck, id, privs.View)
	if err != nil {
		return 0, nil, err
	}
	up, err := levelParam(p, "up", 1)
	if err != nil {
		return 0, nil, err
	}
	down, err := levelParam(p, "down", 1)
	if err != nil {
		return 0, nil, err
	}
	out, err := viz.GroupGraph(store.TxFrom(r.Context()), ck, g.ID, up, down)
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, out, nil
}

func (s *Server) personGraph(r *http.Request, p *params) (int, any, error) {
	ident, err := strconv.ParseInt(p.path["identity_id"], 10, 64)
	if err != nil || ident < 1 {
		return 0, nil, grpNotFound("identity")
	}
	levels, err := levelParam(p, "levels", 3)
	if err != nil {
		return 0, nil, err
	}
	out, err := viz.PersonGraph(store.TxFrom(r.Context()), s.grpChecker(r), ident, levels, s.clock())
	if err != nil {
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, out, nil
}
