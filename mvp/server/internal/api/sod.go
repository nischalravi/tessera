package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Separation of duties as functions, risks and rulesets (issue #298):
//
//	GET  /api/sod/functions                        every function, with the risks that use it
//	POST /api/sod/functions                        {key?, name, description, owner_id, selectors, note}
//	GET  /api/sod/functions/{function_id}          one, with its versions
//	PUT  /api/sod/functions/{function_id}          {version, name, description, owner_id, selectors, note}
//	POST /api/sod/functions/{function_id}/retire   {reason}: only when no active risk uses it
//	GET  /api/sod/risks, POST, GET/PUT/{risk_id}, POST /{risk_id}/retire   the same for risks
//	GET  /api/sod/rulesets, POST, GET/PUT/{ruleset_id}, POST /{ruleset_id}/retire
//	GET  /api/sod/rulesets/{ruleset_id}/export     {filename, yaml}: the ruleset as a file
//	POST /api/sod/rulesets/import                  {yaml, prune, dry_run}: make a ruleset match a file
//	POST /api/sod/import-legacy                    import the separation_of_duties policy files
//	GET  /api/sod/violations                       ?risk&priority&ruleset&system&business_process&identity
//	POST /api/sod/simulate                         {beneficiary_ids, catalog_item_ids, duration_hours}
//
// Reading needs graph.read, like the policy violations. Changing needs
// sod.manage and a fresh phishing-resistant sign-in. Simulating answers "if this
// request were granted, which risks would it trigger" for the access request
// form, so it needs only requests.create (and requests.create_for_others for
// people other than the caller); it changes nothing.

func (s *Server) registerSodRoutes() {
	const G, P, U = http.MethodGet, http.MethodPost, http.MethodPut
	rd := need(auth.PermGraphRead)
	manage := needStepUp(auth.PermSoDManage, auth.StepUpPolicy)
	s.handle(G, "/api/sod/functions", read, rd, s.listSodFunctions)
	s.handle(P, "/api/sod/functions", write, manage, s.createSodFunction)
	s.handle(G, "/api/sod/functions/{function_id}", read, rd, s.getSodFunction)
	s.handle(U, "/api/sod/functions/{function_id}", write, manage, s.updateSodFunction)
	s.handle(P, "/api/sod/functions/{function_id}/retire", write, manage, s.retireSodFunction)
	s.handle(G, "/api/sod/risks", read, rd, s.listSodRisks)
	s.handle(P, "/api/sod/risks", write, manage, s.createSodRisk)
	s.handle(G, "/api/sod/risks/{risk_id}", read, rd, s.getSodRisk)
	s.handle(U, "/api/sod/risks/{risk_id}", write, manage, s.updateSodRisk)
	s.handle(P, "/api/sod/risks/{risk_id}/retire", write, manage, s.retireSodRisk)
	s.handle(G, "/api/sod/rulesets", read, rd, s.listSodRulesets)
	s.handle(P, "/api/sod/rulesets", write, manage, s.createSodRuleset)
	s.handle(P, "/api/sod/rulesets/import", write, manage, s.importSodRuleset)
	s.handle(G, "/api/sod/rulesets/{ruleset_id}", read, rd, s.getSodRuleset)
	s.handle(U, "/api/sod/rulesets/{ruleset_id}", write, manage, s.updateSodRuleset)
	s.handle(P, "/api/sod/rulesets/{ruleset_id}/retire", write, manage, s.retireSodRuleset)
	s.handle(G, "/api/sod/rulesets/{ruleset_id}/export", read, rd, s.exportSodRuleset)
	s.handle(P, "/api/sod/import-legacy", write, manage, s.importLegacySod)
	s.handle(G, "/api/sod/violations", read, rd, s.sodViolations)
	s.handle(P, "/api/sod/simulate", write, need(auth.PermRequestsCreate), s.simulateSod).answersRead = true
}

func sodErr(err error) error {
	var rf *sod.Refusal
	if errors.As(err, &rf) {
		return &readiness.Error{Status: rf.Status, Code: rf.Code, Msg: rf.Msg}
	}
	return err
}

func (s *Server) sodWriter(r *http.Request) (*sod.Writer, error) {
	a, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	return &sod.Writer{Tx: store.TxFrom(r.Context()), By: sod.Actor{UserID: a.UserID, Display: a.Display}, Now: s.clock().UTC()}, nil
}

func notFound(code, msg string) error {
	return &readiness.Error{Status: http.StatusNotFound, Code: code, Msg: msg}
}

// ---------------------------------------------------------------- views

type sodRiskRef struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type sodFunctionView struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Owner       *personRef     `json:"owner"`
	Selectors   []sod.Selector `json:"selectors"`
	Status      string         `json:"status"`
	Version     int            `json:"version"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedBy   *userRef       `json:"updated_by"`
	UpdatedAt   time.Time      `json:"updated_at"`
	UsedBy      []sodRiskRef   `json:"used_by"`
	Versions    []versionView  `json:"versions,omitempty"`
}

type sodRiskView struct {
	ID              string          `json:"id"`
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Priority        string          `json:"priority"`
	BusinessProcess string          `json:"business_process"`
	Owner           *personRef      `json:"owner"`
	Ruleset         sod.RulesetRef  `json:"ruleset"`
	Functions       []sod.Ref       `json:"functions"`
	Subjects        json.RawMessage `json:"subjects"`
	Status          string          `json:"status"`
	Version         int             `json:"version"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedBy       *userRef        `json:"updated_by"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Violations      *int            `json:"violations,omitempty"`
	Versions        []versionView   `json:"versions,omitempty"`
}

type sodRulesetView struct {
	ID          string        `json:"id"`
	Key         string        `json:"key"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Enabled     bool          `json:"enabled"`
	Status      string        `json:"status"`
	Version     int           `json:"version"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedBy   *userRef      `json:"updated_by"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Risks       int           `json:"risks"`
	Violations  *int          `json:"violations,omitempty"`
	Versions    []versionView `json:"versions,omitempty"`
}

// sodCatalog is everything the views need, loaded once per request.
type sodCatalog struct {
	v         *viewer
	functions map[string]*store.SodFunction
	risks     map[string]*store.SodRisk
	rulesets  map[string]*store.SodRuleset
	fnOfRisk  map[string][]string
	counts    map[string]int // violations by risk key, when asked
}

func (s *Server) loadSod(r *http.Request, withCounts bool) (*sodCatalog, error) {
	tx := store.TxFrom(r.Context())
	c := &sodCatalog{v: newViewer(tx), functions: map[string]*store.SodFunction{}, risks: map[string]*store.SodRisk{},
		rulesets: map[string]*store.SodRuleset{}, fnOfRisk: map[string][]string{}}
	fs, err := tx.SodFunctions()
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		c.functions[f.ID] = f
	}
	rs, err := tx.SodRisks()
	if err != nil {
		return nil, err
	}
	for _, x := range rs {
		c.risks[x.ID] = x
	}
	ss, err := tx.SodRulesets()
	if err != nil {
		return nil, err
	}
	for _, x := range ss {
		c.rulesets[x.ID] = x
	}
	links, err := tx.SodRiskFunctions()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		c.fnOfRisk[l.RiskID] = append(c.fnOfRisk[l.RiskID], l.FunctionID)
	}
	if withCounts {
		a, err := s.newAnalysis(tx)
		if err != nil {
			return nil, err
		}
		vs, err := s.sodDetect(a)
		if err != nil {
			return nil, err
		}
		c.counts = map[string]int{}
		for _, v := range vs {
			c.counts[v.RiskKey]++
		}
	}
	return c, nil
}

func (c *sodCatalog) owner(id *int64) *personRef {
	if id == nil {
		return nil
	}
	p, err := c.v.person(*id)
	if err != nil {
		return nil
	}
	return &p
}

func (c *sodCatalog) updatedBy(by *string) *userRef {
	if by == nil {
		return nil
	}
	u := c.v.user(*by)
	return &u
}

func (c *sodCatalog) function(f *store.SodFunction) sodFunctionView {
	var sels []sod.Selector
	_ = json.Unmarshal([]byte(f.Selectors), &sels)
	out := sodFunctionView{ID: f.ID, Key: f.Key, Name: f.Name, Description: f.Description, Owner: c.owner(f.OwnerID), Selectors: sels,
		Status: f.Status, Version: f.Version, CreatedAt: f.CreatedAt, UpdatedBy: c.updatedBy(f.UpdatedBy), UpdatedAt: f.UpdatedAt,
		UsedBy: []sodRiskRef{}}
	for rid, fids := range c.fnOfRisk {
		if rk := c.risks[rid]; rk != nil && rk.Status == store.SodActive && slices.Contains(fids, f.ID) {
			out.UsedBy = append(out.UsedBy, sodRiskRef{rk.ID, rk.Key, rk.Name})
		}
	}
	slices.SortFunc(out.UsedBy, func(a, b sodRiskRef) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (c *sodCatalog) risk(x *store.SodRisk) sodRiskView {
	out := sodRiskView{ID: x.ID, Key: x.Key, Name: x.Name, Description: x.Description, Priority: x.Priority,
		BusinessProcess: x.BusinessProcess, Owner: c.owner(x.OwnerID), Subjects: json.RawMessage(x.Subjects), Status: x.Status,
		Version: x.Version, CreatedAt: x.CreatedAt, UpdatedBy: c.updatedBy(x.UpdatedBy), UpdatedAt: x.UpdatedAt, Functions: []sod.Ref{}}
	if rs := c.rulesets[x.RulesetID]; rs != nil {
		out.Ruleset = sod.RulesetRef{ID: rs.ID, Key: rs.Key, Name: rs.Name}
	}
	for _, fid := range c.fnOfRisk[x.ID] {
		if f := c.functions[fid]; f != nil {
			out.Functions = append(out.Functions, sod.Ref{ID: f.ID, Key: f.Key, Name: f.Name})
		}
	}
	if c.counts != nil {
		n := c.counts[x.Key]
		out.Violations = &n
	}
	return out
}

func (c *sodCatalog) ruleset(x *store.SodRuleset) sodRulesetView {
	out := sodRulesetView{ID: x.ID, Key: x.Key, Name: x.Name, Description: x.Description, Enabled: x.Enabled, Status: x.Status,
		Version: x.Version, CreatedAt: x.CreatedAt, UpdatedBy: c.updatedBy(x.UpdatedBy), UpdatedAt: x.UpdatedAt}
	n := 0
	for _, rk := range c.risks {
		if rk.RulesetID == x.ID && rk.Status == store.SodActive {
			out.Risks++
			n += c.counts[rk.Key]
		}
	}
	if c.counts != nil {
		out.Violations = &n
	}
	return out
}

func versionViews(vs []*store.SodVersion) []versionView {
	out := make([]versionView, len(vs))
	for i, x := range vs {
		out[i] = versionView{x.Version, json.RawMessage(x.Snapshot), x.Note, x.Actor, x.ChangedAt}
	}
	return out
}

// ---------------------------------------------------------------- functions

type sodFunctionBody struct {
	Version     int            `json:"version"`
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	OwnerID     *int64         `json:"owner_id"`
	Selectors   []sod.Selector `json:"selectors"`
	Note        string         `json:"note"`
}

func (b sodFunctionBody) input() sod.FunctionInput {
	return sod.FunctionInput{Key: b.Key, Name: b.Name, Description: b.Description, OwnerID: b.OwnerID, Selectors: b.Selectors, Note: b.Note}
}

func (s *Server) listSodFunctions(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c, err := s.loadSod(r, false)
	if err != nil {
		return nil, err
	}
	fs, err := store.TxFrom(r.Context()).SodFunctions()
	if err != nil {
		return nil, err
	}
	out := struct {
		CanManage  bool              `json:"can_manage"`
		Attributes []string          `json:"attributes"`
		Functions  []sodFunctionView `json:"functions"`
	}{s.can(r, auth.PermSoDManage), sod.Attributes, make([]sodFunctionView, 0, len(fs))}
	for _, f := range fs {
		out.Functions = append(out.Functions, c.function(f))
	}
	return out, nil
}

func (s *Server) sodFunctionDetail(r *http.Request, id string) (sodFunctionView, error) {
	c, err := s.loadSod(r, false)
	if err != nil {
		return sodFunctionView{}, err
	}
	f := c.functions[id]
	if f == nil {
		return sodFunctionView{}, notFound("function_not_found", "function not found")
	}
	vs, err := store.TxFrom(r.Context()).SodVersions(store.SodKindFunction, id)
	if err != nil {
		return sodFunctionView{}, err
	}
	out := c.function(f)
	out.Versions = versionViews(vs)
	return out, nil
}

func (s *Server) getSodFunction(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.sodFunctionDetail(r, strings.TrimSpace(p.path["function_id"]))
}

func (s *Server) createSodFunction(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodFunctionBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	f, err := w.CreateFunction(b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	out, err := s.sodFunctionDetail(r, f.ID)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) updateSodFunction(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodFunctionBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	f, err := w.UpdateFunction(strings.TrimSpace(p.path["function_id"]), b.Version, b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodFunctionDetail(r, f.ID)
}

type sodRetireBody struct {
	Reason string `json:"reason"`
}

func (s *Server) retireSodFunction(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRetireBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	f, err := w.RetireFunction(strings.TrimSpace(p.path["function_id"]), b.Reason)
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodFunctionDetail(r, f.ID)
}

// ---------------------------------------------------------------- risks

type sodRiskBody struct {
	Version         int          `json:"version"`
	Key             string       `json:"key"`
	Name            string       `json:"name"`
	Description     string       `json:"description"`
	Priority        string       `json:"priority"`
	BusinessProcess string       `json:"business_process"`
	OwnerID         *int64       `json:"owner_id"`
	RulesetID       string       `json:"ruleset_id"`
	FunctionIDs     []string     `json:"function_ids"`
	Subjects        sod.Subjects `json:"subjects"`
	Note            string       `json:"note"`
}

func (b sodRiskBody) input() sod.RiskInput {
	return sod.RiskInput{Key: b.Key, Name: b.Name, Description: b.Description, Priority: b.Priority, BusinessProcess: b.BusinessProcess,
		OwnerID: b.OwnerID, RulesetID: strings.TrimSpace(b.RulesetID), FunctionIDs: b.FunctionIDs, Subjects: b.Subjects, Note: b.Note}
}

func (s *Server) listSodRisks(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c, err := s.loadSod(r, true)
	if err != nil {
		return nil, err
	}
	rs, err := store.TxFrom(r.Context()).SodRisks()
	if err != nil {
		return nil, err
	}
	out := struct {
		CanManage  bool          `json:"can_manage"`
		Priorities []string      `json:"priorities"`
		Risks      []sodRiskView `json:"risks"`
	}{s.can(r, auth.PermSoDManage), sod.Priorities, make([]sodRiskView, 0, len(rs))}
	for _, x := range rs {
		out.Risks = append(out.Risks, c.risk(x))
	}
	return out, nil
}

func (s *Server) sodRiskDetail(r *http.Request, id string) (sodRiskView, error) {
	c, err := s.loadSod(r, true)
	if err != nil {
		return sodRiskView{}, err
	}
	x := c.risks[id]
	if x == nil {
		return sodRiskView{}, notFound("risk_not_found", "risk not found")
	}
	vs, err := store.TxFrom(r.Context()).SodVersions(store.SodKindRisk, id)
	if err != nil {
		return sodRiskView{}, err
	}
	out := c.risk(x)
	out.Versions = versionViews(vs)
	return out, nil
}

func (s *Server) getSodRisk(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.sodRiskDetail(r, strings.TrimSpace(p.path["risk_id"]))
}

func (s *Server) createSodRisk(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRiskBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	x, err := w.CreateRisk(b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	out, err := s.sodRiskDetail(r, x.ID)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) updateSodRisk(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRiskBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	x, err := w.UpdateRisk(strings.TrimSpace(p.path["risk_id"]), b.Version, b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodRiskDetail(r, x.ID)
}

func (s *Server) retireSodRisk(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRetireBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	x, err := w.RetireRisk(strings.TrimSpace(p.path["risk_id"]), b.Reason)
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodRiskDetail(r, x.ID)
}

// ---------------------------------------------------------------- rulesets

type sodRulesetBody struct {
	Version     int    `json:"version"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
	Note        string `json:"note"`
}

func (b sodRulesetBody) input() sod.RulesetInput {
	return sod.RulesetInput{Key: b.Key, Name: b.Name, Description: b.Description, Enabled: b.Enabled == nil || *b.Enabled, Note: b.Note}
}

func (s *Server) listSodRulesets(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c, err := s.loadSod(r, true)
	if err != nil {
		return nil, err
	}
	ss, err := store.TxFrom(r.Context()).SodRulesets()
	if err != nil {
		return nil, err
	}
	out := struct {
		CanManage bool             `json:"can_manage"`
		Legacy    bool             `json:"legacy"` // no stored ruleset yet: the policy files are checked
		Rulesets  []sodRulesetView `json:"rulesets"`
	}{CanManage: s.can(r, auth.PermSoDManage), Legacy: len(ss) == 0, Rulesets: make([]sodRulesetView, 0, len(ss))}
	for _, x := range ss {
		out.Rulesets = append(out.Rulesets, c.ruleset(x))
	}
	return out, nil
}

func (s *Server) sodRulesetDetail(r *http.Request, id string) (sodRulesetView, error) {
	c, err := s.loadSod(r, true)
	if err != nil {
		return sodRulesetView{}, err
	}
	x := c.rulesets[id]
	if x == nil {
		return sodRulesetView{}, notFound("ruleset_not_found", "ruleset not found")
	}
	vs, err := store.TxFrom(r.Context()).SodVersions(store.SodKindRuleset, id)
	if err != nil {
		return sodRulesetView{}, err
	}
	out := c.ruleset(x)
	out.Versions = versionViews(vs)
	return out, nil
}

func (s *Server) getSodRuleset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.sodRulesetDetail(r, strings.TrimSpace(p.path["ruleset_id"]))
}

func (s *Server) createSodRuleset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRulesetBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	x, err := w.CreateRuleset(b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	out, err := s.sodRulesetDetail(r, x.ID)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) updateSodRuleset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRulesetBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	x, err := w.UpdateRuleset(strings.TrimSpace(p.path["ruleset_id"]), b.Version, b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodRulesetDetail(r, x.ID)
}

func (s *Server) retireSodRuleset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodRetireBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	x, err := w.RetireRuleset(strings.TrimSpace(p.path["ruleset_id"]), b.Reason)
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodRulesetDetail(r, x.ID)
}

func (s *Server) exportSodRuleset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	rs, err := tx.SodRuleset(strings.TrimSpace(p.path["ruleset_id"]))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("ruleset_not_found", "ruleset not found")
	} else if err != nil {
		return nil, err
	}
	b, err := sod.BundleOf(tx, rs)
	if err != nil {
		return nil, err
	}
	y, err := b.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return struct {
		Filename string `json:"filename"`
		Version  int    `json:"version"`
		YAML     string `json:"yaml"`
	}{rs.Key + ".sod.yaml", rs.Version, string(y)}, nil
}

func (s *Server) importSodRuleset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		YAML   string `json:"yaml"`
		Prune  bool   `json:"prune"`
		DryRun bool   `json:"dry_run"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	bundle, err := sod.ParseYAML([]byte(b.YAML))
	if err != nil {
		return nil, sodErr(err)
	}
	res, err := w.Import(bundle, sod.ImportOptions{Prune: b.Prune, DryRun: b.DryRun})
	if err != nil {
		return nil, sodErr(err)
	}
	return res, nil
}

func (s *Server) importLegacySod(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		DryRun bool `json:"dry_run"`
	}
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	files, err := s.policies()
	if err != nil {
		return nil, err
	}
	bundle, err := policy.LegacyBundle(files, true)
	if err != nil {
		return nil, badRequest("legacy_not_convertible", err.Error())
	}
	if bundle == nil {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "nothing_to_import", Msg: "there are no separation_of_duties policy files to import"}
	}
	res, err := w.Import(bundle, sod.ImportOptions{DryRun: b.DryRun})
	if err != nil {
		return nil, sodErr(err)
	}
	return res, nil
}

// ---------------------------------------------------------------- violations

// sodRisks are the compiled risks of the analysis's policies.
func (a *analysis) sodRisks() []*sod.Risk {
	var out []*sod.Risk
	for _, p := range a.policies {
		if rk, ok := p.Spec["risk"].(*sod.Risk); ok && p.Type == policy.TypeSoDRisk {
			out = append(out, rk)
		}
	}
	return out
}

func (s *Server) sodDetect(a *analysis) ([]sod.Violation, error) {
	return policy.NewContext(a.g, a.c, a.now).SoD(a.sodRisks()), nil
}

func (s *Server) sodViolations(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	risk := p.queryOptStr("risk")
	priority := p.queryOptLiteral("priority", sod.Priorities)
	ruleset := p.queryOptStr("ruleset")
	system := p.queryOptStr("system")
	process := p.queryOptStr("business_process")
	identity := p.queryOptStr("identity")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	for _, v := range []*string{risk, ruleset, system, process, identity} {
		if v != nil && len(*v) > sod.MaxName {
			return nil, badRequest("invalid_filter", "a filter is at most 120 characters")
		}
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	all, err := s.sodDetect(a)
	if err != nil {
		return nil, err
	}
	var idID int64 = -1
	if identity != nil {
		if n, err := strconv.ParseInt(*identity, 10, 64); err == nil {
			idID = n
		}
	}
	out := []sod.Violation{}
	for _, v := range all {
		switch {
		case risk != nil && v.RiskKey != *risk && v.RiskID != *risk:
		case priority != nil && v.Priority != *priority:
		case ruleset != nil && v.Ruleset.Key != *ruleset && v.Ruleset.ID != *ruleset:
		case system != nil && !slices.Contains(v.Systems, *system):
		case process != nil && !strings.EqualFold(v.BusinessProcess, *process):
		case identity != nil && v.IdentityID != idID && !strings.Contains(strings.ToLower(v.IdentityName), strings.ToLower(*identity)):
		default:
			out = append(out, v)
		}
	}
	return struct {
		Total      int             `json:"total"`
		Violations []sod.Violation `json:"violations"`
	}{len(out), out}, nil
}

// ---------------------------------------------------------------- simulate

const maxSimulatedLines = 50

type sodSimTrigger struct {
	RiskID          string         `json:"risk_id"`
	RiskKey         string         `json:"risk_key"`
	RiskName        string         `json:"risk_name"`
	Priority        string         `json:"priority"`
	BusinessProcess string         `json:"business_process"`
	Ruleset         sod.RulesetRef `json:"ruleset"`
	IdentityID      int64          `json:"identity_id"`
	IdentityName    string         `json:"identity_name"`
	Function1       sod.Ref        `json:"function1"`
	Function2       sod.Ref        `json:"function2"`
	Entitlement     string         `json:"entitlement"`
	Message         string         `json:"message"`
}

func (s *Server) simulateSod(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b struct {
		BeneficiaryIDs []int64  `json:"beneficiary_ids"`
		CatalogItemIDs []string `json:"catalog_item_ids"`
		DurationHours  *float64 `json:"duration_hours"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	switch {
	case len(b.BeneficiaryIDs) == 0 || len(b.CatalogItemIDs) == 0:
		return nil, badRequest("empty_request", "name at least one person and one item")
	case len(b.BeneficiaryIDs)*len(b.CatalogItemIDs) > maxSimulatedLines:
		return nil, badRequest("too_many_lines", "at most 50 person-item pairs")
	case b.DurationHours != nil && (*b.DurationHours <= 0 || *b.DurationHours > 24*365):
		return nil, badRequest("invalid_duration", "the duration is between 0 and 8760 hours")
	}
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	forOthers := s.can(r, auth.PermRequestsCreateOthers)
	tx := store.TxFrom(r.Context())
	a, err := s.newAnalysis(tx)
	if err != nil {
		return nil, err
	}
	after := a.g.Copy()
	var exp *time.Time
	if b.DurationHours != nil {
		t := a.now.Add(time.Duration(*b.DurationHours * float64(time.Hour)))
		exp = &t
	}
	type skip struct {
		Beneficiary int64  `json:"beneficiary_id"`
		Item        string `json:"catalog_item_id"`
		Reason      string `json:"reason"`
	}
	skipped := []skip{}
	checked := 0
	for _, bid := range b.BeneficiaryIDs {
		ben, err := tx.Identity(bid)
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("beneficiary_not_found", "person not found")
		} else if err != nil {
			return nil, err
		}
		if (me.IdentityID == nil || *me.IdentityID != ben.ID) && !forOthers {
			return nil, &readiness.Error{Status: http.StatusForbidden, Code: "for_others_not_allowed", Msg: "you can request access only for yourself"}
		}
		for _, iid := range b.CatalogItemIDs {
			it, err := tx.CatalogItem(iid)
			if errors.Is(err, store.ErrNotFound) {
				return nil, notFound("item_not_found", "catalog item not found")
			} else if err != nil {
				return nil, err
			}
			g, err := tx.Group(it.GroupID)
			if err != nil {
				return nil, err
			}
			acct, err := jit.AccountFor(tx, ben.ID, g)
			var je *jit.Error
			if errors.As(err, &je) {
				skipped = append(skipped, skip{ben.ID, iid, "no active account can receive it"})
				continue
			} else if err != nil {
				return nil, err
			}
			src, dst := graph.Key("account", acct.ID), graph.Key("group", g.ID)
			if after.EdgeData(src, dst) != nil {
				skipped = append(skipped, skip{ben.ID, iid, "already granted"})
				continue
			}
			if err := after.AddEdge(src, dst, "member_of", "simulated", exp); err != nil {
				return nil, err
			}
			checked++
		}
	}
	risks := a.sodRisks()
	env := func(g *graph.Snapshot) []sod.Violation {
		return policy.NewContext(g, tx, a.now).SoD(risks)
	}
	introduced := sod.Introduced(env(a.g), env(after))
	out := make([]sodSimTrigger, 0, len(introduced))
	highest := ""
	for _, v := range introduced {
		out = append(out, sodSimTrigger{v.RiskID, v.RiskKey, v.RiskName, v.Priority, v.BusinessProcess, v.Ruleset, v.IdentityID,
			v.IdentityName, v.Function1, v.Function2, v.Entitlement, v.Message})
		if sod.PriorityRank[v.Priority] > sod.PriorityRank[highest] {
			highest = v.Priority
		}
	}
	return struct {
		Checked      int             `json:"checked"`
		Skipped      []skip          `json:"skipped"`
		WouldTrigger []sodSimTrigger `json:"would_trigger"`
		Highest      string          `json:"highest_priority"`
	}{checked, skipped, out, highest}, nil
}
