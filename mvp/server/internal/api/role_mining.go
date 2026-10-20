package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/roles/mining"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Role mining (issue #298): business roles suggested from the access people
// hold.
//
//	GET  /api/role-mining/runs                              recent runs (newest first), with whether the user may manage
//	POST /api/role-mining/runs                              {filters, settings, async?}: start a run (201 done inline, 202 queued)
//	GET  /api/role-mining/runs/{run_id}                     a run with its candidates
//	GET  /api/role-mining/candidates/{candidate_id}         a candidate with its members and outliers
//	POST /api/role-mining/candidates/{candidate_id}/accept  {name?, description?, risk?, entitlement_group_ids?}: create the role
//	POST /api/role-mining/candidates/{candidate_id}/dismiss {reason}
//
// Reading needs graph.read (it shows who holds what); starting a run and
// dismissing need roles.manage; accepting creates a role, so it needs
// roles.manage and a fresh phishing-resistant sign-in like POST /api/roles.
// Accepting creates a role with no rule, no members and not requestable: it
// grants and removes nothing, and assignment follows the role flows.

func (s *Server) registerRoleMiningRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	graph := need(auth.PermGraphRead)
	s.handle(G, "/api/role-mining/runs", read, graph, s.listMiningRuns)
	s.handle(P, "/api/role-mining/runs", write, need(auth.PermRolesManage), s.startMiningRun)
	s.handle(G, "/api/role-mining/runs/{run_id}", read, graph, s.getMiningRun)
	s.handle(G, "/api/role-mining/candidates/{candidate_id}", read, graph, s.getMiningCandidate)
	s.handle(P, "/api/role-mining/candidates/{candidate_id}/accept", write, needStepUp(auth.PermRolesManage, auth.StepUpPolicy), s.acceptMiningCandidate)
	s.handle(P, "/api/role-mining/candidates/{candidate_id}/dismiss", write, need(auth.PermRolesManage), s.dismissMiningCandidate)
}

// queueRoleMining computes a queued run.
func (s *Server) queueRoleMining(ctx context.Context, j queue.Job) (any, error) {
	var pl struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(j.Payload), &pl); err != nil || pl.RunID == "" {
		return nil, queue.Permanent(errors.New("role mining job without a run id"))
	}
	now := s.clock().UTC()
	var status string
	err := s.store.InTenant(audit.WithSystemActor(ctx, mining.Worker), j.Tenant, func(tx *store.TenantTx) error {
		if err := mining.Execute(ctx, tx, pl.RunID, now); err != nil {
			return err
		}
		run, err := tx.MiningRun(pl.RunID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		status = run.Status
		return err
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"run_id": pl.RunID, "status": status}, nil
}

// ---------------------------------------------------------------- views

type miningRunView struct {
	ID              string          `json:"id"`
	Status          string          `json:"status"`
	Params          json.RawMessage `json:"params"`
	Algorithm       string          `json:"algorithm"`
	SnapshotHash    string          `json:"snapshot_hash"`
	People          int             `json:"people"`
	Entitlements    int             `json:"entitlements"`
	Candidates      int             `json:"candidates"`
	SkippedExisting int             `json:"skipped_existing"`
	Truncated       bool            `json:"truncated"`
	Error           string          `json:"error"`
	RequestedBy     string          `json:"requested_by"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at"`
}

func viewMiningRun(r *store.MiningRun) miningRunView {
	return miningRunView{ID: r.ID, Status: r.Status, Params: json.RawMessage(r.Params), Algorithm: r.Algorithm,
		SnapshotHash: r.SnapshotHash, People: r.People, Entitlements: r.Entitlements, Candidates: r.Candidates,
		SkippedExisting: r.SkippedExisting, Truncated: r.Truncated, Error: r.Error, RequestedBy: r.RequestedActor,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt}
}

type miningCandidateView struct {
	ID             string          `json:"id"`
	RunID          string          `json:"run_id"`
	Rank           int             `json:"rank"`
	Name           string          `json:"name"`
	Entitlements   []groupRef      `json:"entitlements"`
	Coverage       int             `json:"coverage"`
	OutlierCount   int             `json:"outlier_count"`
	Rule           json.RawMessage `json:"rule"` // {attribute, values, precision, recall}; null: none
	Confidence     int             `json:"confidence"`
	Cohesion       int             `json:"cohesion"`
	SimilarRole    *roleRefView    `json:"similar_role"`
	Similarity     int             `json:"similarity"`
	Status         string          `json:"status"`
	DecidedBy      *string         `json:"decided_by"`
	DecidedAt      *time.Time      `json:"decided_at"`
	DecisionReason *string         `json:"decision_reason"`
	RoleID         *string         `json:"role_id"`
	// detail only
	Members  []personRef         `json:"members,omitempty"`
	Outliers []miningOutlierView `json:"outliers,omitempty"`
}

type roleRefView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type miningOutlierView struct {
	Person personRef  `json:"person"`
	Extra  []groupRef `json:"extra"`
}

func (s *Server) viewMiningCandidate(v *viewer, tx *store.TenantTx, c *store.MiningCandidate, detail bool) (miningCandidateView, error) {
	out := miningCandidateView{ID: c.ID, RunID: c.RunID, Rank: c.Rank, Name: c.Name, Coverage: c.Coverage,
		Confidence: c.Confidence, Cohesion: c.Cohesion, Similarity: c.Similarity, Status: c.Status, DecidedBy: c.DecidedActor,
		DecidedAt: c.DecidedAt, DecisionReason: c.DecisionReason, RoleID: c.RoleID, Rule: json.RawMessage("null")}
	if c.Rule != nil {
		out.Rule = json.RawMessage(*c.Rule)
	}
	var ents, members []int64
	var outliers []mining.Outlier
	for _, x := range []struct {
		raw string
		dst any
	}{{c.Entitlements, &ents}, {c.Members, &members}, {c.Outliers, &outliers}} {
		if err := json.Unmarshal([]byte(x.raw), x.dst); err != nil {
			return out, err
		}
	}
	out.OutlierCount = len(outliers)
	out.Entitlements = make([]groupRef, 0, len(ents))
	for _, g := range ents {
		gr, err := v.group(g)
		if err != nil {
			return out, err
		}
		out.Entitlements = append(out.Entitlements, gr)
	}
	if c.SimilarRoleID != nil {
		if r, err := tx.BusinessRole(*c.SimilarRoleID); err == nil {
			out.SimilarRole = &roleRefView{r.ID, r.Name}
		} else if !errors.Is(err, store.ErrNotFound) {
			return out, err
		}
	}
	if !detail {
		return out, nil
	}
	out.Members = make([]personRef, 0, len(members))
	for _, id := range members {
		p, err := v.person(id)
		if err != nil {
			return out, err
		}
		out.Members = append(out.Members, p)
	}
	out.Outliers = make([]miningOutlierView, 0, len(outliers))
	for _, o := range outliers {
		p, err := v.person(o.IdentityID)
		if err != nil {
			return out, err
		}
		ov := miningOutlierView{Person: p, Extra: make([]groupRef, 0, len(o.Extra))}
		for _, g := range o.Extra {
			gr, err := v.group(g)
			if err != nil {
				return out, err
			}
			ov.Extra = append(ov.Extra, gr)
		}
		out.Outliers = append(out.Outliers, ov)
	}
	return out, nil
}

// ---------------------------------------------------------------- reads

func (s *Server) listMiningRuns(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	runs, err := store.TxFrom(r.Context()).MiningRuns(20)
	if err != nil {
		return nil, err
	}
	out := struct {
		CanManage bool            `json:"can_manage"`
		Defaults  mining.Params   `json:"defaults"`
		Runs      []miningRunView `json:"runs"`
	}{CanManage: s.can(r, auth.PermRolesManage), Runs: make([]miningRunView, 0, len(runs))}
	out.Defaults, _ = mining.Params{}.Normalize()
	for _, run := range runs {
		out.Runs = append(out.Runs, viewMiningRun(run))
	}
	return out, nil
}

func (s *Server) getMiningRun(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	run, err := tx.MiningRun(strings.TrimSpace(p.path["run_id"]))
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "run_not_found", Msg: "run not found"}
	} else if err != nil {
		return nil, err
	}
	cs, err := tx.MiningCandidates(run.ID)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := struct {
		Run        miningRunView         `json:"run"`
		Candidates []miningCandidateView `json:"candidates"`
	}{viewMiningRun(run), make([]miningCandidateView, 0, len(cs))}
	for _, c := range cs {
		cv, err := s.viewMiningCandidate(v, tx, c, false)
		if err != nil {
			return nil, err
		}
		out.Candidates = append(out.Candidates, cv)
	}
	return out, nil
}

func (s *Server) loadMiningCandidate(tx *store.TenantTx, p *params) (*store.MiningCandidate, error) {
	c, err := tx.MiningCandidate(strings.TrimSpace(p.path["candidate_id"]))
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "candidate_not_found", Msg: "candidate not found"}
	}
	return c, err
}

func (s *Server) getMiningCandidate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	c, err := s.loadMiningCandidate(tx, p)
	if err != nil {
		return nil, err
	}
	return s.viewMiningCandidate(newViewer(tx), tx, c, true)
}

// ---------------------------------------------------------------- changes

type miningRunBody struct {
	Department      []string `json:"department"`
	Title           []string `json:"title"`
	Type            []string `json:"type"`
	MinMembers      int      `json:"min_members"`
	MinEntitlements int      `json:"min_entitlements"`
	MinSimilarity   int      `json:"min_similarity"`
	MaxCandidates   int      `json:"max_candidates"`
	Async           bool     `json:"async"`
}

func (s *Server) startMiningRun(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b miningRunBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	mp := mining.Params{Department: b.Department, Title: b.Title, Type: b.Type, MinMembers: b.MinMembers,
		MinEntitlements: b.MinEntitlements, MinSimilarity: b.MinSimilarity, MaxCandidates: b.MaxCandidates}
	run, err := mining.Request(store.TxFrom(r.Context()), mp, by, b.Async, s.queue.EnqueueTx, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	code := http.StatusCreated
	if run.Status == store.MiningQueued {
		code = http.StatusAccepted
	}
	return statusBody{code, viewMiningRun(run)}, nil
}

type miningAcceptBody struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Risk         string  `json:"risk"`
	Entitlements []int64 `json:"entitlement_group_ids"`
}

func (s *Server) acceptMiningCandidate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	c, err := s.loadMiningCandidate(tx, p)
	if err != nil {
		return nil, err
	}
	var b miningAcceptBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	res, err := mining.Accept(tx, c.ID, mining.Edit{Name: b.Name, Description: b.Description, Risk: b.Risk,
		Entitlements: b.Entitlements}, by, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	role, err := s.roleDetail(r, res.Role.Role)
	if err != nil {
		return nil, err
	}
	cv, err := s.viewMiningCandidate(newViewer(tx), tx, res.Candidate, false)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, struct {
		Candidate miningCandidateView `json:"candidate"`
		Role      roleView            `json:"role"`
	}{cv, role}}, nil
}

type miningDismissBody struct {
	Reason string `json:"reason"`
}

func (s *Server) dismissMiningCandidate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	c, err := s.loadMiningCandidate(tx, p)
	if err != nil {
		return nil, err
	}
	var b miningDismissBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	d, err := mining.Dismiss(tx, c.ID, b.Reason, by, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	return s.viewMiningCandidate(newViewer(tx), tx, d, false)
}
