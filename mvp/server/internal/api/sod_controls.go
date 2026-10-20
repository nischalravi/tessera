package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Mitigating controls and remediation of SoD violations (issue #298):
//
//	GET  /api/sod/controls                          the control library, with what uses each
//	POST /api/sod/controls                          {name, description, owner_id, type, frequency, evidence_requirement}
//	GET|PUT /api/sod/controls/{control_id}          one; PUT {version, ...}
//	POST /api/sod/controls/{control_id}/retire      {reason}
//	GET  /api/sod/mitigations                       ?status&expiring_within_days
//	POST /api/sod/mitigations                       {risk_id, identity_id, kind, control_id, justification, ends_at, evidence}
//	POST /api/sod/mitigations/{id}/approve|reject   {note}: the second person (four-eyes)
//	POST /api/sod/mitigations/{id}/cancel           the requester withdraws a pending request
//	POST /api/sod/mitigations/{id}/revoke           {reason}: a risk owner or an approver ends it early
//	POST /api/sod/violations/escalate               {risk_id, identity_id, note}: to the risk owner
//	POST /api/sod/violations/revoke                 {risk_id, identity_id, edge_id, dry_run}: through the revoke path
//	GET  /api/sod/review-context?campaign_id=       the SoD risk and cover of each review item
//
// A risk offers some of revoke, mitigate, accept and escalate; the server refuses
// the others. Reading needs graph.read; the library needs sod.manage; requesting
// and escalating need sod.mitigate; approving needs sod.approve and a fresh
// phishing-resistant sign-in, and never the requester. A mitigation always has an
// end date, at most TESSERA_SOD_MAX_MITIGATION_DAYS away.

func (s *Server) registerSodControlRoutes() {
	const G, P, U = http.MethodGet, http.MethodPost, http.MethodPut
	rd := need(auth.PermGraphRead)
	manage := needStepUp(auth.PermSoDManage, auth.StepUpPolicy)
	mitigate := need(auth.PermSoDMitigate)
	s.handle(G, "/api/sod/controls", read, rd, s.listSodControls)
	s.handle(P, "/api/sod/controls", write, manage, s.createSodControl)
	s.handle(G, "/api/sod/controls/{control_id}", read, rd, s.getSodControl)
	s.handle(U, "/api/sod/controls/{control_id}", write, manage, s.updateSodControl)
	s.handle(P, "/api/sod/controls/{control_id}/retire", write, manage, s.retireSodControl)
	s.handle(G, "/api/sod/mitigations", read, rd, s.listSodMitigations)
	s.handle(P, "/api/sod/mitigations", write, mitigate, s.requestSodMitigation)
	s.handle(P, "/api/sod/mitigations/{mitigation_id}/approve", write, needStepUp(auth.PermSoDApprove, auth.StepUpPolicy), s.decideSodMitigation(true))
	s.handle(P, "/api/sod/mitigations/{mitigation_id}/reject", write, need(auth.PermSoDApprove), s.decideSodMitigation(false))
	s.handle(P, "/api/sod/mitigations/{mitigation_id}/cancel", write, mitigate, s.cancelSodMitigation)
	// risk owners may end a mitigation too: the handler checks (and asks for a fresh sign-in)
	s.handle(P, "/api/sod/mitigations/{mitigation_id}/revoke", write, need(auth.PermRequestsCreate), s.revokeSodMitigation)
	s.handle(P, "/api/sod/violations/escalate", write, mitigate, s.escalateSodViolation)
	s.handle(P, "/api/sod/violations/revoke", write, rd, s.revokeSodViolation).answersRead = true
	s.handle(G, "/api/sod/review-context", read, rd, s.sodReviewContext)
}

func (s *Server) sodSettings() sod.Settings { return s.cfg.SoD.WithDefaults() }

// ---------------------------------------------------------------- controls

type sodControlView struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Description         string     `json:"description"`
	Owner               *personRef `json:"owner"`
	Type                string     `json:"type"`
	Frequency           string     `json:"frequency"`
	EvidenceRequirement string     `json:"evidence_requirement"`
	Status              string     `json:"status"`
	Version             int        `json:"version"`
	UpdatedBy           *userRef   `json:"updated_by"`
	UpdatedAt           time.Time  `json:"updated_at"`
	ActiveMitigations   int        `json:"active_mitigations"`
}

func (s *Server) controlViews(r *http.Request) ([]sodControlView, error) {
	tx := store.TxFrom(r.Context())
	cs, err := tx.SodControls()
	if err != nil {
		return nil, err
	}
	ms, err := tx.SodMitigations()
	if err != nil {
		return nil, err
	}
	live := map[string]int{}
	for _, m := range ms {
		if m.ControlID != nil && (m.Status == store.MitigationActive || m.Status == store.MitigationPending) {
			live[*m.ControlID]++
		}
	}
	v := newViewer(tx)
	out := make([]sodControlView, 0, len(cs))
	for _, c := range cs {
		cv := sodControlView{ID: c.ID, Name: c.Name, Description: c.Description, Type: c.Type, Frequency: c.Frequency,
			EvidenceRequirement: c.EvidenceRequirement, Status: c.Status, Version: c.Version, UpdatedAt: c.UpdatedAt, ActiveMitigations: live[c.ID]}
		if c.OwnerID != nil {
			if p, err := v.person(*c.OwnerID); err == nil {
				cv.Owner = &p
			}
		}
		if c.UpdatedBy != nil {
			u := v.user(*c.UpdatedBy)
			cv.UpdatedBy = &u
		}
		out = append(out, cv)
	}
	return out, nil
}

func (s *Server) listSodControls(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	cs, err := s.controlViews(r)
	if err != nil {
		return nil, err
	}
	return struct {
		CanManage   bool             `json:"can_manage"`
		Types       []string         `json:"types"`
		Frequencies []string         `json:"frequencies"`
		Controls    []sodControlView `json:"controls"`
	}{s.can(r, auth.PermSoDManage), sod.ControlTypes, sod.ControlFrequencies, cs}, nil
}

func (s *Server) sodControlDetail(r *http.Request, id string) (sodControlView, error) {
	cs, err := s.controlViews(r)
	if err != nil {
		return sodControlView{}, err
	}
	for _, c := range cs {
		if c.ID == id {
			return c, nil
		}
	}
	return sodControlView{}, notFound("control_not_found", "control not found")
}

func (s *Server) getSodControl(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.sodControlDetail(r, strings.TrimSpace(p.path["control_id"]))
}

type sodControlBody struct {
	Version             int    `json:"version"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	OwnerID             *int64 `json:"owner_id"`
	Type                string `json:"type"`
	Frequency           string `json:"frequency"`
	EvidenceRequirement string `json:"evidence_requirement"`
}

func (b sodControlBody) input() sod.ControlInput {
	return sod.ControlInput{Name: b.Name, Description: b.Description, OwnerID: b.OwnerID, Type: b.Type, Frequency: b.Frequency,
		EvidenceRequirement: b.EvidenceRequirement}
}

func (s *Server) createSodControl(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodControlBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, err := w.CreateControl(b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	out, err := s.sodControlDetail(r, c.ID)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) updateSodControl(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b sodControlBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, err := w.UpdateControl(strings.TrimSpace(p.path["control_id"]), b.Version, b.input())
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodControlDetail(r, c.ID)
}

func (s *Server) retireSodControl(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
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
	c, err := w.RetireControl(strings.TrimSpace(p.path["control_id"]), b.Reason)
	if err != nil {
		return nil, sodErr(err)
	}
	return s.sodControlDetail(r, c.ID)
}

// ---------------------------------------------------------------- mitigations

type sodMitigationView struct {
	ID            string       `json:"id"`
	Risk          sodRiskBrief `json:"risk"`
	Identity      personRef    `json:"identity"`
	Kind          string       `json:"kind"`
	Control       *sodRef      `json:"control"`
	Justification string       `json:"justification"`
	Evidence      []string     `json:"evidence"`
	Status        string       `json:"status"`
	StartsAt      *time.Time   `json:"starts_at"`
	EndsAt        time.Time    `json:"ends_at"`
	DaysLeft      *int         `json:"days_left"`
	RequestedBy   userRef      `json:"requested_by"`
	RequestedAt   time.Time    `json:"requested_at"`
	DecidedBy     *userRef     `json:"decided_by"`
	DecidedAt     *time.Time   `json:"decided_at"`
	DecisionNote  *string      `json:"decision_note"`
	RevokedBy     *userRef     `json:"revoked_by"`
	RevokeReason  *string      `json:"revoke_reason"`
	Mine          bool         `json:"requested_by_me"`
}

type sodRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sodRiskBrief struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Name     string `json:"name"`
	Priority string `json:"priority"`
}

func (s *Server) mitigationViews(r *http.Request, ms []*store.SodMitigation) ([]sodMitigationView, error) {
	tx := store.TxFrom(r.Context())
	v := newViewer(tx)
	risks := map[string]*store.SodRisk{}
	rs, err := tx.SodRisks()
	if err != nil {
		return nil, err
	}
	for _, x := range rs {
		risks[x.ID] = x
	}
	controls := map[string]*store.SodControl{}
	cs, err := tx.SodControls()
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		controls[c.ID] = c
	}
	var me string
	if pr := principal(r); pr != nil && pr.UserID != nil {
		me = pr.UserID.String()
	}
	now := s.clock().UTC()
	out := make([]sodMitigationView, 0, len(ms))
	for _, m := range ms {
		who, err := v.person(m.IdentityID)
		if err != nil {
			return nil, err
		}
		mv := sodMitigationView{ID: m.ID, Identity: who, Kind: m.Kind, Justification: m.Justification, Evidence: sod.EvidenceRefs(m),
			Status: m.Status, StartsAt: m.StartsAt, EndsAt: m.EndsAt, RequestedBy: v.user(m.RequestedBy), RequestedAt: m.RequestedAt,
			DecidedAt: m.DecidedAt, DecisionNote: m.DecisionNote, RevokeReason: m.RevokeReason, Mine: m.RequestedBy == me}
		if rk := risks[m.RiskID]; rk != nil {
			mv.Risk = sodRiskBrief{rk.ID, rk.Key, rk.Name, rk.Priority}
		}
		if m.ControlID != nil && controls[*m.ControlID] != nil {
			mv.Control = &sodRef{*m.ControlID, controls[*m.ControlID].Name}
		}
		if m.DecidedBy != nil {
			u := v.user(*m.DecidedBy)
			mv.DecidedBy = &u
		}
		if m.RevokedBy != nil {
			u := v.user(*m.RevokedBy)
			mv.RevokedBy = &u
		}
		if m.Status == store.MitigationActive || m.Status == store.MitigationPending {
			d := int(m.EndsAt.Sub(now).Hours() / 24)
			mv.DaysLeft = &d
		}
		out = append(out, mv)
	}
	return out, nil
}

func (s *Server) listSodMitigations(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	status := p.queryOptLiteral("status", []string{"pending", "active", "rejected", "cancelled", "expired", "revoked"})
	within := p.queryOptInt("expiring_within_days")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	ms, err := store.TxFrom(r.Context()).SodMitigations()
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	var keep []*store.SodMitigation
	for _, m := range ms {
		if status != nil && m.Status != *status {
			continue
		}
		if within != nil && (m.Status != store.MitigationActive || m.EndsAt.After(now.Add(time.Duration(*within)*24*time.Hour))) {
			continue
		}
		keep = append(keep, m)
	}
	views, err := s.mitigationViews(r, keep)
	if err != nil {
		return nil, err
	}
	return struct {
		CanRequest  bool                `json:"can_request"`
		CanApprove  bool                `json:"can_approve"`
		MaxDays     int                 `json:"max_days"`
		WarnDays    int                 `json:"warn_days"`
		Mitigations []sodMitigationView `json:"mitigations"`
	}{s.can(r, auth.PermSoDMitigate), s.can(r, auth.PermSoDApprove), s.sodSettings().MaxDays, s.sodSettings().WarnDays, views}, nil
}

// parseEnd reads an end date: an RFC 3339 time, or a day (it ends at the end of that day, UTC).
func parseEnd(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.UTC().Add(24*time.Hour - time.Second), nil
	}
	return time.Time{}, badRequest("invalid_end_date", "the end date is a day (2026-12-31) or an RFC 3339 time")
}

// currentViolation finds the open violation of the risk by the identity now.
func (s *Server) currentViolation(r *http.Request, riskID string, identityID int64) (*sod.Violation, error) {
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	all, err := s.sodDetect(a)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].RiskID == riskID && all[i].IdentityID == identityID {
			return &all[i], nil
		}
	}
	return nil, nil
}

func (s *Server) requestSodMitigation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		RiskID        string   `json:"risk_id"`
		IdentityID    int64    `json:"identity_id"`
		Kind          string   `json:"kind"`
		ControlID     string   `json:"control_id"`
		Justification string   `json:"justification"`
		EndsAt        string   `json:"ends_at"`
		Evidence      []string `json:"evidence"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	end, err := parseEnd(b.EndsAt)
	if err != nil {
		return nil, err
	}
	in := sod.MitigationInput{RiskID: strings.TrimSpace(b.RiskID), IdentityID: b.IdentityID, Kind: b.Kind, ControlID: strings.TrimSpace(b.ControlID),
		Justification: b.Justification, EndsAt: end, Evidence: b.Evidence}
	// the violation must exist now; the risk-level checks (offered, end date) come first so their refusals are the same either way
	m, err := w.RequestMitigation(in, s.sodSettings())
	if err != nil {
		return nil, sodErr(err)
	}
	if v, err := s.currentViolation(r, m.RiskID, m.IdentityID); err != nil {
		return nil, err
	} else if v == nil {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "no_violation", Msg: "that person does not hold both sides of this risk now"}
	}
	views, err := s.mitigationViews(r, []*store.SodMitigation{m})
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, views[0]}, nil
}

func (s *Server) decideSodMitigation(approve bool) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		if err := validated(p, nil); err != nil {
			return nil, err
		}
		w, err := s.sodWriter(r)
		if err != nil {
			return nil, err
		}
		var b struct {
			Note string `json:"note"`
		}
		if err := decodeBody(r, &b, true); err != nil {
			return nil, err
		}
		m, err := w.DecideMitigation(strings.TrimSpace(p.path["mitigation_id"]), approve, b.Note)
		if err != nil {
			return nil, sodErr(err)
		}
		views, err := s.mitigationViews(r, []*store.SodMitigation{m})
		if err != nil {
			return nil, err
		}
		return views[0], nil
	}
}

func (s *Server) cancelSodMitigation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	m, err := w.CancelMitigation(strings.TrimSpace(p.path["mitigation_id"]))
	if err != nil {
		return nil, sodErr(err)
	}
	views, err := s.mitigationViews(r, []*store.SodMitigation{m})
	if err != nil {
		return nil, err
	}
	return views[0], nil
}

func (s *Server) revokeSodMitigation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	id := strings.TrimSpace(p.path["mitigation_id"])
	m, err := tx.SodMitigation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("mitigation_not_found", "mitigation not found")
	} else if err != nil {
		return nil, err
	}
	risk, err := tx.SodRisk(m.RiskID)
	if err != nil {
		return nil, err
	}
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	owner := risk.OwnerID != nil && me.IdentityID != nil && *risk.OwnerID == *me.IdentityID
	if !owner && !s.can(r, auth.PermSoDApprove) {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "owner_or_approver_only", Msg: "only the risk owner or an approver can end a mitigation early"}
	}
	if d := auth.Check(principal(r), auth.PermRequestsCreate, &auth.StepUpPolicy, s.clock()); d != nil {
		return nil, denial{d}
	}
	var b sodRetireBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	m, err = w.RevokeMitigation(id, b.Reason)
	if err != nil {
		return nil, sodErr(err)
	}
	views, err := s.mitigationViews(r, []*store.SodMitigation{m})
	if err != nil {
		return nil, err
	}
	return views[0], nil
}

// ---------------------------------------------------------------- remediation

func (s *Server) escalateSodViolation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	w, err := s.sodWriter(r)
	if err != nil {
		return nil, err
	}
	var b struct {
		RiskID     string `json:"risk_id"`
		IdentityID int64  `json:"identity_id"`
		Note       string `json:"note"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	e, err := w.Escalate(strings.TrimSpace(b.RiskID), b.IdentityID, b.Note)
	if err != nil {
		return nil, sodErr(err)
	}
	if v, err := s.currentViolation(r, e.RiskID, e.IdentityID); err != nil {
		return nil, err
	} else if v == nil {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "no_violation", Msg: "that person does not hold both sides of this risk now"}
	}
	return statusBody{http.StatusCreated, struct {
		ID string `json:"id"`
	}{e.ID}}, nil
}

// revokeSodViolation removes one of the grants behind a violation through the
// revoke path, if the risk offers revoke and the grant is one of the violation's.
func (s *Server) revokeSodViolation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b struct {
		RiskID     string `json:"risk_id"`
		IdentityID int64  `json:"identity_id"`
		EdgeID     int64  `json:"edge_id"`
		DryRun     bool   `json:"dry_run"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	risk, err := tx.SodRisk(strings.TrimSpace(b.RiskID))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("risk_not_found", "risk not found")
	} else if err != nil {
		return nil, err
	}
	opts, err := sod.RiskOptions(tx, risk.ID)
	if err != nil {
		return nil, err
	}
	if !sod.Offers(opts, sod.OptRevoke) {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "option_not_offered", Msg: risk.Name + ` does not offer "revoke" as a remediation`}
	}
	v, err := s.currentViolation(r, risk.ID, b.IdentityID)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "no_violation", Msg: "that person does not hold both sides of this risk now"}
	}
	e, err := getOrNil(tx.Edge(b.EdgeID))
	if err != nil {
		return nil, err
	}
	if e == nil || !slices.ContainsFunc(v.Edges, func(x []string) bool { return x[0] == e.Src && x[1] == e.Dst }) {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "not_a_cause", Msg: "that grant is not one of the grants behind this violation"}
	}
	return s.revokeEdge(r, e.ID, b.DryRun)
}

// ---------------------------------------------------------------- reviews

type sodReviewItem struct {
	ItemID     int64         `json:"item_id"`
	Violations []sodReviewOf `json:"violations"`
}

type sodReviewOf struct {
	RiskID     string     `json:"risk_id"`
	RiskKey    string     `json:"risk_key"`
	RiskName   string     `json:"risk_name"`
	Priority   string     `json:"priority"`
	Status     string     `json:"status"`
	Mitigation *sod.Cover `json:"mitigation,omitempty"`
	IdentityID int64      `json:"identity_id"`
	Offers     []string   `json:"remediation"`
}

// sodReviewContext tells a reviewer which SoD risks the grant of each review item
// is behind, and whether a mitigation covers them, so they can request one.
func (s *Server) sodReviewContext(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	cid := p.queryInt("campaign_id", 0, nil, nil)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if cid == 0 { // no campaign named: nothing to say
		return struct {
			CanRequest bool            `json:"can_request"`
			Items      []sodReviewItem `json:"items"`
		}{s.can(r, auth.PermSoDMitigate), []sodReviewItem{}}, nil
	}
	if _, err := tx.Campaign(cid); errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "campaign not found")
	} else if err != nil {
		return nil, err
	}
	items, err := tx.CampaignItems(cid)
	if err != nil {
		return nil, err
	}
	a, err := s.readAnalysis(r)
	if err != nil {
		return nil, err
	}
	all, err := s.sodDetect(a)
	if err != nil {
		return nil, err
	}
	opts, err := tx.SodRiskOptions()
	if err != nil {
		return nil, err
	}
	explicit := map[string][]string{}
	for _, o := range opts {
		explicit[o.RiskID] = append(explicit[o.RiskID], o.Option)
	}
	out := []sodReviewItem{}
	for _, it := range items {
		var vs []sodReviewOf
		for _, v := range all {
			if v.IdentityID != it.IdentityID || !slices.ContainsFunc(v.Edges, func(x []string) bool { return x[0] == it.EdgeSrc && x[1] == it.EdgeDst }) {
				continue
			}
			offers := []string{}
			for _, o := range sod.RemediationOptions {
				if sod.Offers(explicit[v.RiskID], o) {
					offers = append(offers, o)
				}
			}
			vs = append(vs, sodReviewOf{v.RiskID, v.RiskKey, v.RiskName, v.Priority, v.Status, v.Mitigation, v.IdentityID, offers})
		}
		if len(vs) > 0 {
			out = append(out, sodReviewItem{it.ID, vs})
		}
	}
	return struct {
		CanRequest bool            `json:"can_request"`
		Items      []sodReviewItem `json:"items"`
	}{s.can(r, auth.PermSoDMitigate), out}, nil
}
