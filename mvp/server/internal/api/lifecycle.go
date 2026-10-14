package api

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The identity lifecycle (issue #159):
//
//	GET  /api/lifecycle                                    ?state=upcoming|active|ending|ended: people with a lifecycle
//	GET  /api/lifecycle/sponsored                          the people the signed-in user sponsors
//	POST /api/lifecycle/sweep                              send due warnings and end due terms now
//	GET  /api/identities/{identity_id}/lifecycle           one person's lifecycle and history
//	PUT  /api/identities/{identity_id}/lifecycle           {worker_type, sponsor_identity_id, organization, starts_at, ends_at, reason}
//	POST /api/identities/{identity_id}/lifecycle/extend    {ends_at, reason}: the sponsor or a lifecycle admin
//
// Reading needs graph.read; setting, converting and sweeping need
// lifecycle.manage (setting with a fresh phishing-resistant sign-in).
// Everyone may list the people they sponsor and extend their terms.

func (s *Server) registerLifecycleRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	graph, create := need(auth.PermGraphRead), need(auth.PermRequestsCreate)
	s.handle(G, "/api/lifecycle", read, graph, s.listLifecycle)
	s.handle(G, "/api/lifecycle/sponsored", read, create, s.sponsoredLifecycle)
	s.handle(P, "/api/lifecycle/sweep", phased, need(auth.PermLifecycleManage), s.sweepLifecycle)
	s.handle(G, "/api/identities/{identity_id}/lifecycle", read, graph, s.getLifecycle)
	s.handle(http.MethodPut, "/api/identities/{identity_id}/lifecycle", write, needStepUp(auth.PermLifecycleManage, auth.StepUpPolicy), s.putLifecycle)
	s.handle(P, "/api/identities/{identity_id}/lifecycle/extend", write, create, s.extendLifecycle)
}

type lifecycleView struct {
	Person       personRef  `json:"person"`
	WorkerType   string     `json:"worker_type"`
	Sponsor      *personRef `json:"sponsor"`
	Organization *string    `json:"organization"`
	StartsAt     *time.Time `json:"starts_at"`
	EndsAt       *time.Time `json:"ends_at"`
	EndedAt      *time.Time `json:"ended_at"`
	State        string     `json:"state"`
	DaysLeft     *int       `json:"days_left"`
	WarnedDays   *int       `json:"warned_days"`
	Source       string     `json:"source"`
	UpdatedAt    *time.Time `json:"updated_at"`
	// Default: no lifecycle row (an employee with no end date).
	Default bool `json:"default"`
	// What the signed-in user may do (the API checks again).
	CanExtend bool             `json:"can_extend"`
	CanManage bool             `json:"can_manage"`
	Events    []lifecycleEvent `json:"events,omitempty"`
}

type lifecycleEvent struct {
	Event      string     `json:"event"`
	WorkerType *string    `json:"worker_type"`
	EndsAt     *time.Time `json:"ends_at"`
	Note       *string    `json:"note"`
	Actor      string     `json:"actor"`
	At         time.Time  `json:"at"`
}

func (s *Server) lifecycleView(r *http.Request, v *viewer, l *store.Lifecycle, me *int64) (lifecycleView, error) {
	p, err := v.person(l.IdentityID)
	if err != nil {
		return lifecycleView{}, err
	}
	now := s.clock().UTC()
	out := lifecycleView{Person: p, WorkerType: l.WorkerType, Organization: l.Organization, StartsAt: l.StartsAt, EndsAt: l.EndsAt,
		EndedAt: l.EndedAt, State: lifecycle.State(l, now), DaysLeft: lifecycle.DaysLeft(l, now), WarnedDays: l.WarnedDays,
		Source: l.Source, UpdatedAt: &l.UpdatedAt, CanManage: s.can(r, auth.PermLifecycleManage)}
	if l.SponsorID != nil {
		sp, err := v.person(*l.SponsorID)
		if err != nil {
			return out, err
		}
		out.Sponsor = &sp
	}
	sponsor := me != nil && l.SponsorID != nil && *me == *l.SponsorID
	self := me != nil && *me == l.IdentityID
	out.CanExtend = l.EndedAt == nil && l.EndsAt != nil && !self && (sponsor || out.CanManage)
	return out, nil
}

func myIdentity(r *http.Request) *int64 {
	me, err := requestActor(r)
	if err != nil {
		return nil
	}
	return me.IdentityID
}

func (s *Server) listLifecycle(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	state := qs(p, "state")
	if state != "" && !slices.Contains([]string{lifecycle.StateUpcoming, lifecycle.StateActive, lifecycle.StateEnding, lifecycle.StateEnded}, state) {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_state", Msg: "state is upcoming, active, ending or ended"}
	}
	tx := store.TxFrom(r.Context())
	ls, err := tx.Lifecycles()
	if err != nil {
		return nil, err
	}
	v, me := newViewer(tx), myIdentity(r)
	out := make([]lifecycleView, 0, len(ls))
	for _, l := range ls {
		lv, err := s.lifecycleView(r, v, l, me)
		if err != nil {
			return nil, err
		}
		if state == "" || lv.State == state {
			out = append(out, lv)
		}
	}
	return map[string]any{"can_manage": s.can(r, auth.PermLifecycleManage), "rows": out}, nil
}

func (s *Server) sponsoredLifecycle(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	me := myIdentity(r)
	out := []lifecycleView{}
	if me == nil {
		return out, nil
	}
	tx := store.TxFrom(r.Context())
	ls, err := tx.Lifecycles()
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	for _, l := range ls {
		if l.SponsorID == nil || *l.SponsorID != *me {
			continue
		}
		lv, err := s.lifecycleView(r, v, l, me)
		if err != nil {
			return nil, err
		}
		out = append(out, lv)
	}
	return out, nil
}

// lifecycleOf loads a person (404 for another tenant's or a missing one) and
// their lifecycle row (nil: none).
func (s *Server) lifecycleOf(r *http.Request, p *params) (*store.Identity, *store.Lifecycle, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, nil, err
	}
	tx := store.TxFrom(r.Context())
	person, err := tx.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, &readiness.Error{Status: http.StatusNotFound, Code: "identity_not_found", Msg: "person not found"}
	} else if err != nil {
		return nil, nil, err
	}
	l, err := tx.LifecycleFor(id)
	if errors.Is(err, store.ErrNotFound) {
		return person, nil, nil
	}
	return person, l, err
}

func (s *Server) fullLifecycleView(r *http.Request, person *store.Identity, l *store.Lifecycle) (any, error) {
	tx := store.TxFrom(r.Context())
	v := newViewer(tx)
	if l == nil {
		pr, err := v.person(person.ID)
		if err != nil {
			return nil, err
		}
		return lifecycleView{Person: pr, WorkerType: store.WorkerEmployee, State: lifecycle.StateActive, Source: "manual",
			Default: true, CanManage: s.can(r, auth.PermLifecycleManage), Events: []lifecycleEvent{}}, nil
	}
	out, err := s.lifecycleView(r, v, l, myIdentity(r))
	if err != nil {
		return nil, err
	}
	evs, err := tx.LifecycleEvents(l.IdentityID)
	if err != nil {
		return nil, err
	}
	out.Events = make([]lifecycleEvent, len(evs))
	for i, e := range evs {
		out.Events[i] = lifecycleEvent{e.Event, e.WorkerType, e.EndsAt, e.Note, e.Actor, e.At}
	}
	return out, nil
}

func (s *Server) getLifecycle(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	person, l, err := s.lifecycleOf(r, p)
	if err != nil {
		return nil, err
	}
	return s.fullLifecycleView(r, person, l)
}

type lifecycleBody struct {
	WorkerType   string     `json:"worker_type"`
	SponsorID    *int64     `json:"sponsor_identity_id"`
	Organization *string    `json:"organization"`
	StartsAt     *time.Time `json:"starts_at"`
	EndsAt       *time.Time `json:"ends_at"`
	Reason       string     `json:"reason"`
}

func (s *Server) putLifecycle(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	person, _, err := s.lifecycleOf(r, p)
	if err != nil {
		return nil, err
	}
	by, err := requestActor(r)
	if err != nil {
		return nil, err
	}
	var b lifecycleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	l, err := lifecycle.Set(tx, person.ID, lifecycle.Spec{WorkerType: b.WorkerType, SponsorID: b.SponsorID, Organization: b.Organization,
		StartsAt: utcp(b.StartsAt), EndsAt: utcp(b.EndsAt), Reason: b.Reason}, by, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.fullLifecycleView(r, person, l)
}

func utcp(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

type extendBody struct {
	EndsAt time.Time `json:"ends_at"`
	Reason string    `json:"reason"`
}

func (s *Server) extendLifecycle(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	person, _, err := s.lifecycleOf(r, p)
	if err != nil {
		return nil, err
	}
	by, err := requestActor(r)
	if err != nil {
		return nil, err
	}
	var b extendBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	l, err := lifecycle.Extend(tx, person.ID, b.EndsAt.UTC(), b.Reason, by, s.can(r, auth.PermLifecycleManage), s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.fullLifecycleView(r, person, l)
}

func (s *Server) sweepLifecycle(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	res, err := lifecycle.SweepTenant(r.Context(), p.scope, s.containment, s.clock().UTC())
	if err != nil {
		return nil, err
	}
	return map[string]int{"warned": res.Warned, "ended": res.Ended}, nil
}
