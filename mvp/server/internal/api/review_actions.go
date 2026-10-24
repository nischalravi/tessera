package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Certification actions (issue #588):
//
//	POST /api/reviews/items/{item_id}/consult         {identity_id, question}: ask another person for advice (the item's reviewer)
//	POST /api/reviews/items/{item_id}/reassign        {identity_id, reason}: move the item to a person who can decide reviews (the item's reviewer; step-up)
//	GET  /api/reviews/items/{item_id}/events          the consult, answer and reassign trail (reviews.manage, the reviewer, or anyone asked or who acted on the item)
//	GET  /api/reviews/consultations                   the questions asked of the signed-in person and not yet answered
//	POST /api/reviews/consultations/{consultation_id}/answer   {answer}: only the person asked
//	POST /api/reviews/campaigns/{campaign_id}/lock    {reason}: pauses decisions (reviews.manage + step-up)
//	POST /api/reviews/campaigns/{campaign_id}/unlock  {reason?}
//	POST /api/reviews/campaigns/{campaign_id}/close   {reason}: final; undecided items stay undecided, nothing is revoked
//
// A decision on an item of a locked or closed campaign is refused with 409 campaign_locked or
// campaign_closed. The item's reviewer is the person its reviewer_id names; reviews.manage may act
// for any reviewer.

func (s *Server) registerReviewActionRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	manage := needStepUp(auth.PermReviewsManage, auth.StepUpPolicy)
	s.handle(P, "/api/reviews/items/{item_id}/consult", write, need(auth.PermReviewsDecide), s.reviewConsult)
	s.handle(P, "/api/reviews/items/{item_id}/reassign", write, needStepUp(auth.PermReviewsDecide, auth.StepUpPolicy), s.reviewReassign)
	s.handle(G, "/api/reviews/items/{item_id}/events", read, need(auth.PermGraphRead), s.reviewItemEvents)
	s.handle(G, "/api/reviews/consultations", read, need(auth.PermGraphRead), s.myConsultations)
	s.handle(P, "/api/reviews/consultations/{consultation_id}/answer", write, need(auth.PermGraphRead), s.answerConsultation)
	s.handle(P, "/api/reviews/campaigns/{campaign_id}/lock", write, manage, s.campaignAction(reviews.ActionLock))
	s.handle(P, "/api/reviews/campaigns/{campaign_id}/unlock", write, manage, s.campaignAction(reviews.ActionUnlock))
	s.handle(P, "/api/reviews/campaigns/{campaign_id}/close", write, manage, s.campaignAction(reviews.ActionClose))
}

func actionErr(err error) error {
	var ae *reviews.ActionError
	if errors.As(err, &ae) {
		return &readiness.Error{Status: ae.Status, Code: ae.Code, Msg: ae.Msg}
	}
	return err
}

func (s *Server) reviewActor(r *http.Request) (reviews.Actor, error) {
	pr := principal(r)
	if pr == nil || pr.UserID == nil {
		return reviews.Actor{}, &readiness.Error{Status: http.StatusForbidden, Code: "user_required", Msg: "reviews are acted on by a signed-in user"}
	}
	a := reviews.Actor{User: pr.User(), Manager: s.can(r, auth.PermReviewsManage)}
	u, err := store.TxFrom(r.Context()).PlatformUser(*pr.UserID)
	if err != nil {
		return a, err
	}
	a.IdentityID = u.IdentityID
	return a, nil
}

type personBody struct {
	IdentityID int64  `json:"identity_id"`
	Question   string `json:"question"`
	Reason     string `json:"reason"`
	Answer     string `json:"answer"`
}

type reviewEventView struct {
	ID     int64         `json:"id"`
	ItemID int64         `json:"item_id"`
	Kind   string        `json:"kind"`
	RefID  *int64        `json:"ref_id,omitempty"`
	Actor  string        `json:"actor"`
	Target *reviewPerson `json:"target,omitempty"`
	Note   string        `json:"note"`
	At     string        `json:"at"`
}

type reviewPerson struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func eventView(c *store.TenantTx, e *store.ReviewItemEvent) (reviewEventView, error) {
	v := reviewEventView{ID: e.ID, ItemID: e.ItemID, Kind: e.Kind, RefID: e.RefID, Actor: e.Actor, Note: e.Note, At: e.At.UTC().Format(time.RFC3339)}
	if e.TargetIdentityID != nil {
		p, err := c.Identity(*e.TargetIdentityID)
		if err != nil {
			return v, err
		}
		v.Target = &reviewPerson{p.ID, p.Name}
	}
	return v, nil
}

func (s *Server) reviewConsult(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("item_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.reviewActor(r)
	if err != nil {
		return nil, err
	}
	var b personBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	ev, err := reviews.Consult(tx, s.clock().UTC(), id, by, b.IdentityID, b.Question)
	if err != nil {
		return nil, actionErr(err)
	}
	v, err := eventView(tx, ev)
	return statusBody{http.StatusCreated, v}, err
}

func (s *Server) reviewReassign(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("item_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.reviewActor(r)
	if err != nil {
		return nil, err
	}
	var b personBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	it, err := reviews.Reassign(store.TxFrom(r.Context()), s.clock().UTC(), id, by, b.IdentityID, b.Reason)
	if err != nil {
		return nil, actionErr(err)
	}
	return map[string]any{"id": it.ID, "reviewer_id": it.ReviewerID}, nil
}

func (s *Server) reviewItemEvents(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("item_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.reviewActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	it, err := tx.Item(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "unknown review item")
	} else if err != nil {
		return nil, err
	}
	evs, err := tx.ReviewItemEvents(id)
	if err != nil {
		return nil, err
	}
	// the questions and answers on an item are for its reviewer, the people asked or who acted, and managers
	involved := by.Manager || (by.IdentityID != nil && it.ReviewerID != nil && *it.ReviewerID == *by.IdentityID)
	for _, e := range evs {
		involved = involved || e.ActorUserID == by.User.ID.String() || (by.IdentityID != nil && e.TargetIdentityID != nil && *e.TargetIdentityID == *by.IdentityID)
	}
	if !involved {
		return nil, errStatus(http.StatusNotFound, "unknown review item")
	}
	out := make([]reviewEventView, 0, len(evs))
	for _, e := range evs {
		v, err := eventView(tx, e)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return map[string]any{"events": out}, nil
}

func (s *Server) myConsultations(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := s.reviewActor(r)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	if by.IdentityID == nil {
		return map[string]any{"consultations": out}, nil
	}
	tx := store.TxFrom(r.Context())
	evs, err := tx.OpenReviewConsultations(*by.IdentityID)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		it, err := tx.Item(e.ItemID)
		if err != nil {
			return nil, err
		}
		if it.Decision != nil && *it.Decision != "" {
			continue
		}
		subj, err := tx.Identity(it.IdentityID)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": e.ID, "item_id": it.ID, "campaign_id": it.CampaignID, "grant": it.GrantLabel,
			"subject": subj.Name, "asked_by": e.Actor, "question": e.Note, "at": e.At.UTC().Format(time.RFC3339)})
	}
	return map[string]any{"consultations": out}, nil
}

func (s *Server) answerConsultation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("consultation_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.reviewActor(r)
	if err != nil {
		return nil, err
	}
	var b personBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	ev, err := reviews.Answer(tx, s.clock().UTC(), id, by, b.Answer)
	if err != nil {
		return nil, actionErr(err)
	}
	v, err := eventView(tx, ev)
	return statusBody{http.StatusCreated, v}, err
}

func (s *Server) campaignAction(action string) handlerFunc {
	return func(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
		id := p.pathInt("campaign_id")
		if err := validated(p, nil); err != nil {
			return nil, err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decodeBody(r, &b, action == reviews.ActionUnlock); err != nil {
			return nil, err
		}
		cmp, err := reviews.ChangeCampaign(store.TxFrom(r.Context()), s.clock().UTC(), id, action, principal(r).User(), b.Reason)
		if err != nil {
			return nil, actionErr(err)
		}
		return map[string]any{"id": cmp.ID, "status": cmp.Status}, nil
	}
}
