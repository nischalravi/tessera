package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Request access drafts (Access > Request access, "Save draft"):
//
//	GET    /api/request-drafts               the signed-in user's drafts, most recently saved first
//	POST   /api/request-drafts               {beneficiary_ids, items, duration_hours, justification}
//	GET    /api/request-drafts/{draft_id}
//	PUT    /api/request-drafts/{draft_id}    replaces the draft
//	DELETE /api/request-drafts/{draft_id}
//
// An item is {"kind":"group","group_id":N} or {"kind":"role","role_id":"..."}.
// Drafts are private to the user who saved them (another user's id looks
// missing) and need requests.create. A draft never submits by itself: the
// client submits through POST /api/requests or /api/role-requests and then
// deletes the draft.

func (s *Server) registerRequestDraftRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	create := need(auth.PermRequestsCreate)
	s.handle(G, "/api/request-drafts", read, create, s.listDrafts)
	s.handle(P, "/api/request-drafts", write, create, s.createDraft)
	s.handle(G, "/api/request-drafts/{draft_id}", read, create, s.getDraft)
	s.handle(http.MethodPut, "/api/request-drafts/{draft_id}", write, create, s.updateDraft)
	s.handle(http.MethodDelete, "/api/request-drafts/{draft_id}", write, create, s.deleteDraft)
}

type draftPerson struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type draftItemView struct {
	Kind       string `json:"kind"`
	GroupID    int64  `json:"group_id,omitempty"`
	RoleID     string `json:"role_id,omitempty"`
	Name       string `json:"name"`
	System     string `json:"system,omitempty"`
	Privileged bool   `json:"privileged"`
}

type draftView struct {
	ID            string          `json:"id"`
	Beneficiaries []draftPerson   `json:"beneficiaries"`
	Items         []draftItemView `json:"items"`
	DurationHours *float64        `json:"duration_hours"`
	Justification string          `json:"justification"`
	// Unavailable counts people and items the draft named that no longer exist.
	Unavailable int       `json:"unavailable"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type draftBody struct {
	BeneficiaryIDs []int64              `json:"beneficiary_ids"`
	Items          []requests.DraftItem `json:"items"`
	DurationHours  *float64             `json:"duration_hours"`
	Justification  string               `json:"justification"`
}

// draftView resolves the names a draft refers to; what no longer exists is counted, not failed on.
func viewDraft(tx *store.TenantTx, d *store.RequestDraft) (draftView, error) {
	out := draftView{ID: d.ID, Beneficiaries: []draftPerson{}, Items: []draftItemView{}, DurationHours: d.DurationHours,
		Justification: d.Justification, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt}
	for _, id := range d.BeneficiaryIDs {
		i, err := tx.Identity(id)
		if errors.Is(err, store.ErrNotFound) {
			out.Unavailable++
			continue
		} else if err != nil {
			return out, err
		}
		out.Beneficiaries = append(out.Beneficiaries, draftPerson{i.ID, i.Name})
	}
	var items []requests.DraftItem
	if err := json.Unmarshal(d.Items, &items); err != nil {
		return out, err
	}
	for _, it := range items {
		switch it.Kind {
		case "group":
			g, err := tx.Group(it.GroupID)
			if errors.Is(err, store.ErrNotFound) {
				out.Unavailable++
				continue
			} else if err != nil {
				return out, err
			}
			out.Items = append(out.Items, draftItemView{Kind: "group", GroupID: g.ID, Name: g.Name, System: g.System, Privileged: g.Privileged})
		case "role":
			r, err := tx.BusinessRole(it.RoleID)
			if errors.Is(err, store.ErrNotFound) {
				out.Unavailable++
				continue
			} else if err != nil {
				return out, err
			}
			out.Items = append(out.Items, draftItemView{Kind: "role", RoleID: r.ID, Name: r.Name, Privileged: r.Risk == "high"})
		}
	}
	return out, nil
}

func (s *Server) listDrafts(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	ds, err := tx.RequestDrafts(me.UserID.String())
	if err != nil {
		return nil, err
	}
	out := make([]draftView, 0, len(ds))
	for _, d := range ds {
		v, err := viewDraft(tx, d)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func draftID(p *params) (string, error) {
	id := strings.TrimSpace(p.path["draft_id"])
	if !idRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "draft_not_found", Msg: "draft not found"}
	}
	return id, nil
}

func (s *Server) getDraft(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	id, err := draftID(p)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	d, err := tx.RequestDraft(id, me.UserID.String())
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "draft_not_found", Msg: "draft not found"}
	} else if err != nil {
		return nil, err
	}
	return viewDraft(tx, d)
}

func (s *Server) saveDraft(r *http.Request, id string) (*store.RequestDraft, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	var b draftBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	d, err := requests.SaveDraft(store.TxFrom(r.Context()), id, requests.DraftSpec{BeneficiaryIDs: b.BeneficiaryIDs, Items: b.Items,
		DurationHours: b.DurationHours, Justification: b.Justification}, me, s.clock().UTC())
	return d, reqErr(err)
}

func (s *Server) createDraft(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	d, err := s.saveDraft(r, "")
	if err != nil {
		return nil, err
	}
	v, err := viewDraft(store.TxFrom(r.Context()), d)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, v}, nil
}

func (s *Server) updateDraft(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := draftID(p)
	if err != nil {
		return nil, err
	}
	d, err := s.saveDraft(r, id)
	if err != nil {
		return nil, err
	}
	return viewDraft(store.TxFrom(r.Context()), d)
}

func (s *Server) deleteDraft(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	me, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	id, err := draftID(p)
	if err != nil {
		return nil, err
	}
	if err := requests.DeleteDraft(store.TxFrom(r.Context()), id, me, s.clock().UTC()); err != nil {
		return nil, reqErr(err)
	}
	return map[string]any{"id": id, "deleted": true}, nil
}
