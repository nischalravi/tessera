package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/questionnaires"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/svcaccounts"
)

// Questionnaires (issue #298): forms asked of requesters and reviewers.
//
//	GET  /api/questionnaires                    every questionnaire at its current version (catalog.manage)
//	POST /api/questionnaires                    {title, description, questions}: version 1
//	GET  /api/questionnaires/needed             what must be answered: ?catalog_item_ids=a,b | ?role_id= | ?review_item_id= | ?review_campaign_id= |
//	                                            ?service_account_kind=create|change|transfer&primary_owner_id=&system=&identity_id= (what its workflow asks)
//	GET  /api/questionnaires/{id}               one, with its earlier versions (catalog.manage)
//	PUT  /api/questionnaires/{id}               {version, title, description, questions}: appends the next version
//	POST /api/questionnaires/{id}/retire        stops it being asked; its answers stay
//	PUT  /api/questionnaires/{id}/attachments   {targets: [{kind, target_id}]}: where it is asked
//
// Creating, editing, retiring and attaching need catalog.manage and are audited in the same
// transaction. "needed" is open to anyone who can request (the request form and the review panel
// read it). Answers travel with the request (POST /api/requests and /api/role-requests: "answers")
// or the review decision ("answers"), and the server validates them against the version in force.

func (s *Server) registerQuestionnaireRoutes() {
	const G, P, PU = http.MethodGet, http.MethodPost, http.MethodPut
	manage := need(auth.PermCatalogManage)
	s.handle(G, "/api/questionnaires", read, manage, s.listQuestionnaires)
	s.handle(P, "/api/questionnaires", write, manage, s.createQuestionnaire)
	// a literal segment, so it comes before {id}: the first registered route that matches wins
	s.handle(G, "/api/questionnaires/needed", read, need(auth.PermRequestsCreate), s.neededQuestionnaires)
	s.handle(G, "/api/questionnaires/{id}", read, manage, s.getQuestionnaire)
	s.handle(PU, "/api/questionnaires/{id}", write, manage, s.editQuestionnaire)
	s.handle(P, "/api/questionnaires/{id}/retire", write, manage, s.retireQuestionnaire)
	s.handle(PU, "/api/questionnaires/{id}/attachments", write, manage, s.attachQuestionnaire)
}

// qErr gives a questionnaire refusal its status and code.
func qErr(err error) error {
	var qe *questionnaires.Error
	if errors.As(err, &qe) {
		return &readiness.Error{Status: qe.Status, Code: qe.Code, Msg: qe.Msg}
	}
	return err
}

func questionnaireID(p *params) (string, error) {
	id := strings.TrimSpace(p.path["id"])
	if !idRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "questionnaire_not_found", Msg: "questionnaire not found"}
	}
	return id, nil
}

type questionnaireList struct {
	Questionnaires []*questionnaires.Definition `json:"questionnaires"`
	Types          []string                     `json:"types"`
	Limits         map[string]int               `json:"limits"`
}

func (s *Server) listQuestionnaires(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	ds, err := questionnaires.List(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return questionnaireList{Questionnaires: ds, Types: questionnaires.Types, Limits: map[string]int{
		"questions": questionnaires.MaxQuestions, "title": questionnaires.MaxTitle, "question_text": questionnaires.MaxQuestionText,
		"options": questionnaires.MaxOptions, "option_text": questionnaires.MaxOptionText, "short_text": questionnaires.CapShortText,
		"long_text": questionnaires.CapLongText}}, nil
}

func (s *Server) createQuestionnaire(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b questionnaires.Spec
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	d, err := questionnaires.Create(store.TxFrom(r.Context()), b, actor(r), s.clock().UTC())
	if err != nil {
		return nil, qErr(err)
	}
	return statusBody{http.StatusCreated, d}, nil
}

type questionnaireDetail struct {
	*questionnaires.Definition
	Versions []questionnaireVersion `json:"versions"`
}

type questionnaireVersion struct {
	Version int `json:"version"`
	questionnaires.Spec
}

func (s *Server) getQuestionnaire(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := questionnaireID(p)
	if err != nil {
		return nil, err
	}
	return s.questionnaireDetail(store.TxFrom(r.Context()), id)
}

func (s *Server) questionnaireDetail(tx *store.TenantTx, id string) (any, error) {
	d, err := questionnaires.Get(tx, id)
	if err != nil {
		return nil, qErr(err)
	}
	specs, nums, err := questionnaires.Versions(tx, id)
	if err != nil {
		return nil, qErr(err)
	}
	out := questionnaireDetail{Definition: d, Versions: make([]questionnaireVersion, len(specs))}
	for i := range specs {
		out.Versions[i] = questionnaireVersion{nums[i], specs[i]}
	}
	return out, nil
}

type editQuestionnaireBody struct {
	Version int `json:"version"`
	questionnaires.Spec
}

func (s *Server) editQuestionnaire(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := questionnaireID(p)
	if err != nil {
		return nil, err
	}
	var b editQuestionnaireBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if _, err := questionnaires.Edit(tx, id, b.Version, b.Spec, actor(r), s.clock().UTC()); err != nil {
		return nil, qErr(err)
	}
	return s.questionnaireDetail(tx, id)
}

func (s *Server) retireQuestionnaire(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := questionnaireID(p)
	if err != nil {
		return nil, err
	}
	d, err := questionnaires.Retire(store.TxFrom(r.Context()), id, actor(r), s.clock().UTC())
	return d, qErr(err)
}

type attachBody struct {
	Targets []questionnaires.Target `json:"targets"`
}

func (s *Server) attachQuestionnaire(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := questionnaireID(p)
	if err != nil {
		return nil, err
	}
	var b attachBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	d, err := questionnaires.SetTargets(store.TxFrom(r.Context()), id, b.Targets, actor(r), s.clock().UTC())
	return d, qErr(err)
}

// neededView is what the request form and the review panel render.
type neededView struct {
	Questionnaires []questionnaires.Need `json:"questionnaires"`
}

func (s *Server) neededQuestionnaires(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	out := neededView{Questionnaires: []questionnaires.Need{}}
	var lists [][]questionnaires.Need
	add := func(n []questionnaires.Need, err error) error {
		lists = append(lists, n)
		return err
	}
	missing := &readiness.Error{Status: http.StatusNotFound, Code: "target_not_found", Msg: "not found"}
	if ids := qs(p, "catalog_item_ids"); ids != "" {
		parts := strings.Split(ids, ",")
		if len(parts) > 50 {
			return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "too_many_items", Msg: "at most 50 items"}
		}
		for _, id := range parts {
			if id = strings.TrimSpace(id); !idRE.MatchString(id) {
				return nil, missing
			}
			if err := add(questionnaires.ForItem(tx, id)); errors.Is(err, store.ErrNotFound) {
				return nil, missing
			} else if err != nil {
				return nil, err
			}
		}
	}
	if id := qs(p, "role_id"); id != "" {
		if err := add(questionnaires.ForRole(tx, id)); errors.Is(err, store.ErrNotFound) {
			return nil, missing
		} else if err != nil {
			return nil, err
		}
	}
	if raw := qs(p, "review_item_id"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			return nil, missing
		}
		it, err := tx.Item(n)
		if errors.Is(err, store.ErrNotFound) {
			return nil, missing
		} else if err != nil {
			return nil, err
		}
		if err := add(questionnaires.ForCampaign(tx, it.CampaignID)); err != nil {
			return nil, err
		}
	}
	if raw := qs(p, "review_campaign_id"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			return nil, missing
		}
		if _, err := tx.Campaign(n); errors.Is(err, store.ErrNotFound) {
			return nil, missing
		} else if err != nil {
			return nil, err
		}
		if err := add(questionnaires.ForCampaign(tx, n)); err != nil {
			return nil, err
		}
	}
	if kind := qs(p, "service_account_kind"); kind != "" { // what a service-account request's workflow asks (issue #298)
		owner, err := strconv.ParseInt(qs(p, "primary_owner_id"), 10, 64)
		if err != nil || owner < 1 {
			return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "primary_owner_required", Msg: "primary_owner_id names the new primary owner"}
		}
		var identity *int64
		if raw := qs(p, "identity_id"); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n < 1 {
				return nil, missing
			}
			identity = &n
		}
		me, err := s.requestActor(r)
		if err != nil {
			return nil, err
		}
		if err := add(svcaccounts.Needs(tx, kind, qs(p, "system"), identity, owner, me.UserID.String())); err != nil {
			return nil, reqErr(err)
		}
	}
	out.Questionnaires = append(out.Questionnaires, questionnaires.Union(lists...)...)
	return out, nil
}
