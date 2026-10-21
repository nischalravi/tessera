package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Campaign configuration per review type (issue #298):
//
//	GET /api/review-types            every type with its settings (defaults filled in) and version
//	PUT /api/review-types/{type}     {version, enabled, reviewer_source, reviewer_id, fallback_reviewer_id,
//	                                 on_incomplete, escalation_days}: replaces one type's settings
//
// Reading needs graph.read. Changing needs reviews.manage and a fresh
// phishing-resistant sign-in, and is audited in the same transaction. A review
// schedule runs as a type through the review_type field of
// /api/reviews/schedules; its reviewers and its close-out then follow the type.

func (s *Server) registerReviewTypeRoutes() {
	s.handle(http.MethodGet, "/api/review-types", read, need(auth.PermGraphRead), s.listReviewTypes)
	s.handle(http.MethodPut, "/api/review-types/{review_type}", write, needStepUp(auth.PermReviewsManage, auth.StepUpPolicy), s.putReviewType)
}

type reviewTypeView struct {
	reviews.TypeSettings
	Label            string       `json:"label"`
	Scope            string       `json:"scope"`
	Version          int          `json:"version"`
	Reviewer         string       `json:"reviewer"` // in words, who reviews by default
	ReviewerPerson   *personBrief `json:"reviewer_person"`
	FallbackPerson   *personBrief `json:"fallback_reviewer_person"`
	Schedules        int          `json:"schedules"`
	ReviewerSources  []string     `json:"reviewer_sources"`
	IncompleteChoice []string     `json:"on_incomplete_choices"`
}

func personByID(tx *store.TenantTx, id *int64) (*personBrief, error) {
	if id == nil {
		return nil, nil
	}
	i, err := tx.Identity(*id)
	if err != nil {
		return nil, err
	}
	return &personBrief{i.ID, i.Name}, nil
}

func reviewTypeViewOf(tx *store.TenantTx, info reviews.TypeInfo, v reviews.TypeVersion, uses map[string]int) (reviewTypeView, error) {
	out := reviewTypeView{TypeSettings: v.TypeSettings, Label: info.Label, Scope: info.Scope, Version: v.Version, Reviewer: info.Reviewer,
		Schedules: uses[info.Type], ReviewerSources: []string{reviews.SourceOwner, reviews.SourceOwnerOrBackup, reviews.SourceFixed},
		IncompleteChoice: []string{reviews.IncompleteRevoke, reviews.IncompleteEscalate, reviews.IncompleteKeep}}
	var err error
	if out.ReviewerPerson, err = personByID(tx, v.ReviewerID); err != nil {
		return out, err
	}
	out.FallbackPerson, err = personByID(tx, v.FallbackID)
	return out, err
}

func (s *Server) listReviewTypes(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	all, err := reviews.LoadTypes(tx)
	if err != nil {
		return nil, err
	}
	tt, err := tx.TemplateReviewTypes()
	if err != nil {
		return nil, err
	}
	uses := map[string]int{}
	for _, t := range tt {
		uses[t.ReviewType]++
	}
	out := make([]reviewTypeView, 0, len(all))
	for i, v := range all {
		tv, err := reviewTypeViewOf(tx, reviews.Types[i], v, uses)
		if err != nil {
			return nil, err
		}
		out = append(out, tv)
	}
	return map[string]any{"types": out, "can_manage": s.can(r, auth.PermReviewsManage)}, nil
}

type reviewTypeBody struct {
	Version int `json:"version"`
	reviews.TypeSettings
}

func (s *Server) putReviewType(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b reviewTypeBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	b.TypeSettings.Type = p.path["review_type"]
	if b.OnIncomplete != reviews.IncompleteEscalate && b.EscalationDays == 0 {
		// escalation_days only matters when an incomplete review escalates; keep and revoke store the default
		b.EscalationDays = reviews.DefaultTypeSettings(b.Type).EscalationDays
	}
	tx := store.TxFrom(r.Context())
	saved, ver, err := reviews.SaveType(tx, b.TypeSettings, b.Version, principal(r).Display, s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	var info reviews.TypeInfo
	for _, ti := range reviews.Types {
		if ti.Type == saved.Type {
			info = ti
		}
	}
	return reviewTypeViewOf(tx, info, reviews.TypeVersion{TypeSettings: saved, Version: ver}, map[string]int{})
}
