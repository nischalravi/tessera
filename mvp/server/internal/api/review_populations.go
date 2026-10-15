package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Frozen review populations and auditor export (issue #110):
//
//	GET /api/reviews/campaigns/{campaign_id}/population  hash, counts, QA queue
//	GET /api/reviews/campaigns/{campaign_id}/export      ?format=csv|json (audited)
//	POST /api/reviews/qa/{qa_id}/decision                {decision, comment}
//	PUT /api/reviews/settings                            {qa_sample_pct}
//
// The export is a write route (like POST /api/simulate it answers data) so its
// review.population_exported event commits with the response.
func (s *Server) registerReviewPopulationRoutes() {
	s.handle(http.MethodGet, "/api/reviews/campaigns/{campaign_id}/population", read, need(auth.PermGraphRead), s.campaignPopulation)
	s.handle(http.MethodGet, "/api/reviews/campaigns/{campaign_id}/export", write, need(auth.PermReviewsExport), s.campaignExport)
	s.handle(http.MethodPost, "/api/reviews/qa/{qa_id}/decision", write, needStepUp(auth.PermReviewsDecide, auth.StepUpPolicy), s.qaDecide)
	s.handle(http.MethodPut, "/api/reviews/settings", write, need(auth.PermReviewsManage), s.putReviewSettings)
}

// populationErr maps the reviews package's errors to HTTP statuses.
func populationErr(err error) error {
	var re *reviews.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errStatus(http.StatusNotFound, "campaign not found")
	case errors.Is(err, reviews.ErrNoPopulation):
		return errStatus(http.StatusNotFound, reviews.ErrNoPopulation.Msg)
	case errors.As(err, &re):
		return errStatus(http.StatusBadRequest, re.Msg)
	}
	return err
}

func (s *Server) campaignPopulation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("campaign_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	v, err := reviews.PopulationView(store.TxFrom(r.Context()), id, s.clock())
	if err != nil {
		return nil, populationErr(err)
	}
	return v, nil
}

func (s *Server) campaignExport(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("campaign_id")
	format := p.queryOptLiteral("format", []string{"csv", "json"})
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	f := "json"
	if format != nil {
		f = *format
	}
	c := store.TxFrom(r.Context())
	now := s.clock()
	e, err := reviews.BuildExport(c, id, now)
	if err != nil {
		return nil, populationErr(err)
	}
	if err := c.Audit(now, principal(r).User().Display, "review.population_exported", ojson.Object{
		{Key: "campaign_id", Value: id}, {Key: "format", Value: f}, {Key: "population_hash", Value: e.Population.PopulationHash},
		{Key: "hash_match", Value: e.HashMatch()}, {Key: "rows", Value: len(e.Rows)}}); err != nil {
		return nil, err
	}
	name := "tessera-review-population-" + strconv.FormatInt(id, 10) + "." + f
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if f == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		return nil, e.WriteCSV(w)
	}
	doc, err := e.JSON()
	if err != nil {
		return nil, err
	}
	return doc, nil
}

var qaDecisionFields = []field{
	{name: "decision", kind: kLiteral, required: true, lits: []string{"keep", "revoke"}},
	{name: "comment", kind: kStr, nullable: true, def: nil},
}

func (s *Server) qaDecide(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("qa_id")
	body, berrs, err := bodyModel(r, qaDecisionFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	var comment *string
	if v, ok := body["comment"].(string); ok {
		comment = &v
	}
	ad, err := reviews.QADecide(store.TxFrom(r.Context()), s.clock(), id, body["decision"].(string), principal(r).User(), comment)
	if err != nil {
		return nil, populationErr(err)
	}
	return ojson.Object{{Key: "id", Value: ad.ID}, {Key: "qa_decision", Value: ad.QADecision},
		{Key: "overturned", Value: ad.Overturned}}, nil
}

var reviewSettingsFields = []field{{name: "qa_sample_pct", kind: kInt, required: true}}

func (s *Server) putReviewSettings(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, reviewSettingsFields, true)
	if err != nil {
		return nil, err
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	pct := body["qa_sample_pct"].(int64)
	if err := reviews.SetQASamplePct(store.TxFrom(r.Context()), s.clock(), int(pct), principal(r).User()); err != nil {
		return nil, populationErr(err)
	}
	return ojson.Object{{Key: "qa_sample_pct", Value: pct}}, nil
}
