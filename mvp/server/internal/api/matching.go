package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/merge"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Identity matching, the review queue and four-eyes merges (guest accounts
// design §5.6, §9.2, issue #68). Colon actions are not used: like the rest of
// the API, an action is a path segment.
//
//	GET  /api/identity-matches?status=review     the queue: one item per intake with the candidates the matcher found
//	                                             (status: review (default), reverification, decided, all; limit)
//	POST /api/identity-matches/{match_id}/decide {decision: link|new_person|reject, reason}
//	GET  /api/identity-merge-requests?status=    merges and links waiting for a second reviewer (default pending)
//	POST /api/identity-merge-requests/{merge_request_id}/approve {}        a reviewer other than the requester
//	POST /api/identity-merge-requests/{merge_request_id}/reject  {reason}  anyone with the permission; the requester withdraws it
//	GET|PUT /api/admin/matching                  {auto_link_tier_b, require_review_tier_a, unmerge_window_days}
//
// The queue shows masked attributes (a name's first letters, an address's
// first letter and domain), the rules that fired, and for each candidate the
// affiliations, whether they hold privileged access, their IAL and why a second
// reviewer is needed. Decisions change who a person is and what they can reach,
// so they need identity_matches.review and a fresh phishing-resistant sign-in.

func (s *Server) registerMatchingRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	review := needStepUp(auth.PermIdentityMatchesReview, auth.StepUpPolicy)
	approve := needStepUp(auth.PermIdentitiesMerge, auth.StepUpPolicy)
	s.handle(G, "/api/identity-matches", read, need(auth.PermIdentityMatchesReview), s.listMatches)
	s.handle(P, "/api/identity-matches/{match_id}/decide", write, review, s.decideMatch)
	s.handle(G, "/api/identity-merge-requests", read, need(auth.PermIdentitiesMerge), s.listMergeRequests)
	s.handle(P, "/api/identity-merge-requests/{merge_request_id}/approve", write, approve, s.approveMergeRequest)
	s.handle(P, "/api/identity-merge-requests/{merge_request_id}/reject", write, approve, s.rejectMergeRequest)
	s.handle(G, "/api/admin/matching", read, need(auth.PermMatchingConfigure), s.getMatchingSettings)
	s.handle(http.MethodPut, "/api/admin/matching", write, needStepUp(auth.PermMatchingConfigure, auth.StepUpPolicy), s.putMatchingSettings)
}

// ---------------------------------------------------------------- views

type mergeRequestView struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Status         string     `json:"status"`
	Survivor       personRef  `json:"survivor"`
	Merged         personRef  `json:"merged"`
	MatchID        *string    `json:"match_id"`
	Reason         string     `json:"reason"`
	Risk           []string   `json:"risk"`
	RequestedBy    userRef    `json:"requested_by"`
	RequestedAt    time.Time  `json:"requested_at"`
	DecidedBy      *userRef   `json:"decided_by"`
	DecidedAt      *time.Time `json:"decided_at"`
	DecisionReason *string    `json:"decision_reason"`
	MergeID        *string    `json:"merge_id"`
}

func viewMergeRequest(v *viewer, q *store.MergeRequest) (mergeRequestView, error) {
	sv, err := v.person(q.SurvivorID)
	if err != nil {
		return mergeRequestView{}, err
	}
	mg, err := v.person(q.MergedID)
	if err != nil {
		return mergeRequestView{}, err
	}
	risk := []string{}
	_ = json.Unmarshal([]byte(q.Risk), &risk)
	out := mergeRequestView{ID: q.ID, Kind: q.Kind, Status: q.Status, Survivor: sv, Merged: mg, MatchID: q.MatchID, Reason: q.Reason,
		Risk: risk, RequestedBy: v.user(q.RequestedBy), RequestedAt: q.RequestedAt, DecidedAt: q.DecidedAt,
		DecisionReason: q.DecisionReason, MergeID: q.MergeID}
	if q.DecidedBy != nil {
		u := v.user(*q.DecidedBy)
		out.DecidedBy = &u
	}
	return out, nil
}

type affView struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Source string `json:"source"`
}

type matchCandidateView struct {
	MatchID        string            `json:"match_id"`
	CandidateID    int64             `json:"candidate_id"`
	Name           string            `json:"name"`  // masked
	Email          *string           `json:"email"` // masked
	Type           string            `json:"type"`
	Tier           string            `json:"tier"`
	Score          float64           `json:"score"`
	Outcome        string            `json:"outcome"`
	Status         string            `json:"status"`
	Decision       *string           `json:"decision"`
	Rules          []match.Fired     `json:"rules"`
	Affiliations   []affView         `json:"affiliations"`
	Privileged     bool              `json:"privileged_access"`
	IAL            int               `json:"ial"`
	Employee       bool              `json:"employee"`
	SecondReviewer []string          `json:"second_reviewer_because"` // why a link needs a second reviewer; empty: it does not
	Reverification bool              `json:"reverification_required"`
	DecidedBy      *userRef          `json:"decided_by"`
	SecondBy       *userRef          `json:"second_reviewer"`
	Reason         *string           `json:"reason"`
	DecidedAt      *time.Time        `json:"decided_at"`
	Pending        *mergeRequestView `json:"pending_request"`
	MergeID        *string           `json:"merge_id"`
}

type matchSubjectView struct {
	IdentityID  *int64     `json:"identity_id"`
	Name        string     `json:"name"`  // masked
	Email       *string    `json:"email"` // masked
	Population  *string    `json:"population"`
	Purpose     *string    `json:"purpose"`
	Sponsor     *personRef `json:"sponsor"`
	Sponsorship *string    `json:"sponsorship_id"`
}

type matchItemView struct {
	ID              string               `json:"id"` // the best candidate's match id; decide accepts any candidate's
	IntakeID        string               `json:"intake_id"`
	Channel         string               `json:"channel"`
	Mode            string               `json:"mode"`
	Status          string               `json:"status"`
	ReceivedAt      time.Time            `json:"received_at"`
	ExistingAccount *string              `json:"claimant_says_has_account"` // the claimant's own answer; it never links anyone
	Subject         matchSubjectView     `json:"subject"`
	Candidates      []matchCandidateView `json:"candidates"`
}

func maskedEmail(e *string) *string {
	if e == nil || *e == "" {
		return nil
	}
	m := match.MaskEmail(*e)
	return &m
}

// matchItems renders the results, grouped by intake, in the order they first appear.
func (s *Server) matchItems(c *store.TenantTx, now time.Time, rows []*store.MatchResult) ([]matchItemView, error) {
	v, as := newViewer(c), merge.NewAssessor(c, now)
	var order []string
	byIntake := map[string][]*store.MatchResult{}
	for _, r := range rows {
		if _, ok := byIntake[r.IntakeID]; !ok {
			order = append(order, r.IntakeID)
		}
		byIntake[r.IntakeID] = append(byIntake[r.IntakeID], r)
	}
	out := make([]matchItemView, 0, len(order))
	for _, id := range order {
		rs := byIntake[id]
		in, err := c.Intake(id)
		if err != nil {
			return nil, err
		}
		item := matchItemView{IntakeID: id, Channel: in.Channel, Mode: in.MatchMode, Status: in.Status, ReceivedAt: in.CreatedAt,
			ExistingAccount: in.ExistingAccount, Candidates: []matchCandidateView{}}
		var subject *int64
		for _, r := range rs {
			if r.SubjectID != nil {
				subject = r.SubjectID
			}
		}
		if item.Subject, err = s.matchSubject(c, in, subject, rs); err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.CandidateID == nil {
				continue
			}
			cv, err := s.matchCandidate(c, v, as, r, subject)
			if err != nil {
				return nil, err
			}
			item.Candidates = append(item.Candidates, cv)
		}
		if len(item.Candidates) == 0 {
			continue // a "no match" record: nothing to decide
		}
		item.ID = item.Candidates[0].MatchID
		out = append(out, item)
	}
	return out, nil
}

func (s *Server) matchSubject(c *store.TenantTx, in *store.IntakeRecord, subject *int64, rs []*store.MatchResult) (matchSubjectView, error) {
	out := matchSubjectView{IdentityID: subject}
	if subject == nil {
		return out, nil
	}
	who, err := c.Identity(*subject)
	if err != nil {
		return out, err
	}
	out.Name, out.Email = match.MaskName(who.Name), maskedEmail(who.Email)
	// the sponsorship of the intake: with the provisional person, or with whoever it was linked into
	holders := []int64{*subject}
	for _, r := range rs {
		if r.CandidateID != nil {
			holders = append(holders, *r.CandidateID)
		}
	}
	for _, h := range holders {
		all, err := c.Sponsorships(store.SponsorshipFilter{Guest: h})
		if err != nil {
			return out, err
		}
		for _, ss := range all {
			if ss.IntakeID != in.ID {
				continue
			}
			sp, err := c.Identity(ss.SponsorIdentityID)
			if err != nil {
				return out, err
			}
			pop, purpose, id := ss.Population, ss.Purpose, ss.ID
			out.Population, out.Purpose, out.Sponsorship = &pop, &purpose, &id
			out.Sponsor = &personRef{sp.ID, sp.Name, sp.Type, sp.Status}
			return out, nil
		}
	}
	return out, nil
}

func (s *Server) matchCandidate(c *store.TenantTx, v *viewer, as *merge.Assessor, r *store.MatchResult, subject *int64) (matchCandidateView, error) {
	who, err := c.Identity(*r.CandidateID)
	if err != nil {
		return matchCandidateView{}, err
	}
	cv := matchCandidateView{MatchID: r.ID, CandidateID: who.ID, Name: match.MaskName(who.Name), Email: maskedEmail(who.Email), Type: who.Type,
		Tier: r.Tier, Score: r.Score, Outcome: r.Outcome, Status: r.Status, Decision: r.Decision, Reason: r.Reason, DecidedAt: r.DecidedAt,
		Rules: []match.Fired{}, Affiliations: []affView{}, SecondReviewer: []string{}, MergeID: r.MergeID,
		Reverification: r.Status == store.MatchReverification}
	var doc struct {
		Rules []match.Fired `json:"rules"`
	}
	if json.Unmarshal([]byte(r.Rules), &doc) == nil && doc.Rules != nil {
		cv.Rules = doc.Rules
		for i := range cv.Rules {
			if cv.Rules[i].Compared == nil {
				cv.Rules[i].Compared = map[string]string{}
			}
		}
	}
	affs, err := c.AffiliationsFor(who.ID)
	if err != nil {
		return cv, err
	}
	for _, a := range affs {
		cv.Affiliations = append(cv.Affiliations, affView{a.Type, a.Status, a.Source})
	}
	f, err := as.Facts(who.ID)
	if err != nil {
		return cv, err
	}
	cv.Privileged, cv.IAL, cv.Employee = f.Privileged, f.IAL, f.Employee
	if r.Status == store.MatchReview || r.Status == store.MatchReverification {
		ids := []int64{who.ID}
		if subject != nil {
			ids = append(ids, *subject)
		}
		if risk, err := as.Risk(ids...); err != nil {
			return cv, err
		} else if len(risk) > 0 {
			cv.SecondReviewer = risk
		}
	}
	if r.DecidedBy != nil {
		u := v.user(*r.DecidedBy)
		cv.DecidedBy = &u
	}
	if r.SecondReviewer != nil {
		u := v.user(*r.SecondReviewer)
		cv.SecondBy = &u
	}
	if subject != nil && r.Status == store.MatchReview {
		if q, err := c.PendingMergeRequestFor(*subject); err == nil && q.MatchID != nil && *q.MatchID == r.ID {
			qv, err := viewMergeRequest(v, q)
			if err != nil {
				return cv, err
			}
			cv.Pending = &qv
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return cv, err
		}
	}
	return cv, nil
}

// ---------------------------------------------------------------- queue

func (s *Server) listMatches(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	status := p.queryOptLiteral("status", []string{"review", "reverification", "decided", "all"})
	limit := p.queryInt("limit", 100, ptr(int64(1)), ptr(int64(500)))
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	want := "review"
	if status != nil {
		want = *status
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	var rows []*store.MatchResult
	var err error
	switch want {
	case "review", "reverification":
		rows, err = c.MatchResults(store.MatchFilter{Status: want})
	default:
		if rows, err = c.MatchResults(store.MatchFilter{}); err == nil && want == "decided" {
			rows = slices.DeleteFunc(rows, func(r *store.MatchResult) bool {
				return r.Status == store.MatchReview || r.Status == store.MatchReverification
			})
		}
	}
	if err != nil {
		return nil, err
	}
	// the siblings of an item (its other candidates) belong to it whatever their own status
	if want == "review" || want == "reverification" {
		all, err := c.MatchResults(store.MatchFilter{})
		if err != nil {
			return nil, err
		}
		keep := map[string]bool{}
		for _, r := range rows {
			keep[r.IntakeID] = true
		}
		rows = slices.DeleteFunc(all, func(r *store.MatchResult) bool {
			return !keep[r.IntakeID] || r.Status != store.MatchReview && r.Status != store.MatchReverification
		})
	}
	items, err := s.matchItems(c, now, rows)
	if err != nil {
		return nil, err
	}
	if int64(len(items)) > limit {
		items = items[:limit]
	}
	return ojson.Object{{Key: "items", Value: items}, {Key: "count", Value: len(items)}}, nil
}

func ptr[T any](v T) *T { return &v }

type decideBody struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// rejectIntake is what rejecting an intake does beyond the decision: the
// sponsorships of the provisional person end, which revokes the invitation.
func (s *Server) rejectIntake(actor merge.Actor, identity *int64) func(*store.TenantTx, string, *int64, string, time.Time) error {
	return func(tx *store.TenantTx, intakeID string, subject *int64, reason string, now time.Time) error {
		if subject == nil {
			return nil
		}
		all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: *subject})
		if err != nil {
			return err
		}
		by := sponsorship.Actor{Display: actor.Display, IdentityID: identity, Approver: true}
		if uid, err := uuid.Parse(actor.UserID); err == nil {
			by.UserID = uid
		}
		for _, ss := range all {
			if ss.IntakeID != intakeID {
				continue
			}
			switch ss.Status {
			case store.SponsorActive, store.SponsorTransferPending, store.SponsorPendingApproval:
				if _, err := s.guests.End(tx, by, ss.ID, "intake rejected: "+reason, now); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func (s *Server) decideMatch(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := mergeActor(r)
	if err != nil {
		return nil, err
	}
	var b decideBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.path["match_id"]
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	d, err := merge.Decide(c, id, b.Decision, b.Reason, actor, merge.Hooks{RejectIntake: s.rejectIntake(actor, nil)}, now)
	if err != nil {
		return nil, corrErr(err)
	}
	rows, err := c.MatchResults(store.MatchFilter{Intake: d.Match.IntakeID})
	if err != nil {
		return nil, err
	}
	items, err := s.matchItems(c, now, rows)
	if err != nil {
		return nil, err
	}
	out := ojson.Object{{Key: "result", Value: d.Match.Status}}
	if len(items) > 0 {
		out = append(out, ojson.KV{Key: "item", Value: items[0]})
	}
	status := http.StatusOK
	if o := d.Outcome; o != nil {
		switch {
		case o.Pending != nil:
			qv, err := viewMergeRequest(newViewer(c), o.Pending)
			if err != nil {
				return nil, err
			}
			out[0].Value = "pending_approval"
			out = append(out, ojson.KV{Key: "request", Value: qv})
			status = http.StatusAccepted
		case o.Reverification:
			out[0].Value = "reverification_required"
		case o.Merge != nil:
			mv, err := viewMerge(c, o.Merge)
			if err != nil {
				return nil, err
			}
			out = append(out, ojson.KV{Key: "merge", Value: mv})
		}
	}
	if status != http.StatusOK {
		return statusBody{status, out}, nil
	}
	return out, nil
}

// ---------------------------------------------------------------- merge requests

func (s *Server) listMergeRequests(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	status := p.queryOptLiteral("status", []string{"pending", "approved", "rejected", "cancelled", "all"})
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	want := "pending"
	if status != nil {
		want = *status
	}
	if want == "all" {
		want = ""
	}
	c := store.TxFrom(r.Context())
	qs, err := c.MergeRequests(want)
	if err != nil {
		return nil, err
	}
	v := newViewer(c)
	out := make([]mergeRequestView, 0, len(qs))
	for _, q := range qs {
		qv, err := viewMergeRequest(v, q)
		if err != nil {
			return nil, err
		}
		out = append(out, qv)
	}
	return ojson.Object{{Key: "items", Value: out}, {Key: "count", Value: len(out)}}, nil
}

func (s *Server) approveMergeRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := mergeActor(r)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	out, err := merge.Approve(c, p.path["merge_request_id"], actor, now)
	if err != nil {
		return nil, corrErr(err)
	}
	qv, err := viewMergeRequest(newViewer(c), out.Pending)
	if err != nil {
		return nil, err
	}
	res := ojson.Object{{Key: "request", Value: qv}}
	switch {
	case out.Reverification:
		res = append(res, ojson.KV{Key: "result", Value: "reverification_required"})
	case out.Merge != nil:
		mv, err := viewMerge(c, out.Merge)
		if err != nil {
			return nil, err
		}
		res = append(res, ojson.KV{Key: "result", Value: "merged"}, ojson.KV{Key: "merge", Value: mv})
	}
	return res, nil
}

func (s *Server) rejectMergeRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := mergeActor(r)
	if err != nil {
		return nil, err
	}
	var b reasonBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	q, err := merge.Reject(c, p.path["merge_request_id"], actor, b.Reason, now)
	if err != nil {
		return nil, corrErr(err)
	}
	qv, err := viewMergeRequest(newViewer(c), q)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "request", Value: qv}}, nil
}

// ---------------------------------------------------------------- settings

type matchingSettingsView struct {
	AutoLinkTierB      bool       `json:"auto_link_tier_b"`
	RequireReviewTierA bool       `json:"require_review_tier_a"`
	UnmergeWindowDays  int        `json:"unmerge_window_days"`
	UpdatedBy          *userRef   `json:"updated_by"`
	UpdatedAt          *time.Time `json:"updated_at"`
}

func viewSettings(v *viewer, st store.MatchingSettings) matchingSettingsView {
	out := matchingSettingsView{st.AutoLinkTierB, st.RequireReviewTierA, st.UnmergeWindowDays, nil, st.UpdatedAt}
	if st.UpdatedBy != nil {
		u := v.user(*st.UpdatedBy)
		out.UpdatedBy = &u
	}
	return out
}

func (s *Server) getMatchingSettings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	st, err := c.MatchingSettings()
	if err != nil {
		return nil, err
	}
	return viewSettings(newViewer(c), st), nil
}

type putMatchingBody struct {
	AutoLinkTierB      bool `json:"auto_link_tier_b"`
	RequireReviewTierA bool `json:"require_review_tier_a"`
	UnmergeWindowDays  int  `json:"unmerge_window_days"`
}

func (s *Server) putMatchingSettings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	actor, err := mergeActor(r)
	if err != nil {
		return nil, err
	}
	var b putMatchingBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.UnmergeWindowDays < 1 || b.UnmergeWindowDays > 3650 {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_window", Msg: "unmerge_window_days is 1 to 3650"}
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	old, err := c.MatchingSettings()
	if err != nil {
		return nil, err
	}
	st := store.MatchingSettings{AutoLinkTierB: b.AutoLinkTierB, RequireReviewTierA: b.RequireReviewTierA,
		UnmergeWindowDays: b.UnmergeWindowDays}
	if err := c.PutMatchingSettings(st, actor.UserID, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor.Display, "identity.matching.configure", ojson.Object{
		{Key: "auto_link_tier_b", Value: ojson.Object{{Key: "from", Value: old.AutoLinkTierB}, {Key: "to", Value: st.AutoLinkTierB}}},
		{Key: "require_review_tier_a", Value: ojson.Object{{Key: "from", Value: old.RequireReviewTierA}, {Key: "to", Value: st.RequireReviewTierA}}},
		{Key: "unmerge_window_days", Value: ojson.Object{{Key: "from", Value: old.UnmergeWindowDays}, {Key: "to", Value: st.UnmergeWindowDays}}}}); err != nil {
		return nil, err
	}
	got, err := c.MatchingSettings()
	if err != nil {
		return nil, err
	}
	return viewSettings(newViewer(c), got), nil
}
