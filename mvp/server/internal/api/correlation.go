package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Account correlation (issue #160):
//
//	GET    /api/correlation/queue                     unlinked user accounts with proposed people
//	GET    /api/correlation/decisions                 pinned decisions
//	POST   /api/accounts/{account_id}/link            {identity_id, reason}
//	POST   /api/accounts/{account_id}/not-person      {reason}
//	DELETE /api/accounts/{account_id}/link            release the decision
//	POST   /api/identities/{identity_id}/merge        {into, reason}: merge identity_id into "into"
//	GET    /api/identity-merges                       merges, newest first
//	POST   /api/identity-merges/{merge_id}/unmerge    {reason}
//
// Decisions change whose access an account counts as, so they need
// identities.correlate (merges identities.merge) and a fresh
// phishing-resistant sign-in, and a signed-in user: the decider is recorded.

func (s *Server) registerCorrelationRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	correlate := needStepUp(auth.PermIdentitiesCorrelate, auth.StepUpPolicy)
	merge := needStepUp(auth.PermIdentitiesMerge, auth.StepUpPolicy)
	s.handle(G, "/api/correlation/queue", read, need(auth.PermGraphRead), s.correlationQueue)
	s.handle(G, "/api/correlation/decisions", read, need(auth.PermGraphRead), s.correlationDecisions)
	s.handle(P, "/api/accounts/{account_id}/link", write, correlate, s.linkAccount)
	s.handle(P, "/api/accounts/{account_id}/not-person", write, correlate, s.markNotPerson)
	s.handle(http.MethodDelete, "/api/accounts/{account_id}/link", write, correlate, s.releaseAccount)
	s.handle(P, "/api/identities/{identity_id}/merge", write, merge, s.mergeIdentity)
	s.handle(G, "/api/identity-merges", read, need(auth.PermGraphRead), s.listMerges)
	s.handle(P, "/api/identity-merges/{merge_id}/unmerge", write, merge, s.unmergeIdentity)
}

type accountView struct {
	ID         int64  `json:"id"`
	System     string `json:"system"`
	ExternalID string `json:"external_id"`
	Username   string `json:"username"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	IdentityID *int64 `json:"identity_id"`
}

func viewAccount(a *store.Account) accountView {
	return accountView{a.ID, a.System, a.ExternalID, a.Username, a.Kind, a.Status, a.IdentityID}
}

type candidateView struct {
	IdentityID int64  `json:"identity_id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Rule       string `json:"rule"`
}

type queueItemView struct {
	Account    accountView     `json:"account"`
	Candidates []candidateView `json:"candidates"`
}

type decisionView struct {
	AccountID          int64     `json:"account_id"`
	Decision           string    `json:"decision"`
	IdentityID         *int64    `json:"identity_id"`
	PreviousIdentityID *int64    `json:"previous_identity_id"`
	Reason             string    `json:"reason"`
	DecidedBy          string    `json:"decided_by"`
	DecidedAt          time.Time `json:"decided_at"`
}

func viewDecision(l *store.AccountLink) decisionView {
	return decisionView{l.AccountID, l.Decision, l.IdentityID, l.PreviousIdentityID, l.Reason, l.DecidedBy, l.DecidedAt}
}

type moveView struct {
	Table  string `json:"table"`
	ID     int64  `json:"id"`
	Column string `json:"column"`
}

func viewMoves(ms []store.MergeMove) []moveView {
	out := make([]moveView, len(ms))
	for i, m := range ms {
		out[i] = moveView{m.Table, m.ID, m.Column}
	}
	return out
}

type mergeView struct {
	ID            string     `json:"id"`
	SurvivorID    int64      `json:"survivor_id"`
	SurvivorName  string     `json:"survivor_name"`
	MergedID      int64      `json:"merged_id"`
	MergedName    string     `json:"merged_name"`
	MergedStatus  string     `json:"merged_status"`
	Moves         []moveView `json:"moves"`
	Reason        string     `json:"reason"`
	MergedBy      string     `json:"merged_by"`
	MergedAt      time.Time  `json:"merged_at"`
	UnmergeBefore time.Time  `json:"unmerge_before"`
	UnmergedBy    *string    `json:"unmerged_by"`
	UnmergedAt    *time.Time `json:"unmerged_at"`
	UnmergeReason *string    `json:"unmerge_reason"`
}

func viewMerge(c *store.TenantTx, m *store.IdentityMerge) (mergeView, error) {
	name := func(id int64) (string, error) {
		i, err := c.Identity(id)
		if err != nil {
			return "", err
		}
		return i.Name, nil
	}
	sn, err := name(m.SurvivorID)
	if err != nil {
		return mergeView{}, err
	}
	mn, err := name(m.MergedID)
	if err != nil {
		return mergeView{}, err
	}
	return mergeView{ID: m.ID, SurvivorID: m.SurvivorID, SurvivorName: sn, MergedID: m.MergedID, MergedName: mn,
		MergedStatus: m.MergedStatus, Moves: viewMoves(m.Moves), Reason: m.Reason, MergedBy: m.MergedBy,
		MergedAt: m.MergedAt, UnmergeBefore: m.MergedAt.Add(correlation.UnmergeWindow), UnmergedBy: m.UnmergedBy,
		UnmergedAt: m.UnmergedAt, UnmergeReason: m.UnmergeReason}, nil
}

// corrErr maps a refused decision to the readiness error body
// ({"error": code, "detail": msg}); returning it rolls the transaction back.
func corrErr(err error) error {
	var ce *correlation.Error
	if errors.As(err, &ce) {
		return &readiness.Error{Status: ce.Status, Code: ce.Code, Msg: ce.Msg}
	}
	return err
}

// decider is the signed-in user making a decision.
func decider(r *http.Request) (string, error) {
	pr := principal(r)
	if pr == nil || pr.UserID == nil {
		return "", &readiness.Error{Status: http.StatusForbidden, Code: "user_required",
			Msg: "correlation decisions are made by a signed-in user"}
	}
	return pr.UserID.String(), nil
}

func (s *Server) correlationQueue(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	q, err := correlation.Queue(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	out := make([]queueItemView, 0, len(q))
	for _, it := range q {
		v := queueItemView{Account: viewAccount(it.Account), Candidates: []candidateView{}}
		for _, c := range it.Candidates {
			v.Candidates = append(v.Candidates, candidateView{c.IdentityID, c.Name, c.Email, c.Rule})
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) correlationDecisions(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	links, err := store.TxFrom(r.Context()).AccountLinks()
	if err != nil {
		return nil, err
	}
	out := make([]decisionView, 0, len(links))
	for _, l := range links {
		out = append(out, viewDecision(l))
	}
	return out, nil
}

type linkBody struct {
	IdentityID int64  `json:"identity_id"`
	Reason     string `json:"reason"`
}

type reasonBody struct {
	Reason string `json:"reason"`
}

type mergeBody struct {
	Into   int64  `json:"into"`
	Reason string `json:"reason"`
}

func (s *Server) decided(r *http.Request, action string, d *correlation.Decision) (any, error) {
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	det := ojson.Object{{Key: "account_id", Value: d.Account.ID},
		{Key: "account", Value: d.Account.System + ":" + d.Account.Username},
		{Key: "decision", Value: d.Link.Decision}, {Key: "from_identity_id", Value: d.Previous},
		{Key: "to_identity_id", Value: d.Account.IdentityID}, {Key: "reason", Value: d.Link.Reason}}
	if err := c.Audit(now, principal(r).Display, action, det); err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "account", Value: viewAccount(d.Account)}, {Key: "decision", Value: viewDecision(d.Link)}}, nil
}

func (s *Server) linkAccount(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := decider(r)
	if err != nil {
		return nil, err
	}
	var b linkBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("account_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	d, err := correlation.Link(store.TxFrom(r.Context()), id, b.IdentityID, b.Reason, actor, s.clock().UTC())
	if err != nil {
		return nil, corrErr(err)
	}
	return s.decided(r, "identity.account.link", d)
}

func (s *Server) markNotPerson(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := decider(r)
	if err != nil {
		return nil, err
	}
	var b reasonBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("account_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	d, err := correlation.MarkNotPerson(store.TxFrom(r.Context()), id, b.Reason, actor, s.clock().UTC())
	if err != nil {
		return nil, corrErr(err)
	}
	return s.decided(r, "identity.account.not_person", d)
}

func (s *Server) releaseAccount(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if _, err := decider(r); err != nil {
		return nil, err
	}
	id := p.pathInt("account_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	d, err := correlation.Release(store.TxFrom(r.Context()), id)
	if err != nil {
		return nil, corrErr(err)
	}
	return s.decided(r, "identity.account.release", d)
}

func (s *Server) mergeIdentity(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := decider(r)
	if err != nil {
		return nil, err
	}
	var b mergeBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	m, err := correlation.Merge(c, uuid.NewString(), id, b.Into, b.Reason, actor, now)
	if err != nil {
		return nil, corrErr(err)
	}
	v, err := viewMerge(c, m)
	if err != nil {
		return nil, err
	}
	if err := c.Audit(now, principal(r).Display, "identity.merge", ojson.Object{{Key: "merge_id", Value: m.ID},
		{Key: "merged_id", Value: m.MergedID}, {Key: "survivor_id", Value: m.SurvivorID},
		{Key: "moves", Value: v.Moves}, {Key: "reason", Value: m.Reason}}); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Server) listMerges(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	ms, err := c.IdentityMerges()
	if err != nil {
		return nil, err
	}
	out := make([]mergeView, 0, len(ms))
	for _, m := range ms {
		v, err := viewMerge(c, m)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) unmergeIdentity(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := decider(r)
	if err != nil {
		return nil, err
	}
	var b reasonBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	id := strings.TrimSpace(p.path["merge_id"])
	res, err := correlation.Unmerge(c, id, b.Reason, actor, now)
	if err != nil {
		return nil, corrErr(err)
	}
	v, err := viewMerge(c, res.Merge)
	if err != nil {
		return nil, err
	}
	restored, kept := viewMoves(res.Restored), viewMoves(res.Kept)
	if err := c.Audit(now, principal(r).Display, "identity.unmerge", ojson.Object{{Key: "merge_id", Value: id},
		{Key: "merged_id", Value: res.Merge.MergedID}, {Key: "survivor_id", Value: res.Merge.SurvivorID},
		{Key: "restored", Value: restored}, {Key: "kept", Value: kept}, {Key: "reason", Value: *res.Merge.UnmergeReason}}); err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "merge", Value: v}, {Key: "restored", Value: restored}, {Key: "kept", Value: kept}}, nil
}
