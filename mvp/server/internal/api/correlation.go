package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/merge"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Account correlation (issue #160):
//
//	GET    /api/correlation/queue                     unlinked user accounts with proposed people
//	GET    /api/correlation/decisions                 pinned decisions
//	POST   /api/accounts/{account_id}/link            {identity_id, reason}: needs two admins (202 pending_second_admin, see accountLinkGate)
//	POST   /api/accounts/{account_id}/not-person      {reason}
//	DELETE /api/accounts/{account_id}/link            release the decision: needs two admins too
//	GET    /api/correlation/link-requests             pins and releases waiting for a second admin
//	DELETE /api/correlation/link-requests/{account_id}  the requester withdraws a pending request
//	POST   /api/identities/{identity_id}/merge        {into, reason}: merge identity_id into "into" (202 and a request when a second reviewer is needed, see matching.go)
//	GET    /api/identity-merges                       merges, newest first
//	POST   /api/identity-merges/{merge_id}/unmerge    {reason}: restores the moves; lists what was created since (created_after)
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
	s.handle(G, "/api/correlation/link-requests", read, correlate, s.listAccountLinkRequests)
	s.handle(http.MethodDelete, "/api/correlation/link-requests/{account_id}", write, correlate, s.cancelAccountLinkRequest)
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
	Key    string `json:"key,omitempty"` // the row's id where it is text (the guest tables)
	Column string `json:"column"`
}

func viewMoves(ms []store.MergeMove) []moveView {
	out := make([]moveView, len(ms))
	for i, m := range ms {
		out[i] = moveView{m.Table, m.ID, m.Key, m.Column}
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
	window, err := merge.Window(c)
	if err != nil {
		return mergeView{}, err
	}
	return mergeView{ID: m.ID, SurvivorID: m.SurvivorID, SurvivorName: sn, MergedID: m.MergedID, MergedName: mn,
		MergedStatus: m.MergedStatus, Moves: viewMoves(m.Moves), Reason: m.Reason, MergedBy: m.MergedBy,
		MergedAt: m.MergedAt, UnmergeBefore: m.MergedAt.Add(window), UnmergedBy: m.UnmergedBy,
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

func (s *Server) decided(r *http.Request, action string, d *correlation.Decision, extra ...ojson.KV) (any, error) {
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	det := ojson.Object{{Key: "account_id", Value: d.Account.ID},
		{Key: "account", Value: d.Account.System + ":" + d.Account.Username},
		{Key: "decision", Value: d.Link.Decision}, {Key: "from_identity_id", Value: d.Previous},
		{Key: "to_identity_id", Value: d.Account.IdentityID}, {Key: "reason", Value: d.Link.Reason}}
	det = append(det, extra...)
	if err := c.Audit(now, principal(r).Display, action, det); err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "account", Value: viewAccount(d.Account)}, {Key: "decision", Value: viewDecision(d.Link)}}, nil
}

// accountLinkWindow is how long a pin or release waits for its second admin.
const accountLinkWindow = 72 * time.Hour

// accountLinkGate is the four-eyes step of a pin or release (issue #376, the
// pattern of #357 for platform users). The caller has already validated the
// change. It answers one of:
//
//   - a pending request that matches (same action, same identity, made
//     against the account's current identity, not expired, by another admin):
//     the caller applies the change and must delete the request (matched);
//   - 403 four_eyes_required: the same admin repeats their own request;
//   - a 202 pending_second_admin body: no matching request, so this one is
//     stored, replacing any other pending one for the account (the first
//     admin's request is never applied by a differing second request).
func (s *Server) accountLinkGate(r *http.Request, c *store.TenantTx, now time.Time, a *store.Account, action string,
	identityID *int64, reason string) (matched *store.AccountLinkRequest, pending any, err error) {
	by := principal(r).User()
	pend, err := c.AccountLinkRequest(a.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	m := pend != nil && now.Before(pend.ExpiresAt) && pend.Action == action &&
		sameLink(pend.PreviousIdentityID, a.IdentityID) && sameLink(pend.IdentityID, identityID)
	same := false
	if m {
		if same, err = sameActor(c, pend.RequestedByUserID, by.ID); err != nil {
			return nil, nil, err
		}
	}
	switch {
	case m && same:
		return nil, nil, &readiness.Error{Status: http.StatusForbidden, Code: "four_eyes_required",
			Msg: "this account change needs a second admin: another admin with identities.correlate must make the same request"}
	case m:
		return pend, nil, nil
	}
	req := &store.AccountLinkRequest{AccountID: a.ID, Action: action, IdentityID: identityID, PreviousIdentityID: a.IdentityID,
		Reason: reason, RequestedByUserID: by.ID, RequestedBy: by.Display, RequestedAt: now, ExpiresAt: now.Add(accountLinkWindow)}
	if err := c.PutAccountLinkRequest(req); err != nil {
		return nil, nil, err
	}
	det := ojson.Object{{Key: "account_id", Value: a.ID}, {Key: "account", Value: a.System + ":" + a.Username},
		{Key: "action", Value: action}, {Key: "identity_id", Value: identityID},
		{Key: "from_identity_id", Value: a.IdentityID}, {Key: "reason", Value: reason}, {Key: "expires_at", Value: req.ExpiresAt}}
	if err := c.Audit(now, by.Display, "identity.account."+action+"_requested", det); err != nil {
		return nil, nil, err
	}
	return nil, statusBody{http.StatusAccepted, ojson.Object{{Key: "status", Value: "pending_second_admin"},
		{Key: "request", Value: viewAccountLinkRequest(req)}}}, nil
}

// sameActor reports whether two platform users are the same admin: the same
// user, or two users linked to the same identity (one person can hold a
// sign-in user per IdP connection). A missing user is nobody's twin.
func sameActor(c *store.TenantTx, a, b uuid.UUID) (bool, error) {
	if a == b {
		return true, nil
	}
	ua, err := c.PlatformUser(a)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	ub, err := c.PlatformUser(b)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return ua.IdentityID != nil && ub.IdentityID != nil && *ua.IdentityID == *ub.IdentityID, nil
}

type accountLinkRequestView struct {
	AccountID          int64     `json:"account_id"`
	Action             string    `json:"action"`
	IdentityID         *int64    `json:"identity_id"`
	PreviousIdentityID *int64    `json:"previous_identity_id"`
	Reason             string    `json:"reason"`
	RequestedBy        string    `json:"requested_by"`
	RequestedByUserID  string    `json:"requested_by_user_id"`
	RequestedAt        time.Time `json:"requested_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

func viewAccountLinkRequest(q *store.AccountLinkRequest) accountLinkRequestView {
	return accountLinkRequestView{q.AccountID, q.Action, q.IdentityID, q.PreviousIdentityID, q.Reason, q.RequestedBy,
		q.RequestedByUserID.String(), q.RequestedAt, q.ExpiresAt}
}

// requestedKV is the audit detail naming the first admin of an applied change.
func requestedKV(q *store.AccountLinkRequest) []ojson.KV {
	return []ojson.KV{{Key: "requested_by", Value: q.RequestedBy}, {Key: "requested_by_user_id", Value: q.RequestedByUserID.String()},
		{Key: "requested_reason", Value: q.Reason}}
}

// linkAccount pins an account to an identity. It needs two admins: the first
// request answers 202, a second admin's identical request applies it.
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
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	a, _, err := correlation.CheckLink(c, id, b.IdentityID, b.Reason)
	if err != nil {
		return nil, corrErr(err)
	}
	matched, pending, err := s.accountLinkGate(r, c, now, a, store.AccountLinkActionLink, &b.IdentityID, strings.TrimSpace(b.Reason))
	if err != nil || pending != nil {
		return pending, err
	}
	if err := c.DeleteAccountLinkRequest(id); err != nil {
		return nil, err
	}
	d, err := correlation.Link(c, id, b.IdentityID, b.Reason, actor, now)
	if err != nil {
		return nil, corrErr(err)
	}
	return s.decided(r, "identity.account.link", d, requestedKV(matched)...)
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

// releaseAccount removes an account's pin. It needs two admins, like linkAccount.
func (s *Server) releaseAccount(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if _, err := decider(r); err != nil {
		return nil, err
	}
	id := p.pathInt("account_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	a, _, err := correlation.CheckRelease(c, id)
	if err != nil {
		return nil, corrErr(err)
	}
	matched, pending, err := s.accountLinkGate(r, c, now, a, store.AccountLinkActionRelease, nil, "")
	if err != nil || pending != nil {
		return pending, err
	}
	if err := c.DeleteAccountLinkRequest(id); err != nil {
		return nil, err
	}
	d, err := correlation.Release(c, id)
	if err != nil {
		return nil, corrErr(err)
	}
	return s.decided(r, "identity.account.release", d, requestedKV(matched)...)
}

type accountLinkRequestRowView struct {
	accountLinkRequestView
	Account      string `json:"account"`
	IdentityName string `json:"identity_name"`
	PreviousName string `json:"previous_identity_name"`
}

// listAccountLinkRequests lists the pins and releases waiting for a second
// admin; approving is the same request the first admin made.
func (s *Server) listAccountLinkRequests(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	rows, err := store.TxFrom(r.Context()).AccountLinkRequests(s.clock().UTC())
	if err != nil {
		return nil, err
	}
	items := make([]accountLinkRequestRowView, 0, len(rows))
	for _, q := range rows {
		items = append(items, accountLinkRequestRowView{viewAccountLinkRequest(&q.AccountLinkRequest), q.System + ":" + q.Username,
			q.IdentityName, q.PreviousName})
	}
	return ojson.Object{{Key: "items", Value: items}, {Key: "count", Value: len(items)}}, nil
}

// cancelAccountLinkRequest withdraws a pending request; only its requester may.
func (s *Server) cancelAccountLinkRequest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if _, err := decider(r); err != nil {
		return nil, err
	}
	id := p.pathInt("account_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, c, now := principal(r).User(), store.TxFrom(r.Context()), s.clock().UTC()
	q, err := c.AccountLinkRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "no_request", Msg: "the account has no pending request"}
	} else if err != nil {
		return nil, err
	}
	same, err := sameActor(c, q.RequestedByUserID, by.ID)
	if err != nil {
		return nil, err
	}
	if !same {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "not_requester", Msg: "only the admin who made the request can cancel it"}
	}
	if err := c.DeleteAccountLinkRequest(id); err != nil {
		return nil, err
	}
	det := ojson.Object{{Key: "account_id", Value: id}, {Key: "action", Value: q.Action}, {Key: "identity_id", Value: q.IdentityID}}
	if err := c.Audit(now, by.Display, "identity.account.link_request_cancelled", det); err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "cancelled", Value: true}, {Key: "account_id", Value: id}}, nil
}

// mergeActor is the signed-in user who merges, approves or decides.
func mergeActor(r *http.Request) (merge.Actor, error) {
	id, err := decider(r)
	if err != nil {
		return merge.Actor{}, err
	}
	return merge.Actor{UserID: id, Display: principal(r).Display}, nil
}

// mergeIdentity asks for a merge. Where either person holds privileged access,
// has IAL 2 or more, or is an employee it answers 202 with a request that a
// second reviewer approves (POST /api/identity-merge-requests/{id}/approve);
// otherwise it applies at once and answers the merge, as before.
func (s *Server) mergeIdentity(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := mergeActor(r)
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
	out, err := merge.Request(c, merge.Input{MergedID: id, SurvivorID: b.Into, Reason: b.Reason, Basis: merge.BasisReviewer}, actor, now)
	if err != nil {
		return nil, corrErr(err)
	}
	if out.Pending != nil {
		v, err := viewMergeRequest(newViewer(c), out.Pending)
		if err != nil {
			return nil, err
		}
		return statusBody{http.StatusAccepted, ojson.Object{{Key: "status", Value: "pending_approval"}, {Key: "request", Value: v}}}, nil
	}
	return viewMerge(c, out.Merge)
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
	actor, err := mergeActor(r)
	if err != nil {
		return nil, err
	}
	var b reasonBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	id := strings.TrimSpace(p.path["merge_id"])
	res, err := merge.Unmerge(c, id, b.Reason, actor, now)
	if err != nil {
		return nil, corrErr(err)
	}
	v, err := viewMerge(c, res.Merge)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "merge", Value: v}, {Key: "restored", Value: viewMoves(res.Restored)}, {Key: "kept", Value: viewMoves(res.Kept)},
		{Key: "created_after", Value: res.CreatedAfter}}, nil
}
