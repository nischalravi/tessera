// Package merge is the policy around the merge engine of internal/correlation
// (guest accounts design §5.4 to §5.6, issue #68 / GU-5). The engine moves the
// rows and records every one so an unmerge can put them back; this package
// decides when a merge may happen and what else it sets in motion:
//
//   - Four eyes. A merge, or a reviewer's link of an intake to a person, where
//     either person holds privileged access, has IAL 2 or more, or is an
//     employee, does not apply when asked. It becomes a pending request that a
//     second reviewer, not the one who asked, must approve (a self-approval is
//     refused here and by the table). A link by sign-in is proof of
//     possession of the existing person's credential and needs no reviewer.
//   - Credentials never transfer. The merged person's sessions are ended and
//     their sign-in users disabled (a user that holds a role is refused: the
//     administrator removes the roles first), and the survivor's credentials
//     are untouched. The binding of a disabled user cannot sign in again.
//   - Both people's contact channels are told (internal/notify).
//   - Memberships follow the moved accounts; Tessera-managed bundle and
//     reference memberships are brought up to date through internal/guests/access
//     (the groups engine, GR-1/GR-2, is not built).
//   - A reviewer's link needs re-verification at the existing person's IAL
//     (§5.5.3): while the claimant's IAL is below it, nothing is linked and no
//     access is granted; the decision is recorded as "reverification required"
//     and completes when the claimant signs in as the existing person.
//
// Every function works in the caller's tenant transaction, which also carries
// the audit event.
package merge

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/correlation"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Error is a refused change; Code is stable for API clients.
type Error = correlation.Error

func refuse(status int, code, msg string) error { return &Error{Status: status, Code: code, Msg: msg} }

// Actor is the signed-in user who asks or approves.
type Actor struct {
	UserID  string // platform user id
	Display string
}

// Basis says what justifies a merge.
type Basis string

// Bases.
const (
	BasisReviewer Basis = "reviewer" // a person decided: four eyes where the risk is high
	BasisSignIn   Basis = "sign_in"  // the claimant authenticated as the existing person
)

// Reasons a second reviewer is needed.
const (
	RiskPrivileged = "privileged_access"
	RiskIAL2       = "ial2"
	RiskEmployee   = "employee"
)

// Risk is why a merge needs a second reviewer; empty means it does not.
type Risk []string

// Facts are what makes a person risky to merge.
type Facts struct {
	Privileged bool
	IAL        int // effective: recorded, or an HR or student record's equivalent
	Employee   bool
}

// Reasons lists the risk reasons the facts carry.
func (f Facts) Reasons() Risk {
	var out Risk
	if f.IAL >= 2 {
		out = append(out, RiskIAL2)
	}
	if f.Employee {
		out = append(out, RiskEmployee)
	}
	if f.Privileged {
		out = append(out, RiskPrivileged)
	}
	return out
}

// Assessor reads the facts about people, building the access graph once.
type Assessor struct {
	tx   *store.TenantTx
	now  time.Time
	snap *graph.Snapshot
}

// NewAssessor returns an Assessor for one transaction.
func NewAssessor(tx *store.TenantTx, now time.Time) *Assessor { return &Assessor{tx: tx, now: now} }

// Facts returns the facts about one person. A person holding privileged access
// has a privileged effective permission (a standing or time-bound grant).
func (a *Assessor) Facts(id int64) (Facts, error) {
	var f Facts
	var err error
	if f.IAL, err = EffectiveIAL(a.tx, id); err != nil {
		return f, err
	}
	affs, err := a.tx.AffiliationsFor(id)
	if err != nil {
		return f, err
	}
	for _, x := range affs {
		if x.Type == store.AffEmployee && x.Status != store.AffEnded && x.Status != store.AffRevoked {
			f.Employee = true
		}
	}
	if a.snap == nil {
		if a.snap, err = graph.Build(a.tx, a.now); err != nil {
			return f, err
		}
	}
	// privileged access is membership of a privileged group (or a direct grant of a
	// privileged permission) through any of the person's accounts, or any privileged
	// permission that reaches them through the groups they are in
	accts, err := a.tx.IdentityAccounts(id)
	if err != nil {
		return f, err
	}
	for _, acct := range accts {
		for _, next := range a.snap.Successors(graph.Key("account", acct.ID)) {
			if n := a.snap.Node(next); n != nil && n.Privileged {
				f.Privileged = true
			}
		}
	}
	if eff := a.snap.EffectivePermissions(id); eff != nil && !f.Privileged {
		for _, p := range eff.Values() {
			if p.Privileged {
				f.Privileged = true
				break
			}
		}
	}
	return f, nil
}

// Risk is the union of the reasons for the given people.
func (a *Assessor) Risk(ids ...int64) (Risk, error) {
	out := Risk{}
	for _, id := range ids {
		f, err := a.Facts(id)
		if err != nil {
			return nil, err
		}
		for _, r := range f.Reasons() {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// Assess looks at both people. Either one holding privileged access, IAL 2 or
// more (recorded, or an HR or student record, which was vetted at hire), or an
// employee affiliation needs a second reviewer.
func Assess(tx *store.TenantTx, now time.Time, ids ...int64) (Risk, error) {
	return NewAssessor(tx, now).Risk(ids...)
}

// EffectiveIAL is the identity assurance level a person holds: the level
// recorded for them, or 2 for a person from an HR or student record (vetted at hire).
func EffectiveIAL(tx *store.TenantTx, id int64) (int, error) {
	ial := 0
	if a, err := tx.IdentityAssurance(id); err == nil {
		ial = a.IAL
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	affs, err := tx.AffiliationsFor(id)
	if err != nil {
		return 0, err
	}
	for _, a := range affs {
		if (a.Source == store.AffSourceHRIS || a.Source == store.AffSourceSIS) && a.Status != store.AffRevoked {
			return max(ial, access.EmployeeEquivalentIAL), nil
		}
	}
	return ial, nil
}

// Input is a merge to ask for.
type Input struct {
	MergedID, SurvivorID int64
	Reason               string
	Basis                Basis
	// MatchID is the match result a reviewer's link decides; "" for a plain merge.
	MatchID string
}

// Outcome is what asking for a merge did: it applied, it waits for a second
// reviewer, or (a link) it waits for the claimant to re-verify.
type Outcome struct {
	Merge          *store.IdentityMerge
	Pending        *store.MergeRequest
	Reverification bool
	Risk           Risk
	Contacts       int // channels told
}

func checkReason(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	if r == "" || len(r) > correlation.MaxReason {
		return "", refuse(422, "reason_required", "a reason of 1 to 500 characters is required")
	}
	return r, nil
}

// Request asks for a merge of in.MergedID into in.SurvivorID. When the risk
// needs a second reviewer it records a pending request and applies nothing.
func Request(tx *store.TenantTx, in Input, actor Actor, now time.Time) (*Outcome, error) {
	reason, err := checkReason(in.Reason)
	if err != nil {
		return nil, err
	}
	if in.MergedID == in.SurvivorID {
		return nil, refuse(422, "same_identity", "an identity cannot be merged into itself")
	}
	var match *store.MatchResult
	if in.MatchID != "" {
		if match, err = tx.MatchResult(in.MatchID); err != nil {
			return nil, err
		}
	}
	risk := Risk{}
	if in.Basis != BasisSignIn {
		if risk, err = Assess(tx, now, in.MergedID, in.SurvivorID); err != nil {
			return nil, err
		}
	}
	if len(risk) == 0 {
		return applyFor(tx, in, reason, actor, actor, nil, match, now)
	}
	// the rest of the checks run now so a doomed request is refused to the asker, not the approver
	if err := precheck(tx, in); err != nil {
		return nil, err
	}
	if _, err := tx.PendingMergeRequestFor(in.MergedID); err == nil {
		return nil, refuse(409, "request_pending", "a merge of this person is already waiting for a second reviewer")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	kind := store.MergeKindMerge
	var matchID *string
	if match != nil {
		kind, matchID = store.MergeKindMatchLink, &match.ID
	}
	rj, err := json.Marshal(risk)
	if err != nil {
		return nil, err
	}
	q := &store.MergeRequest{ID: uuid.NewString(), Kind: kind, SurvivorID: in.SurvivorID, MergedID: in.MergedID, MatchID: matchID,
		Reason: reason, Risk: string(rj), RequestedBy: actor.UserID, RequestedAt: now, Status: store.MergeReqPending}
	if err := tx.InsertMergeRequest(q); err != nil {
		return nil, err
	}
	approvers, err := notify.Holders(tx, now, auth.PermIdentitiesMerge)
	if err != nil {
		return nil, err
	}
	if err := notify.MergeApprovalNeeded(tx, now, q.ID, actor.UserID, approvers); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor.Display, "identity.merge.request", ojson.Object{{Key: "request_id", Value: q.ID},
		{Key: "kind", Value: kind}, {Key: "merged_id", Value: in.MergedID}, {Key: "survivor_id", Value: in.SurvivorID},
		{Key: "match_id", Value: matchID}, {Key: "risk", Value: []string(risk)}, {Key: "reason", Value: reason}}); err != nil {
		return nil, err
	}
	return &Outcome{Pending: q, Risk: risk}, nil
}

// precheck refuses what the engine would refuse, without writing.
func precheck(tx *store.TenantTx, in Input) error {
	m, err := tx.Identity(in.MergedID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "identity_not_found", "identity not found")
	} else if err != nil {
		return err
	}
	s, err := tx.Identity(in.SurvivorID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "survivor_not_found", "identity not found")
	} else if err != nil {
		return err
	}
	switch {
	case m.Status == store.IdentityStatusMerged || s.Status == store.IdentityStatusMerged:
		return refuse(409, "identity_merged", "one of the identities is already merged")
	case m.Type != s.Type:
		return refuse(409, "type_mismatch", "identities of different types cannot be merged")
	}
	return nil
}

// Approve is the second reviewer's approval of a pending request: it applies
// the merge. The approver must be someone other than the requester.
func Approve(tx *store.TenantTx, requestID string, actor Actor, now time.Time) (*Outcome, error) {
	q, err := tx.MergeRequest(requestID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "request_not_found", "request not found")
	} else if err != nil {
		return nil, err
	}
	if q.Status != store.MergeReqPending {
		return nil, refuse(409, "request_decided", "the request was already decided")
	}
	if q.RequestedBy == actor.UserID {
		return nil, refuse(403, "second_reviewer_required", "a different reviewer must approve; you asked for this change")
	}
	in := Input{MergedID: q.MergedID, SurvivorID: q.SurvivorID, Reason: q.Reason, Basis: BasisReviewer}
	var match *store.MatchResult
	if q.MatchID != nil {
		in.MatchID = *q.MatchID
		if match, err = tx.MatchResult(*q.MatchID); err != nil {
			return nil, err
		}
		if match.Status != store.MatchReview && match.Status != store.MatchReverification {
			return nil, refuse(409, "already_decided", "the match this request is about was decided meanwhile; reject the request")
		}
	}
	first := Actor{UserID: q.RequestedBy, Display: q.RequestedBy}
	out, err := applyFor(tx, in, q.Reason, first, actor, &actor, match, now)
	if err != nil {
		return nil, err
	}
	var mergeID *string
	if out.Merge != nil {
		mergeID = &out.Merge.ID
	}
	if err := tx.DecideMergeRequest(q.ID, store.MergeReqApproved, actor.UserID, nil, mergeID, now); err != nil {
		return nil, err
	}
	q.Status, q.DecidedBy, q.DecidedAt, q.MergeID = store.MergeReqApproved, &actor.UserID, &now, mergeID
	out.Pending = q
	return out, tx.Audit(now, actor.Display, "identity.merge.approve", ojson.Object{{Key: "request_id", Value: q.ID},
		{Key: "requested_by", Value: q.RequestedBy}, {Key: "merge_id", Value: mergeID}, {Key: "reverification_required", Value: out.Reverification}})
}

// Reject declines a pending request. The requester may withdraw it (cancelled);
// anyone else with the permission rejects it (a reason is required).
func Reject(tx *store.TenantTx, requestID string, actor Actor, reason string, now time.Time) (*store.MergeRequest, error) {
	r, err := checkReason(reason)
	if err != nil {
		return nil, err
	}
	q, err := tx.MergeRequest(requestID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "request_not_found", "request not found")
	} else if err != nil {
		return nil, err
	}
	if q.Status != store.MergeReqPending {
		return nil, refuse(409, "request_decided", "the request was already decided")
	}
	status := store.MergeReqRejected
	if q.RequestedBy == actor.UserID {
		status = store.MergeReqCancelled
	}
	if err := tx.DecideMergeRequest(q.ID, status, actor.UserID, &r, nil, now); err != nil {
		return nil, err
	}
	q.Status, q.DecidedBy, q.DecidedAt, q.DecisionReason = status, &actor.UserID, &now, &r
	return q, tx.Audit(now, actor.Display, "identity.merge."+status, ojson.Object{{Key: "request_id", Value: q.ID},
		{Key: "merged_id", Value: q.MergedID}, {Key: "survivor_id", Value: q.SurvivorID}, {Key: "reason", Value: r}})
}

// applyFor applies a merge (and, for a link, what the link decides). first is
// who asked; exec is who is doing it now (the same person, or the approver);
// second is the approver when there was one.
func applyFor(tx *store.TenantTx, in Input, reason string, first, exec Actor, second *Actor, match *store.MatchResult, now time.Time) (*Outcome, error) {
	if match != nil && in.Basis != BasisSignIn {
		// §5.5.3: the claimant must be at the existing person's IAL before anything is linked
		need, err := EffectiveIAL(tx, in.SurvivorID)
		if err != nil {
			return nil, err
		}
		have, err := EffectiveIAL(tx, in.MergedID)
		if err != nil {
			return nil, err
		}
		if have < need {
			return &Outcome{Reverification: true}, recordReverification(tx, match, reason, first, exec, second, have, need, now)
		}
	}
	m, err := apply(tx, in, reason, first, exec, second, now)
	if err != nil {
		return nil, err
	}
	if match != nil {
		if err := finishMatch(tx, match, m, reason, first, exec, second, in.Basis, now); err != nil {
			return nil, err
		}
	}
	return &Outcome{Merge: m}, nil
}

// apply is the merge itself: credentials, the engine, memberships, claim
// links, notifications and the ledger entry.
func apply(tx *store.TenantTx, in Input, reason string, first, exec Actor, second *Actor, now time.Time) (*store.IdentityMerge, error) {
	mergedC, err := notify.ContactsOf(tx, in.MergedID)
	if err != nil {
		return nil, err
	}
	survivorC, err := notify.ContactsOf(tx, in.SurvivorID)
	if err != nil {
		return nil, err
	}
	// credentials never transfer: the merged person's users stop signing in
	users, err := tx.UsersLinkedTo(in.MergedID)
	if err != nil {
		return nil, err
	}
	var disabled []string
	sessions := int64(0)
	for _, u := range users {
		uid, err := uuid.Parse(u)
		if err != nil {
			continue
		}
		roles, err := tx.RoleAssignments(uid)
		if err != nil {
			return nil, err
		}
		if len(roles) > 0 {
			return nil, refuse(409, "merged_identity_signs_in",
				"the person to merge signs in to Tessera with a role; credentials never move, so remove the role and disable the user first, or merge the other way")
		}
		n, err := tx.RevokeUserSessions(uid, "identity merged", now)
		if err != nil {
			return nil, err
		}
		sessions += n
		if err := tx.DisableUser(uid, fmt.Sprintf("identity merged into %d", in.SurvivorID), now); err != nil {
			return nil, err
		}
		disabled = append(disabled, u)
	}
	id := uuid.NewString()
	m, err := correlation.Merge(tx, id, in.MergedID, in.SurvivorID, reason, first.UserID, now)
	if err != nil {
		return nil, err
	}
	// the intakes of the merged person's guest sponsorships can no longer be claimed as that person
	if in.Basis != BasisSignIn {
		seen := map[string]bool{}
		for _, mv := range m.Moves {
			if mv.Table != "sponsorships" || mv.Column != "guest_identity_id" {
				continue
			}
			ss, err := tx.Sponsorship(mv.Key)
			if err != nil {
				return nil, err
			}
			if seen[ss.IntakeID] {
				continue
			}
			seen[ss.IntakeID] = true
			if _, err := tx.RevokeClaimTokens(ss.IntakeID); err != nil {
				return nil, err
			}
			if err := tx.RevokeClaimSessions(ss.IntakeID, now); err != nil {
				return nil, err
			}
		}
	}
	// memberships follow the moved accounts; the Tessera-managed ones go through the access code
	if err := access.Merged(tx, now, exec.Display, in.SurvivorID); err != nil {
		return nil, err
	}
	for _, c := range [][]notify.Recipient{mergedC, survivorC} {
		if err := notify.IdentityCombined(tx, now, m.ID, c); err != nil {
			return nil, err
		}
	}
	var secondID any
	if second != nil {
		secondID = second.UserID
	}
	return m, tx.Audit(now, exec.Display, "identity.merge", ojson.Object{{Key: "merge_id", Value: m.ID},
		{Key: "merged_id", Value: m.MergedID}, {Key: "survivor_id", Value: m.SurvivorID}, {Key: "moves", Value: movesView(m.Moves)},
		{Key: "reason", Value: m.Reason}, {Key: "basis", Value: string(in.Basis)}, {Key: "second_reviewer", Value: secondID},
		{Key: "sessions_revoked", Value: sessions}, {Key: "users_disabled", Value: disabled}})
}

type moveJSON struct {
	Table  string `json:"table"`
	ID     any    `json:"id"`
	Column string `json:"column"`
}

func movesView(ms []store.MergeMove) []moveJSON {
	out := make([]moveJSON, len(ms))
	for i, m := range ms {
		out[i] = moveJSON{m.Table, m.ID, m.Column}
		if m.Key != "" {
			out[i].ID = m.Key
		}
	}
	return out
}
