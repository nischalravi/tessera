// Package correlation applies reviewers' account-correlation decisions to the
// live identities and accounts (issue #160): link an account to a person,
// mark it as belonging to no person, release a decision, merge two
// identities and undo a merge.
//
// The rules follow the guest design's §5.4 and the readiness design's K12:
//
//   - Self-asserted matches (email, UPN, login) only ever propose; a person
//     decides. Queue lists unlinked user accounts with proposed candidates.
//   - A decision is pinned (account_links), so connector sync never undoes
//     it (ingest.Resolver.AccountIdentity).
//   - A merge moves the merged identity's accounts, account pins, owned
//     identities, reports and agent delegations to the survivor, in one
//     transaction, and records every moved row. Since the guest design (§5.4,
//     issue #68) it also moves the person's source records, identifiers,
//     affiliations, sponsorships (as guest, and as sponsor while live),
//     access bundle items, lifecycle record (when the survivor has none) and
//     pending access requests, each recorded as a move so an unmerge restores
//     it. History (usage, reviews, decided requests, HRIS events) stays where
//     it was.
//   - Credentials never move: an identity with an active Tessera sign-in user
//     cannot be the merged side. internal/identity/merge disables that user
//     (and ends its sessions) first, when it holds no role; this package only
//     enforces the rule.
//   - Unmerge, within the window (UnmergeWindow, or the tenant's setting),
//     moves back each recorded row that still points at the survivor; rows
//     changed since are kept and reported.
//
// This is the move engine. The policy around it (four eyes, credential
// revocation, notifications, memberships through the access code) is
// internal/identity/merge, which calls it; there is no second engine.
//
// Every function works inside the caller's tenant transaction, which also
// carries the audit event.
package correlation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// UnmergeWindow is how long a merge can be undone unless the tenant sets another
// (matching_settings.unmerge_window_days).
const UnmergeWindow = 180 * 24 * time.Hour

// MaxReason caps a decision's reason.
const MaxReason = 500

// Error is a refused decision; Code is stable for API clients.
type Error struct {
	Status int // HTTP status
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, msg string) error { return &Error{Status: status, Code: code, Msg: msg} }

// Candidate is an identity proposed for an account.
type Candidate struct {
	IdentityID int64
	Name       string
	Email      string
	Rule       string // "email" (the login is the identity's email) or "email_local_part"
}

// QueueItem is an unlinked user account awaiting a decision.
type QueueItem struct {
	Account    *store.Account
	Candidates []Candidate
}

// Queue lists user accounts without an identity and without a decision,
// each with the identities its login proposes (never linked automatically).
func Queue(tx *store.TenantTx) ([]QueueItem, error) {
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	links, err := tx.AccountLinks()
	if err != nil {
		return nil, err
	}
	pinned := make(map[int64]bool, len(links))
	for _, l := range links {
		pinned[l.AccountID] = true
	}
	idents, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	byEmail, byLocal := map[string][]*store.Identity{}, map[string][]*store.Identity{}
	for _, i := range idents {
		if i.Type != "human" || i.Status == store.IdentityStatusMerged || i.Email == nil || *i.Email == "" {
			continue
		}
		e := strings.ToLower(*i.Email)
		byEmail[e] = append(byEmail[e], i)
		byLocal[localPart(e)] = append(byLocal[localPart(e)], i)
	}
	var out []QueueItem
	for _, a := range accts {
		if a.IdentityID != nil || pinned[a.ID] || a.Kind != "user" {
			continue
		}
		login := strings.ToLower(strings.TrimSpace(a.Username))
		var cands []Candidate
		seen := map[int64]bool{}
		add := func(is []*store.Identity, rule string) {
			for _, i := range is {
				if !seen[i.ID] {
					seen[i.ID] = true
					cands = append(cands, Candidate{IdentityID: i.ID, Name: i.Name, Email: *i.Email, Rule: rule})
				}
			}
		}
		if strings.Contains(login, "@") {
			add(byEmail[login], "email")
		}
		if lp := localPart(login); lp != "" {
			add(byLocal[lp], "email_local_part")
		}
		out = append(out, QueueItem{Account: a, Candidates: cands})
	}
	return out, nil
}

func localPart(s string) string {
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '\\'); i >= 0 { // DOMAIN\user
		s = s[i+1:]
	}
	return s
}

func checkReason(reason string) error {
	if r := strings.TrimSpace(reason); r == "" || len(r) > MaxReason {
		return refuse(422, "reason_required", "a reason of 1 to 500 characters is required")
	}
	return nil
}

func account(tx *store.TenantTx, id int64) (*store.Account, error) {
	a, err := tx.Account(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "account_not_found", "account not found")
	}
	return a, err
}

func identity(tx *store.TenantTx, id int64, code string) (*store.Identity, error) {
	i, err := tx.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, code, "identity not found")
	}
	return i, err
}

// Decision is the outcome of Link, MarkNotPerson or Release.
type Decision struct {
	Account  *store.Account
	Previous *int64 // the account's identity before
	Link     *store.AccountLink
}

// Link pins an account to an identity and applies it.
func Link(tx *store.TenantTx, accountID, identityID int64, reason, actor string, now time.Time) (*Decision, error) {
	if err := checkReason(reason); err != nil {
		return nil, err
	}
	a, err := account(tx, accountID)
	if err != nil {
		return nil, err
	}
	i, err := identity(tx, identityID, "identity_not_found")
	if err != nil {
		return nil, err
	}
	switch {
	case i.Status == store.IdentityStatusMerged:
		return nil, refuse(409, "identity_merged", "the identity was merged into another; link to the survivor")
	case a.Kind == "user" && i.Type != "human":
		return nil, refuse(409, "type_mismatch", "a user account links only to a person")
	}
	return pin(tx, a, &store.AccountLink{AccountID: a.ID, Decision: store.LinkDecisionLink, IdentityID: &i.ID,
		Reason: strings.TrimSpace(reason), DecidedBy: actor, DecidedAt: now})
}

// MarkNotPerson pins an account as belonging to no identity.
func MarkNotPerson(tx *store.TenantTx, accountID int64, reason, actor string, now time.Time) (*Decision, error) {
	if err := checkReason(reason); err != nil {
		return nil, err
	}
	a, err := account(tx, accountID)
	if err != nil {
		return nil, err
	}
	return pin(tx, a, &store.AccountLink{AccountID: a.ID, Decision: store.LinkDecisionNotPerson,
		Reason: strings.TrimSpace(reason), DecidedBy: actor, DecidedAt: now})
}

func pin(tx *store.TenantTx, a *store.Account, l *store.AccountLink) (*Decision, error) {
	prev := a.IdentityID
	// a replaced decision keeps the identity the connector gave, for Release
	if old, err := tx.AccountLink(a.ID); err == nil {
		l.PreviousIdentityID = old.PreviousIdentityID
	} else if errors.Is(err, store.ErrNotFound) {
		l.PreviousIdentityID = prev
	} else {
		return nil, err
	}
	if err := tx.PutAccountLink(l); err != nil {
		return nil, err
	}
	if err := tx.SetAccountIdentity(a.ID, l.IdentityID); err != nil {
		return nil, err
	}
	a.IdentityID = l.IdentityID
	return &Decision{Account: a, Previous: prev, Link: l}, nil
}

// Release removes an account's decision and gives it back the identity it
// had before the first decision (the connector's mapping; the next sync
// recomputes it anyway).
func Release(tx *store.TenantTx, accountID int64) (*Decision, error) {
	a, err := account(tx, accountID)
	if err != nil {
		return nil, err
	}
	l, err := tx.AccountLink(a.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "no_decision", "the account has no correlation decision")
	} else if err != nil {
		return nil, err
	}
	if err := tx.DeleteAccountLink(a.ID); err != nil {
		return nil, err
	}
	back := l.PreviousIdentityID
	if back != nil {
		surv, err := tx.MergeSurvivors()
		if err != nil {
			return nil, err
		}
		if s, ok := surv[*back]; ok {
			back = &s
		}
	}
	if err := tx.SetAccountIdentity(a.ID, back); err != nil {
		return nil, err
	}
	prev := a.IdentityID
	a.IdentityID = back
	return &Decision{Account: a, Previous: prev, Link: l}, nil
}

// Merge merges identity mergedID into survivorID.
func Merge(tx *store.TenantTx, id string, mergedID, survivorID int64, reason, actor string, now time.Time) (*store.IdentityMerge, error) {
	if err := checkReason(reason); err != nil {
		return nil, err
	}
	if mergedID == survivorID {
		return nil, refuse(422, "same_identity", "an identity cannot be merged into itself")
	}
	m, err := identity(tx, mergedID, "identity_not_found")
	if err != nil {
		return nil, err
	}
	s, err := identity(tx, survivorID, "survivor_not_found")
	if err != nil {
		return nil, err
	}
	switch {
	case m.Status == store.IdentityStatusMerged || s.Status == store.IdentityStatusMerged:
		return nil, refuse(409, "identity_merged", "one of the identities is already merged")
	case m.Type != s.Type:
		return nil, refuse(409, "type_mismatch", "identities of different types cannot be merged")
	}
	if users, err := tx.UsersLinkedTo(m.ID); err != nil {
		return nil, err
	} else if len(users) > 0 {
		return nil, refuse(409, "merged_identity_signs_in",
			"the identity to merge has an active sign-in user; credentials never move, so merge the other way or disable the user first")
	}
	var moves []store.MergeMove
	accts, err := tx.IdentityAccounts(m.ID)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		moves = append(moves, store.MergeMove{Table: "accounts", ID: a.ID, Column: "identity_id"})
	}
	links, err := tx.AccountLinksTo(m.ID)
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		moves = append(moves, store.MergeMove{Table: "account_links", ID: l.AccountID, Column: "identity_id"})
	}
	owned, err := tx.IdentitiesOwnedBy(m.ID)
	if err != nil {
		return nil, err
	}
	for _, i := range owned {
		if i.ID != s.ID {
			moves = append(moves, store.MergeMove{Table: "identities", ID: i.ID, Column: "owner_id"})
		}
	}
	reports, err := tx.IdentitiesManagedBy(m.ID)
	if err != nil {
		return nil, err
	}
	for _, i := range reports {
		if i.ID != s.ID { // the survivor never becomes its own manager
			moves = append(moves, store.MergeMove{Table: "identities", ID: i.ID, Column: "manager_id"})
		}
	}
	dels, err := tx.DelegationIDsByPrincipal(m.ID)
	if err != nil {
		return nil, err
	}
	for _, d := range dels {
		moves = append(moves, store.MergeMove{Table: "agent_delegations", ID: d, Column: "principal_id"})
	}
	guest, err := guestMoves(tx, m.ID, s.ID)
	if err != nil {
		return nil, err
	}
	moves = append(moves, guest...)
	if moves == nil {
		moves = []store.MergeMove{}
	}
	// the record comes first: the schema lets guest rows change identity only
	// between the two sides of an open merge record
	rec := &store.IdentityMerge{ID: id, SurvivorID: s.ID, MergedID: m.ID, MergedStatus: m.Status, Moves: moves,
		Reason: strings.TrimSpace(reason), MergedBy: actor, MergedAt: now}
	if err := tx.InsertIdentityMerge(rec); err != nil {
		return nil, err
	}
	for _, mv := range moves {
		if err := tx.ApplyMove(mv, s.ID); err != nil {
			return nil, err
		}
	}
	if err := tx.SetIdentityStatus(m.ID, store.IdentityStatusMerged); err != nil {
		return nil, err
	}
	return rec, nil
}

// UnmergeResult says what an unmerge moved back and what it left.
type UnmergeResult struct {
	Merge    *store.IdentityMerge
	Restored []store.MergeMove
	Kept     []store.MergeMove // changed since the merge (or gone): left as they are
}

// Unmerge undoes a merge within the default window.
func Unmerge(tx *store.TenantTx, mergeID, reason, actor string, now time.Time) (*UnmergeResult, error) {
	return UnmergeWithin(tx, mergeID, reason, actor, now, UnmergeWindow)
}

// UnmergeWithin undoes a merge made at most window ago.
func UnmergeWithin(tx *store.TenantTx, mergeID, reason, actor string, now time.Time, window time.Duration) (*UnmergeResult, error) {
	if err := checkReason(reason); err != nil {
		return nil, err
	}
	m, err := tx.IdentityMerge(mergeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "merge_not_found", "merge not found")
	} else if err != nil {
		return nil, err
	}
	if m.UnmergedAt != nil {
		return nil, refuse(409, "already_unmerged", "the merge was already undone")
	}
	if now.Sub(m.MergedAt) > window {
		return nil, refuse(409, "unmerge_window_passed", fmt.Sprintf("merges can be undone for %d days", int(window/(24*time.Hour))))
	}
	s, err := tx.Identity(m.SurvivorID)
	if err != nil {
		return nil, err
	}
	if s.Status == store.IdentityStatusMerged {
		return nil, refuse(409, "survivor_merged", "the survivor was merged since; undo that merge first")
	}
	res := &UnmergeResult{Merge: m, Restored: []store.MergeMove{}, Kept: []store.MergeMove{}}
	for _, mv := range m.Moves {
		cur, err := tx.MoveRef(mv)
		if errors.Is(err, store.ErrNotFound) {
			res.Kept = append(res.Kept, mv)
			continue
		} else if err != nil {
			return nil, err
		}
		if cur == nil || *cur != m.SurvivorID {
			res.Kept = append(res.Kept, mv)
			continue
		}
		if err := tx.ApplyMove(mv, m.MergedID); err != nil {
			return nil, err
		}
		res.Restored = append(res.Restored, mv)
	}
	if err := tx.SetIdentityStatus(m.MergedID, m.MergedStatus); err != nil {
		return nil, err
	}
	r := strings.TrimSpace(reason)
	if err := tx.MarkUnmerged(m.ID, actor, r, now); err != nil {
		return nil, err
	}
	m.UnmergedBy, m.UnmergedAt, m.UnmergeReason = &actor, &now, &r
	return res, nil
}
