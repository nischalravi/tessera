package notify

import (
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Producers for identity merges and links (issue #68). The message goes to every
// contact channel on record for the person (§5.4, §5.5): each active sign-in
// user's inbox and the addresses the person is known by, whether or not they
// sign in. It names no one else and carries no secret.

// ContactsOf returns the recipients for a person's contact channels, even when
// the person is not active (a provisional guest, or one just merged away).
// Call it before the change that would make the person unreachable.
func ContactsOf(tx *store.TenantTx, identityID int64) ([]Recipient, error) {
	ident, err := tx.Identity(identityID)
	if err != nil {
		return nil, err
	}
	users, err := tx.UsersLinkedTo(identityID)
	if err != nil {
		return nil, err
	}
	var out []Recipient
	seen := map[string]bool{}
	for _, uid := range users {
		r, ok, err := User(tx, uid)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, r)
			seen[strings.ToLower(r.Email)] = true
		}
	}
	addrs := []string{emailOf(ident.Email)}
	ids, err := tx.IdentifiersFor(identityID)
	if err != nil {
		return nil, err
	}
	for _, x := range ids {
		if x.Type == store.IdentEmail && x.VerifiedAt != nil && x.ValueNorm != nil && x.Status == store.RecordActive {
			addrs = append(addrs, *x.ValueNorm)
		}
	}
	for _, a := range addrs {
		if a == "" || seen[strings.ToLower(a)] {
			continue
		}
		seen[strings.ToLower(a)] = true
		out = append(out, Recipient{IdentityID: identityID, Email: a})
	}
	return out, nil
}

// IdentityCombined tells a person that records for them were combined (a merge
// or a link). key is the merge's id. The message names no one else.
func IdentityCombined(tx *store.TenantTx, now time.Time, key string, to []Recipient) error {
	_, err := Emit(tx, now, Message{Kind: KindSecurityAlert, Key: "identity.combined:" + key,
		Subject: "Two records for you were combined",
		Body: lines("Two records that belong to you at your organization were combined into one.",
			"Your sign-in did not change, and nothing was transferred from one to the other.",
			"If you do not recognize this, contact your administrator at once: the change can be undone.")}, to...)
	return err
}

// IdentitySeparated tells a person that a merge that included them was undone.
func IdentitySeparated(tx *store.TenantTx, now time.Time, key string, to []Recipient) error {
	_, err := Emit(tx, now, Message{Kind: KindSecurityAlert, Key: "identity.separated:" + key,
		Subject: "A combination of records for you was undone",
		Body:    lines("A change that combined two records for you at your organization was undone.")}, to...)
	return err
}

// MergeApprovalNeeded tells the people who can approve that a merge or link waits
// for a second reviewer. The requester is skipped.
func MergeApprovalNeeded(tx *store.TenantTx, now time.Time, requestID, requester string, to []Recipient) error {
	_, err := Emit(tx, now, Message{Kind: KindMergeApproval, Key: "identity.merge_request:" + requestID,
		Subject: "An identity merge needs a second reviewer",
		Body:    lines("A merge or link of two people waits for a second reviewer. It cannot be approved by the person who asked for it."),
		Link:    "/identity-matches", Skip: []string{requester}}, to...)
	return err
}
