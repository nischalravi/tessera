package notify

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Producers: one function per domain event. Each takes the caller's
// transaction, so the notification commits or rolls back with the event, and
// is idempotent: calling it again for the same event writes nothing more.

const (
	linkApprovals = "/inbox"
	linkRequests  = "/access/requests"
	linkReviews   = "/governance/reviews"
	linkJIT       = "/access/jit"
)

func when(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func lines(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}

func groupName(tx *store.TenantTx, id int64) (string, error) {
	g, err := tx.Group(id)
	if errors.Is(err, store.ErrNotFound) {
		return "a group", nil
	} else if err != nil {
		return "", err
	}
	return g.System + ":" + g.Name, nil
}

func personName(tx *store.TenantTx, id int64) (string, error) {
	i, err := tx.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		return "someone", nil
	} else if err != nil {
		return "", err
	}
	return i.Name, nil
}

func userName(tx *store.TenantTx, id string) (string, error) {
	u, err := uuidOf(id)
	if err != nil {
		return "someone", nil
	}
	pu, err := tx.PlatformUser(u)
	if errors.Is(err, store.ErrNotFound) {
		return "someone", nil
	} else if err != nil {
		return "", err
	}
	return pu.DisplayName, nil
}

// lineParties are the users who must not decide a line and so are never asked
// to: its requester and the people who would get the access.
func lineParties(tx *store.TenantTx, l *store.RequestLine) ([]string, error) {
	skip := []string{l.RequestedBy}
	users, err := identityUsers(tx, l.BeneficiaryID)
	return append(skip, users...), err
}

// lineRecipients are the requester and the beneficiary, who are told how
// their request went.
func lineRecipients(tx *store.TenantTx, l *store.RequestLine) ([]Recipient, error) {
	var out []Recipient
	if r, ok, err := User(tx, l.RequestedBy); err != nil {
		return nil, err
	} else if ok {
		out = append(out, r)
	}
	ben, err := Identity(tx, l.BeneficiaryID)
	return append(out, ben...), err
}

// stageApprovers are the people who can act on a waiting stage now: deciders
// for a decider stage or one past due, otherwise the assignee and anyone the
// assignee delegated to.
func stageApprovers(tx *store.TenantTx, now time.Time, st *store.RequestStage) ([]Recipient, error) {
	if st.Kind == store.StageDecider || st.AssigneeID == nil || st.DueAt != nil && !now.Before(*st.DueAt) {
		return Deciders(tx, now)
	}
	users, err := identityUsers(tx, *st.AssigneeID)
	if err != nil {
		return nil, err
	}
	var out []Recipient
	add := func(id string) error {
		r, ok, err := User(tx, id)
		if ok {
			out = append(out, r)
		}
		return err
	}
	for _, u := range users {
		if err := add(u); err != nil {
			return nil, err
		}
		dels, err := tx.ApprovalDelegations(u)
		if err != nil {
			return nil, err
		}
		for _, d := range dels {
			if d.FromUser == u && d.RevokedAt == nil && !now.Before(d.StartsAt) && now.Before(d.EndsAt) {
				if err := add(d.ToUser); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

// ApprovalNeeded tells the approvers of a line's waiting stage st (of total
// stages) that it needs them: when a line is submitted and each time the next
// stage starts.
func ApprovalNeeded(tx *store.TenantTx, now time.Time, l *store.RequestLine, st *store.RequestStage, total int) error {
	to, err := stageApprovers(tx, now, st)
	if err != nil {
		return err
	}
	skip, err := lineParties(tx, l)
	if err != nil {
		return err
	}
	stages, err := tx.RequestStages(l.ID)
	if err != nil {
		return err
	}
	for _, s := range stages {
		if s.Status == store.StageApproved && s.DecidedBy != nil {
			skip = append(skip, *s.DecidedBy) // four eyes: a person approves one stage per line
		}
	}
	grp, err := groupName(tx, l.GroupID)
	if err != nil {
		return err
	}
	ben, err := personName(tx, l.BeneficiaryID)
	if err != nil {
		return err
	}
	by, err := userName(tx, l.RequestedBy)
	if err != nil {
		return err
	}
	stage := st.Kind + " stage"
	if total > 1 {
		stage += " (" + strconv.Itoa(st.Idx+1) + " of " + strconv.Itoa(total) + ")"
	}
	dur := ""
	if l.DurationHours != nil {
		dur = fmt.Sprintf("Duration: %g hours.", *l.DurationHours)
	}
	_, err = Emit(tx, now, Message{Kind: KindApprovalNeeded, Key: "request.approval_needed:" + l.ID + ":" + strconv.Itoa(st.Idx),
		Subject: "Approval needed: " + grp + " for " + ben,
		Body: lines(by+" requested "+grp+" for "+ben+".", "Justification: "+clip(l.Justification, 300), dur,
			"It is waiting for your approval at the "+stage+"."),
		Link: linkApprovals, Skip: skip}, to...)
	return err
}

// RequestDecided tells the requester and the beneficiary that a line was
// approved or denied (the final decision, not a stage). by is the deciding
// platform user, who is not told.
func RequestDecided(tx *store.TenantTx, now time.Time, l *store.RequestLine, approved bool, by string, reason *string) error {
	to, err := lineRecipients(tx, l)
	if err != nil {
		return err
	}
	grp, err := groupName(tx, l.GroupID)
	if err != nil {
		return err
	}
	ben, err := personName(tx, l.BeneficiaryID)
	if err != nil {
		return err
	}
	kind, verb := KindRequestDenied, "denied"
	var ends string
	if approved {
		kind, verb = KindRequestApproved, "approved"
		ends = "The access has no end date."
		if l.ExpiresAt != nil {
			ends = "The access ends " + when(*l.ExpiresAt) + "."
		}
	}
	why := ""
	if reason != nil {
		why = "Reason: " + clip(*reason, 300)
	}
	_, err = Emit(tx, now, Message{Kind: kind, Key: kind + ":" + l.ID, Subject: "Request " + verb + ": " + grp + " for " + ben,
		Body: lines("The request for "+grp+" for "+ben+" was "+verb+".", ends, why), Link: linkRequests,
		Skip: []string{by}}, to...)
	return err
}

// ApprovalEscalated tells the deciders (and the stage's assignee) that a
// stage was not decided in time and is open to every decider.
func ApprovalEscalated(tx *store.TenantTx, now time.Time, l *store.RequestLine, st *store.RequestStage) (int, error) {
	rows, err := PlanApprovalEscalated(tx, now, l, st)
	if err != nil {
		return 0, err
	}
	return Write(tx, rows)
}

// PlanApprovalEscalated is ApprovalEscalated without writing (see Plan).
func PlanApprovalEscalated(tx *store.TenantTx, now time.Time, l *store.RequestLine, st *store.RequestStage) ([]*store.Notification, error) {
	to, err := Deciders(tx, now)
	if err != nil {
		return nil, err
	}
	if st.AssigneeID != nil {
		users, err := identityUsers(tx, *st.AssigneeID)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if r, ok, err := User(tx, u); err != nil {
				return nil, err
			} else if ok {
				to = append(to, r)
			}
		}
	}
	skip, err := lineParties(tx, l)
	if err != nil {
		return nil, err
	}
	grp, err := groupName(tx, l.GroupID)
	if err != nil {
		return nil, err
	}
	ben, err := personName(tx, l.BeneficiaryID)
	if err != nil {
		return nil, err
	}
	due := now
	if st.DueAt != nil {
		due = *st.DueAt
	}
	return Plan(tx, now, Message{Kind: KindApprovalEscalated, Key: "approval.escalated:" + l.ID + ":" + strconv.Itoa(st.Idx),
		Subject: "Escalated: " + grp + " for " + ben + " is overdue",
		Body: lines("The "+st.Kind+" stage of the request for "+grp+" for "+ben+" was not decided by "+when(due)+".",
			"Any decider can now approve or deny it."), Link: linkApprovals, Skip: skip}, to...)
}

// ApprovalDelegated tells the delegate that someone handed them their approvals.
func ApprovalDelegated(tx *store.TenantTx, now time.Time, d *store.ApprovalDelegationRow) error {
	to, ok, err := User(tx, d.ToUser)
	if err != nil || !ok {
		return err
	}
	from, err := userName(tx, d.FromUser)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindApprovalDelegated, Key: "approval.delegated:" + d.ID,
		Subject: from + " delegated their approvals to you",
		Body: lines("From "+when(d.StartsAt)+" until "+when(d.EndsAt)+", you can decide the requests "+from+" would approve.",
			"Reason: "+clip(d.Reason, 300)), Link: linkApprovals}, to)
	return err
}

// reviewers returns each reviewer of a campaign with their load.
func reviewers(tx *store.TenantTx, campaignID int64) ([]store.ReviewerLoad, error) {
	return tx.ReviewerLoads(campaignID)
}

// ReviewLaunched tells each reviewer how many items of a new campaign are theirs.
func ReviewLaunched(tx *store.TenantTx, now time.Time, campaignID int64) error {
	c, err := tx.Campaign(campaignID)
	if err != nil {
		return err
	}
	loads, err := reviewers(tx, campaignID)
	if err != nil {
		return err
	}
	for _, l := range loads {
		to, err := Identity(tx, l.ReviewerID)
		if err != nil {
			return err
		}
		if _, err := Emit(tx, now, Message{Kind: KindReviewLaunched, Key: "review.launched:" + strconv.FormatInt(c.ID, 10),
			Subject: "Access review launched: " + c.Name,
			Body:    lines(fmt.Sprintf("%d grants are waiting for your decision (keep or revoke) in %q.", l.Items, c.Name)), Link: linkReviews}, to...); err != nil {
			return err
		}
	}
	return nil
}

// PlanReviewReminder reminds the reviewers who still have open items in an
// open campaign; week numbers the reminder (one per week of age).
func PlanReviewReminder(tx *store.TenantTx, now time.Time, c *store.ReviewCampaign, week int) ([]*store.Notification, error) {
	loads, err := reviewers(tx, c.ID)
	if err != nil {
		return nil, err
	}
	var out []*store.Notification
	for _, l := range loads {
		if l.Open == 0 {
			continue
		}
		to, err := Identity(tx, l.ReviewerID)
		if err != nil {
			return nil, err
		}
		rows, err := Plan(tx, now, Message{Kind: KindReviewReminder,
			Key:     "review.reminder:" + strconv.FormatInt(c.ID, 10) + ":" + strconv.Itoa(week),
			Subject: "Reminder: access review " + c.Name,
			Body:    lines(fmt.Sprintf("%d of your %d grants in %q still need a decision.", l.Open, l.Items, c.Name)), Link: linkReviews}, to...)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// ReviewClosed tells the reviewers that a campaign is complete.
func ReviewClosed(tx *store.TenantTx, now time.Time, campaignID int64) error {
	c, err := tx.Campaign(campaignID)
	if err != nil {
		return err
	}
	loads, err := reviewers(tx, campaignID)
	if err != nil {
		return err
	}
	for _, l := range loads {
		to, err := Identity(tx, l.ReviewerID)
		if err != nil {
			return err
		}
		if _, err := Emit(tx, now, Message{Kind: KindReviewClosed, Key: "review.closed:" + strconv.FormatInt(c.ID, 10),
			Subject: "Access review closed: " + c.Name,
			Body:    lines(fmt.Sprintf("Every item of %q has a decision. Thank you.", c.Name)), Link: linkReviews}, to...); err != nil {
			return err
		}
	}
	return nil
}

// jitRecipients are the person who requested just-in-time access and the
// person it is for.
func jitRecipients(tx *store.TenantTx, r *store.AccessRequest) ([]Recipient, error) {
	var out []Recipient
	if r.RequestedByUserID != nil {
		if u, ok, err := User(tx, r.RequestedByUserID.String()); err != nil {
			return nil, err
		} else if ok {
			out = append(out, u)
		}
	}
	who, err := Identity(tx, r.IdentityID)
	return append(out, who...), err
}

// JITDecided tells the requester and the person that just-in-time access was
// granted (r approved, with its end time) or denied. by is the deciding
// platform user, who is not told ("" for none).
func JITDecided(tx *store.TenantTx, now time.Time, r *store.AccessRequest, by string) error {
	to, err := jitRecipients(tx, r)
	if err != nil {
		return err
	}
	grp, err := groupName(tx, r.GroupID)
	if err != nil {
		return err
	}
	who, err := personName(tx, r.IdentityID)
	if err != nil {
		return err
	}
	id := strconv.FormatInt(r.ID, 10)
	m := Message{Kind: KindJITDenied, Key: "jit.denied:" + id, Subject: "Just-in-time access denied: " + grp + " for " + who,
		Body: lines("The just-in-time request for " + grp + " for " + who + " was denied."), Link: linkJIT}
	if r.Status == "approved" {
		ends := ""
		if r.ExpiresAt != nil {
			ends = "The access ends " + when(*r.ExpiresAt) + "."
		}
		m = Message{Kind: KindJITGranted, Key: "jit.granted:" + id, Subject: "Just-in-time access granted: " + grp + " for " + who,
			Body: lines("Just-in-time access to "+grp+" was granted to "+who+".", ends), Link: linkJIT}
	}
	if by != "" {
		m.Skip = []string{by}
	}
	_, err = Emit(tx, now, m, to...)
	return err
}

// PlanJITExpiring warns the requester and the person that approved
// just-in-time access ends soon.
func PlanJITExpiring(tx *store.TenantTx, now time.Time, r *store.AccessRequest) ([]*store.Notification, error) {
	if r.ExpiresAt == nil {
		return nil, nil
	}
	to, err := jitRecipients(tx, r)
	if err != nil {
		return nil, err
	}
	grp, err := groupName(tx, r.GroupID)
	if err != nil {
		return nil, err
	}
	who, err := personName(tx, r.IdentityID)
	if err != nil {
		return nil, err
	}
	return Plan(tx, now, Message{Kind: KindJITExpiring, Key: "jit.expiring:" + strconv.FormatInt(r.ID, 10) + ":" + timeutil.ISO(*r.ExpiresAt),
		Subject: "Just-in-time access ends soon: " + grp + " for " + who,
		Body:    lines("Just-in-time access to " + grp + " for " + who + " ends " + when(*r.ExpiresAt) + "."), Link: linkJIT}, to...)
}

// PlanRequestExpiring warns the requester and the beneficiary that approved
// access ends soon.
func PlanRequestExpiring(tx *store.TenantTx, now time.Time, l *store.RequestLine) ([]*store.Notification, error) {
	if l.ExpiresAt == nil {
		return nil, nil
	}
	to, err := lineRecipients(tx, l)
	if err != nil {
		return nil, err
	}
	grp, err := groupName(tx, l.GroupID)
	if err != nil {
		return nil, err
	}
	ben, err := personName(tx, l.BeneficiaryID)
	if err != nil {
		return nil, err
	}
	return Plan(tx, now, Message{Kind: KindRequestExpiring, Key: "request.expiring:" + l.ID + ":" + timeutil.ISO(*l.ExpiresAt),
		Subject: "Access ends soon: " + grp + " for " + ben,
		Body: lines("The access to "+grp+" for "+ben+" ends "+when(*l.ExpiresAt)+".",
			"Request it again if it is still needed."), Link: linkRequests}, to...)
}

// Ending describes something whose end date is near: an identity's end date
// or a grant's expiry (issue #159 calls Expiring for these).
type Ending struct {
	// Key identifies what ends ("identity:42", "grant:17"). The end date is
	// added to it, so a moved end date is a new notification and a repeated
	// call for the same date is not.
	Key        string
	IdentityID int64   // the person told: whose access or employment ends
	Also       []int64 // other people told, for example their manager
	What       string  // "Your contract", "Access to aws:ProdAdmin for Ada"
	EndsAt     time.Time
	Link       string // an app path; default "/access/mine"
}

// Expiring writes an "end date approaching" (KindAccessEnding) notification
// for the person and the identities in Also, in the caller's transaction.
// It is the producer for identity and grant end dates (#159): call it from
// the job that finds them within their warning window; calling it again for
// the same Key and EndsAt writes nothing. It returns how many it wrote.
func Expiring(tx *store.TenantTx, now time.Time, e Ending) (int, error) {
	link := e.Link
	if link == "" {
		link = "/access/mine"
	}
	var to []Recipient
	for _, id := range append([]int64{e.IdentityID}, e.Also...) {
		if id == 0 {
			continue
		}
		r, err := Identity(tx, id)
		if err != nil {
			return 0, err
		}
		to = append(to, r...)
	}
	return Emit(tx, now, Message{Kind: KindAccessEnding, Key: "access.ending:" + e.Key + ":" + timeutil.ISO(e.EndsAt),
		Subject: "Ends " + when(e.EndsAt) + ": " + clip(e.What, 120), Body: lines(clip(e.What, 300) + " ends " + when(e.EndsAt) + "."), Link: link}, to...)
}

// SecurityAlert writes a security alert that recipients cannot turn off. The
// admin-change notifications (#16) use it.
func SecurityAlert(tx *store.TenantTx, now time.Time, key, subject, body, link string, to ...Recipient) (int, error) {
	return Emit(tx, now, Message{Kind: KindSecurityAlert, Key: "security.alert:" + key, Subject: subject, Body: body, Link: link}, to...)
}
