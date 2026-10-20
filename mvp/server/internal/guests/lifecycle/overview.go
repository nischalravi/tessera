package guestlife

import (
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Buckets of the Governance → Guest lifecycle page: each is a count and a list.
const (
	BucketExpiring30      = "expiring_30"
	BucketExpiring14      = "expiring_14"
	BucketExpiring3       = "expiring_3"
	BucketPendingTransfer = "pending_transfer"
	BucketAutoEnded       = "auto_ended"
	BucketSuspended       = "suspended"
	BucketInGrace         = "in_grace"
	BucketDeprovisioned   = "deprovisioned"
	BucketPurged          = "purged"
	BucketStepUp          = "stepup_required"
	BucketRenewals        = "renewal_requests"
	BucketDualStatus      = "dual_status"
)

// Buckets lists every bucket in display order.
var Buckets = []string{BucketExpiring30, BucketExpiring14, BucketExpiring3, BucketRenewals, BucketStepUp, BucketPendingTransfer,
	BucketAutoEnded, BucketSuspended, BucketDualStatus, BucketInGrace, BucketDeprovisioned, BucketPurged}

// Person is a person as the lifecycle page names them.
type Person struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Item is one row of a bucket's list.
type Item struct {
	SponsorshipID string     `json:"sponsorship_id,omitempty"`
	TaskID        string     `json:"task_id,omitempty"`
	TaskKind      string     `json:"task_kind,omitempty"`
	Guest         Person     `json:"guest"`
	Sponsor       *Person    `json:"sponsor,omitempty"`
	Population    string     `json:"population,omitempty"`
	Status        string     `json:"status,omitempty"` // sponsorship status or deprovisioning stage
	EndsAt        *time.Time `json:"ends_at,omitempty"`
	DaysLeft      *int       `json:"days_left,omitempty"`
	Deadline      *time.Time `json:"deadline,omitempty"`
	Outcome       string     `json:"outcome,omitempty"`
	Trigger       string     `json:"trigger,omitempty"`
	GraceUntil    *time.Time `json:"grace_until,omitempty"`
	RetentionEnd  *time.Time `json:"retention_until,omitempty"`
	HeldAccess    *bool      `json:"held_access,omitempty"`
	RequiredIAL   int        `json:"required_ial,omitempty"`
	// CanAct is true when the viewer may decide the task (set by the API).
	CanAct bool `json:"can_act"`
}

// Overview is the counts of the page.
type Overview struct {
	Counts   map[string]int `json:"counts"`
	Settings store.GuestLifecycleSettings
}

type namer struct {
	tx *store.TenantTx
	m  map[int64]Person
}

func (n *namer) person(id int64) (Person, error) {
	if p, ok := n.m[id]; ok {
		return p, nil
	}
	i, err := n.tx.Identity(id)
	p := Person{ID: id, Name: "someone"}
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return p, err
	default:
		p.Name = i.Name
	}
	n.m[id] = p
	return p, nil
}

// Items returns the rows of a bucket, soonest first.
func Items(tx *store.TenantTx, bucket string, now time.Time) ([]Item, error) {
	if !slices.Contains(Buckets, bucket) {
		return nil, refuse(422, "invalid_bucket", "bucket is one of %v", Buckets)
	}
	nm := &namer{tx: tx, m: map[int64]Person{}}
	var out []Item
	spItem := func(ss *store.Sponsorship) (Item, error) {
		g, err := nm.person(ss.GuestIdentityID)
		if err != nil {
			return Item{}, err
		}
		sp, err := nm.person(ss.SponsorIdentityID)
		if err != nil {
			return Item{}, err
		}
		it := Item{SponsorshipID: ss.ID, Guest: g, Sponsor: &sp, Population: ss.Population, Status: ss.Status, EndsAt: &ss.EndsAt,
			RequiredIAL: ss.RequiredIAL}
		d := daysLeft(ss.EndsAt, now)
		it.DaysLeft = &d
		return it, nil
	}
	taskItem := func(t *store.LifecycleTask) (Item, error) {
		ss, err := tx.Sponsorship(t.SponsorshipID)
		if err != nil {
			return Item{}, err
		}
		it, err := spItem(ss)
		if err != nil {
			return it, err
		}
		it.TaskID, it.TaskKind, it.Deadline, it.Trigger = t.ID, t.Kind, t.Deadline, t.Trigger
		if t.Outcome != nil {
			it.Outcome = *t.Outcome
		}
		if t.Kind == store.TaskSponsorTransfer { // the person who left is the one the task is about
			p, err := nm.person(t.SubjectIdentityID)
			if err != nil {
				return it, err
			}
			it.Sponsor = &p
		}
		return it, nil
	}
	switch bucket {
	case BucketExpiring30, BucketExpiring14, BucketExpiring3:
		n := map[string]int{BucketExpiring30: 30, BucketExpiring14: 14, BucketExpiring3: 3}[bucket]
		sps, err := tx.Sponsorships(store.SponsorshipFilter{Status: store.SponsorActive})
		if err != nil {
			return nil, err
		}
		for _, ss := range sps {
			if ss.EndsAt.After(now) && !ss.EndsAt.After(now.AddDate(0, 0, n)) {
				it, err := spItem(ss)
				if err != nil {
					return nil, err
				}
				out = append(out, it)
			}
		}
		slices.SortFunc(out, func(a, b Item) int { return a.EndsAt.Compare(*b.EndsAt) })
	case BucketPendingTransfer, BucketRenewals, BucketDualStatus:
		kind := map[string]string{BucketPendingTransfer: store.TaskSponsorTransfer, BucketRenewals: store.TaskRenewalRequest,
			BucketDualStatus: store.TaskDualStatus}[bucket]
		ts, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Kind: kind, Status: store.TaskOpen})
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			it, err := taskItem(t)
			if err != nil {
				return nil, err
			}
			out = append(out, it)
		}
	case BucketAutoEnded:
		ts, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Kind: store.TaskSponsorTransfer})
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if t.Outcome != nil && (*t.Outcome == store.OutcomeEnded || *t.Outcome == store.OutcomeSuspended) {
				it, err := taskItem(t)
				if err != nil {
					return nil, err
				}
				out = append(out, it)
			}
		}
	case BucketSuspended:
		sps, err := tx.Sponsorships(store.SponsorshipFilter{Status: store.SponsorSuspended})
		if err != nil {
			return nil, err
		}
		for _, ss := range sps {
			it, err := spItem(ss)
			if err != nil {
				return nil, err
			}
			out = append(out, it)
		}
	case BucketStepUp:
		ups, err := tx.Stepups(store.StepupPending, "")
		if err != nil {
			return nil, err
		}
		for _, u := range ups {
			ss, err := tx.Sponsorship(u.SponsorshipID)
			if err != nil {
				return nil, err
			}
			it, err := spItem(ss)
			if err != nil {
				return nil, err
			}
			it.RequiredIAL = u.RequiredIAL
			it.Deadline = &u.RequestedEndsAt // the end the renewal asks for
			out = append(out, it)
		}
	case BucketInGrace, BucketDeprovisioned, BucketPurged:
		stage := map[string]string{BucketInGrace: store.StageGrace, BucketDeprovisioned: store.StageDeprovisioned, BucketPurged: store.StagePurged}[bucket]
		rows, err := tx.DeprovisioningList(stage)
		if err != nil {
			return nil, err
		}
		for _, d := range rows {
			g, err := nm.person(d.IdentityID)
			if err != nil {
				return nil, err
			}
			held := d.HeldAccess
			out = append(out, Item{Guest: g, Population: d.Population, Status: d.Stage, EndsAt: &d.EndedAt, GraceUntil: &d.GraceUntil,
				RetentionEnd: &d.RetentionUntil, HeldAccess: &held})
		}
	}
	if out == nil {
		out = []Item{}
	}
	return out, nil
}

// Counts returns the number in each bucket.
func Counts(tx *store.TenantTx, now time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, b := range Buckets {
		items, err := Items(tx, b, now)
		if err != nil {
			return nil, err
		}
		out[b] = len(items)
	}
	return out, nil
}
