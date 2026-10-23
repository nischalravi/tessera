package deleteguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Sources of a request (where the deletion came from).
const (
	SourceUser        = "user"
	SourceLoader      = "loader"
	SourceRule        = "rule"
	SourceConnector   = "connector"
	SourceProvisioner = "provisioner"
	SourceLifecycle   = "lifecycle"
	SourceSystem      = "system"
)

// Item is one thing a request would delete. Kind and Ref identify it for the code that applies it
// (a release looks it up again); Label is what a person reads.
type Item struct {
	Kind  string `json:"kind"`
	Ref   string `json:"ref"`
	Label string `json:"label"`
}

// Request is a batch of deletions of one category to vet.
type Request struct {
	Category string
	Items    []Item
	// Actor is the platform user who asked ("" when a worker did). Source says what kind of
	// caller it is and SourceID which one (the loader id, connector id, provisioner id).
	Actor    string
	Source   string
	SourceID string
	// SourceRef names the source whose own settings apply when it is not implied by Source and SourceID
	// (a loader, a connection) or by ScopeSource.
	SourceRef SourceRef
	// Correlation groups the calls of one request, run or sync: items held under the same
	// correlation join one hold. "" gives each call its own hold.
	Correlation string
	// SourceDriven marks a removal set computed from an inbound source feed (a sync, an import, a
	// loader): unless the tenant set the category's mode itself, the default for these is hold_all, so a
	// corrupted feed applies none of its removals.
	SourceDriven bool
	// Sanity are reasons the feed itself looks wrong (FeedChecks); any of them holds the whole batch
	// whatever the threshold. PrevCount and NewCount are the source's record counts before and now.
	Sanity              []string
	PrevCount, NewCount int
	// RunID names the run or request that made the call (the request id when empty and there is one);
	// a hold records it with the actor, see Contributor.
	RunID string
	// CoActors are further platform users answerable for the run besides Actor (a queued sync that
	// another admin retried): a hold records each as a contributor, so none of them can release it.
	CoActors []string
}

// DefaultFeedDropPercent is how far a source's record count may fall against the last good run
// before its removals are held whatever the thresholds say.
const DefaultFeedDropPercent = 20.0

// FeedChecks is FeedChecksWith under the default feed settings (sources.go).
func FeedChecks(prev, now int, partial string) []string {
	return FeedChecksWith(prev, now, partial, DefaultFeed())
}

// Decision is what Admit decided: the caller applies Applied and nothing else.
type Decision struct {
	Category  string `json:"category"`
	Attempted int    `json:"attempted"`
	Applied   []Item `json:"-"`
	Held      []Item `json:"-"`
	HoldID    string `json:"hold_id,omitempty"`
	// Limit is the threshold in force (nil: none); Used what the window held before this call.
	Limit         *int   `json:"limit"`
	Used          int    `json:"used"`
	WindowMinutes int    `json:"window_minutes"`
	Mode          string `json:"mode"`
}

// NApplied and NHeld are the counts.
func (d *Decision) NApplied() int { return len(d.Applied) }
func (d *Decision) NHeld() int    { return len(d.Held) }

// Summary says it in words, for the API and the UI ("Deleted 25 of 40: 15 held for approval (threshold 25 per hour)").
func (d *Decision) Summary() string {
	if len(d.Held) == 0 {
		return fmt.Sprintf("Deleted %d", len(d.Applied))
	}
	return fmt.Sprintf("Deleted %d of %d: %d held for approval (threshold %s)", len(d.Applied), d.Attempted, len(d.Held), d.thresholdText())
}

func (d *Decision) thresholdText() string {
	per := "per " + windowText(d.WindowMinutes)
	if d.Limit == nil {
		return "none"
	}
	return fmt.Sprintf("%d %s", *d.Limit, per)
}

func windowText(m int) string {
	switch {
	case m == 60:
		return "hour"
	case m == 1440:
		return "day"
	case m%60 == 0:
		return fmt.Sprintf("%d hours", m/60)
	}
	return fmt.Sprintf("%d minutes", m)
}

// Collector gathers the decisions of one API call, so it can answer 202 with what was applied and
// held. The zero value is ready; a nil *Collector ignores everything.
type Collector struct{ Decisions []*Decision }

// Add records a decision.
func (c *Collector) Add(d *Decision) {
	if c != nil && d != nil {
		c.Decisions = append(c.Decisions, d)
	}
}

// Held is the number of items held across the decisions.
func (c *Collector) Held() (n int) {
	if c != nil {
		for _, d := range c.Decisions {
			n += len(d.Held)
		}
	}
	return n
}

// Applied is the number of items applied across the decisions.
func (c *Collector) Applied() (n int) {
	if c != nil {
		for _, d := range c.Decisions {
			n += len(d.Applied)
		}
	}
	return n
}

// Last is the most recent decision that held something, or nil.
func (c *Collector) Last() *Decision {
	if c == nil {
		return nil
	}
	for i := len(c.Decisions) - 1; i >= 0; i-- {
		if len(c.Decisions[i].Held) > 0 {
			return c.Decisions[i]
		}
	}
	return nil
}

// Result is the body of a 202 answer.
type Result struct {
	Applied int    `json:"applied"`
	Held    int    `json:"held"`
	HoldID  string `json:"hold_id,omitempty"`
	Message string `json:"message"`
	// Threshold says the limit in force, e.g. "25 per hour".
	Threshold string `json:"threshold,omitempty"`
}

// Result sums the collector; nil when nothing was held.
func (c *Collector) Result() *Result {
	last := c.Last()
	if last == nil {
		return nil
	}
	applied, held, attempted := 0, 0, 0
	for _, d := range c.Decisions {
		applied += len(d.Applied)
		held += len(d.Held)
		attempted += d.Attempted
	}
	return &Result{Applied: applied, Held: held, HoldID: last.HoldID, Threshold: last.thresholdText(),
		Message: fmt.Sprintf("Deleted %d of %d: %d held for approval (threshold %s)", applied, attempted, held, last.thresholdText())}
}

// overrides marks the transactions that apply an approved release: whatever they delete is an
// approved override, not counted and not held (a release runs code that calls Admit again).
var overrides sync.Map // *store.TenantTx -> struct{}

// Overriding reports whether tx is applying an approved release.
func Overriding(tx *store.TenantTx) bool { _, ok := overrides.Load(tx); return ok }

// AdmitFrom is Admit for a path that has no actor of its own (an ingest, a job): the actor and
// source are read from the transaction's audit context (a signed-in user, or a named system job).
func AdmitFrom(tx *store.TenantTx, now time.Time, category, source, sourceID, correlation string, items ...Item) (*Decision, error) {
	return AdmitWith(tx, now, Request{Category: category, Items: items, Source: source, SourceID: sourceID, Correlation: correlation})
}

type requesterKey struct{}

// WithRequester names the platform users answerable for the work a worker is running (a queued sync:
// who queued it, and who retried it after it died, #495), so the holds it makes record each as a
// contributor and none of them can release them (#487). A run nobody
// queued (a schedule) carries none: its contributor has no actor and exempts no one.
func WithRequester(ctx context.Context, userIDs ...string) context.Context {
	var ids []string
	for _, id := range userIDs {
		if id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return ctx
	}
	return context.WithValue(ctx, requesterKey{}, ids)
}

// AdmitWith is AdmitFrom for a request built by the caller (a source-driven run with feed checks).
func AdmitWith(tx *store.TenantTx, now time.Time, req Request) (*Decision, error) {
	if ac, ok := store.AuditContextFrom(tx.Context()); ok {
		if ac.Actor.Type == "user" && ac.Actor.ID != nil {
			req.Actor = *ac.Actor.ID
			if req.Source == "" || req.Source == SourceSystem {
				req.Source = SourceUser
			}
		} else if req.SourceID == "" && ac.Actor.Display != nil {
			req.SourceID = *ac.Actor.Display
		}
	}
	if ids, ok := tx.Context().Value(requesterKey{}).([]string); ok {
		for _, id := range ids {
			if req.Actor == "" {
				req.Actor = id
			} else if id != req.Actor {
				req.CoActors = append(req.CoActors, id)
			}
		}
	}
	return Admit(tx, now, req)
}

// Admit vets a batch. It must run in the transaction that makes the deletions, and the caller
// must make exactly the Applied ones in it: the ledger rows and the hold commit with them.
func Admit(tx *store.TenantTx, now time.Time, req Request) (*Decision, error) {
	if !ValidCategory(req.Category) {
		return nil, fmt.Errorf("deleteguard: %q is not a category", req.Category)
	}
	items := append([]Item(nil), req.Items...)
	sortItems(items)
	d := &Decision{Category: req.Category, Attempted: len(items)}
	if len(items) == 0 {
		return d, nil
	}
	if Overriding(tx) {
		d.Applied = items
		return d, nil
	}
	ref := refOf(tx, req)
	tp, err := PolicyOf(tx, req.Category)
	if err != nil {
		return nil, err
	}
	ov, err := SourcePolicyOf(tx, ref, req.Category)
	if err != nil {
		return nil, err
	}
	res := Resolve(tp, ov, req.SourceDriven)
	pol := res.Policy
	d.Mode, d.WindowMinutes = pol.Mode, pol.WindowMinutes
	if pol.Mode == ModeOff {
		d.Applied = items
		return d, nil
	}
	// serialize with every other check of the category until this transaction ends
	if err := tx.LockDeletionCategory(req.Category); err != nil {
		return nil, err
	}
	pop := 0
	if pol.MaxPercent != nil {
		if pop, err = tx.DeletionPopulation(req.Category); err != nil {
			return nil, err
		}
		if res.Overridden {
			// the percent of what the source itself reported last time, when it has reported
			if n, ok, err := tx.DeletionSourceCount(ref.Kind, ref.ID, req.Category); err != nil {
				return nil, err
			} else if ok && n > 0 {
				pop = n
			}
		}
	}
	var used int
	if res.Overridden {
		used, err = tx.DeletionsAppliedBySource(ref.Kind, ref.ID, req.Category, now.Add(-pol.Window()))
	} else {
		used, err = tx.DeletionsApplied(req.Category, now.Add(-pol.Window()))
	}
	if err != nil {
		return nil, err
	}
	d.Used, d.Limit = used, pol.Limit(pop)
	room := len(items)
	if d.Limit != nil {
		room = max(*d.Limit-used, 0)
	}
	holdAll := pol.Mode == ModeHoldAll
	if res.Overridden {
		// A source's own threshold bounds the source; it does not lift it out of the tenant-wide
		// budget (#485). Every deletion also counts against the category's limit, so N sources with
		// identical overrides cannot apply N times what the category allows in one window. An override
		// is its own budget only when two admins approved it as looser than the category (recorded when
		// the change was approved, #494) and it still is: a category tightened later by one admin never
		// turns an override into one.
		cat := Resolve(tp, nil, req.SourceDriven)
		catPop, err := tx.DeletionPopulation(req.Category)
		if err != nil {
			return nil, err
		}
		approved, err := tx.DeletionSourceApproved(ref.Kind, ref.ID, req.Category)
		if err != nil {
			return nil, err
		}
		if cat.Mode != ModeOff && !(approved && Loosens(cat.Policy, pol, catPop)) {
			catUsed, err := tx.DeletionsApplied(req.Category, now.Add(-cat.Window()))
			if err != nil {
				return nil, err
			}
			if cl := cat.Limit(catPop); cl != nil {
				if catRoom := max(*cl-catUsed, 0); catRoom < room {
					room, d.Limit, d.Used, d.WindowMinutes, d.Mode = catRoom, cl, catUsed, cat.WindowMinutes, cat.Mode
					holdAll = cat.Mode == ModeHoldAll
				} else if len(items) > catRoom && cat.Mode == ModeHoldAll {
					holdAll = true
				}
			}
		}
	}
	switch {
	case len(req.Sanity) > 0:
		d.Held = items // a broken feed: everything it would remove is held, whatever the room
	case len(items) <= room:
		d.Applied = items
	case holdAll:
		d.Held = items
	default:
		d.Applied, d.Held = items[:room], items[room:]
	}
	if err := tx.RecordDeletions(req.Category, len(d.Applied), req.Source, now, now.Add(-pol.Window()-MaxPrune)); err != nil {
		return nil, err
	}
	if ref.Valid() {
		if err := tx.RecordSourceDeletions(ref.Kind, ref.ID, req.Category, len(d.Applied), now, now.Add(-pol.Window()-MaxPrune)); err != nil {
			return nil, err
		}
	}
	if len(d.Held) == 0 {
		return d, nil
	}
	if err := hold(tx, now, req, res, ref, pop, d); err != nil {
		return nil, err
	}
	return d, nil
}

// MaxPrune is how long past its window a ledger row is kept (for the usage the UI shows).
const MaxPrune = 24 * time.Hour

// reason is the JSON a hold keeps about why it was made.
type reason struct {
	Category      string   `json:"category"`
	WindowMinutes int      `json:"window_minutes"`
	MaxCount      *int     `json:"max_count"`
	MaxPercent    *float64 `json:"max_percent"`
	Population    int      `json:"population"`
	Limit         *int     `json:"limit"`
	UsedBefore    int      `json:"used_before"`
	Attempted     int      `json:"attempted"`
	Applied       int      `json:"applied"`
	Mode          string   `json:"mode"`
	Sanity        []string `json:"sanity,omitempty"`
	PreviousCount int      `json:"previous_count,omitempty"`
	NewCount      int      `json:"new_count,omitempty"`
	SourceDriven  bool     `json:"source_driven,omitempty"`
	// SourceKind and SourceRef name the source whose settings were in force; SourceOverride says they
	// were its own thresholds.
	SourceKind     string `json:"source_kind,omitempty"`
	SourceRef      string `json:"source_ref,omitempty"`
	SourceOverride bool   `json:"source_override,omitempty"`
	// Contributors are every actor and run that added items to the hold, the first run included.
	// A release is refused to any of them (#467).
	Contributors []Contributor `json:"contributors,omitempty"`
}

// Contributor is one run that added items to a hold: who (a platform user id, "" for a worker),
// from which source and run, when, and how many items it added.
type Contributor struct {
	Actor    string    `json:"actor,omitempty"`
	Source   string    `json:"source,omitempty"`
	SourceID string    `json:"source_id,omitempty"`
	RunID    string    `json:"run_id,omitempty"`
	At       time.Time `json:"at"`
	Added    int       `json:"added"`
}

// contributorsOf is the contributor of the run, and one for each co-actor.
func contributorsOf(tx *store.TenantTx, now time.Time, req Request, added int) []Contributor {
	out := []Contributor{contributorOf(tx, now, req, added)}
	for _, id := range req.CoActors {
		c := out[0]
		c.Actor = id
		out = append(out, c)
	}
	return out
}

func contributorOf(tx *store.TenantTx, now time.Time, req Request, added int) Contributor {
	run := req.RunID
	if run == "" {
		if ac, ok := store.AuditContextFrom(tx.Context()); ok && ac.RequestID != nil {
			run = *ac.RequestID
		}
	}
	return Contributor{Actor: req.Actor, Source: orSource(req.Source), SourceID: req.SourceID, RunID: run, At: now.UTC(), Added: added}
}

// MaxContributors is how many entries a hold keeps before they are collapsed to one per actor and source.
const MaxContributors = 100

// addContributor records c once per (actor, source, source id, run): a run that extends a hold again
// adds to its entry, so a hold's reason does not grow with the items or calls of a run (#486). Past
// MaxContributors the run ids are dropped and entries merge per actor and source; the actors, which a
// release is refused to, are never dropped.
func addContributor(list []Contributor, c Contributor) []Contributor {
	for i := range list {
		if o := &list[i]; o.Actor == c.Actor && o.Source == c.Source && o.SourceID == c.SourceID && o.RunID == c.RunID {
			o.Added += c.Added
			o.At = c.At
			return list
		}
	}
	list = append(list, c)
	if len(list) <= MaxContributors {
		return list
	}
	out := list[:0:0]
	for _, x := range list {
		x.RunID = ""
		merged := false
		for i := range out {
			if o := &out[i]; o.Actor == x.Actor && o.Source == x.Source && o.SourceID == x.SourceID {
				o.Added += x.Added
				if x.At.After(o.At) {
					o.At = x.At
				}
				merged = true
				break
			}
		}
		if !merged {
			out = append(out, x)
		}
	}
	return out
}

// Contributors reads them back from a hold's reason; a hold from before they were kept has none and
// is judged by its actor alone.
func Contributors(h *store.DeletionHold) []Contributor {
	var r reason
	if json.Unmarshal([]byte(h.Reason), &r) != nil {
		return nil
	}
	return r.Contributors
}

func hold(tx *store.TenantTx, now time.Time, req Request, res Resolved, ref SourceRef, pop int, d *Decision) error {
	pol := res.Policy
	items := make([]store.DeletionHoldItem, len(d.Held))
	for i, it := range d.Held {
		items[i] = store.DeletionHoldItem{Kind: it.Kind, Ref: it.Ref, Label: it.Label}
	}
	corr := req.Correlation
	var h *store.DeletionHold
	if corr != "" {
		switch found, err := tx.OpenDeletionHoldByCorrelation(req.Category, corr); {
		case err == nil:
			h = found
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
	}
	if h != nil {
		// an item already held (a retried run) is not held twice
		have, err := tx.DeletionHoldItems(h.ID)
		if err != nil {
			return err
		}
		held := make(map[[2]string]bool, len(have))
		for _, it := range have {
			held[[2]string{it.Kind, it.Ref}] = true
		}
		fresh := items[:0:0]
		for _, it := range items {
			if !held[[2]string{it.Kind, it.Ref}] {
				fresh = append(fresh, it)
			}
		}
		if len(fresh) == 0 {
			d.HoldID = h.ID
			return nil
		}
		items = fresh
		if err := tx.AppendDeletionHoldItems(h, items); err != nil {
			return err
		}
		// the hold now also describes this run: who added items, and the sanity counts the approver sees
		var rs reason
		if json.Unmarshal([]byte(h.Reason), &rs) == nil {
			for _, c := range contributorsOf(tx, now, req, len(items)) {
				rs.Contributors = addContributor(rs.Contributors, c)
			}
			rs.Attempted += d.Attempted
			rs.Applied += len(d.Applied)
			if req.NewCount > 0 || req.PrevCount > 0 {
				rs.PreviousCount, rs.NewCount = req.PrevCount, req.NewCount
			}
			for _, sn := range req.Sanity {
				if !slices.Contains(rs.Sanity, sn) {
					rs.Sanity = append(rs.Sanity, sn)
				}
			}
			raw, err := json.Marshal(rs)
			if err != nil {
				return err
			}
			h.Reason = string(raw)
			if err := tx.SetDeletionHoldReason(h.ID, h.Reason); err != nil {
				return err
			}
		}
		d.HoldID = h.ID
		return audit(tx, now, "deletion_guard.hold_extended", h, ojson.Object{{Key: "hold_id", Value: h.ID},
			{Key: "category", Value: h.Category}, {Key: "added", Value: len(items)}, {Key: "items", Value: h.ItemCount}, {Key: "actor", Value: req.Actor}, {Key: "run_id", Value: contributorOf(tx, now, req, 0).RunID},
			{Key: "correlation_id", Value: corr}})
	}
	if corr == "" {
		corr = uuid.NewString()
	}
	hours, err := HoldExpiryHours(tx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(reason{Category: req.Category, WindowMinutes: pol.WindowMinutes, MaxCount: pol.MaxCount,
		MaxPercent: pol.MaxPercent, Population: pop, Limit: d.Limit, UsedBefore: d.Used, Attempted: d.Attempted,
		Applied: len(d.Applied), Mode: pol.Mode, Sanity: req.Sanity, PreviousCount: req.PrevCount, NewCount: req.NewCount,
		SourceDriven: req.SourceDriven, SourceKind: ref.Kind, SourceRef: ref.ID, SourceOverride: res.Overridden,
		Contributors: contributorsOf(tx, now, req, len(items))})
	if err != nil {
		return err
	}
	h = &store.DeletionHold{Category: req.Category, Mode: pol.Mode, Reason: string(raw), Actor: req.Actor, Source: orSource(req.Source),
		SourceID: req.SourceID, CorrelationID: corr, CreatedAt: now, ExpiresAt: now.Add(time.Duration(hours) * time.Hour)}
	if err := tx.InsertDeletionHold(h, items); err != nil {
		return err
	}
	d.HoldID = h.ID
	if err := openTask(tx, now, h, d); err != nil {
		return err
	}
	return audit(tx, now, "deletion_guard.held", h, ojson.Object{{Key: "hold_id", Value: h.ID}, {Key: "category", Value: h.Category},
		{Key: "mode", Value: pol.Mode}, {Key: "window_minutes", Value: pol.WindowMinutes}, {Key: "limit", Value: d.Limit},
		{Key: "used_before", Value: d.Used}, {Key: "attempted", Value: d.Attempted}, {Key: "applied", Value: len(d.Applied)},
		{Key: "held", Value: len(d.Held)}, {Key: "actor", Value: req.Actor}, {Key: "source", Value: h.Source},
		{Key: "source_id", Value: req.SourceID}, {Key: "correlation_id", Value: corr}})
}

func orSource(s string) string {
	if s == "" {
		return SourceSystem
	}
	return s
}

func audit(tx *store.TenantTx, now time.Time, action string, h *store.DeletionHold, detail ojson.Object) error {
	_, err := tx.RecordAudit(store.AuditRecord{At: now, Action: action, LegacyActor: "deleteguard", TargetType: "deletion_hold",
		TargetID: h.ID, Detail: detail})
	return err
}
