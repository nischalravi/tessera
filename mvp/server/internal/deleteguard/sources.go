package deleteguard

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Per-source settings. A source (a connection, a group loader, a VMS feed, a SCIM client) may carry
// its own threshold per category in place of the category's, and its own feed sanity checks: how far
// its record count may fall against its last good run, and whether an empty feed is held. Rows are
// stored by schema/0690 and change through the admin change request deletion_guard.update (a
// looser setting takes two admins).

// Source kinds.
const (
	SrcConnection = "connection"
	SrcLoader     = "loader"
	SrcVMS        = "vms_source"
	SrcSCIM       = "scim_client"
)

// SourceKinds lists them.
var SourceKinds = []string{SrcConnection, SrcLoader, SrcVMS, SrcSCIM}

// SourceCategories are the categories each kind of source deletes in (what its settings page shows).
var SourceCategories = map[string][]string{
	SrcConnection: {CatAccounts, CatIdentities},
	SrcLoader:     {CatMembers},
	SrcVMS:        {CatIdentities, CatAccounts},
	SrcSCIM:       {CatGroups, CatMembers, CatAccounts, CatIdentities},
}

// SourceRef names a source.
type SourceRef struct{ Kind, ID string }

// Valid says whether r names a source.
func (r SourceRef) Valid() bool { return r.ID != "" && ValidSourceKind(r.Kind) }

// ValidSourceKind says whether k is a source kind.
func ValidSourceKind(k string) bool {
	for _, s := range SourceKinds {
		if s == k {
			return true
		}
	}
	return false
}

// The feed sanity defaults.
const DefaultFeedEmptyCheck = true

// Feed is a source's feed sanity settings for a category.
type Feed struct {
	// DropPercent is how far the record count may fall against the last good run (0 to 100; 100 never trips).
	DropPercent float64 `json:"drop_percent"`
	// EmptyCheck holds the removals of an empty feed whatever DropPercent says.
	EmptyCheck bool `json:"empty_check"`
}

// DefaultFeed is the feed sanity of a source with no settings.
func DefaultFeed() Feed {
	return Feed{DropPercent: DefaultFeedDropPercent, EmptyCheck: DefaultFeedEmptyCheck}
}

// SourcePolicy is a source's override for one category. Mode "" inherits the category's thresholds
// (MaxCount, MaxPercent and WindowMinutes unset); FeedDropPercent nil and FeedEmptyCheck nil are the defaults.
type SourcePolicy struct {
	Kind            string     `json:"kind"`
	SourceID        string     `json:"source_id"`
	Category        string     `json:"category"`
	Mode            string     `json:"mode,omitempty"`
	MaxCount        *int       `json:"max_count"`
	MaxPercent      *float64   `json:"max_percent"`
	WindowMinutes   int        `json:"window_minutes,omitempty"`
	FeedDropPercent *float64   `json:"feed_drop_percent"`
	FeedEmptyCheck  *bool      `json:"feed_empty_check"`
	Version         int        `json:"version,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

// Ref is the source the policy is for.
func (p SourcePolicy) Ref() SourceRef { return SourceRef{p.Kind, p.SourceID} }

// Check validates an override.
func (p SourcePolicy) Check() error {
	if !p.Ref().Valid() {
		return fmt.Errorf("%q is not a source kind (connection, loader, vms_source, scim_client) with an id", p.Kind)
	}
	if !ValidCategory(p.Category) {
		return fmt.Errorf("%q is not a deletion category", p.Category)
	}
	if p.Mode == "" {
		if p.MaxCount != nil || p.MaxPercent != nil || p.WindowMinutes != 0 {
			return errors.New("max_count, max_percent and window_minutes need a mode")
		}
	} else if err := (Policy{Category: p.Category, MaxCount: p.MaxCount, MaxPercent: p.MaxPercent, WindowMinutes: p.WindowMinutes, Mode: p.Mode}).Check(); err != nil {
		return err
	}
	if p.FeedDropPercent != nil && (math.IsNaN(*p.FeedDropPercent) || *p.FeedDropPercent < 0 || *p.FeedDropPercent > 100) {
		return fmt.Errorf("%s: feed_drop_percent is 0 to 100", p.Category)
	}
	if p.Mode == "" && p.FeedDropPercent == nil && p.FeedEmptyCheck == nil {
		return fmt.Errorf("%s: set a mode with thresholds, feed_drop_percent or feed_empty_check, or remove the override", p.Category)
	}
	return nil
}

// Feed is the feed sanity the override sets (the defaults where it sets none).
// FeedSettings is the feed sanity the override sets (the defaults where it sets none).
func (p SourcePolicy) FeedSettings() Feed { return p.feed() }

func (p *SourcePolicy) feed() Feed {
	f := DefaultFeed()
	if p != nil {
		if p.FeedDropPercent != nil {
			f.DropPercent = *p.FeedDropPercent
		}
		if p.FeedEmptyCheck != nil {
			f.EmptyCheck = *p.FeedEmptyCheck
		}
	}
	return f
}

// SourcePolicyFromRow converts a stored override.
func SourcePolicyFromRow(r *store.DeletionSourcePolicy) *SourcePolicy { return fromSourceRow(r) }

func fromSourceRow(r *store.DeletionSourcePolicy) *SourcePolicy {
	if r == nil {
		return nil
	}
	at := r.UpdatedAt
	return &SourcePolicy{Kind: r.Kind, SourceID: r.SourceID, Category: r.Category, Mode: r.Mode, MaxCount: r.MaxCount, MaxPercent: r.MaxPercent,
		WindowMinutes: r.WindowMinutes, FeedDropPercent: r.FeedDropPercent, FeedEmptyCheck: r.FeedEmptyCheck, Version: r.Version, UpdatedAt: &at}
}

// Resolved is what applies to a source's deletions of a category.
type Resolved struct {
	Policy
	Feed Feed `json:"feed"`
	// Overridden says the source's own thresholds are in force (not the category's).
	Overridden bool `json:"overridden"`
}

// Resolve gives the settings in force for a source: its override where it has one, otherwise the
// category's. A source-driven run under a category whose mode the tenant never set holds the whole set
// past the threshold (hold_all), as Admit does.
func Resolve(tenant Policy, ov *SourcePolicy, sourceDriven bool) Resolved {
	r := Resolved{Policy: tenant, Feed: ov.feed()}
	if ov != nil && ov.Mode != "" {
		r.Policy = Policy{Category: tenant.Category, MaxCount: ov.MaxCount, MaxPercent: ov.MaxPercent, WindowMinutes: ov.WindowMinutes,
			Mode: ov.Mode, Version: ov.Version, UpdatedAt: ov.UpdatedAt}
		r.Overridden = true
	}
	if sourceDriven && r.Default && r.Mode == ModeHoldExcess {
		r.Mode = ModeHoldAll
	}
	return r
}

// LoosensResolved reports whether next is a weaker safety setting than cur: a weaker mode or a higher
// limit per minute of window (as Loosens), a higher feed drop percent, or the empty feed check turned off.
func LoosensResolved(cur, next Resolved, pop int) bool {
	if Loosens(cur.Policy, next.Policy, pop) {
		return true
	}
	return next.Feed.DropPercent > cur.Feed.DropPercent || (cur.Feed.EmptyCheck && !next.Feed.EmptyCheck)
}

// SourcePolicyOf returns a source's override of a category, nil when it has none.
func SourcePolicyOf(tx *store.TenantTx, ref SourceRef, category string) (*SourcePolicy, error) {
	if !ref.Valid() {
		return nil, nil
	}
	r, err := tx.DeletionSourcePolicy(ref.Kind, ref.ID, category)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromSourceRow(r), nil
}

// ResolveFor gives the settings in force for a source and category.
func ResolveFor(tx *store.TenantTx, ref SourceRef, category string, sourceDriven bool) (Resolved, error) {
	tp, err := PolicyOf(tx, category)
	if err != nil {
		return Resolved{}, err
	}
	ov, err := SourcePolicyOf(tx, ref, category)
	if err != nil {
		return Resolved{}, err
	}
	return Resolve(tp, ov, sourceDriven), nil
}

// SetSource stores a source's override (the admin change that applies it has checked who may).
func SetSource(tx *store.TenantTx, p SourcePolicy, by *string, now time.Time) error {
	if err := p.Check(); err != nil {
		return err
	}
	return tx.PutDeletionSourcePolicy(&store.DeletionSourcePolicy{Kind: p.Kind, SourceID: p.SourceID, Category: p.Category, Mode: p.Mode,
		MaxCount: p.MaxCount, MaxPercent: p.MaxPercent, WindowMinutes: p.WindowMinutes, FeedDropPercent: p.FeedDropPercent,
		FeedEmptyCheck: p.FeedEmptyCheck, UpdatedBy: by}, now)
}

// SetSourceApproved records that the source's override of the category was approved by two admins
// as looser than the category's setting at that time (false clears it). Admit exempts an override
// from the category's tenant-wide budget only when this holds (#494): the judgement is made when the
// change is approved, not from whatever the category is later set to.
func SetSourceApproved(tx *store.TenantTx, ref SourceRef, category string, approved bool, by *string, now time.Time) error {
	return tx.SetDeletionSourceApproved(ref.Kind, ref.ID, category, approved, by, now)
}

// FeedChecksWith says why a feed looks broken under f: reported as a partial or failed read (partial
// is the reason, "" if not), empty (when f.EmptyCheck), or shorter than the last good run by more than
// f.DropPercent. With the empty check off an empty feed is judged by the percent alone.
func FeedChecksWith(prev, now int, partial string, f Feed) []string {
	var out []string
	if partial != "" {
		out = append(out, "the source reported a partial or failed read: "+partial)
	}
	if now == 0 && prev > 0 && f.EmptyCheck {
		out = append(out, fmt.Sprintf("the feed is empty (the last good run had %d records)", prev))
	} else if prev > 0 && now < prev {
		if pct := 100 * float64(prev-now) / float64(prev); pct > f.DropPercent {
			out = append(out, fmt.Sprintf("the feed has %d records, %.0f%% fewer than the last good run's %d (limit %.0f%%)", now, pct, prev, f.DropPercent))
		}
	}
	return out
}

// CheckFeed is FeedChecksWith under the source's settings for the category (the defaults for a
// source with none, or none named).
func CheckFeed(tx *store.TenantTx, ref SourceRef, category string, prev, now int, partial string) ([]string, error) {
	ov, err := SourcePolicyOf(tx, ref, category)
	if err != nil {
		return nil, err
	}
	return FeedChecksWith(prev, now, partial, ov.feed()), nil
}

// PreviousCount is the record count a source's next feed is measured against: that of its last good
// run, or fallback when the source has none yet (its first run).
func PreviousCount(tx *store.TenantTx, ref SourceRef, category string, fallback int) (int, error) {
	if !ref.Valid() {
		return fallback, nil
	}
	n, ok, err := tx.DeletionSourceCount(ref.Kind, ref.ID, category)
	if err != nil || !ok {
		return fallback, err
	}
	return n, nil
}

// RecordGoodRun keeps the record count of a run the sanity checks passed, the basis of the next.
func RecordGoodRun(tx *store.TenantTx, now time.Time, ref SourceRef, category string, n int) error {
	if !ref.Valid() {
		return nil
	}
	return tx.PutDeletionSourceCount(ref.Kind, ref.ID, category, n, now)
}

// scopes marks the transactions that run on behalf of a source whose caller does not pass it down
// (the lifecycle leaver path of a VMS feed).
var scopes sync.Map // *store.TenantTx -> SourceRef

// ScopeSource says that deletions admitted in tx without a source of their own come from ref, until
// the returned function is called.
func ScopeSource(tx *store.TenantTx, ref SourceRef) (restore func()) {
	prev, had := scopes.Load(tx)
	scopes.Store(tx, ref)
	return func() {
		if had {
			scopes.Store(tx, prev)
		} else {
			scopes.Delete(tx)
		}
	}
}

// ScopeOf is the source tx is scoped to (the zero SourceRef when none).
func ScopeOf(tx *store.TenantTx) SourceRef {
	if v, ok := scopes.Load(tx); ok {
		return v.(SourceRef)
	}
	return SourceRef{}
}

// refOf is the source a request comes from: the one it names (a loader, a connection), else the scope.
func refOf(tx *store.TenantTx, req Request) SourceRef {
	if req.SourceRef.Valid() {
		return req.SourceRef
	}
	switch req.Source {
	case SourceLoader:
		return SourceRef{SrcLoader, req.SourceID}
	case SourceConnector, SourceProvisioner:
		return SourceRef{SrcConnection, req.SourceID}
	}
	if v, ok := scopes.Load(tx); ok {
		return v.(SourceRef)
	}
	return SourceRef{}
}

// SourceUsage is one override with its window usage, for the settings pages and the list.
type SourceView struct {
	Category string `json:"category"`
	// Tenant is the category's own setting; Override the source's (nil: none); Effective what applies.
	Tenant    Policy        `json:"tenant"`
	Override  *SourcePolicy `json:"override"`
	Effective Resolved      `json:"effective"`
	// LastCount is the record count of the source's last good run (nil: none yet).
	LastCount *int `json:"last_count"`
	Used      int  `json:"used"`
	Limit     *int `json:"limit"`
}

// ViewSource reports a source's settings for the categories it deletes in.
func ViewSource(tx *store.TenantTx, ref SourceRef, now time.Time) ([]SourceView, error) {
	var out []SourceView
	for _, c := range SourceCategories[ref.Kind] {
		tp, err := PolicyOf(tx, c)
		if err != nil {
			return nil, err
		}
		ov, err := SourcePolicyOf(tx, ref, c)
		if err != nil {
			return nil, err
		}
		res := Resolve(tp, ov, true)
		v := SourceView{Category: c, Tenant: tp, Override: ov, Effective: res}
		if n, ok, err := tx.DeletionSourceCount(ref.Kind, ref.ID, c); err != nil {
			return nil, err
		} else if ok {
			v.LastCount = &n
		}
		pop, err := tx.DeletionPopulation(c)
		if err != nil {
			return nil, err
		}
		if res.Overridden {
			if v.Used, err = tx.DeletionsAppliedBySource(ref.Kind, ref.ID, c, now.Add(-res.Window())); err != nil {
				return nil, err
			}
			if v.LastCount != nil && *v.LastCount > 0 {
				pop = *v.LastCount
			}
		} else if v.Used, err = tx.DeletionsApplied(c, now.Add(-res.Window())); err != nil {
			return nil, err
		}
		v.Limit = res.Limit(pop)
		out = append(out, v)
	}
	return out, nil
}
