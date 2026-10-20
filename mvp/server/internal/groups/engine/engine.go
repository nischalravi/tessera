// Package engine is the membership engine of native groups (design
// docs/design/groups-grouper-parity.md §6): it keeps grp_effective, the
// materialized members of every group, equal to what the stored inputs say.
//
// Stored inputs: direct memberships, nesting and factor edges (grp_deps) and
// composite definitions. Derived: grp_closure, grp_levels, grp_effective.
//
// A change produces seeds, "recompute group g, list L, identity i". The engine
// processes seeds in ascending grp_levels order, so a composite is evaluated
// after its factors are final, and it follows an identity upward only while
// that identity's membership of a group actually changes (support counts stop
// the walk early). Each seed recomputes the truth from the stored rows rather
// than adding or subtracting one, which makes the result independent of the
// order work arrives in: a queued recompute can interleave with direct changes
// and the engine still converges to the semantics of §6.1.
//
// The engine runs inside the caller's tenant transaction, so a change commits
// together with its audit event. Work that does not fit the synchronous
// budget is queued (budget.go) and drained in chunks by the Runner.
package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Defaults of the budget (TESSERA_GROUPS_SYNC_BUDGET) and of one queue chunk.
const (
	DefaultBudget = 5000
	DefaultChunk  = 2000
	// MaxFactors bounds a composite's factor list.
	MaxFactors = 100
)

// Engine holds the engine's tunables. The zero value uses the defaults.
type Engine struct {
	// Budget is the most effective-row operations a request may do
	// synchronously; more is queued. Zero means DefaultBudget.
	Budget int
	// Chunk is how many candidate identities one queue transaction handles.
	// Zero means DefaultChunk.
	Chunk int
	// Log receives verification repairs (ERROR). Nil means slog.Default().
	Log *slog.Logger

	repairs atomic.Int64
}

// New returns an engine with the given synchronous budget (<= 0: the default).
func New(budget int) *Engine { return &Engine{Budget: budget} }

func (e *Engine) budget() int64 {
	if e.Budget > 0 {
		return int64(e.Budget)
	}
	return DefaultBudget
}

func (e *Engine) chunk() int {
	if e.Chunk > 0 {
		return e.Chunk
	}
	return DefaultChunk
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// Repairs is the number of corrupt rows verification has repaired since the
// process started (the groups_engine_repairs_total counter).
func (e *Engine) Repairs() int64 { return e.repairs.Load() }

// Change is one effective-membership change: Identity became (Member) or
// stopped being a member of Group in List. GR-3 turns these into events.
type Change struct {
	Group    store.GroupID
	List     store.ListID
	Identity int64
	Member   bool
}

// Seed asks the engine to recompute one identity's membership of a group.
type Seed struct {
	Group    store.GroupID
	List     store.ListID
	Identity int64
}

// Outcome says whether a change was fully applied in the caller's transaction
// or queued. Op is the operation id (the queue sequence number) when queued.
type Outcome struct {
	Queued bool
	Op     int64
}

// CycleError is returned when an edge would make the dependency graph cyclic:
// Parent is already a descendant of Child. Path runs from Child down to Parent
// along existing edges (design §6.1).
type CycleError struct {
	Parent, Child store.GroupID
	Path          []store.GroupID
}

func (e *CycleError) Error() string {
	ids := make([]string, len(e.Path))
	for i, p := range e.Path {
		ids[i] = string(p)
	}
	return fmt.Sprintf("engine: edge %s <- %s would create a cycle (%s)", e.Parent, e.Child, strings.Join(ids, " > "))
}

// IsCycle reports whether err is a CycleError.
func IsCycle(err error) (*CycleError, bool) {
	var ce *CycleError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}

// gmeta is what the engine needs to know about a group, loaded once per run.
type gmeta struct {
	g       *store.NativeGroup
	live    bool
	op      store.CompositeOp
	factors []store.GroupID
}

// Live reports whether a group counts at now: active, inside its own enabled
// and disabled dates. A group that is not live is an empty set (§6.1).
func Live(g *store.NativeGroup, now time.Time) bool {
	if g.Status != store.GroupActive {
		return false
	}
	if g.EnabledFrom != nil && g.EnabledFrom.After(now) {
		return false
	}
	if g.DisabledAt != nil && !now.Before(*g.DisabledAt) {
		return false
	}
	return true
}

func loadMeta(tx *store.TenantTx, now time.Time, id store.GroupID) (*gmeta, error) {
	g, err := tx.GrpGroup(id)
	if err != nil {
		return nil, err
	}
	m := &gmeta{g: g, live: Live(g, now), op: store.CompUnion}
	if g.Definition != store.DefinitionBasic {
		if g.CompositeOp != nil {
			m.op = *g.CompositeOp
		}
		if m.factors, err = tx.GrpFactors(id); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// lists returns the lists a group can have members in: the built-in members
// list and every list it has direct rows in.
func lists(tx *store.TenantTx, g store.GroupID) ([]store.ListID, error) {
	members := store.MembersListID(tx.Tenant())
	out := []store.ListID{members}
	direct, err := tx.GrpDirectLists(g)
	if err != nil {
		return nil, err
	}
	for _, l := range direct {
		if l != members {
			out = append(out, l)
		}
	}
	return out, nil
}

// Touch makes sure the tenant's engine bookkeeping exists: the built-in
// members list, the state row and the time wheel's starting point. Every
// operation that changes memberships or structure calls it first.
func Touch(tx *store.TenantTx, now time.Time) error {
	if _, err := tx.EnsureGrpMembersList(); err != nil {
		return err
	}
	st, err := tx.GrpEngineState()
	if err != nil {
		return err
	}
	if st.WheelAt == nil {
		return tx.SetGrpWheelAt(now)
	}
	return nil
}
