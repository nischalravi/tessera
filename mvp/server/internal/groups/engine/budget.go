package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The synchronous budget (design §6.5). A change whose estimated work,
// |ancestors(g)| x |identities affected|, fits TESSERA_GROUPS_SYNC_BUDGET is
// propagated in the caller's transaction, so the response already reflects the
// effective memberships. A bigger one commits only its direct change and
// queues a recompute of the group: the group is marked recompute_state
// 'pending', the caller answers 202 with the operation id, and the Runner
// drains the queue in chunks of Chunk identities per transaction.
//
// A queued job is a recompute of one (group, list): it walks the identities
// that could be affected (those the group already holds, its direct identity
// rows and the members of its children or factors) in id order, recomputes
// each with Apply, and remembers where it stopped. Because Apply recomputes
// from the stored rows, a job and direct changes made while it waits cannot
// disagree about the result.

// jobPayload is the payload of a recompute_group job.
type jobPayload struct {
	Group   store.GroupID `json:"group"`
	List    store.ListID  `json:"list"`
	After   int64         `json:"after"`
	Done    int64         `json:"done"`
	Total   int64         `json:"total"`
	Changed int64         `json:"changed"`
}

// work estimates the effective-row operations of recomputing n identities of
// group g: every ancestor, and g itself, may be touched once per identity.
func (e *Engine) work(tx *store.TenantTx, g store.GroupID, n int64) (int64, error) {
	anc, err := tx.GrpClosureAncestorCount(g)
	if err != nil {
		return 0, err
	}
	return n * int64(anc+1), nil
}

// sources estimates how many identities a recompute of g has to look at: the
// members it has, its direct identity rows and its children's members.
func (e *Engine) sources(tx *store.TenantTx, g store.GroupID) (int64, error) {
	gr, err := tx.GrpGroup(g)
	if err != nil {
		return 0, err
	}
	direct, err := tx.GrpDirectCount(store.GrpDirectFilter{Group: g, MemberType: store.MemberIdentity})
	if err != nil {
		return 0, err
	}
	kids, err := tx.GrpChildEffectiveSum(g)
	if err != nil {
		return 0, err
	}
	return gr.EffectiveCount + int64(direct) + kids, nil
}

// RecomputeSeeds applies seeds for identities of one group when that fits the
// budget, and otherwise queues a recompute of the group.
func (e *Engine) RecomputeSeeds(tx *store.TenantTx, now time.Time, g store.GroupID, l store.ListID, ids []int64) (Outcome, error) {
	if len(ids) == 0 {
		return Outcome{}, nil
	}
	if err := Touch(tx, now); err != nil {
		return Outcome{}, err
	}
	w, err := e.work(tx, g, int64(len(ids)))
	if err != nil {
		return Outcome{}, err
	}
	if w > e.budget() {
		return e.enqueue(tx, now, g)
	}
	seeds := make([]Seed, len(ids))
	for i, id := range ids {
		seeds[i] = Seed{g, l, id}
	}
	_, err = e.Apply(tx, now, seeds)
	return Outcome{}, err
}

// RecomputeMembersOf recomputes group g for every member of group h in list l:
// what changes when h is nested into g, removed from it, or its dates change.
func (e *Engine) RecomputeMembersOf(tx *store.TenantTx, now time.Time, g, h store.GroupID, l store.ListID) (Outcome, error) {
	if err := Touch(tx, now); err != nil {
		return Outcome{}, err
	}
	n, err := tx.GrpEffectiveCount(h, l)
	if err != nil {
		return Outcome{}, err
	}
	w, err := e.work(tx, g, int64(n))
	if err != nil {
		return Outcome{}, err
	}
	if w > e.budget() {
		return e.enqueue(tx, now, g)
	}
	return e.recomputeNow(tx, now, g)
}

// RecomputeGroup recomputes every identity that could be a member of g (after a
// status or date change, a conversion to composite or a redefinition). Under
// the budget it is done before returning; otherwise it is queued.
func (e *Engine) RecomputeGroup(tx *store.TenantTx, now time.Time, g store.GroupID) (Outcome, error) {
	if err := Touch(tx, now); err != nil {
		return Outcome{}, err
	}
	n, err := e.sources(tx, g)
	if err != nil {
		return Outcome{}, err
	}
	w, err := e.work(tx, g, n)
	if err != nil {
		return Outcome{}, err
	}
	if w > e.budget() {
		return e.enqueue(tx, now, g)
	}
	return e.recomputeNow(tx, now, g)
}

// recomputeNow walks the candidates of every list of g and applies them, in
// chunks so one Apply stays small.
func (e *Engine) recomputeNow(tx *store.TenantTx, now time.Time, g store.GroupID) (Outcome, error) {
	ls, err := lists(tx, g)
	if err != nil {
		return Outcome{}, err
	}
	for _, l := range ls {
		var after int64 = math.MinInt64
		for {
			ids, exhausted, err := candidates(tx, g, l, after, e.chunk())
			if err != nil {
				return Outcome{}, err
			}
			seeds := make([]Seed, len(ids))
			for i, id := range ids {
				seeds[i] = Seed{g, l, id}
			}
			if _, err := e.Apply(tx, now, seeds); err != nil {
				return Outcome{}, err
			}
			if exhausted {
				break
			}
			after = ids[len(ids)-1]
		}
	}
	return Outcome{}, nil
}

// enqueue queues a recompute job per list of g and marks the group pending.
// The operation id is the first job's sequence number.
func (e *Engine) enqueue(tx *store.TenantTx, now time.Time, g store.GroupID) (Outcome, error) {
	ls, err := lists(tx, g)
	if err != nil {
		return Outcome{}, err
	}
	total, err := e.sources(tx, g)
	if err != nil {
		return Outcome{}, err
	}
	var first int64
	for _, l := range ls {
		p, err := json.Marshal(jobPayload{Group: g, List: l, After: math.MinInt64, Total: total})
		if err != nil {
			return Outcome{}, err
		}
		seq, err := tx.EnqueueGrpJob(store.JobRecomputeGroup, string(p), now)
		if err != nil {
			return Outcome{}, err
		}
		if first == 0 {
			first = seq
		}
	}
	if err := tx.SetGrpRecomputeState(g, "pending"); err != nil {
		return Outcome{}, err
	}
	return Outcome{Queued: true, Op: first}, nil
}

// candidates returns up to about limit identities of (g, l) above after, in
// ascending order, that a recompute has to look at: those g already holds,
// those with a direct identity row in g, and the members of each child group
// (nested group or composite factor). exhausted says there are no more above
// the last one returned.
//
// Each source is read in id order with the same limit; the batch ends at the
// smallest last id of a source that hit the limit, so no id below it is
// missing.
func candidates(tx *store.TenantTx, g store.GroupID, l store.ListID, after int64, limit int) (ids []int64, exhausted bool, err error) {
	var srcs [][]int64
	add := func(s []int64, err error) error {
		if err == nil {
			srcs = append(srcs, s)
		}
		return err
	}
	if err = add(tx.GrpEffectiveIdentitiesAfter(g, l, after, limit)); err != nil {
		return nil, false, err
	}
	if err = add(tx.GrpDirectIdentitiesAfter(g, l, after, limit)); err != nil {
		return nil, false, err
	}
	kids, err := tx.GrpDepChildren(g, l)
	if err != nil {
		return nil, false, err
	}
	for _, k := range kids {
		if err = add(tx.GrpEffectiveIdentitiesAfter(k, l, after, limit)); err != nil {
			return nil, false, err
		}
	}
	bound, exhausted := int64(math.MaxInt64), true
	for _, s := range srcs {
		if len(s) >= limit {
			exhausted = false
			bound = min(bound, s[len(s)-1])
		}
	}
	for _, s := range srcs {
		for _, id := range s {
			if id <= bound {
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), exhausted, nil
}

// Drain runs one chunk of the oldest queued job inside tx and reports whether
// there was a job. A finished job is deleted, its group marked clean once no
// other job waits on it, and an audit event recorded.
func (e *Engine) Drain(tx *store.TenantTx, now time.Time) (bool, error) {
	job, err := tx.GrpFirstJob()
	if isNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if job.Kind != store.JobRecomputeGroup {
		return true, tx.DeleteGrpJob(job.Seq) // not ours: a newer server wrote it
	}
	var p jobPayload
	if err := json.Unmarshal([]byte(job.Payload), &p); err != nil {
		return true, fmt.Errorf("engine: job %d: %w", job.Seq, err)
	}
	if _, err := tx.GrpGroup(p.Group); isNotFound(err) {
		return true, tx.DeleteGrpJob(job.Seq)
	} else if err != nil {
		return false, err
	}
	ids, exhausted, err := candidates(tx, p.Group, p.List, p.After, e.chunk())
	if err != nil {
		return false, err
	}
	seeds := make([]Seed, len(ids))
	for i, id := range ids {
		seeds[i] = Seed{p.Group, p.List, id}
	}
	changes, err := e.Apply(tx, now, seeds)
	if err != nil {
		return false, err
	}
	p.Done += int64(len(ids))
	p.Changed += int64(len(changes))
	if !exhausted {
		p.After = ids[len(ids)-1]
		raw, err := json.Marshal(p)
		if err != nil {
			return false, err
		}
		return true, tx.SetGrpJobPayload(job.Seq, string(raw))
	}
	if err := tx.DeleteGrpJob(job.Seq); err != nil {
		return false, err
	}
	left, err := tx.GrpQueuedFor(p.Group)
	if err != nil {
		return false, err
	}
	if left == 0 {
		if err := tx.SetGrpRecomputeState(p.Group, "clean"); err != nil {
			return false, err
		}
	}
	return true, tx.Audit(now, "groups.engine", "groups.engine.recomputed", ojson.Object{
		{Key: "op", Value: job.Seq}, {Key: "group_id", Value: string(p.Group)}, {Key: "identities", Value: p.Done},
		{Key: "changes", Value: p.Changed}})
}

// Progress is how far a queued operation has got: "41,200 of 120,000".
type Progress struct {
	State string // pending | done | unknown
	Done  int64
	Total int64
}

// OpProgress reports an operation id returned with 202.
func OpProgress(tx *store.TenantTx, op int64) (Progress, error) {
	st, err := tx.GrpOpState(op)
	if err != nil {
		return Progress{}, err
	}
	pr := Progress{State: st}
	if st != store.OpPending {
		return pr, nil
	}
	job, err := tx.GrpJob(op)
	if err != nil {
		return pr, err
	}
	var p jobPayload
	if err := json.Unmarshal([]byte(job.Payload), &p); err != nil {
		return pr, err
	}
	pr.Done, pr.Total = p.Done, p.Total
	return pr, nil
}
