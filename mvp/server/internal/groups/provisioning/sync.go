package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Consumer is the event cursor name of a provisioner (grp_event_cursors).
func Consumer(provisioner string) string { return "provisioner:" + provisioner }

// Tunables of a run.
const (
	// MaxAttempts is how often an op is applied before it is given up (README rule 4).
	MaxAttempts = 3
	// staleRun is how long a run may stay "running" before it counts as abandoned.
	staleRun = 30 * time.Minute
	// RetryAfter is how long a group left in drift or failed waits before an
	// incremental pass tries it again.
	RetryAfter = 10 * time.Minute
)

// RunOptions chooses a run.
type RunOptions struct {
	Kind string // store.RunFull or store.RunIncremental
	// IgnoreCache re-reads every group even if its change token is unchanged.
	IgnoreCache bool
	// Cause is the event cause: store.CauseAPI for a manual run, otherwise CauseEngine.
	Cause string
}

// Summary is what a run records and the API returns.
type Summary struct {
	Kind          string     `json:"kind"`
	Mode          string     `json:"mode"`
	Groups        int        `json:"groups"`
	Creates       int        `json:"creates"`
	Updates       int        `json:"updates"`
	MemberOps     int        `json:"member_ops"`
	Deletes       int        `json:"deletes"`
	MemberAdds    int        `json:"member_adds"`
	MemberRemoves int        `json:"member_removes"`
	Verified      int        `json:"verified"`
	Applied       int        `json:"applied_unverified"`
	Failed        int        `json:"failed"`
	Drift         int        `json:"drift"`
	Skipped       int        `json:"skipped"`
	Adopted       int        `json:"adopted"`
	CacheHits     int        `json:"cache_hits"`
	Unmapped      int        `json:"unmapped_members"`
	Deferred      int        `json:"deferred_groups"`
	Conflicts     []Conflict `json:"conflicts,omitempty"`
	TemplateErrs  int        `json:"template_errors"`
	// Held lists why the failsafe refused the plan; the run applied nothing.
	Held []string `json:"held,omitempty"`
	// Unverifiable: the target cannot be read back, so ops stay "applied".
	Unverifiable bool `json:"unverifiable,omitempty"`
}

// Report is the result of Run.
type Report struct {
	Run     *store.SyncRun
	Summary Summary
	// Idle: nothing was due (an incremental pass with no events for this provisioner).
	Idle bool
}

// snapshot is what a run starts from: everything it needs from the database,
// read in one transaction so the desired state and the event position agree.
type snapshot struct {
	prov    *store.Provisioner
	cc      *Compiled
	limits  Limits
	secret  map[string]string
	desired *Desired
	owned   map[string]*store.SyncGroup // group id -> what the provisioner owns
	// ownedKey maps Key(target_name) to the group id that owns it.
	ownedKey map[string]string
	head     int64 // the last event the snapshot reflects
	from     int64 // the cursor when the run started
	upto     int64 // the cursor after the run (incremental: the last event polled)
	dirty    map[string]int64
	approve  bool
	// noop: an incremental batch with no group event; only the cursor moves.
	noop bool
}

// Run runs one full or incremental sync of a provisioner. The network is only
// touched outside database transactions.
func (s *Service) Run(ctx context.Context, tenant tenancy.ID, id string, o RunOptions) (*Report, error) {
	mu := s.lock(tenant, id)
	mu.Lock()
	defer mu.Unlock()
	if o.Kind == "" {
		o.Kind = store.RunFull
	}
	if o.Cause == "" {
		o.Cause = store.CauseEngine
	}
	snap, err := s.snapshot(ctx, tenant, id, o)
	if errors.Is(err, ErrNeedsFull) && o.Kind == store.RunIncremental {
		o.Kind = store.RunFull
		snap, err = s.snapshot(ctx, tenant, id, o)
	}
	if err != nil {
		return nil, err
	}
	if snap == nil { // incremental, nothing for this provisioner
		return &Report{Idle: true}, nil
	}
	now := s.now()
	if snap.noop {
		err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
			return events.Ack(tx, Consumer(id), snap.upto, now)
		})
		return &Report{Idle: true}, err
	}
	run := &store.SyncRun{ID: newID(), ProvisionerID: id, Kind: o.Kind, Mode: snap.prov.Mode, FromSeq: snap.from,
		ToSeq: snap.upto, StartedAt: now}
	if err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		if err := tx.FailAbandonedSyncRuns(id, now.Add(-staleRun), now); err != nil {
			return err
		}
		if busy, err := tx.SyncRunActive(id, now.Add(-staleRun)); err != nil || busy {
			if err == nil {
				err = ErrBusy
			}
			return err
		}
		return tx.InsertSyncRun(run)
	}); err != nil {
		return nil, err
	}
	rep, err := s.execute(ctx, tenant, snap, run, o)
	if err != nil {
		// the run could not be completed: record why (best effort, the cause is err)
		fin := s.now()
		run.Status, run.Error, run.FinishedAt = store.RunFailed, truncate(err.Error(), 500), &fin
		if run.Summary == nil {
			run.Summary = json.RawMessage("{}")
		}
		_ = s.DB.InTenant(context.WithoutCancel(ctx), tenant, func(tx *store.TenantTx) error {
			if err := tx.FinishSyncRun(run); err != nil {
				return err
			}
			if o.Kind == store.RunFull { // try again, after a pause (the runner)
				if err := tx.SetProvisionerNeedsFull(id, true, snap.approve); err != nil {
					return err
				}
			}
			_, err := tx.RecordAudit(store.AuditRecord{At: fin, Action: "groups.prov.run_failed", LegacyActor: "groups.provisioning",
				TargetType: "provisioner", TargetID: id, Detail: ojson.Object{{Key: "run_id", Value: run.ID}, {Key: "error", Value: run.Error}}})
			return err
		})
		return &Report{Run: run}, err
	}
	return rep, nil
}

// newID is a time-ordered UUID (v7), so runs and ops sort by creation even
// when their timestamps tie.
func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// snapshot reads the provisioner, its marks and desired state, what it owns and
// (incremental) the events after its cursor.
func (s *Service) snapshot(ctx context.Context, tenant tenancy.ID, id string, o RunOptions) (*snapshot, error) {
	var snap *snapshot
	err := s.DB.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		p, err := tx.Provisioner(id)
		if err != nil {
			return err
		}
		if p.Mode == store.ProvModePaused {
			return ErrPaused
		}
		cc, err := ParseCommonFor(p.TargetType, p.Config)
		if err != nil {
			return err
		}
		fs, err := ParseFailsafe(p.Failsafe)
		if err != nil {
			return err
		}
		sec, err := s.openSecret(tenant, p)
		if err != nil {
			return err
		}
		head, err := tx.GrpEventHead()
		if err != nil {
			return err
		}
		from, err := tx.GrpCursor(Consumer(id))
		if err != nil {
			return err
		}
		sn := &snapshot{prov: p, cc: cc, limits: fs.Resolve(), secret: sec, head: head.LastSeq, from: from, upto: head.LastSeq,
			approve: p.ApproveNext, owned: map[string]*store.SyncGroup{}, ownedKey: map[string]string{}}
		for off := 0; ; off += 1000 {
			page, err := tx.SyncGroups(id, 1000, off)
			if err != nil {
				return err
			}
			for _, g := range page {
				sn.owned[g.GroupID] = g
				if g.Status != "removed" && g.TargetName != "" {
					sn.ownedKey[Key(g.TargetName)] = g.GroupID
				}
			}
			if len(page) < 1000 {
				break
			}
		}
		if o.Kind == store.RunFull {
			sn.desired, err = Compute(tx, p, cc, nil)
			snap = sn
			return err
		}
		// incremental: the events after the cursor, through the GR-3 consumer API
		if p.Mode != store.ProvModeActive {
			return ErrNotActive
		}
		batch, err := events.Poll(tx, Consumer(id), events.MaxBatch)
		if err != nil {
			return err
		}
		sn.dirty = map[string]int64{}
		for _, e := range batch {
			sn.upto = e.Seq
			switch e.ObjectType {
			case store.EventObjGroup:
				sn.dirty[e.ObjectID] = e.Seq
			case store.EventObjFolder:
				if e.Type == events.FolderRenamed || e.Type == events.FolderMoved || e.Type == events.FolderDeleted {
					return ErrNeedsFull // names and inherited marks of every group below may have changed
				}
			}
		}
		retry, err := tx.SyncGroupsRetryDue(id, s.now().Add(-RetryAfter), 1000)
		if err != nil {
			return err
		}
		for _, g := range retry {
			if _, ok := sn.dirty[g.GroupID]; !ok {
				sn.dirty[g.GroupID] = 0
			}
		}
		if len(batch) == 0 && len(sn.dirty) == 0 {
			return nil // snap stays nil: nothing to do
		}
		if len(sn.dirty) == 0 {
			sn.noop = true // events that concern no group (our own provisioning events): only move the cursor
			snap = sn
			return nil
		}
		only := map[string]bool{}
		for g := range sn.dirty {
			only[g] = true
		}
		sn.desired, err = Compute(tx, p, cc, only)
		snap = sn
		return err
	})
	return snap, err
}

// execute reads the target, plans, applies and verifies, then records the result.
func (s *Service) execute(ctx context.Context, tenant tenancy.ID, snap *snapshot, run *store.SyncRun, o RunOptions) (*Report, error) {
	spec := TargetSpec{Tenant: tenant, ProvisionerID: snap.prov.ID, Type: snap.prov.TargetType, Common: snap.cc, Secret: snap.secret, Deps: s.Deps}
	target, err := s.open(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("open the target: %w", err)
	}
	defer target.Close()
	caps := target.Capabilities()
	full := o.Kind == store.RunFull

	sum := Summary{Kind: o.Kind, Mode: snap.prov.Mode, Groups: len(snap.desired.ByGroup), Conflicts: snap.desired.Conflicts,
		Deferred: len(snap.desired.Deferred), TemplateErrs: len(snap.desired.Errors), Unverifiable: !caps.Readable}
	for _, dg := range snap.desired.ByGroup {
		sum.Unmapped += len(dg.Unmapped)
	}

	refs, ownedOnly := s.refsOf(snap, full)
	state, hits, err := s.readState(ctx, target, caps, snap, refs, full, o.IgnoreCache)
	if err != nil {
		return nil, fmt.Errorf("read the target: %w", err)
	}
	sum.CacheHits = hits

	plan, adopted, conflicts := s.buildPlan(caps, snap, state, ownedOnly, full)
	sum.Conflicts = append(sum.Conflicts, conflicts...)
	for i := range plan {
		plan[i].CauseSeq = snap.dirty[plan[i].GroupID]
	}
	orderOps(plan)
	tot := totalsOf(plan)
	sum.Creates, sum.Updates, sum.MemberOps, sum.Deletes = tot.Creates, tot.Updates, tot.MemberOps, tot.Deletes
	sum.MemberAdds, sum.MemberRemoves = tot.MemberAdds, tot.MemberRemoves

	res := &execResult{target: target, caps: caps, snap: snap, state: state, plan: plan, o: o, now: s.now}
	switch snap.prov.Mode {
	case store.ProvModeAdopt:
		res.skip("adopt mode: nothing is changed on the target until an admin reviews this diff and sets the mode to active")
		res.adopted = adopted
	case store.ProvModeDryRun:
		res.skip("dry run: the plan is recorded and not applied")
	default:
		total := 0
		for _, g := range state.Groups {
			total += len(g.Members)
		}
		// an admin's approval covers the next full sync only
		if why := snap.limits.failsafe(tot, total, full); len(why) > 0 && !(snap.approve && full) {
			sum.Held = why
			res.skip("held by the failsafe: " + strings.Join(why, "; "))
			res.held = true
		} else {
			// the plan is recorded before anything is applied, so a crash leaves the trace of what was in flight
			for _, po := range plan {
				res.ops = append(res.ops, &opState{id: newID(), po: po, status: store.OpPlanned})
			}
			if err := s.persistPlanned(ctx, tenant, snap, run, res); err != nil {
				return nil, err
			}
			if err := s.applyVerify(ctx, res); err != nil {
				return nil, err
			}
		}
	}
	for _, op := range res.ops {
		switch op.status {
		case store.OpVerified:
			sum.Verified++
		case store.OpApplied:
			sum.Applied++
		case store.OpFailed:
			sum.Failed++
		case store.OpDrift:
			sum.Drift++
		case store.OpSkipped:
			sum.Skipped++
		}
	}
	sum.Adopted = len(res.adopted)
	return s.record(ctx, tenant, snap, run, res, sum, o)
}

// refsOf lists the target groups a run needs: every desired group and every
// group the provisioner owns that is not desired (to delete or release). For an
// incremental run only the groups of the dirty set. ownedOnly marks the owned
// groups that are not desired.
func (s *Service) refsOf(snap *snapshot, full bool) (refs []TargetRef, ownedOnly map[string]*store.SyncGroup) {
	ownedOnly = map[string]*store.SyncGroup{}
	seen := map[string]bool{}
	add := func(r TargetRef) {
		if k := Key(r.Name); !seen[k] {
			seen[k] = true
			refs = append(refs, r)
		}
	}
	ids := make([]string, 0, len(snap.desired.ByGroup))
	for id := range snap.desired.ByGroup {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		dg := snap.desired.ByGroup[id]
		r := TargetRef{Name: dg.Name}
		if sg := snap.owned[id]; sg != nil && sg.Status != "removed" && Key(sg.TargetName) == Key(dg.Name) {
			r.ID = sg.TargetID
		}
		add(r)
	}
	owned := make([]string, 0, len(snap.owned))
	for id := range snap.owned {
		owned = append(owned, id)
	}
	slices.Sort(owned)
	for _, id := range owned {
		sg := snap.owned[id]
		if sg.Status == "removed" {
			continue
		}
		if !full {
			if _, dirty := snap.dirty[id]; !dirty {
				continue
			}
		}
		if dg := snap.desired.ByGroup[id]; dg != nil && Key(dg.Name) == Key(sg.TargetName) {
			continue
		}
		ownedOnly[id] = sg
		add(TargetRef{Name: sg.TargetName, ID: sg.TargetID})
	}
	return refs, ownedOnly
}

// readState reads the target groups of refs. A target that cannot be read gives
// back what was last verified (the sync-back cache). A target with change
// tokens is asked only for the tokens, and only the groups whose token moved
// (or that have no cache) are read.
func (s *Service) readState(ctx context.Context, t Provisioner, caps Capabilities, snap *snapshot, refs []TargetRef, full, ignoreCache bool) (TargetState, int, error) {
	st := NewState()
	cacheOf := func(ref TargetRef) *TargetGroup {
		if sg := snap.owned[snap.ownedKey[Key(ref.Name)]]; sg != nil && sg.StateCache != nil {
			return groupFromCache(ref, sg)
		}
		return nil
	}
	if !caps.Readable {
		for _, r := range refs {
			if g := cacheOf(r); g != nil {
				st.Groups[Key(r.Name)] = g
			}
		}
		return st, 0, nil
	}
	want := map[string]bool{}
	for _, r := range refs {
		want[Key(r.Name)] = true
	}
	var toRead []TargetRef
	hits := 0
	tr, hasTokens := t.(TokenReader)
	if full && hasTokens && caps.ChangeTokens && !ignoreCache {
		tokens, err := tr.Tokens(ctx, Scope{})
		if err != nil {
			return st, 0, err
		}
		for _, r := range refs {
			tok, exists := tokens[Key(r.Name)]
			if !exists {
				continue // not on the target
			}
			if g := cacheOf(r); g != nil && tok != "" && g.Token == tok {
				st.Groups[Key(r.Name)] = g
				hits++
				continue
			}
			toRead = append(toRead, r)
		}
		if len(toRead) > 0 {
			got, err := t.Read(ctx, toRead)
			if err != nil {
				return st, 0, err
			}
			for k, g := range got.Groups {
				st.Groups[k] = g
			}
		}
		return st, hits, nil
	}
	if full && len(refs) > 20 {
		all, err := t.ReadAll(ctx, Scope{})
		if err != nil {
			return st, 0, err
		}
		for k, g := range all.Groups {
			if want[k] {
				st.Groups[k] = g
			}
		}
		return st, 0, nil
	}
	if len(refs) == 0 {
		return st, 0, nil
	}
	got, err := t.Read(ctx, refs)
	if err != nil {
		return st, 0, err
	}
	for k, g := range got.Groups {
		if want[k] {
			st.Groups[k] = g
		}
	}
	return st, 0, nil
}

// stateCache is the JSON a sync group caches.
type stateCache struct {
	Attrs   map[string][]string `json:"attrs"`
	Members []string            `json:"members"`
}

func groupFromCache(ref TargetRef, sg *store.SyncGroup) *TargetGroup {
	var c stateCache
	if json.Unmarshal(sg.StateCache, &c) != nil {
		return nil
	}
	r := TargetRef{Name: ref.Name, ID: ref.ID}
	if r.ID == "" {
		r.ID = sg.TargetID
	}
	return &TargetGroup{Ref: r, Attrs: c.Attrs, Members: c.Members, Token: sg.ChangeToken}
}

func cacheJSON(g *TargetGroup) json.RawMessage {
	b, _ := json.Marshal(stateCache{Attrs: g.Attrs, Members: g.Members})
	return b
}

// buildPlan diffs the desired state against the target state. adopted are the
// desired groups that already exist on the target (adopt mode records them).
func (s *Service) buildPlan(caps Capabilities, snap *snapshot, state TargetState, ownedOnly map[string]*store.SyncGroup, full bool) (plan []*PlannedOp, adopted map[string]*TargetGroup, conflicts []Conflict) {
	adopted = map[string]*TargetGroup{}
	ids := make([]string, 0, len(snap.desired.ByGroup))
	for id := range snap.desired.ByGroup {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		dg := snap.desired.ByGroup[id]
		k := Key(dg.Name)
		// another owned group holds this target name: do not touch it
		if other := snap.ownedKey[k]; other != "" && other != id {
			if od := snap.desired.ByGroup[other]; od == nil || Key(od.Name) == k {
				conflicts = append(conflicts, Conflict{Name: dg.Name, Groups: []string{id, other}})
				continue
			}
		}
		ag := state.Groups[k]
		if ag != nil {
			adopted[id] = ag
		}
		ref := TargetRef{Name: dg.Name}
		plan = append(plan, planGroup(caps, dg, ag, ref)...)
	}
	owned := make([]string, 0, len(ownedOnly))
	for id := range ownedOnly {
		owned = append(owned, id)
	}
	slices.Sort(owned)
	for _, id := range owned {
		sg := ownedOnly[id]
		k := Key(sg.TargetName)
		if _, deferred := slices.BinarySearch(snap.desired.Deferred, id); deferred {
			continue
		}
		if _, bad := snap.desired.Errors[id]; bad {
			continue
		}
		if claimed, ok := snap.desired.ByKey[k]; ok && claimed.GroupID != id {
			continue // the name now belongs to another group
		}
		if inConflict(snap.desired.Conflicts, id) {
			continue
		}
		plan = append(plan, planDelete(caps, id, TargetRef{Name: sg.TargetName, ID: sg.TargetID}, state.Groups[k])...)
	}
	return plan, adopted, conflicts
}

func inConflict(cs []Conflict, id string) bool {
	for _, c := range cs {
		if slices.Contains(c.Groups, id) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- apply and verify

// opState tracks one op through attempts. persisted says it has a row.
type opState struct {
	id         string
	po         *PlannedOp
	status     string
	attempts   int
	err        string
	appliedAt  *time.Time
	verifiedAt *time.Time
	note       string
	persisted  bool
}

type execResult struct {
	target  Provisioner
	caps    Capabilities
	snap    *snapshot
	state   TargetState
	plan    []*PlannedOp
	o       RunOptions
	now     func() time.Time
	ops     []*opState
	held    bool
	adopted map[string]*TargetGroup
	// final is the last read of each touched group (by Key), nil when absent.
	final map[string]*TargetGroup
}

// skip records every planned op as skipped with a reason.
func (r *execResult) skip(reason string) {
	for _, po := range r.plan {
		r.ops = append(r.ops, &opState{id: newID(), po: po, status: store.OpSkipped, note: reason})
	}
}

// applyVerify applies the plan and re-reads every touched group. An op is
// verified only when the re-read shows its effect; otherwise it is retried
// (re-planned from what the re-read shows) up to MaxAttempts times and ends
// failed (the target refused it) or drift (the target accepted it and the
// state did not change).
func (s *Service) applyVerify(ctx context.Context, r *execResult) error {
	r.final = map[string]*TargetGroup{}
	byGroup := map[string][]*opState{}
	var order []string
	for _, os := range r.ops { // the planned ops, persisted before anything is applied
		k := Key(os.po.Op.Ref.Name)
		if _, ok := byGroup[k]; !ok {
			order = append(order, k)
		}
		byGroup[k] = append(byGroup[k], os)
	}
	pending := order
	unverified := false
	for attempt := 1; attempt <= MaxAttempts && len(pending) > 0; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var ops []Op
		idOf := map[string]*opState{}
		for _, k := range pending {
			for _, os := range byGroup[k] {
				if os.status == store.OpVerified {
					continue
				}
				op := os.po.Op
				op.ID = os.id
				ops = append(ops, op)
				idOf[os.id] = os
			}
		}
		applyErr := s.applyChunks(ctx, r, ops, idOf)
		now := r.now()
		for _, os := range idOf {
			os.attempts++
			os.appliedAt = &now
			if os.status == store.OpPlanned || os.status == store.OpFailed || os.status == store.OpDrift {
				os.status = store.OpApplied
			}
			if os.err != "" {
				os.status = store.OpFailed
			}
		}
		if applyErr != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if !r.caps.Readable {
			// nothing to re-read: the target accepted it, which is all we can say
			pending = nil
			break
		}
		refs := make([]TargetRef, 0, len(pending))
		for _, k := range pending {
			refs = append(refs, byGroup[k][0].po.Op.Ref)
		}
		got, err := r.target.Read(ctx, refs)
		if err != nil {
			for _, k := range pending {
				for _, os := range byGroup[k] {
					if os.status != store.OpVerified {
						os.note = "the verification read failed: " + truncate(err.Error(), 200)
						if os.status == store.OpFailed && os.err == "" {
							os.err = os.note
						}
					}
				}
			}
			if attempt < MaxAttempts {
				s.sleep(ctx, s.backoff(attempt))
				continue
			}
			unverified = true // applied, and the target would not say what it now holds
			break
		}
		var next []string
		vnow := r.now()
		for _, k := range pending {
			ag := got.Groups[k]
			r.final[k] = ag
			remaining := s.replan(r, byGroup[k], ag)
			kinds := map[OpKind]bool{}
			for _, po := range remaining {
				kinds[po.Op.Kind] = true
			}
			open := false
			for _, os := range byGroup[k] {
				if os.status == store.OpVerified {
					continue
				}
				if kinds[os.po.Op.Kind] {
					open = true
					for _, po := range remaining {
						if po.Op.Kind == os.po.Op.Kind {
							os.po = po // retry what is still missing, not what was asked at first
						}
					}
					continue
				}
				os.status, os.verifiedAt, os.err = store.OpVerified, &vnow, ""
			}
			// a kind the first plan did not have (the group exists now but members are missing)
			for _, po := range remaining {
				found := false
				for _, os := range byGroup[k] {
					if os.po.Op.Kind == po.Op.Kind {
						found = true
					}
				}
				if !found {
					os := &opState{id: newID(), po: po, status: store.OpPlanned}
					byGroup[k] = append(byGroup[k], os)
					r.ops = append(r.ops, os)
					open = true
				}
			}
			if open {
				next = append(next, k)
			}
		}
		pending = next
		if len(pending) > 0 && attempt < MaxAttempts {
			s.sleep(ctx, s.backoff(attempt))
		}
	}
	// whatever is still open after the last attempt
	if unverified {
		pending = nil
	}
	for _, k := range pending {
		for _, os := range byGroup[k] {
			switch os.status {
			case store.OpVerified:
			case store.OpFailed:
			default:
				os.status = store.OpDrift
				if os.err == "" {
					os.err = "the target accepted the change but the re-read does not show it"
				}
			}
		}
	}
	return nil
}

// applyChunks sends ops to the target in batches of at most MaxBatch and
// records each op's error. A transport error fails the whole batch.
func (s *Service) applyChunks(ctx context.Context, r *execResult, ops []Op, idOf map[string]*opState) error {
	size := r.caps.MaxBatch
	if size <= 0 {
		size = len(ops)
	}
	var first error
	for i := 0; i < len(ops); i += max(size, 1) {
		chunk := ops[i:min(i+max(size, 1), len(ops))]
		results, err := r.target.Apply(ctx, chunk)
		if err != nil {
			if first == nil {
				first = err
			}
			for _, op := range chunk {
				idOf[op.ID].err = truncate(err.Error(), 300)
			}
			continue
		}
		seen := map[string]bool{}
		for _, res := range results {
			os := idOf[res.ID]
			if os == nil {
				continue
			}
			seen[res.ID] = true
			if res.Err != nil {
				os.err = truncate(res.Err.Error(), 300)
				if first == nil {
					first = res.Err
				}
			} else {
				os.err = ""
			}
			if res.Ref.ID != "" {
				os.po.Op.Ref.ID = res.Ref.ID
			}
		}
		for _, op := range chunk {
			if !seen[op.ID] {
				idOf[op.ID].err = "the target returned no result for this op"
			}
		}
	}
	return first
}

// replan computes what is still to do for one group after a re-read: the ops of
// the group's desired state against what the target now holds.
func (s *Service) replan(r *execResult, ops []*opState, ag *TargetGroup) []*PlannedOp {
	first := ops[0].po
	dg := r.snap.desired.ByGroup[first.GroupID]
	if dg == nil || Key(dg.Name) != Key(first.Op.Ref.Name) {
		// the group is not wanted under this name: the ops delete it (or empty it)
		return planDelete(r.caps, first.GroupID, first.Op.Ref, ag)
	}
	return planGroup(r.caps, dg, ag, TargetRef{Name: dg.Name, ID: first.Op.Ref.ID})
}

// ---------------------------------------------------------------- recording

// record writes the result of a run in one transaction: the ops, the groups the
// provisioner now owns, one event per finished op, the cursor, and the audit
// event.
func (s *Service) record(ctx context.Context, tenant tenancy.ID, snap *snapshot, run *store.SyncRun, res *execResult, sum Summary, o RunOptions) (*Report, error) {
	fin := s.now()
	run.FinishedAt, run.Status = &fin, store.RunDone
	if res.held {
		run.Status = store.RunHeld
	}
	run.ToSeq = snap.upto
	run.Summary, _ = json.Marshal(sum)
	full := o.Kind == store.RunFull
	// finishing a run must not be lost to a cancelled request context
	wctx := context.WithoutCancel(ctx)
	err := s.DB.InTenant(wctx, tenant, func(tx *store.TenantTx) error {
		prov := snap.prov.ID
		for _, os := range res.ops {
			op := storeOp(os, prov, run.ID, run.StartedAt)
			var err error
			if os.persisted {
				err = tx.UpdateSyncOp(op)
			} else {
				err = tx.InsertSyncOp(op)
			}
			if err != nil {
				return err
			}
			if err := s.emitOp(tx, os, prov, run.ID, fin, o.Cause); err != nil {
				return err
			}
		}
		if err := s.recordGroups(tx, snap, res, fin); err != nil {
			return err
		}
		if err := tx.FinishSyncRun(run); err != nil {
			return err
		}
		if full {
			if err := tx.SetProvisionerNeedsFull(prov, false, false); err != nil {
				return err
			}
		}
		// The cursor moves only when this run's state is on the target. A held
		// incremental run moves it too and asks for a full sync instead: that
		// run re-checks the failsafe over the whole difference and, if it is
		// held as well, waits for an admin, rather than being retried forever.
		if snap.prov.Mode == store.ProvModeActive && (!res.held || !full) {
			if err := events.Ack(tx, Consumer(prov), snap.upto, fin); err != nil {
				return err
			}
			if res.held {
				if err := tx.SetProvisionerNeedsFull(prov, true, false); err != nil {
					return err
				}
			}
		}
		detail := ojson.Object{{Key: "run_id", Value: run.ID}, {Key: "kind", Value: o.Kind}, {Key: "mode", Value: snap.prov.Mode},
			{Key: "status", Value: run.Status}, {Key: "creates", Value: sum.Creates}, {Key: "updates", Value: sum.Updates},
			{Key: "member_adds", Value: sum.MemberAdds}, {Key: "member_removes", Value: sum.MemberRemoves},
			{Key: "group_deletes", Value: sum.Deletes}, {Key: "verified", Value: sum.Verified}, {Key: "failed", Value: sum.Failed},
			{Key: "drift", Value: sum.Drift}, {Key: "skipped", Value: sum.Skipped}}
		action := "groups.prov.run"
		if res.held {
			action = "groups.prov.held"
			detail = append(detail, ojson.KV{Key: "reasons", Value: strings.Join(sum.Held, "; ")})
		}
		_, err := tx.RecordAudit(store.AuditRecord{At: fin, Action: action, LegacyActor: "groups.provisioning",
			TargetType: "provisioner", TargetID: prov, Detail: detail})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Report{Run: run, Summary: sum}, nil
}

// storeOp is the row of an op.
func storeOp(os *opState, prov, run string, planned time.Time) *store.SyncOp {
	op := &store.SyncOp{ID: os.id, ProvisionerID: prov, RunID: run, Op: string(os.po.Op.Kind), ObjectRef: os.po.Op.Ref.Name,
		GroupID: os.po.GroupID, PayloadHash: os.po.Hash(), Status: os.status, Attempts: os.attempts, Error: os.err,
		PlannedAt: planned, AppliedAt: os.appliedAt, VerifiedAt: os.verifiedAt}
	if os.note != "" && os.err == "" {
		op.Error = os.note
	}
	op.Detail, _ = json.Marshal(map[string]int{"add": os.po.Adds, "remove": os.po.Removes})
	if os.po.CauseSeq > 0 {
		c := os.po.CauseSeq
		op.CauseSeq = &c
	}
	return op
}

// persistPlanned writes the ops of a run as planned, before any is applied.
func (s *Service) persistPlanned(ctx context.Context, tenant tenancy.ID, snap *snapshot, run *store.SyncRun, res *execResult) error {
	return s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		for _, os := range res.ops {
			if err := tx.InsertSyncOp(storeOp(os, snap.prov.ID, run.ID, run.StartedAt)); err != nil {
				return err
			}
		}
		for _, os := range res.ops {
			os.persisted = true
		}
		return nil
	})
}

// emitOp writes the provisioning event of a finished op (K9: in the same
// transaction as the change it records).
func (s *Service) emitOp(tx *store.TenantTx, os *opState, prov, run string, now time.Time, cause string) error {
	var typ string
	switch os.status {
	case store.OpVerified:
		typ = events.ProvisioningOpVerified
	case store.OpFailed:
		typ = events.ProvisioningOpFailed
	case store.OpDrift:
		typ = events.ProvisioningOpDrift
	default:
		return nil
	}
	e := events.New(typ, prov, now, cause)
	e.Data = events.Data(map[string]any{"op_id": os.id, "run_id": run, "op": string(os.po.Op.Kind), "group": os.po.Op.Ref.Name,
		"group_id": os.po.GroupID, "attempts": os.attempts, "error": os.err})
	return pit.Emit(tx, e)
}

// recordGroups updates what the provisioner owns after a run.
func (s *Service) recordGroups(tx *store.TenantTx, snap *snapshot, res *execResult, now time.Time) error {
	prov := snap.prov.ID
	put := func(id string, name string, g *TargetGroup, status string, verified bool) error {
		sg := &store.SyncGroup{ProvisionerID: prov, GroupID: id, TargetName: name, Status: status, LastReadAt: &now}
		if old := snap.owned[id]; old != nil && Key(old.TargetName) == Key(name) {
			sg.TargetID = old.TargetID
		}
		if g != nil {
			if g.Ref.ID != "" {
				sg.TargetID = g.Ref.ID
			}
			sg.StateHash, sg.ChangeToken, sg.StateCache = stateHash(g), g.Token, cacheJSON(g)
		}
		if verified {
			sg.LastVerifiedAt = &now
		}
		return tx.PutSyncGroup(sg)
	}
	switch snap.prov.Mode {
	case store.ProvModeAdopt:
		ids := make([]string, 0, len(res.adopted))
		for id := range res.adopted {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			if old := snap.owned[id]; old != nil && old.Status != "removed" && Key(old.TargetName) != Key(snap.desired.ByGroup[id].Name) {
				continue // owned under another name: leave it
			}
			if err := put(id, snap.desired.ByGroup[id].Name, res.adopted[id], "adopted", false); err != nil {
				return err
			}
		}
		return nil
	case store.ProvModeDryRun:
		return nil
	}
	if res.held {
		return nil
	}
	// active: the groups touched by ops get the status of their ops
	status := map[string]string{}
	rank := map[string]int{store.OpVerified: 0, store.OpApplied: 1, store.OpFailed: 3, store.OpDrift: 2}
	for _, os := range res.ops {
		k := Key(os.po.Op.Ref.Name)
		if cur, ok := status[k]; !ok || rank[os.status] > rank[cur] {
			status[k] = os.status
		}
	}
	readable := res.caps.Readable
	for id, dg := range snap.desired.ByGroup {
		k := Key(dg.Name)
		if other := snap.ownedKey[k]; other != "" && other != id {
			continue // a conflict: not ours to touch
		}
		st, touched := status[k]
		switch {
		case !touched:
			// nothing was needed: the group is on the target as desired (an untouched group was read, or came from the cache)
			ag := res.state.Groups[k]
			if ag == nil && res.caps.Groups {
				continue // it could not be read and nothing was planned (cannot happen for a plannable group)
			}
			if ag == nil {
				ag = &TargetGroup{Ref: TargetRef{Name: dg.Name}, Attrs: dg.Attrs, Members: dg.Members}
			}
			if err := put(id, dg.Name, ag, "synced", readable); err != nil {
				return err
			}
		default:
			final := res.final[k]
			if final == nil && !readable {
				final = &TargetGroup{Ref: TargetRef{Name: dg.Name}, Attrs: dg.Attrs, Members: dg.Members}
			}
			if st == store.OpDrift || st == store.OpFailed {
				g := "drift"
				if st == store.OpFailed {
					g = "failed"
				}
				if err := put(id, dg.Name, final, g, false); err != nil {
					return err
				}
				continue
			}
			if err := put(id, dg.Name, final, "synced", st == store.OpVerified); err != nil {
				return err
			}
		}
	}
	// groups the provisioner owned and has now deleted (or emptied)
	for id, sg := range snap.owned {
		if sg.Status == "removed" {
			continue
		}
		if snap.desired.ByGroup[id] != nil {
			continue // still wanted (a rename keeps one row, under the new name)
		}
		k := Key(sg.TargetName)
		st, touched := status[k]
		if !touched {
			continue
		}
		if st == store.OpVerified || (!readable && st == store.OpApplied) {
			if err := tx.PutSyncGroup(&store.SyncGroup{ProvisionerID: prov, GroupID: id, TargetID: sg.TargetID, TargetName: sg.TargetName,
				Status: "removed", LastReadAt: &now}); err != nil {
				return err
			}
			continue
		}
		bad := "drift"
		if st == store.OpFailed {
			bad = "failed"
		}
		if err := tx.PutSyncGroup(&store.SyncGroup{ProvisionerID: prov, GroupID: id, TargetID: sg.TargetID, TargetName: sg.TargetName,
			Status: bad, StateHash: sg.StateHash, ChangeToken: sg.ChangeToken, StateCache: sg.StateCache, LastReadAt: &now}); err != nil {
			return err
		}
	}
	return nil
}
