package provisioning

import (
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func opStatuses(ops []*store.SyncOp) map[string]string {
	out := map[string]string{}
	for _, o := range ops {
		out[o.Op+":"+o.ObjectRef] = o.Status
	}
	return out
}

func eventsOfType(x *harness, typ string) []*store.GrpEvent {
	var out []*store.GrpEvent
	x.read(func(tx *store.TenantTx) error {
		h, err := tx.GrpEventHead()
		if err != nil {
			return err
		}
		all, err := tx.GrpEventsAfter(0, h.LastSeq, int(h.LastSeq)+1)
		for _, e := range all {
			if e.Type == typ {
				out = append(out, e)
			}
		}
		return err
	})
	return out
}

// An op is verified only when a targeted re-read shows its effect (README rule
// 4): a target that accepts a change and does not keep it ends in drift after
// three attempts, and a target that cannot be re-read leaves the op "applied".
func TestProvision_VerifiedOnlyAfterReread(t *testing.T) {
	x := newHarness(t, 4)
	g := x.group(x.root, "eng")
	x.add(g, x.idents[0])
	x.add(g, x.idents[1])
	p, f := x.prov("scim", `{}`)
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	x.setMode(p.ID, store.ProvModeActive)

	t.Run("a change is verified after the re-read", func(t *testing.T) {
		rep := x.full(p.ID)
		if rep.Run.Status != store.RunDone || rep.Summary.Verified != 1 || rep.Summary.Drift+rep.Summary.Failed != 0 {
			t.Fatalf("run = %s, summary %+v", rep.Run.Status, rep.Summary)
		}
		if got := f.members("eng"); !slices.Equal(got, []string{"u0", "u1"}) {
			t.Fatalf("members = %v", got)
		}
		// the first apply is followed by a read before anything is called verified
		ai := slices.Index(f.log, "apply")
		if ai < 0 || !slices.Contains(f.log[ai:], "read") {
			t.Fatalf("call order %v: no re-read after the apply", f.log)
		}
		op := x.ops(p.ID, rep.Run.ID)[0]
		if op.Status != store.OpVerified || op.VerifiedAt == nil || op.AppliedAt == nil || op.Attempts != 1 {
			t.Errorf("op = %+v, want verified after one attempt", op)
		}
		if sg := x.syncGroup(p.ID, g); sg == nil || sg.Status != "synced" || sg.LastVerifiedAt == nil {
			t.Errorf("sync group = %+v", sg)
		}
		if n := len(eventsOfType(x, events.ProvisioningOpVerified)); n != 1 {
			t.Errorf("%d op.verified events, want 1", n)
		}
	})

	t.Run("a target that loses the change is drift, not verified", func(t *testing.T) {
		x.tick(time.Minute)
		f.dropAdd["u2"] = true
		x.add(g, x.idents[2])
		before := f.applies
		rep := x.incremental(p.ID)
		ops := x.ops(p.ID, rep.Run.ID)
		if len(ops) != 1 || ops[0].Status != store.OpDrift || ops[0].Attempts != MaxAttempts || ops[0].VerifiedAt != nil {
			t.Fatalf("ops = %v, want one drift op after %d attempts", names(ops), MaxAttempts)
		}
		if f.applies-before != MaxAttempts {
			t.Errorf("%d applies, want %d", f.applies-before, MaxAttempts)
		}
		if rep.Summary.Verified != 0 || rep.Summary.Drift != 1 {
			t.Errorf("summary = %+v", rep.Summary)
		}
		if sg := x.syncGroup(p.ID, g); sg.Status != "drift" || sg.LastVerifiedAt != nil && sg.LastVerifiedAt.After(x.now.Add(-time.Second)) {
			t.Errorf("sync group = %+v, want drift and not newly verified", sg)
		}
		if n := len(eventsOfType(x, events.ProvisioningOpDrift)); n != 1 {
			t.Errorf("%d op.drift events, want 1", n)
		}
		// the drifted group is tried again after RetryAfter, and verified once the target behaves
		delete(f.dropAdd, "u2")
		x.tick(RetryAfter + time.Minute)
		rep = x.incremental(p.ID)
		if rep.Summary.Verified != 1 {
			t.Fatalf("retry summary = %+v", rep.Summary)
		}
		if sg := x.syncGroup(p.ID, g); sg.Status != "synced" {
			t.Errorf("sync group = %+v, want synced", sg)
		}
	})

	t.Run("a target that cannot be re-read leaves the op applied", func(t *testing.T) {
		x.tick(time.Minute)
		f.failVerifyRead = errors.New("read failed")
		x.add(g, x.idents[3])
		rep := x.incremental(p.ID)
		ops := x.ops(p.ID, rep.Run.ID)
		if len(ops) != 1 || ops[0].Status != store.OpApplied || ops[0].VerifiedAt != nil {
			t.Fatalf("ops = %+v, want one applied, unverified op", ops)
		}
		if rep.Summary.Verified != 0 || rep.Summary.Applied != 1 {
			t.Errorf("summary = %+v", rep.Summary)
		}
		f.failVerifyRead = nil
	})
}

// The first run of a provisioner is adopt mode: existing target objects are
// matched and recorded, and nothing on the target is changed until an admin
// enables it. Dry run records the plan and applies nothing either.
func TestProvision_AdoptModeChangesNothing(t *testing.T) {
	x := newHarness(t, 4)
	g := x.group(x.root, "eng")
	x.add(g, x.idents[0])
	x.add(g, x.idents[1])
	p, f := x.prov("scim", `{}`)
	if p.Mode != store.ProvModeAdopt {
		t.Fatalf("a new provisioner is in %q mode, want adopt", p.Mode)
	}
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
	seeded := f.seed("eng", "u1", "u9")
	f.seed("legacy", "u5")

	rep := x.full(p.ID)
	if f.applies != 0 || f.writes != 0 {
		t.Fatalf("adopt mode wrote to the target: %d applies, %d writes", f.applies, f.writes)
	}
	if got := f.members("eng"); !slices.Equal(got, []string{"u1", "u9"}) {
		t.Errorf("eng = %v, want it untouched", got)
	}
	if got := f.names(); !slices.Equal(got, []string{"eng", "legacy"}) {
		t.Errorf("target groups = %v", got)
	}
	if rep.Run.Mode != store.ProvModeAdopt || rep.Summary.Adopted != 1 || rep.Summary.Skipped != 1 {
		t.Errorf("run = %s, summary %+v", rep.Run.Mode, rep.Summary)
	}
	ops := x.ops(p.ID, rep.Run.ID)
	if len(ops) != 1 || ops[0].Op != "members" || ops[0].Status != store.OpSkipped || string(ops[0].Detail) != `{"add":1,"remove":1}` {
		t.Errorf("ops = %+v, want one skipped members op (add 1, remove 1)", ops)
	}
	sg := x.syncGroup(p.ID, g)
	if sg == nil || sg.Status != "adopted" || sg.TargetID != seeded.Ref.ID {
		t.Fatalf("sync group = %+v, want adopted as %s", sg, seeded.Ref.ID)
	}
	// incremental sync is for active provisioners
	if _, err := x.svc.Run(t.Context(), tid, p.ID, RunOptions{Kind: store.RunIncremental}); !errors.Is(err, ErrNotActive) {
		t.Errorf("incremental in adopt mode = %v, want ErrNotActive", err)
	}

	x.setMode(p.ID, store.ProvModeDryRun)
	rep = x.full(p.ID)
	if f.applies != 0 || rep.Summary.Skipped != 1 || rep.Summary.Verified != 0 {
		t.Errorf("dry run applied %d times, summary %+v", f.applies, rep.Summary)
	}

	// enabled by an admin: the target converges, the unrelated group is never touched
	x.setMode(p.ID, store.ProvModeActive)
	rep = x.full(p.ID)
	if rep.Summary.Verified != 1 || rep.Summary.Skipped != 0 {
		t.Errorf("active summary = %+v", rep.Summary)
	}
	if got := f.members("eng"); !slices.Equal(got, []string{"u0", "u1"}) {
		t.Errorf("eng = %v, want [u0 u1]", got)
	}
	if got := f.members("legacy"); !slices.Equal(got, []string{"u5"}) {
		t.Errorf("legacy = %v, want it untouched", got)
	}
}

// The failsafes hold a run whose plan deletes too much: nothing is applied, the
// run is "held", and an admin's approval lets the next full sync through.
func TestProvision_FailsafeMaxDeletes(t *testing.T) {
	setup := func(failsafe string, stale int) (*harness, *store.Provisioner, *fakeTarget, store.GroupID) {
		x := newHarness(t, 3)
		g := x.group(x.root, "eng")
		x.add(g, x.idents[0])
		p, f := x.prov("scim", failsafe)
		x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(g), Include: true})
		var members []string
		for i := 0; i < stale; i++ {
			members = append(members, fmt.Sprintf("old%d", i))
		}
		f.seed("eng", append(members, "u0")...)
		x.setMode(p.ID, store.ProvModeActive)
		return x, p, f, g
	}

	t.Run("too many member removals", func(t *testing.T) {
		x, p, f, _ := setup(`{"max_deletes": 5}`, 10)
		rep := x.full(p.ID)
		if rep.Run.Status != store.RunHeld || len(rep.Summary.Held) == 0 || !strings.Contains(rep.Summary.Held[0], "10 member removals exceed the limit of 5") {
			t.Fatalf("run = %s, held = %v", rep.Run.Status, rep.Summary.Held)
		}
		if f.applies != 0 || len(f.members("eng")) != 11 {
			t.Fatalf("held run changed the target: %d applies, members %v", f.applies, f.members("eng"))
		}
		if ops := x.ops(p.ID, rep.Run.ID); len(ops) != 1 || ops[0].Status != store.OpSkipped || !strings.Contains(ops[0].Error, "held by the failsafe") {
			t.Errorf("ops = %+v", ops)
		}
		// a held run is not retried by itself ...
		x.read(func(tx *store.TenantTx) error {
			if pp, _ := tx.Provisioner(p.ID); pp.NeedsFull {
				t.Error("a held full sync asks for another full sync")
			}
			return nil
		})
		// ... and an admin's approval covers the next full sync only
		x.must(func(e model.Env) error { return x.svc.RequestFull(e.Tx, x.now, "admin", p.ID, true) })
		rep = x.full(p.ID)
		if rep.Run.Status != store.RunDone || rep.Summary.Verified != 1 {
			t.Fatalf("approved run = %s, summary %+v", rep.Run.Status, rep.Summary)
		}
		if got := f.members("eng"); !slices.Equal(got, []string{"u0"}) {
			t.Errorf("members = %v, want [u0]", got)
		}
		x.read(func(tx *store.TenantTx) error {
			if pp, _ := tx.Provisioner(p.ID); pp.ApproveNext || pp.NeedsFull {
				t.Errorf("approval was not consumed: %+v", pp)
			}
			return nil
		})
	})

	t.Run("a share of a large target", func(t *testing.T) {
		x, p, f, _ := setup(`{"max_deletes": 1000, "max_delete_percent": 2}`, 100)
		rep := x.full(p.ID)
		if rep.Run.Status != store.RunHeld || f.applies != 0 || !strings.Contains(strings.Join(rep.Summary.Held, ";"), "% of the target's 101 memberships") {
			t.Fatalf("run = %s, held %v, applies %d", rep.Run.Status, rep.Summary.Held, f.applies)
		}
	})

	t.Run("a small target is not held by the percentage", func(t *testing.T) {
		x, p, f, _ := setup(`{}`, 3)
		rep := x.full(p.ID)
		if rep.Run.Status != store.RunDone || len(f.members("eng")) != 1 {
			t.Fatalf("run = %s, members %v", rep.Run.Status, f.members("eng"))
		}
	})

	t.Run("deleting a group needs approval", func(t *testing.T) {
		x, p, f, g := setup(`{}`, 0)
		x.full(p.ID)
		// the group stops being provisioned: the target group would be deleted
		x.must(func(e model.Env) error { return x.svc.RemoveMark(e.Tx, x.now, "admin", p.ID, "group", string(g)) })
		rep := x.full(p.ID)
		if rep.Run.Status != store.RunHeld || !strings.Contains(strings.Join(rep.Summary.Held, ";"), "1 group deletions exceed the limit of 0") {
			t.Fatalf("run = %s, held %v", rep.Run.Status, rep.Summary.Held)
		}
		if _, ok := f.groups["eng"]; !ok {
			t.Fatal("the group was deleted without approval")
		}
		x.must(func(e model.Env) error { return x.svc.RequestFull(e.Tx, x.now, "admin", p.ID, true) })
		rep = x.full(p.ID)
		if rep.Run.Status != store.RunDone || len(f.groups) != 0 {
			t.Fatalf("approved run = %s, target groups %v", rep.Run.Status, f.names())
		}
		if sg := x.syncGroup(p.ID, g); sg.Status != "removed" {
			t.Errorf("sync group = %+v, want removed", sg)
		}
	})

	t.Run("the limits apply to incremental runs too", func(t *testing.T) {
		x, p, f, g := setup(`{"max_deletes": 2}`, 0)
		x.full(p.ID)
		for _, i := range []int{1, 2} {
			x.add(g, x.idents[i])
		}
		x.incremental(p.ID)
		if len(f.members("eng")) != 3 {
			t.Fatalf("members = %v", f.members("eng"))
		}
		for _, i := range []int{0, 1, 2} {
			x.remove(g, x.idents[i])
		}
		rep := x.incremental(p.ID)
		if rep.Run.Status != store.RunHeld || len(f.members("eng")) != 3 {
			t.Fatalf("run = %s, members %v", rep.Run.Status, f.members("eng"))
		}
		// the held incremental run asks for a full sync, which is held in turn and waits for an admin
		rep = x.full(p.ID)
		if rep.Run.Status != store.RunHeld {
			t.Fatalf("full run = %s", rep.Run.Status)
		}
	})
}

// After any sequence of changes, an incremental sync leaves the target where a
// full sync of the same state would.
func TestProvision_IncrementalEqualsFull(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			x := newHarness(t, 8)
			a := x.folder(x.root, "a")
			b := x.folder(a, "b")
			groups := []store.GroupID{x.group(a, "g0"), x.group(a, "g1"), x.group(b, "g2"), x.group(x.root, "g3")}
			pInc, fInc := x.prov("incremental", `{}`)
			pFull, fFull := x.prov("full", `{}`)
			for _, p := range []*store.Provisioner{pInc, pFull} {
				x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(x.root), Scope: "sub", Include: true})
				x.setMode(p.ID, store.ProvModeActive)
				x.full(p.ID)
			}
			rng := rand.New(rand.NewSource(seed))
			for step := 0; step < 40; step++ {
				x.tick(time.Minute)
				g := groups[rng.Intn(len(groups))]
				h := groups[rng.Intn(len(groups))]
				id := x.idents[rng.Intn(len(x.idents))]
				switch rng.Intn(8) {
				case 0, 1, 2:
					_ = x.run(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Identity: &id}); return err })
				case 3:
					_ = x.run(func(e model.Env) error { _, err := e.RemoveMember(g, fmt.Sprint(id)); return err })
				case 4:
					_ = x.run(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Group: h}); return err })
				case 5:
					_ = x.run(func(e model.Env) error { _, err := e.RemoveMember(g, string(h)); return err })
				case 6:
					status := store.GroupDisabled
					if rng.Intn(2) == 0 {
						status = store.GroupActive
					}
					_ = x.run(func(e model.Env) error {
						_, err := e.UpdateGroup(g, model.UpdateGroupInput{Status: &status})
						return err
					})
				case 7:
					if len(groups) < 7 {
						groups = append(groups, x.group(a, fmt.Sprintf("n%d", step)))
					}
				}
				x.incremental(pInc.ID)
				x.full(pFull.ID)
				want := expected(x, groups)
				for name, f := range map[string]*fakeTarget{"incremental": fInc, "full": fFull} {
					if got := f.snapshot(); !equalState(got, want) {
						t.Fatalf("step %d: %s target = %v, want %v", step, name, got, want)
					}
				}
			}
			x.read(func(tx *store.TenantTx) error {
				lag, err := events.Lag(tx, Consumer(pInc.ID))
				if err != nil {
					t.Fatal(err)
				}
				// the incremental provisioner has seen every group event; only its own provisioning events can be pending
				evs, _ := events.Poll(tx, Consumer(pInc.ID), events.MaxBatch)
				for _, e := range evs {
					if e.ObjectType != store.EventObjProvisioning {
						t.Errorf("unconsumed event %s (lag %d)", e.Type, lag)
					}
				}
				return nil
			})
		})
	}
}

func equalState(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !slices.Equal(v, w) && !(len(v) == 0 && len(w) == 0) {
			return false
		}
	}
	return true
}

// expected is the target state a sync should reach: every group of the tenant,
// named by the "-" form of its path, with its effective members' usernames.
func expected(x *harness, groups []store.GroupID) map[string][]string {
	out := map[string][]string{}
	x.read(func(tx *store.TenantTx) error {
		for _, id := range groups {
			g, err := tx.GrpGroup(id)
			if err != nil {
				return err
			}
			rows, err := tx.GrpEffectiveList(id, store.MembersListID(tid), 10000, 0)
			if err != nil {
				return err
			}
			names := []string{}
			for _, r := range rows {
				if g.Status == store.GroupActive {
					names = append(names, fmt.Sprintf("u%d", slices.Index(x.idents, r.Identity)))
				}
			}
			slices.Sort(names)
			out[Key(strings.ReplaceAll(g.Name, ":", "-"))] = names
		}
		return nil
	})
	return out
}
