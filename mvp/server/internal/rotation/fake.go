package rotation

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
)

// The fake adapter simulates a provider in memory, for the dev stack and the
// demo. It never makes a network call and is refused outside dev and test
// (config.RotationFakeAdapters, Engine.AllowFake, API validation).
//
// Its config can inject a failure ("fail_at": create, handover, disable,
// observe or delete), a delete that is slow to show ("delete_lag": "N" keeps
// the old key listed, inactive, for N more reads after the delete is accepted),
// a Secrets Manager style provider that deprecates instead of deleting
// ("retirement": "deprecated") or a consumer that keeps using the old credential after
// it was disabled ("consumer_still_uses": "true"), to exercise the failed
// states and the retry flow.

type fakeKey struct {
	created  time.Time
	lastUsed *time.Time
	active   bool
	exists   bool
	retiring bool     // the delete was accepted but is not visible yet
	lag      int      // reads left before it is
	stages   []string // deprecated mode: the version stages the key carries
}

// fakeWorld is one fake adapter's simulated provider.
type fakeWorld struct {
	mu     sync.Mutex
	keys   map[string]*fakeKey
	writes []string // destination paths written, in order
}

var (
	fakeMu     sync.Mutex
	fakeWorlds = map[string]*fakeWorld{}
)

func worldFor(id string) *fakeWorld {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	w := fakeWorlds[id]
	if w == nil {
		w = &fakeWorld{keys: map[string]*fakeKey{}}
		fakeWorlds[id] = w
	}
	return w
}

// FakeWrites lists the destination paths a fake adapter was handed credentials
// at (tests).
func FakeWrites(adapterID string) []string {
	w := worldFor(adapterID)
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.writes...)
}

type fakeAdapter struct {
	world *fakeWorld
	cfg   map[string]string
	now   func() time.Time
}

func newFake(adapterID string, cfg map[string]string, now func() time.Time) *fakeAdapter {
	return &fakeAdapter{world: worldFor(adapterID), cfg: cfg, now: now}
}

func (*fakeAdapter) Type() string { return TypeFake }
func (f *fakeAdapter) Capabilities() Capabilities {
	c := Capabilities{CanDisable: true, ReportsLastUsed: true, NeedsDestination: true}
	if f.cfg["retirement"] == RetireDeprecated {
		c.Retirement = RetireDeprecated
	}
	return c
}

func (f *fakeAdapter) Validate(t Target) error {
	if strings.TrimSpace(t.Ref) == "" {
		return badRef("fake", "a non-empty reference")
	}
	return nil
}

func (f *fakeAdapter) failAt(step string) error {
	if f.cfg["fail_at"] == step {
		return fail("simulated "+step, "simulated_failure", "injected by the fake adapter's fail_at setting", false)
	}
	return nil
}

// key returns the simulated key for ref; an unknown ref is an old key that was
// created 120 days ago and used a few hours ago.
func (f *fakeAdapter) key(ref string) *fakeKey {
	k := f.world.keys[ref]
	if k == nil {
		used := f.now().Add(-3 * time.Hour)
		k = &fakeKey{created: f.now().Add(-120 * 24 * time.Hour), lastUsed: &used, active: true, exists: true,
			stages: []string{"AWSPENDING"}}
		f.world.keys[ref] = k
	}
	return k
}

func (f *fakeAdapter) Create(_ context.Context, t Target) (*Minted, error) {
	if err := f.failAt("create"); err != nil {
		return nil, err
	}
	f.world.mu.Lock()
	defer f.world.mu.Unlock()
	loc, _, hasID := splitRef(t.Ref)
	id := "SIM" + seal.RandomString(14, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
	ref := id
	if hasID {
		ref = loc + hashSeparator + id
	}
	f.world.keys[ref] = &fakeKey{created: f.now(), active: true, exists: true}
	return &Minted{Ref: ref, Material: map[string]string{"simulated": "true"}}, nil
}

func (f *fakeAdapter) HandOver(ctx context.Context, t Target, m *Minted, dest Destination, path string) error {
	if err := f.failAt("handover"); err != nil {
		return err
	}
	return handOverToDestination(ctx, t, m, dest, path)
}

func (f *fakeAdapter) DisableOld(_ context.Context, t Target) error {
	if err := f.failAt("disable"); err != nil {
		return err
	}
	f.world.mu.Lock()
	defer f.world.mu.Unlock()
	k := f.key(t.Ref)
	k.active = false
	if f.cfg["consumer_still_uses"] == "true" {
		now := f.now().Add(time.Minute)
		k.lastUsed = &now // a consumer that did not pick up the new credential
	}
	return nil
}

func (f *fakeAdapter) ObserveOld(_ context.Context, t Target) (Observation, error) {
	if err := f.failAt("observe"); err != nil {
		return Observation{}, err
	}
	f.world.mu.Lock()
	defer f.world.mu.Unlock()
	k := f.key(t.Ref)
	if k.retiring {
		if k.lag > 0 {
			k.lag-- // a stale read: the delete is accepted but not visible yet
		} else {
			f.retire(k)
		}
	}
	created := k.created
	return Observation{Exists: k.exists, Active: k.exists && k.active, CreatedAt: &created, LastUsedAt: k.lastUsed,
		Stages: append([]string(nil), k.stages...), LastUsedKnown: true, Detail: "simulated provider"}, nil
}

func (f *fakeAdapter) DeleteOld(_ context.Context, t Target) error {
	if err := f.failAt("delete"); err != nil {
		return err
	}
	f.world.mu.Lock()
	defer f.world.mu.Unlock()
	k := f.key(t.Ref)
	k.active = false
	if k.retiring {
		return nil // idempotent: the delete already accepted is not restarted
	}
	if lag, _ := strconv.Atoi(f.cfg["delete_lag"]); lag > 0 {
		k.retiring, k.lag = true, lag
		return nil
	}
	f.retire(k)
	return nil
}

// retire applies an accepted delete: the key vanishes, or, in deprecated mode,
// keeps only AWSPREVIOUS (the version itself stays).
func (f *fakeAdapter) retire(k *fakeKey) {
	k.retiring = false
	if f.cfg["retirement"] == RetireDeprecated {
		k.stages = []string{"AWSPREVIOUS"}
		return
	}
	k.exists = false
}

func (f *fakeAdapter) DeleteNew(_ context.Context, _ Target, newRef string) error {
	f.world.mu.Lock()
	defer f.world.mu.Unlock()
	if k := f.world.keys[newRef]; k != nil {
		k.exists = false
	}
	return nil
}

func (*fakeAdapter) InventoryRef(_, newRef string) string { return newRef }

func (*fakeAdapter) ValidatePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fail("simulated vault", "invalid_path", "a destination path is required", false)
	}
	return nil
}

func (f *fakeAdapter) Put(_ context.Context, path string, _ map[string]string) error {
	f.world.mu.Lock()
	defer f.world.mu.Unlock()
	f.world.writes = append(f.world.writes, path)
	return nil
}
