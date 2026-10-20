package benchgen

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/provisioning"
)

// MemTarget is an in-memory provisioning target with no latency of its own, so
// that a measurement is Tessera's time, "excluding target API latency" as the
// design says. It records when it was first asked to write.
type MemTarget struct {
	mu     sync.Mutex
	groups map[string]*memGroup
	nextID int

	firstApply time.Time
	applies    int
	ops        int
	adds       int
	removes    int
}

type memGroup struct {
	ref     provisioning.TargetRef
	attrs   map[string][]string
	members map[string]struct{}
}

// NewMemTarget returns an empty target.
func NewMemTarget() *MemTarget { return &MemTarget{groups: map[string]*memGroup{}} }

// Capabilities: groups, memberships, targeted reads, batches of 500 ops.
func (m *MemTarget) Capabilities() provisioning.Capabilities {
	return provisioning.Capabilities{Groups: true, Memberships: true, Incremental: true, Readable: true, MaxBatch: 500}
}

// Close does nothing.
func (m *MemTarget) Close() error { return nil }

func (g *memGroup) out() *provisioning.TargetGroup {
	tg := &provisioning.TargetGroup{Ref: g.ref, Attrs: map[string][]string{}, Members: make([]string, 0, len(g.members))}
	for k, v := range g.attrs {
		tg.Attrs[k] = slices.Clone(v)
	}
	for mem := range g.members {
		tg.Members = append(tg.Members, mem)
	}
	return tg
}

// ReadAll returns every group.
func (m *MemTarget) ReadAll(_ context.Context, _ provisioning.Scope) (provisioning.TargetState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := provisioning.NewState()
	for k, g := range m.groups {
		st.Groups[k] = g.out()
	}
	return st, nil
}

// Read returns the named groups.
func (m *MemTarget) Read(_ context.Context, refs []provisioning.TargetRef) (provisioning.TargetState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := provisioning.NewState()
	for _, r := range refs {
		if g := m.groups[provisioning.Key(r.Name)]; g != nil {
			st.Groups[provisioning.Key(r.Name)] = g.out()
		}
	}
	return st, nil
}

// Apply runs the ops.
func (m *MemTarget) Apply(_ context.Context, ops []provisioning.Op) ([]provisioning.OpResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.firstApply.IsZero() {
		m.firstApply = time.Now()
	}
	m.applies++
	out := make([]provisioning.OpResult, len(ops))
	for i, op := range ops {
		m.ops++
		out[i] = provisioning.OpResult{ID: op.ID, Ref: op.Ref}
		k := provisioning.Key(op.Ref.Name)
		g := m.groups[k]
		switch op.Kind {
		case provisioning.OpCreate:
			m.nextID++
			g = &memGroup{ref: provisioning.TargetRef{Name: op.Ref.Name, ID: fmt.Sprintf("m%d", m.nextID)}, attrs: op.Attrs,
				members: map[string]struct{}{}}
			m.groups[k] = g
			out[i].Ref = g.ref
		case provisioning.OpUpdate:
			if g != nil {
				if g.attrs == nil {
					g.attrs = map[string][]string{}
				}
				for a, v := range op.Attrs {
					g.attrs[a] = v
				}
			}
		case provisioning.OpDelete:
			delete(m.groups, k)
			continue
		case provisioning.OpMembers:
			if g == nil {
				out[i].Err = fmt.Errorf("no such group %s", op.Ref.Name)
				continue
			}
		}
		if g == nil {
			continue
		}
		for _, r := range op.Remove {
			delete(g.members, provisioning.NormMember(r))
			m.removes++
		}
		for _, a := range op.Add {
			g.members[provisioning.NormMember(a)] = struct{}{}
			m.adds++
		}
	}
	return out, nil
}

// FirstApply is when the target was first asked to write (zero: never).
func (m *MemTarget) FirstApply() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.firstApply
}

// Reset forgets the recorded first write and the counters.
func (m *MemTarget) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.firstApply, m.applies, m.ops, m.adds, m.removes = time.Time{}, 0, 0, 0, 0
}

// Counts returns the number of Apply calls, ops and member adds and removes.
func (m *MemTarget) Counts() (applies, ops, adds, removes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applies, m.ops, m.adds, m.removes
}
