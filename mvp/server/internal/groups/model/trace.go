package model

import (
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Membership trace (issue #48, GR-5; design §10.11 "hasMember with trace=true
// for all paths"). A path explains why an identity is a member: it runs from
// the group asked about down to the group that lists the identity directly,
// through nested groups (a group listed as a member) and composite factors.

// Limits of a trace, so that one request cannot walk an arbitrarily wide graph.
const (
	MaxTracePaths = 100
	MaxTraceDepth = 64
)

// Trace steps say how a group on a path is reached from the one before it.
const (
	TraceStart  = "start"  // the group asked about
	TraceNested = "nested" // listed as a member of the group before it
	TraceFactor = "factor" // a factor of the composite before it
)

// TraceStep is one group on a path. Op is the composite operator of a composite
// group (union, intersection or complement); Role is "left" or "right" for the
// factors of a complement.
type TraceStep struct {
	Group store.GroupID
	Name  string
	Via   string
	Op    store.CompositeOp
	Role  string
}

// TracePath is one explanation of the membership: the last step is the group
// whose direct row names the identity.
type TracePath struct {
	Steps []TraceStep
}

// Trace is the answer: whether the identity is a member now (the same answer
// IsMember gives) and every path that makes it one, up to MaxTracePaths.
type Trace struct {
	Member    bool
	Paths     []TracePath
	Truncated bool
}

// TraceMember explains the membership of an identity in a group's built-in
// members list. A disabled or deleted group, or a membership whose own dates
// have passed, has no paths (the identity is not a member).
func (e Env) TraceMember(id store.GroupID, identity int64) (*Trace, error) {
	member, err := e.IsMember(id, identity)
	if err != nil {
		return nil, err
	}
	t := &Trace{Member: member}
	if !member {
		return t, nil
	}
	w := traceWalk{e: e, list: store.MembersListID(e.Tx.Tenant()), identity: identity, out: t}
	return t, w.walk(id, TraceStart, "", nil, 0)
}

type traceWalk struct {
	e        Env
	list     store.ListID
	identity int64
	out      *Trace
}

// in reports whether the identity is in the group's effective members.
func (w *traceWalk) in(g store.GroupID) (bool, error) {
	n, err := w.e.Tx.GrpEffectiveSupport(g, w.list, w.identity)
	return n > 0, err
}

func (w *traceWalk) walk(g store.GroupID, via string, role string, prefix []TraceStep, depth int) error {
	if len(w.out.Paths) >= MaxTracePaths {
		w.out.Truncated = true
		return nil
	}
	if depth > MaxTraceDepth {
		w.out.Truncated = true
		return nil
	}
	grp, err := w.e.Tx.GrpGroup(g)
	if err != nil {
		return err
	}
	step := TraceStep{Group: g, Name: grp.Name, Via: via, Role: role}
	steps := append(append([]TraceStep(nil), prefix...), step)
	switch grp.Definition {
	case store.DefinitionBasic:
		direct, err := w.e.Tx.GrpDirectIdentityActive(g, w.list, w.identity, w.e.Now)
		if err != nil {
			return err
		}
		if direct {
			w.out.add(steps)
		}
		kids, err := w.e.Tx.GrpDirectActiveChildren(g, w.list, w.e.Now)
		if err != nil {
			return err
		}
		for _, k := range kids {
			if ok, err := w.in(k); err != nil {
				return err
			} else if ok {
				if err := w.walk(k, TraceNested, "", steps, depth+1); err != nil {
					return err
				}
			}
		}
	case store.DefinitionComposite:
		op := store.CompositeOp("")
		if grp.CompositeOp != nil {
			op = *grp.CompositeOp
		}
		steps[len(steps)-1].Op = op
		factors, err := w.e.Tx.GrpFactors(g)
		if err != nil {
			return err
		}
		in := make([]bool, len(factors))
		for i, f := range factors {
			if in[i], err = w.in(f); err != nil {
				return err
			}
		}
		if op == store.CompIntersection {
			for _, held := range in {
				if !held {
					return nil // every factor holds a member of an intersection; a stale one explains nothing
				}
			}
		}
		for i, f := range factors {
			role := ""
			switch op {
			case store.CompUnion:
				if !in[i] {
					continue
				}
			case store.CompComplement:
				if i != 0 || !in[0] || (len(in) > 1 && in[1]) {
					continue // only the left factor explains a complement; the right one must not hold the identity
				}
				role = "left"
			}
			if err := w.walk(f, TraceFactor, role, steps, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Trace) add(steps []TraceStep) {
	if len(t.Paths) >= MaxTracePaths {
		t.Truncated = true
		return
	}
	t.Paths = append(t.Paths, TracePath{Steps: steps})
}
