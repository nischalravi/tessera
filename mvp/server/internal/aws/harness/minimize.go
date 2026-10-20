package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// The delta-debug minimizer (§13.9 step 1). Given a spec on which our decision
// and an oracle disagree, it removes policies, statements, values, condition
// blocks and context keys, in that order, for as long as the disagreement
// persists, and keeps the smallest spec found. The reduction at each level is
// Zeller's ddmin over the removable units, so it needs O(n log n) predicate
// calls in the typical case and is exact (1-minimal) at the end of a round that
// changes nothing.

// Predicate reports whether the divergence still reproduces on a spec. A
// *RefusalError is read as false (a reduction that breaks a policy is not a
// reproducer); any other error aborts the minimization.
type Predicate func(ctx context.Context, s *RequestSpec) (bool, error)

// ErrNotReproducible: the predicate is false on the original spec.
var ErrNotReproducible = errors.New("harness: divergence does not reproduce on the original spec")

// ErrBudget: MaxCalls was reached; the result is the best spec found so far.
var ErrBudget = errors.New("harness: minimizer call budget exhausted")

// MinimizeStats reports what the minimizer did.
type MinimizeStats struct {
	Calls  int
	Rounds int
	Before Size
	After  Size
}

// Size counts the removable units of a spec.
type Size struct {
	Policies, Statements, Values, ConditionKeys, ContextKeys int
}

// MinimizeOptions bounds the work.
type MinimizeOptions struct {
	MaxCalls int // predicate calls; 0 means 5000
}

// DDMin returns a 1-minimal subset of {0..n-1} for which test is true,
// assuming test is true on the full set. It tests the empty set first.
func DDMin(n int, test func(keep []int) (bool, error)) ([]int, error) {
	keep := make([]int, n)
	for i := range keep {
		keep[i] = i
	}
	if n == 0 {
		return keep, nil
	}
	if ok, err := test(nil); err != nil || ok {
		return nil, err
	}
	g := 2
	for len(keep) >= 2 {
		chunks := split(keep, g)
		reduced := false
		for _, c := range chunks {
			ok, err := test(c)
			if err != nil {
				return keep, err
			}
			if ok {
				keep, g, reduced = c, 2, true
				break
			}
		}
		if !reduced {
			for i := range chunks {
				comp := complement(chunks, i)
				ok, err := test(comp)
				if err != nil {
					return keep, err
				}
				if ok {
					keep, reduced = comp, true
					if g > 2 {
						g--
					}
					break
				}
			}
		}
		if !reduced {
			if g >= len(keep) {
				break
			}
			g = min(2*g, len(keep))
		}
		if g > len(keep) {
			g = len(keep)
		}
	}
	// A single remaining unit was never tried alone against the empty set above
	// for the reduced list; 1-minimality of a size-1 set follows from the empty test.
	return keep, nil
}

func split(s []int, g int) [][]int {
	out := make([][]int, 0, g)
	size, extra := len(s)/g, len(s)%g
	at := 0
	for i := 0; i < g; i++ {
		n := size
		if i < extra {
			n++
		}
		if n == 0 {
			continue
		}
		out = append(out, s[at:at+n])
		at += n
	}
	return out
}

func complement(chunks [][]int, skip int) []int {
	var out []int
	for i, c := range chunks {
		if i != skip {
			out = append(out, c...)
		}
	}
	return out
}

// Minimize reduces spec. It returns the smallest spec found on which pred holds.
func Minimize(ctx context.Context, spec *RequestSpec, pred Predicate, opts MinimizeOptions) (*RequestSpec, MinimizeStats, error) {
	if opts.MaxCalls <= 0 {
		opts.MaxCalls = 5000
	}
	var st MinimizeStats
	st.Before = sizeOf(spec)
	call := func(s *RequestSpec) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if st.Calls >= opts.MaxCalls {
			return false, ErrBudget
		}
		st.Calls++
		ok, err := pred(ctx, s)
		var ref *RefusalError
		if errors.As(err, &ref) {
			return false, nil
		}
		return ok, err
	}
	ok, err := call(spec)
	if err != nil {
		return nil, st, err
	}
	if !ok {
		return nil, st, ErrNotReproducible
	}
	cur := spec.Clone()
	passes := []func(*RequestSpec, func(*RequestSpec) (bool, error)) (*RequestSpec, error){
		reduceLevels, reducePolicies, reduceStatements, reduceValues, reduceConditionOps, reduceConditionKeys, reduceContext,
	}
	for {
		st.Rounds++
		before := cur.Hash()
		for _, p := range passes {
			next, err := p(cur, call)
			if err != nil {
				st.After = sizeOf(cur)
				return cur, st, err // cur is the best spec found so far
			}
			cur = next
		}
		if cur.Hash() == before {
			break
		}
	}
	st.After = sizeOf(cur)
	return cur, st, nil
}

// DivergencePredicate adapts a function that runs one check (engine plus oracle)
// to a Predicate: true when the check is a disagreement.
func DivergencePredicate(run func(context.Context, *RequestSpec) (*Check, error)) Predicate {
	return func(ctx context.Context, s *RequestSpec) (bool, error) {
		c, err := run(ctx, s)
		if err != nil {
			return false, err
		}
		return c.Verdict == Disagree, nil
	}
}

func sizeOf(s *RequestSpec) Size {
	z := Size{Policies: len(s.allPolicies()), ContextKeys: len(s.Context)}
	for _, d := range decodeDocs(s) {
		z.Statements += len(d.stmts)
		for _, st := range d.stmts {
			for _, f := range valueFields {
				z.Values += len(listOf(st[f]))
			}
			if c, ok := st["Condition"].(map[string]any); ok {
				for _, op := range c {
					if m, ok := op.(map[string]any); ok {
						z.ConditionKeys += len(m)
					}
				}
			}
		}
	}
	return z
}

type caller = func(*RequestSpec) (bool, error)

// subset runs ddmin over n units and returns the kept indices as a set.
func subset(n int, try func(keep map[int]bool) (bool, error)) (map[int]bool, error) {
	idx, err := DDMin(n, func(k []int) (bool, error) {
		m := make(map[int]bool, len(k))
		for _, i := range k {
			m[i] = true
		}
		return try(m)
	})
	if err != nil {
		return nil, err
	}
	m := make(map[int]bool, len(idx))
	for _, i := range idx {
		m[i] = true
	}
	return m, nil
}

func reduceLevels(s *RequestSpec, call caller) (*RequestSpec, error) {
	n := len(s.SCPLevels)
	if n == 0 {
		return s, nil
	}
	build := func(keep map[int]bool) *RequestSpec {
		c := s.Clone()
		c.SCPLevels = nil
		for i, l := range s.SCPLevels {
			if keep[i] {
				c.SCPLevels = append(c.SCPLevels, append([]string(nil), l...))
			}
		}
		return c
	}
	keep, err := subset(n, func(k map[int]bool) (bool, error) { return call(build(k)) })
	if err != nil {
		return s, err
	}
	return build(keep), nil
}

// policySlots returns pointers to every policy string of a (cloned) spec, in
// the order of allPolicies.
func policySlots(s *RequestSpec) []*string {
	var out []*string
	for i := range s.Identity {
		out = append(out, &s.Identity[i])
	}
	for i := range s.Boundary {
		out = append(out, &s.Boundary[i])
	}
	for l := range s.SCPLevels {
		for i := range s.SCPLevels[l] {
			out = append(out, &s.SCPLevels[l][i])
		}
	}
	if s.ResourcePolicy != "" {
		out = append(out, &s.ResourcePolicy)
	}
	return out
}

func reducePolicies(s *RequestSpec, call caller) (*RequestSpec, error) {
	n := len(policySlots(s.Clone()))
	if n == 0 {
		return s, nil
	}
	build := func(keep map[int]bool) *RequestSpec {
		c := s.Clone()
		slots := policySlots(c)
		for i, p := range slots {
			if !keep[i] {
				*p = "" // marked for removal
			}
		}
		c.Identity = dropEmpty(c.Identity)
		c.Boundary = dropEmpty(c.Boundary)
		for l := range c.SCPLevels {
			c.SCPLevels[l] = dropEmpty(c.SCPLevels[l])
		}
		return c
	}
	keep, err := subset(n, func(k map[int]bool) (bool, error) { return call(build(k)) })
	if err != nil {
		return s, err
	}
	return build(keep), nil
}

func dropEmpty(in []string) []string {
	var out []string
	for _, x := range in {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// doc is a decoded policy: its slot, its root object and its statements.
type doc struct {
	slot  int
	root  map[string]any
	stmts []map[string]any
}

var valueFields = []string{"Action", "NotAction", "Resource", "NotResource"}

func decodeDocs(s *RequestSpec) []*doc {
	var out []*doc
	for i, p := range policySlots(s.Clone()) {
		dec := json.NewDecoder(bytes.NewReader([]byte(*p)))
		dec.UseNumber()
		var root map[string]any
		if dec.Decode(&root) != nil || root == nil {
			continue // not an object: atomic
		}
		d := &doc{slot: i, root: root}
		switch v := root["Statement"].(type) {
		case map[string]any:
			d.stmts = []map[string]any{v}
		case []any:
			for _, e := range v {
				if m, ok := e.(map[string]any); ok {
					d.stmts = append(d.stmts, m)
				}
			}
		}
		out = append(out, d)
	}
	return out
}

func listOf(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case string:
		return []any{x}
	}
	return nil
}

// withDocs builds a candidate: it decodes the spec's documents afresh, lets edit
// remove things, and re-encodes only the documents that changed.
func withDocs(s *RequestSpec, edit func(docs []*doc) (changed map[int]bool)) *RequestSpec {
	c := s.Clone()
	docs := decodeDocs(c)
	changed := edit(docs)
	slots := policySlots(c)
	for _, d := range docs {
		if !changed[d.slot] {
			continue
		}
		stmts := make([]any, len(d.stmts))
		for i, st := range d.stmts {
			stmts[i] = st
		}
		d.root["Statement"] = stmts
		if b, err := json.Marshal(d.root); err == nil {
			*slots[d.slot] = string(b)
		}
	}
	return c
}

// unit addresses one removable thing inside the decoded documents.
type unit struct {
	doc, stmt int
	field     string
	idx       int
	op, key   string
}

func reduceUnits(s *RequestSpec, call caller, units func(docs []*doc) []unit, remove func(d *doc, u unit)) (*RequestSpec, error) {
	all := units(decodeDocs(s))
	if len(all) == 0 {
		return s, nil
	}
	build := func(keep map[int]bool) *RequestSpec {
		return withDocs(s, func(docs []*doc) map[int]bool {
			changed := map[int]bool{}
			// Remove from the highest unit down so list indices stay valid.
			for i := len(all) - 1; i >= 0; i-- {
				if keep[i] {
					continue
				}
				u := all[i]
				for _, d := range docs {
					if d.slot == u.doc {
						remove(d, u)
						changed[d.slot] = true
					}
				}
			}
			return changed
		})
	}
	keep, err := subset(len(all), func(k map[int]bool) (bool, error) { return call(build(k)) })
	if err != nil {
		return s, err
	}
	return build(keep), nil
}

func reduceStatements(s *RequestSpec, call caller) (*RequestSpec, error) {
	return reduceUnits(s, call, func(docs []*doc) []unit {
		var us []unit
		for _, d := range docs {
			for i := range d.stmts {
				us = append(us, unit{doc: d.slot, stmt: i})
			}
		}
		return us
	}, func(d *doc, u unit) {
		d.stmts = append(d.stmts[:u.stmt:u.stmt], d.stmts[u.stmt+1:]...)
	})
}

func reduceValues(s *RequestSpec, call caller) (*RequestSpec, error) {
	return reduceUnits(s, call, func(docs []*doc) []unit {
		var us []unit
		for _, d := range docs {
			for i, st := range d.stmts {
				for _, f := range valueFields {
					for j := range listOf(st[f]) {
						us = append(us, unit{doc: d.slot, stmt: i, field: f, idx: j})
					}
				}
			}
		}
		return us
	}, func(d *doc, u unit) {
		st := d.stmts[u.stmt]
		l := listOf(st[u.field])
		if u.idx < len(l) {
			st[u.field] = append(append([]any{}, l[:u.idx]...), l[u.idx+1:]...)
		}
	})
}

func conditionOf(st map[string]any) map[string]any {
	c, _ := st["Condition"].(map[string]any)
	return c
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func reduceConditionOps(s *RequestSpec, call caller) (*RequestSpec, error) {
	return reduceUnits(s, call, func(docs []*doc) []unit {
		var us []unit
		for _, d := range docs {
			for i, st := range d.stmts {
				for _, op := range sortedKeys(conditionOf(st)) {
					us = append(us, unit{doc: d.slot, stmt: i, op: op})
				}
			}
		}
		return us
	}, func(d *doc, u unit) {
		c := conditionOf(d.stmts[u.stmt])
		delete(c, u.op)
		if len(c) == 0 {
			delete(d.stmts[u.stmt], "Condition")
		}
	})
}

func reduceConditionKeys(s *RequestSpec, call caller) (*RequestSpec, error) {
	return reduceUnits(s, call, func(docs []*doc) []unit {
		var us []unit
		for _, d := range docs {
			for i, st := range d.stmts {
				c := conditionOf(st)
				for _, op := range sortedKeys(c) {
					if m, ok := c[op].(map[string]any); ok {
						for _, k := range sortedKeys(m) {
							us = append(us, unit{doc: d.slot, stmt: i, op: op, key: k})
						}
					}
				}
			}
		}
		return us
	}, func(d *doc, u unit) {
		c := conditionOf(d.stmts[u.stmt])
		m, ok := c[u.op].(map[string]any)
		if !ok {
			return
		}
		delete(m, u.key)
		if len(m) == 0 {
			delete(c, u.op)
		}
		if len(c) == 0 {
			delete(d.stmts[u.stmt], "Condition")
		}
	})
}

func reduceContext(s *RequestSpec, call caller) (*RequestSpec, error) {
	keys := s.contextKeys()
	if len(keys) == 0 {
		return s, nil
	}
	build := func(keep map[int]bool) *RequestSpec {
		c := s.Clone()
		for i, k := range keys {
			if !keep[i] {
				delete(c.Context, k)
			}
		}
		return c
	}
	keep, err := subset(len(keys), func(k map[int]bool) (bool, error) { return call(build(k)) })
	if err != nil {
		return s, err
	}
	return build(keep), nil
}

// String renders a Size.
func (z Size) String() string {
	return fmt.Sprintf("%d policies, %d statements, %d values, %d condition keys, %d context keys", z.Policies, z.Statements, z.Values, z.ConditionKeys, z.ContextKeys)
}
