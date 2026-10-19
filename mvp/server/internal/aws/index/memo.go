package index

import (
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// Cell is the part of a decision the queries keep for every (action atom,
// resource atom) cell: the outcome, the reason it is a deny, the fidelity and the
// residual of a conditional. The full trace is not kept; a point query
// recomputes it (§12.4).
type Cell struct {
	Outcome  authz.Outcome
	DenyKind authz.DenyKind
	Fidelity authz.Fidelity
	// Reasons are the fidelity reason codes, sorted; a "!" follows a code that
	// is outcome-sensitive.
	Reasons string
	// Residual is the condition a Conditional outcome depends on (nil otherwise);
	// ResidualText is its canonical rendering, used to compare cells.
	Residual     authz.Residual
	ResidualText string
}

// NewCell summarizes a decision.
func NewCell(d *authz.Decision) *Cell {
	c := &Cell{Outcome: d.Outcome, DenyKind: d.DenyKind, Fidelity: d.Fidelity}
	rs := make([]string, 0, len(d.FidelityReasons))
	for _, r := range d.FidelityReasons {
		s := string(r.Code)
		if r.OutcomeSensitive {
			s += "!"
		}
		rs = append(rs, s)
	}
	sort.Strings(rs)
	c.Reasons = strings.Join(uniqueStrings(rs), ",")
	if d.Outcome == authz.Conditional {
		c.Residual = d.Residual
		c.ResidualText = authz.Render(d.Residual, authz.RenderOptions{})
	}
	return c
}

func uniqueStrings(in []string) []string {
	w := 0
	for i, s := range in {
		if i == 0 || s != in[w-1] {
			in[w] = s
			w++
		}
	}
	return in[:w]
}

// Equal reports whether two cells say the same.
func (c *Cell) Equal(o *Cell) bool {
	if c == nil || o == nil {
		return c == o
	}
	return c.Outcome == o.Outcome && c.DenyKind == o.DenyKind && c.Fidelity == o.Fidelity &&
		c.Reasons == o.Reasons && c.ResidualText == o.ResidualText
}

// Kept reports whether a cell is worth listing: anything but a deny that is
// exact. A deny that is UNSUPPORTED could be an allow the engine cannot read
// (§3.3), so it is listed, and every consumer must fail closed on it.
func (c *Cell) Kept() bool { return c.Outcome != authz.Deny || c.Fidelity == authz.Unsupported }

// String is a compact rendering for test failures.
func (c *Cell) String() string {
	if c == nil {
		return "<none>"
	}
	return c.Outcome.String() + "/" + c.DenyKind.String() + "/" + c.Fidelity.String() + "/" + c.Reasons + "/" + c.ResidualText
}

// MemoKey identifies a decision by the signatures of its three atoms (§12.4). It
// holds hashes of the atom signatures, of the global signature and of the
// request profile. The "relevant policy hash" of the design is inside the
// signatures: a requester's signature names its policy documents by content id,
// and a resource's names its resource policies and RCP chain, so a changed
// document changes the key and nothing else does.
type MemoKey struct{ P, A, R uint64 }

func hash64(parts ...string) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

// NewMemoKey builds the key of a cell. profile identifies the request context
// the cell was evaluated under (mode, assumption profile, supplied keys).
func NewMemoKey(global, profile, psig, asig, rsig string) MemoKey {
	return MemoKey{P: hash64(global, profile, psig), A: hash64(asig), R: hash64(rsig)}
}

const memoShards = 64

// Memo is a concurrent decision cache with a size bound. It keeps two
// generations per shard; when the newer one fills, the older is dropped, so the
// memory stays bounded and recently used cells survive.
type Memo struct {
	shards [memoShards]memoShard
	perGen int
	hits   atomic.Int64
	misses atomic.Int64
}

type memoShard struct {
	mu       sync.Mutex
	cur, old map[MemoKey]*Cell
}

// NewMemo returns a memo that keeps about maxEntries cells (at least 1024).
func NewMemo(maxEntries int) *Memo {
	if maxEntries < 1024 {
		maxEntries = 1024
	}
	m := &Memo{perGen: maxEntries / memoShards / 2}
	if m.perGen < 1 {
		m.perGen = 1
	}
	for i := range m.shards {
		m.shards[i].cur = map[MemoKey]*Cell{}
	}
	return m
}

func (m *Memo) shard(k MemoKey) *memoShard { return &m.shards[(k.P^k.A*31^k.R*131)%memoShards] }

// Get returns the cached cell.
func (m *Memo) Get(k MemoKey) (*Cell, bool) {
	s := m.shard(k)
	s.mu.Lock()
	c, ok := s.cur[k]
	if !ok {
		if c, ok = s.old[k]; ok {
			s.cur[k] = c // promote
		}
	}
	s.mu.Unlock()
	if ok {
		m.hits.Add(1)
	} else {
		m.misses.Add(1)
	}
	return c, ok
}

// Put stores a cell.
func (m *Memo) Put(k MemoKey, c *Cell) {
	s := m.shard(k)
	s.mu.Lock()
	if len(s.cur) >= m.perGen {
		s.old, s.cur = s.cur, make(map[MemoKey]*Cell, m.perGen)
	}
	s.cur[k] = c
	s.mu.Unlock()
}

// Len is the number of cached cells.
func (m *Memo) Len() int {
	n := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		n += len(s.cur) + len(s.old)
		s.mu.Unlock()
	}
	return n
}

// Stats returns the hit and miss counts since the memo was created.
func (m *Memo) Stats() (hits, misses int64) { return m.hits.Load(), m.misses.Load() }
