package index

import "math/bits"

// Bitset is a fixed-size set of small non-negative integers (atom ids). The
// design (§12.6) names roaring bitmaps; this module has no such dependency and
// atom counts are in the thousands, so a plain word slice is enough. Operations
// that combine two sets need equal sizes, which holds for sets over one index.
type Bitset []uint64

// NewBitset returns an empty set that can hold 0..n-1.
func NewBitset(n int) Bitset { return make(Bitset, (n+63)/64) }

// FullBitset returns the set 0..n-1.
func FullBitset(n int) Bitset {
	b := NewBitset(n)
	for i := range b {
		b[i] = ^uint64(0)
	}
	if r := n % 64; r != 0 && len(b) > 0 {
		b[len(b)-1] = (uint64(1) << r) - 1
	}
	return b
}

// Set adds i.
func (b Bitset) Set(i int) { b[i>>6] |= 1 << (uint(i) & 63) }

// Has reports whether i is in the set. An i beyond the size is not.
func (b Bitset) Has(i int) bool {
	w := i >> 6
	return i >= 0 && w < len(b) && b[w]&(1<<(uint(i)&63)) != 0
}

// Or adds every member of o.
func (b Bitset) Or(o Bitset) {
	for i := range b {
		b[i] |= o[i]
	}
}

// And keeps the members that are also in o.
func (b Bitset) And(o Bitset) {
	for i := range b {
		b[i] &= o[i]
	}
}

// AndNot removes every member of o.
func (b Bitset) AndNot(o Bitset) {
	for i := range b {
		b[i] &^= o[i]
	}
}

// Intersects reports whether the sets share a member.
func (b Bitset) Intersects(o Bitset) bool {
	for i := range b {
		if b[i]&o[i] != 0 {
			return true
		}
	}
	return false
}

// Clone returns a copy.
func (b Bitset) Clone() Bitset { return append(Bitset(nil), b...) }

// Count is the number of members.
func (b Bitset) Count() int {
	n := 0
	for _, w := range b {
		n += bits.OnesCount64(w)
	}
	return n
}

// ForEach calls f for each member in ascending order.
func (b Bitset) ForEach(f func(i int)) {
	for wi, w := range b {
		for w != 0 {
			f(wi<<6 + bits.TrailingZeros64(w))
			w &= w - 1
		}
	}
}

// Members lists the members in ascending order.
func (b Bitset) Members() []int32 {
	out := make([]int32, 0, b.Count())
	b.ForEach(func(i int) { out = append(out, int32(i)) }) // #nosec G115 -- a set holds atom ids, under 2^31
	return out
}

// Equal reports whether both sets have the same members.
func (b Bitset) Equal(o Bitset) bool {
	if len(b) != len(o) {
		return false
	}
	for i := range b {
		if b[i] != o[i] {
			return false
		}
	}
	return true
}
