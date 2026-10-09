package connectors

import "math/bits"

// PyRandom reproduces CPython's random.Random (MT19937) bit for bit, so the
// demo company generated from a seed is identical to the one the original
// Python backend generated. Only the methods the demo model uses are provided.
//
// It is a deterministic generator for synthetic demo data, never for secrets.
type PyRandom struct {
	mt  [624]uint32
	mti int
}

// NewPyRandom seeds like random.Random(seed) for a non-negative int seed:
// init_by_array over the seed's 32-bit little-endian words.
func NewPyRandom(seed uint64) *PyRandom {
	key := []uint32{uint32(seed)}
	if hi := uint32(seed >> 32); hi != 0 {
		key = append(key, hi)
	}
	r := &PyRandom{}
	r.initByArray(key)
	return r
}

func (r *PyRandom) initGenrand(s uint32) {
	r.mt[0] = s
	for i := 1; i < 624; i++ {
		r.mt[i] = 1812433253*(r.mt[i-1]^(r.mt[i-1]>>30)) + uint32(i)
	}
	r.mti = 624
}

func (r *PyRandom) initByArray(key []uint32) {
	r.initGenrand(19650218)
	i, j := 1, 0
	k := 624
	if len(key) > k {
		k = len(key)
	}
	for ; k > 0; k-- {
		r.mt[i] = (r.mt[i] ^ ((r.mt[i-1] ^ (r.mt[i-1] >> 30)) * 1664525)) + key[j] + uint32(j)
		i++
		j++
		if i >= 624 {
			r.mt[0] = r.mt[623]
			i = 1
		}
		if j >= len(key) {
			j = 0
		}
	}
	for k = 623; k > 0; k-- {
		r.mt[i] = (r.mt[i] ^ ((r.mt[i-1] ^ (r.mt[i-1] >> 30)) * 1566083941)) - uint32(i)
		i++
		if i >= 624 {
			r.mt[0] = r.mt[623]
			i = 1
		}
	}
	r.mt[0] = 0x80000000
}

func (r *PyRandom) genrand() uint32 {
	const upper, lower = 0x80000000, 0x7fffffff
	mag01 := [2]uint32{0, 0x9908b0df}
	if r.mti >= 624 {
		var kk int
		for kk = 0; kk < 624-397; kk++ {
			y := (r.mt[kk] & upper) | (r.mt[kk+1] & lower)
			r.mt[kk] = r.mt[kk+397] ^ (y >> 1) ^ mag01[y&1]
		}
		for ; kk < 623; kk++ {
			y := (r.mt[kk] & upper) | (r.mt[kk+1] & lower)
			r.mt[kk] = r.mt[kk+(397-624)] ^ (y >> 1) ^ mag01[y&1]
		}
		y := (r.mt[623] & upper) | (r.mt[0] & lower)
		r.mt[623] = r.mt[396] ^ (y >> 1) ^ mag01[y&1]
		r.mti = 0
	}
	y := r.mt[r.mti]
	r.mti++
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	return y
}

// Random is random.random(): a float in [0, 1) with 53 random bits.
func (r *PyRandom) Random() float64 {
	a, b := r.genrand()>>5, r.genrand()>>6
	// a*2^26 is exact, so the explicit rounding only documents that no FMA is wanted.
	return (float64(float64(a)*67108864.0) + float64(b)) * (1.0 / 9007199254740992.0)
}

func (r *PyRandom) getrandbits(k int) uint32 {
	if k <= 0 {
		return 0
	}
	return r.genrand() >> (32 - k)
}

// randbelow is Random._randbelow_with_getrandbits for 0 < n < 2^32.
func (r *PyRandom) randbelow(n int) int {
	k := bits.Len(uint(n))
	v := int(r.getrandbits(k))
	for v >= n {
		v = int(r.getrandbits(k))
	}
	return v
}

// RandInt is random.randint(a, b), inclusive.
func (r *PyRandom) RandInt(a, b int) int { return a + r.randbelow(b-a+1) }

// Uniform is random.uniform(a, b). The float64 conversion forces the product
// to be rounded before the addition, as in CPython; otherwise the compiler may
// fuse them into one FMA instruction (arm64) and produce a different value.
func (r *PyRandom) Uniform(a, b float64) float64 { return a + float64((b-a)*r.Random()) }

// ChoiceIndex is the index random.choice(seq) picks for a sequence of length n.
func (r *PyRandom) ChoiceIndex(n int) int { return r.randbelow(n) }

// ShuffleStrings is random.shuffle(x).
func (r *PyRandom) ShuffleStrings(x []string) {
	for i := len(x) - 1; i > 0; i-- {
		j := r.randbelow(i + 1)
		x[i], x[j] = x[j], x[i]
	}
}
