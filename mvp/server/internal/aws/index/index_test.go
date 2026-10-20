package index

import (
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

func TestBitset(t *testing.T) {
	for _, n := range []int{0, 1, 63, 64, 65, 200} {
		full := FullBitset(n)
		if full.Count() != n {
			t.Errorf("FullBitset(%d) has %d members", n, full.Count())
		}
		if full.Has(n) || full.Has(-1) {
			t.Errorf("FullBitset(%d) holds a number outside 0..n-1", n)
		}
	}
	a, b := NewBitset(130), NewBitset(130)
	for _, i := range []int{0, 5, 64, 129} {
		a.Set(i)
	}
	for _, i := range []int{5, 64, 100} {
		b.Set(i)
	}
	and := a.Clone()
	and.And(b)
	or := a.Clone()
	or.Or(b)
	not := a.Clone()
	not.AndNot(b)
	for name, c := range map[string]struct {
		got  Bitset
		want []int32
	}{
		"and":    {and, []int32{5, 64}},
		"or":     {or, []int32{0, 5, 64, 100, 129}},
		"andnot": {not, []int32{0, 129}},
	} {
		got := c.got.Members()
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %v, want %v", name, got, c.want)
			}
		}
	}
	if !a.Equal(a.Clone()) || a.Equal(b) {
		t.Error("Equal")
	}
}

func TestLiteralPrefixAndSkeleton(t *testing.T) {
	for _, c := range []struct{ in, prefix string }{
		{"arn:aws:s3:::bkt-*", "arn:aws:s3:::bkt-"},
		{"arn:aws:s3:::b?x", "arn:aws:s3:::b"},
		{"arn:aws:s3:::${aws:username}/*", "arn:aws:s3:::"},
		{"arn:aws:s3:::plain", "arn:aws:s3:::plain"},
		{"*", ""},
	} {
		if got := literalPrefix(c.in); got != c.prefix {
			t.Errorf("literalPrefix(%q) = %q, want %q", c.in, got, c.prefix)
		}
	}
	if got := skeleton("a/${aws:username}/b/${aws:PrincipalTag/x, 'd'}/c"); got != "a/*/b/*/c" {
		t.Errorf("skeleton = %q", got)
	}
}

func TestScanPrefix(t *testing.T) {
	keys := []string{"a", "ab", "abc", "abd", "b", "ba"}
	var got []string
	scanPrefix(keys, "ab", func(i int) { got = append(got, keys[i]) })
	if len(got) != 3 || got[0] != "ab" || got[2] != "abd" {
		t.Errorf("scanPrefix = %v", got)
	}
	got = nil
	scanPrefix(keys, "", func(i int) { got = append(got, keys[i]) })
	if len(got) != len(keys) {
		t.Errorf("an empty prefix must scan everything: %v", got)
	}
	got = nil
	scanPrefix(keys, "zz", func(i int) { got = append(got, keys[i]) })
	if len(got) != 0 {
		t.Errorf("scanPrefix = %v", got)
	}
}

func TestNoteVariables(t *testing.T) {
	r := &refs{principalTagKeys: map[string]bool{}, resourceTagKeys: map[string]bool{}}
	r.noteVariables("x/${aws:PrincipalTag/Team}/${aws:ResourceTag/Env, 'dev'}/${*}/${$}")
	if !r.principalTagKeys["team"] || !r.resourceTagKeys["env"] || r.identityVars || r.allPrincipalTags {
		t.Errorf("%+v", r)
	}
	r.noteVariables("${aws:username}")
	if !r.identityVars {
		t.Error("an identity variable must be noticed")
	}
	r.noteVariables("${aws:PrincipalTag/${aws:username}}")
	if !r.allPrincipalTags {
		t.Error("a dynamic tag key must make every tag count")
	}
}

func TestProbeSetDescribe(t *testing.T) {
	ps := newProbeSet([]string{"arn:aws:iam::1:user/a*", "arn:aws:iam::1:user/bob", "ARN:AWS:IAM::1:USER/ALICE"})
	got := ps.describe([]string{"arn:aws:iam::1:user/alice", "arn:aws:iam::1:user/bob", "", "other"})
	if got[0] != "f=ARN:AWS:IAM::1:USER/ALICE;g=arn:aws:iam::1:user/a*;" {
		t.Errorf("alice: %q", got[0])
	}
	if got[1] != "e=arn:aws:iam::1:user/bob;f=arn:aws:iam::1:user/bob;" && got[1] != "e=arn:aws:iam::1:user/bob;" {
		t.Errorf("bob: %q", got[1])
	}
	if got[2] != "" || got[3] != "" {
		t.Errorf("unmatched values must describe as empty: %q", got)
	}
}

func TestMemoRotationBoundsSize(t *testing.T) {
	m := NewMemo(2048)
	for i := 0; i < 20000; i++ {
		m.Put(MemoKey{P: uint64(i), A: uint64(i * 7), R: uint64(i * 13)}, &Cell{Outcome: authz.Allow})
	}
	if n := m.Len(); n > 2048+memoShards {
		t.Errorf("memo holds %d cells, want about 2048", n)
	}
	k := MemoKey{P: 1, A: 2, R: 3}
	m.Put(k, &Cell{Outcome: authz.Deny})
	if c, ok := m.Get(k); !ok || c.Outcome != authz.Deny {
		t.Error("a fresh entry must be found")
	}
	if _, ok := m.Get(MemoKey{P: 99, A: 99, R: 99}); ok {
		t.Error("a missing key must miss")
	}
	hits, misses := m.Stats()
	if hits != 1 || misses < 1 {
		t.Errorf("stats %d/%d", hits, misses)
	}
}

func TestMemoIsSafeForConcurrentUse(t *testing.T) {
	m := NewMemo(1 << 12)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				k := MemoKey{P: uint64(i % 300), A: uint64(g), R: 1}
				if _, ok := m.Get(k); !ok {
					m.Put(k, &Cell{Outcome: authz.Allow})
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestCellEqualAndKept(t *testing.T) {
	deny := &Cell{Outcome: authz.Deny, DenyKind: authz.Implicit, Fidelity: authz.Exact}
	if deny.Kept() {
		t.Error("an exact deny is not kept")
	}
	if !(&Cell{Outcome: authz.Deny, Fidelity: authz.Unsupported}).Kept() {
		t.Error("an unsupported deny must be kept: fail closed")
	}
	if !deny.Equal(&Cell{Outcome: authz.Deny, DenyKind: authz.Implicit, Fidelity: authz.Exact}) || deny.Equal(&Cell{Outcome: authz.Allow}) {
		t.Error("Equal")
	}
	var nilCell *Cell
	if !nilCell.Equal(nil) || nilCell.Equal(deny) {
		t.Error("Equal on nil")
	}
}
