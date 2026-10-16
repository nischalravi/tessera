package pit_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
)

// TestMerkleRootIsRFC6962 checks the tree shape: the left subtree is the
// largest power of two smaller than n, inner nodes are hashed with the 0x01
// prefix.
func TestMerkleRootIsRFC6962(t *testing.T) {
	leaf := func(b byte) [32]byte { return sha256.Sum256([]byte{0, b}) }
	node := func(l, r [32]byte) [32]byte {
		return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
	}
	l := [][32]byte{leaf(1), leaf(2), leaf(3), leaf(4), leaf(5), leaf(6), leaf(7)}
	for n, want := range map[int][32]byte{
		1: l[0],
		2: node(l[0], l[1]),
		3: node(node(l[0], l[1]), l[2]),
		4: node(node(l[0], l[1]), node(l[2], l[3])),
		5: node(node(node(l[0], l[1]), node(l[2], l[3])), l[4]),
		7: node(node(node(l[0], l[1]), node(l[2], l[3])), node(node(l[4], l[5]), l[6])),
	} {
		got, err := pit.MerkleRoot(l[:n])
		if err != nil || got != want {
			t.Errorf("root of %d leaves = %x, %v; want %x", n, got, err, want)
		}
	}
	if _, err := pit.MerkleRoot(nil); !errors.Is(err, pit.ErrNoEvents) {
		t.Errorf("root of no leaves = %v, want ErrNoEvents", err)
	}
	// order matters
	a, _ := pit.MerkleRoot([][32]byte{l[0], l[1]})
	b, _ := pit.MerkleRoot([][32]byte{l[1], l[0]})
	if a == b {
		t.Error("swapping two leaves did not change the root")
	}
}

func TestParseDay(t *testing.T) {
	for _, bad := range []string{"", "2026-1-2", "2026-13-01", "2026-02-30", "2026-10-08T00:00:00Z", "today", "2026-10-08 "} {
		if _, _, err := pit.ParseDay(bad); !errors.Is(err, pit.ErrBadDay) {
			t.Errorf("ParseDay(%q) = %v, want ErrBadDay", bad, err)
		}
	}
	from, to, err := pit.ParseDay("2026-10-08")
	if err != nil || to.Sub(from).Hours() != 24 || from.Hour() != 0 {
		t.Errorf("ParseDay = %v %v %v", from, to, err)
	}
}
