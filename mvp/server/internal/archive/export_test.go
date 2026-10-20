package archive

import (
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// SealedFor seals a value for (t1, g1) and reports whether it opens under (t2, g2).
func SealedFor(s *seal.Sealer, t1 tenancy.ID, g1 *store.ArchiveSegment, t2 tenancy.ID, g2 *store.ArchiveSegment) bool {
	blob, err := s.Seal([]byte("segment"), segmentAAD(t1, g1))
	if err != nil {
		return false
	}
	_, err = s.Open(blob, segmentAAD(t2, g2))
	return err == nil
}
