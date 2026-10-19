package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// Hash is the content hash of a snapshot: SHA-256 of its JSON with the ID field
// cleared. encoding/json writes map keys sorted and Build sorts every list, so
// equal content gives an equal hash.
func Hash(s *model.Snapshot) (string, error) {
	c := *s
	c.ID = ""
	b, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
