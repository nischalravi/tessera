package api

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// targetIdentity is the origin and the keyed, tenant-bound fingerprint of the URL an alert channel or SIEM sink sends to,
// the same values a proposal shows its approver (#886), so an approver can compare an update with what is live. Neither
// carries the path or a token in it. A target that is not a URL (an e-mail list, a syslog host:port), or a server with no
// key-encryption key, gives "" for both.
func (s *Server) targetIdentity(tx *store.TenantTx, target string) (origin, fp string) {
	if !strings.Contains(target, "://") || s.admin == nil || s.admin.Sealer == nil {
		return "", ""
	}
	origin = safehttp.Origin(target)
	if origin == "" {
		return "", ""
	}
	fp, err := admin.TargetFingerprint(s.admin.Sealer, tx.Tenant(), target)
	if err != nil {
		return "", ""
	}
	return origin, fp
}
