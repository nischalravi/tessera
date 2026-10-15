package containment

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// LocalRevocation is what RevokeLocal ended inside Tessera.
type LocalRevocation struct {
	Users    int // platform users linked to the identity
	Sessions int // active Tessera sessions revoked
}

// RevokeLocal ends Tessera's own sessions for an identity: every active
// session of every platform user linked to it (platform_users.identity_id, or
// a sign-in through an IdP connection whose subject is the external id of one
// of the identity's accounts). It is the part of containment no provider
// connection is needed for, so manual contain, the SSF receiver and the
// leaver path all run it, whether or not the identity has an account on a
// kill-switch connection.
//
// Tessera issues no refresh tokens or OAuth grants of its own: a session is
// its only bearer credential (a revoked session is refused on its next
// request, 401), so there is nothing more to revoke locally.
//
// It runs in the caller's write transaction and, when the identity has linked
// platform users, audits containment.local_sessions_revoked (users and
// sessions revoked, which may be zero) in it.
func RevokeLocal(c *store.TenantTx, now time.Time, actor string, identityID int64, trigger string) (LocalRevocation, error) {
	var out LocalRevocation
	ident, err := c.Identity(identityID)
	if err != nil {
		return out, err
	}
	users, err := c.PlatformUserIDsForIdentity(identityID)
	if err != nil {
		return out, err
	}
	out.Users = len(users)
	if out.Users == 0 {
		return out, nil // nobody signs in to Tessera as this identity: nothing changed, nothing to audit
	}
	for _, u := range users {
		n, err := c.RevokeUserSessions(u, "containment: "+trigger, now.UTC())
		if err != nil {
			return out, err
		}
		out.Sessions += int(n)
	}
	err = c.Audit(now, actor, "containment.local_sessions_revoked", ojson.Object{{Key: "identity_id", Value: ident.ID},
		{Key: "identity", Value: ident.Name}, {Key: "trigger", Value: trigger}, {Key: "users", Value: out.Users},
		{Key: "sessions_revoked", Value: out.Sessions}})
	return out, err
}
