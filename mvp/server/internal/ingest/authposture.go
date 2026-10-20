package ingest

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// authPosture stores what connectors reported about how accounts sign in:
// the registered authentication methods of an IdP, whether they could be read,
// and the password / MFA / SSO facts of apps. It runs after accounts, which it
// refers to, and reports nothing in DiscoveryStats.
//
// A system that could not read its methods (a missing scope) is recorded as
// unavailable and its stored methods are left alone: replacing them with
// nothing would show every user as having no MFA. An account the connector
// named but that is not in the database is skipped.
func authPosture(c *store.TenantTx, res *Resolver, now time.Time, results []*connectors.DiscoveryResult) error {
	for _, r := range results {
		if src := r.AuthSource; src != nil {
			status, detail := mfa.SourceOK, ""
			if src.Unavailable {
				status, detail = mfa.SourceUnavailable, src.Detail
			}
			if err := c.PutAuthMethodSource(store.AuthMethodSource{System: src.System, Status: status, Detail: detail, UpdatedAt: now}); err != nil {
				return err
			}
			if !src.Unavailable {
				var rows []store.AuthMethod
				for _, m := range r.AuthMethods {
					aid, ok := res.ID("account", m.Account.System, m.Account.ExternalID)
					if !ok || m.Account.System != src.System || !mfa.Strength(m.Strength).Valid() {
						continue
					}
					rows = append(rows, store.AuthMethod{AccountID: aid, ExternalID: m.ExternalID, System: src.System,
						Strength: m.Strength, Kind: m.Kind, Label: m.Label, EnrolledAt: m.EnrolledAt, ObservedAt: now})
				}
				if err := c.ReplaceAuthMethods(src.System, rows); err != nil {
					return err
				}
			}
		}
		for _, g := range r.AuthSignals {
			aid, ok := res.ID("account", g.Account.System, g.Account.ExternalID)
			if !ok {
				continue
			}
			if err := c.PutAccountAuthSignals(store.AccountAuthSignals{AccountID: aid, HasLocalPassword: g.HasLocalPassword,
				MFAEnabled: g.MFAEnabled, SSOEnforced: g.SSOEnforced, ObservedAt: now}); err != nil {
				return err
			}
		}
	}
	return nil
}

// authPostureRan reports whether any result carries authentication posture.
func authPostureRan(results []*connectors.DiscoveryResult) bool {
	for _, r := range results {
		if r.AuthSource != nil || len(r.AuthSignals) > 0 {
			return true
		}
	}
	return false
}
