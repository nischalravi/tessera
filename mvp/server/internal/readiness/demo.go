package readiness

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SeedDemo creates the demo tenant's Okta connection and takes it through
// validation and a dry run, so Insights → Deployment health has data on a
// fresh demo database (the walkthrough then adds Active Directory). It runs
// from `tessera seed`, never in the parity fixtures' seed.
func (s *Service) SeedDemo(ctx context.Context, st *store.Store, clock func() time.Time, stage StageFunc) error {
	const admin = "j.rivera@larkspur.example"
	company := connectors.GetCompany(connectors.DemoSeed, clock())
	email := func(name string) string { return company.P(name).Email() }
	var helpdesk []string
	for _, p := range company.People {
		if (p.Team == "security" || p.Team == "support") && !p.Lead {
			helpdesk = append(helpdesk, p.Email())
		}
	}
	cfg := map[string]any{
		"technical_owner": "Thandiwe Mokoena", "business_owner": "Esme Thornbury",
		"expected_counts": map[string]int{"users": 60, "groups": 15},
		"sync_schedule":   "System Log every 15 minutes; full sync weekly",
		"privileged_expected": map[string][]string{
			"okta-super-admins": {email("Thandiwe Mokoena"), email("Ingrid Lindqvist"), "scim-provisioner", "old-migration-token"},
			"okta-helpdesk":     append(helpdesk, "hr-sync-token"),
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var id string
	err = st.Write(ctx, func(c *store.Conn) error {
		now := clock()
		b, err := s.Create(c, CreateInput{Name: "Okta (demo)", ConnectorType: "demo-okta", Config: raw}, admin, now)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/okta-service-app"}, admin, now); err != nil {
			return err
		}
		for _, it := range []struct{ item, note string }{
			{"base.owner", "Owners agreed in the IAM steering meeting (CHG-1180)"},
			{"base.correlation.key", "Okta user id selected; login and email are mutable"},
		} {
			if _, err := s.Attest(c, id, it.item, it.note, admin, now); err != nil {
				return err
			}
		}
		_, err = s.Transition(c, id, store.StateReadyToValidate, admin, now)
		return err
	})
	if err != nil {
		return err
	}
	if _, err := s.Validate(ctx, st, id, admin, clock); err != nil {
		return err
	}
	if _, err := s.DryRun(ctx, st, id, admin, clock, stage); err != nil {
		return err
	}
	return st.Write(ctx, func(c *store.Conn) error {
		now := clock()
		for _, it := range []struct{ item, note string }{
			{"base.stale.threshold", "90 days, per the PCI DSS v4 8.2.6 policy"},
			{"base.scope.count", "60 users and 15 groups in the Okta admin console"},
			{"base.schedule", "System Log every 15 minutes, full sync on Sundays"},
		} {
			if _, err := s.Attest(c, id, it.item, it.note, admin, now); err != nil && !strings.Contains(err.Error(), "dependencies") {
				return err
			}
		}
		_, err := s.Skip(c, id, "okta.auth.oauth", "Migration to an OAuth service app is planned for Q1", nil, admin, now)
		return err
	})
}
