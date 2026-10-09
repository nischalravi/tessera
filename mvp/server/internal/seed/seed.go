// Package seed loads the configured connectors (demo by default) into a fresh
// database and adds sample JIT requests and a review campaign.
package seed

import (
	"context"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func one[T any](items []*T, err error, what string) (*T, error) {
	if err != nil {
		return nil, err
	}
	if len(items) != 1 {
		return nil, fmt.Errorf("seed: expected exactly one %s, found %d", what, len(items))
	}
	return items[0], nil
}

// Workflows adds sample JIT requests and an initial review campaign so every
// page has data. now is the wall clock.
func Workflows(c *store.Conn, now time.Time, policies []*policy.Policy) error {
	role := func(system, name string) (*store.Group, error) {
		gs, err := c.Groups("WHERE system = ? AND name = ? ORDER BY id", system, name)
		return one(gs, err, system+" role "+name)
	}
	ident := func(name string) (*store.Identity, error) {
		is, err := c.Identities("WHERE name = ?", name)
		return one(is, err, "identity "+name)
	}
	prodAdmin, err := role("aws", "ProdAdmin")
	if err != nil {
		return err
	}
	breakGlass, err := role("aws", "BreakGlassAdmin")
	if err != nil {
		return err
	}
	acctadmin, err := role("snowflake", "ACCOUNTADMIN")
	if err != nil {
		return err
	}
	alice, err := ident("Alice Okafor")
	if err != nil {
		return err
	}
	kofi, err := ident("Kofi Mensah")
	if err != nil {
		return err
	}
	sreAgent, err := ident("SRE On-call Agent")
	if err != nil {
		return err
	}
	// pending: an AI agent asking for prod admin, and an engineer for a hotfix
	if _, err := jit.CreateRequest(c, now, sreAgent.ID, prodAdmin.ID, 1, "PagerDuty INC-4821: restart wedged ECS tasks in prod"); err != nil {
		return err
	}
	if _, err := jit.CreateRequest(c, now, alice.ID, prodAdmin.ID, 4, "Hotfix for orders-db connection pool exhaustion (INC-4817)"); err != nil {
		return err
	}
	// active: Kofi has break-glass for 2h
	r, err := jit.CreateRequest(c, now, kofi.ID, breakGlass.ID, 2, "Rotate compromised KMS grant during incident INC-4790")
	if err != nil {
		return err
	}
	if _, err := jit.Approve(c, r.ID, "Ingrid Lindqvist", now.Add(-20*time.Minute), now); err != nil {
		return err
	}
	// expired: yesterday's Snowflake admin session
	data, err := c.Identities("WHERE department = 'Data' AND status = 'active' AND name != 'Sana Iyer'")
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("seed: no active Data identity")
	}
	r2, err := jit.CreateRequest(c, now, data[len(data)-1].ID, acctadmin.ID, 3, "Resize warehouse for quarter-end backfill")
	if err != nil {
		return err
	}
	if _, err := jit.Approve(c, r2.ID, "Sana Iyer", now.Add(-24*time.Hour), now); err != nil {
		return err
	}
	if _, err := jit.Sweep(c, now); err != nil {
		return err
	}
	_, err = reviews.GenerateCampaign(c, now, "Q4 exception-only review", 60, policies)
	return err
}

// Stats summarizes a seed run.
type Stats struct {
	Sync     ingest.SyncStats
	Requests int
}

// Run drops and recreates the schema, syncs the connectors and seeds workflows.
func Run(ctx context.Context, s *store.Store, conns []connectors.Connector, now time.Time, policies []*policy.Policy) (Stats, error) {
	var st Stats
	if err := s.Migrate(ctx, true); err != nil {
		return st, err
	}
	err := s.Write(ctx, func(c *store.Conn) error {
		var err error
		if st.Sync, err = ingest.Sync(c, now, conns, nil); err != nil {
			return err
		}
		if err := Workflows(c, now, policies); err != nil {
			return err
		}
		st.Requests, err = c.Count("SELECT count(*) FROM access_requests")
		return err
	})
	return st, err
}
