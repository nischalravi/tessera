package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestGroupEventsAppendOnly: the outbox and the digests refuse UPDATE at the
// database (K9); only the retention job deletes events.
func TestGroupEventsAppendOnly(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tn := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	if err := db.InSystem(ctx, "test", func(s *SystemTx) error {
		_, err := s.CreateTenant(Tenant{ID: tn, Slug: "append-only", Name: "t", CreatedAt: now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := db.InTenant(ctx, tn, func(c *TenantTx) error {
		if err := c.AppendGrpEvent(&GrpEvent{Type: "rule.fired", ObjectType: EventObjRule, ObjectID: "r", CauseType: CauseRule, OccurredAt: now}); err != nil {
			return err
		}
		return c.InsertGrpDigest(PitDigest{Day: "2026-01-02", FirstSeq: 1, LastSeq: 1, EventCount: 1, MerkleRoot: "00", AuditSeq: 1, CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"edit an event":    `UPDATE grp_events SET data = '{"x":1}' WHERE tenant_id = @t`,
		"move an event":    `UPDATE grp_events SET seq = 9 WHERE tenant_id = @t`,
		"edit a digest":    `UPDATE grp_pit_digests SET merkle_root = 'ff' WHERE tenant_id = @t`,
		"invalid JSON":     `INSERT INTO grp_events (tenant_id, seq, type, object_type, object_id, data, cause_type, occurred_at) VALUES (@t, 5, 'rule.fired', 'rule', 'r', '{', 'rule', 'x')`,
		"unknown cause":    `INSERT INTO grp_events (tenant_id, seq, type, object_type, object_id, data, cause_type, occurred_at) VALUES (@t, 5, 'rule.fired', 'rule', 'r', '{}', 'magic', 'x')`,
		"unknown object":   `INSERT INTO grp_events (tenant_id, seq, type, object_type, object_id, data, cause_type, occurred_at) VALUES (@t, 5, 'rule.fired', 'widget', 'r', '{}', 'rule', 'x')`,
		"bad digest day":   `INSERT INTO grp_pit_digests (tenant_id, day, first_seq, last_seq, event_count, merkle_root, audit_seq, created_at) VALUES (@t, 'yesterday', 1, 1, 1, '00', 1, 'x')`,
		"a second digest":  `INSERT INTO grp_pit_digests (tenant_id, day, first_seq, last_seq, event_count, merkle_root, audit_seq, created_at) VALUES (@t, '2026-01-02', 1, 1, 1, '00', 1, 'x')`,
		"a repeated seq":   `INSERT INTO grp_events (tenant_id, seq, type, object_type, object_id, data, cause_type, occurred_at) VALUES (@t, 1, 'rule.fired', 'rule', 'r', '{}', 'rule', 'x')`,
		"a seq of zero":    `INSERT INTO grp_events (tenant_id, seq, type, object_type, object_id, data, cause_type, occurred_at) VALUES (@t, 0, 'rule.fired', 'rule', 'r', '{}', 'rule', 'x')`,
		"direct row shape": `INSERT INTO grp_pit_direct (tenant_id, group_id, list_id, member_type, member_key, source, start_at, start_seq) VALUES (@t, 'g', 'l', 'identity', '1', 'api', 'x', 1)`,
	} {
		if _, err := db.sql.ExecContext(ctx, q, sql.Named("t", tn.String())); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(name, "edit") && !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: %v, want the append-only refusal", name, err)
		}
	}
}
