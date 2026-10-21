package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func archiveCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"RetentionPolicies", "SetRetentionPolicy", "InsertArchiveSegment", "ArchiveSegment", "ArchiveSegments",
		"AuditArchiveSegments", "OpenArchiveSegments", "MarkArchiveVerified", "MarkArchivePurged", "MarkArchiveFailed", "PurgeArchivedAudit",
		"ArchiveCandidates", "ArchiveDocument", "ArchiveDelete", "InsertArchiveSegmentItems", "ArchiveSegmentItems"} {
		out[k] = true // TestIsolation_RetentionAndArchive
	}
	return out
}

// Retention settings and archive segments (issue #298) are per tenant: another
// tenant cannot read, advance or purge them, the records an archive job picks
// are the tenant's own, and a segment cannot be deleted or moved backwards.
func TestIsolation_RetentionAndArchive(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	old := now.Add(-3 * 365 * 24 * time.Hour)
	var campaign int64
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.SetRetentionPolicy(store.ClassAudit, 400, now, "chg-1"); err != nil {
			return err
		}
		if err := c.InsertJobRun(&store.JobRun{ID: "arch-job-a", Kind: "sync", Trigger: "manual", Status: "succeeded", Actor: "a",
			StartedAt: old}); err != nil {
			return err
		}
		id, err := c.InsertCampaign(&store.ReviewCampaign{TenantID: f.A.ID, Name: "old", CreatedAt: old, Status: "completed"})
		campaign = id
		if err != nil {
			return err
		}
		return c.InsertArchiveSegment(&store.ArchiveSegment{ID: "seg-a", Class: store.ClassJobRuns, RangeFrom: "x", RangeTo: "y",
			Count: 1, Location: store.LocationLocal, ObjectKey: "k", Size: 10, SHA256: "0123456789012345678901234567890123456789012345678901234567890123",
			CreatedAt: now})
	})
	inA(t, f, func(c *store.TenantTx) error { return c.InsertArchiveSegmentItems("seg-a", []string{"7", "8"}) })
	before := storetest.Dump(t, f.DB, f.A.ID)

	inB(t, f, func(c *store.TenantTx) error {
		if ps, err := c.RetentionPolicies(); err != nil || len(ps) != 0 {
			t.Errorf("RetentionPolicies = %v, %v", ps, err)
		}
		if _, err := c.ArchiveSegment("seg-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ArchiveSegment(A's) = %v", err)
		}
		if gs, err := c.ArchiveSegments(store.ArchiveSegmentFilter{}); err != nil || len(gs) != 0 {
			t.Errorf("ArchiveSegments = %v, %v", gs, err)
		}
		if gs, err := c.AuditArchiveSegments(); err != nil || len(gs) != 0 {
			t.Errorf("AuditArchiveSegments = %v, %v", gs, err)
		}
		if gs, err := c.OpenArchiveSegments(store.ClassJobRuns); err != nil || len(gs) != 0 {
			t.Errorf("OpenArchiveSegments = %v, %v", gs, err)
		}
		if err := c.MarkArchiveVerified("seg-a", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MarkArchiveVerified(A's) = %v", err)
		}
		if err := c.MarkArchivePurged("seg-a", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MarkArchivePurged(A's) = %v", err)
		}
		if its, err := c.ArchiveSegmentItems("seg-a"); err != nil || len(its) != 0 {
			t.Errorf("ArchiveSegmentItems(A's) = %v, %v", its, err)
		}
		if err := c.InsertArchiveSegmentItems("seg-a", []string{"1"}); err == nil {
			t.Error("B listed an item under A's segment")
		}
		if err := c.MarkArchiveFailed("seg-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MarkArchiveFailed(A's) = %v", err)
		}
		for _, class := range []string{store.ClassJobRuns, store.ClassCampaigns, store.ClassRequests, store.ClassOutbox} {
			ids, err := c.ArchiveCandidates(class, now, 100)
			if err != nil || len(ids) != 0 {
				t.Errorf("ArchiveCandidates(%s) = %v, %v", class, ids, err)
			}
		}
		if _, err := c.ArchiveDocument(store.ClassJobRuns, "arch-job-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ArchiveDocument(A's job run) = %v", err)
		}
		if _, err := c.ArchiveDocument(store.ClassCampaigns, "1"); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ArchiveDocument(A's campaign) = %v", err)
		}
		if err := c.ArchiveDelete(store.ClassJobRuns, "arch-job-a"); err != nil {
			t.Errorf("ArchiveDelete(A's job run) = %v", err)
		}
		if err := c.ArchiveDelete(store.ClassCampaigns, itoa(campaign)); err != nil {
			t.Errorf("ArchiveDelete(A's campaign) = %v", err)
		}
		// B has no verified audit segment, so even its own events cannot go
		if err := c.PurgeArchivedAudit("seg-a"); err == nil {
			t.Error("PurgeArchivedAudit without a verified segment succeeded")
		}
		return nil
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}

	// A's own records are found.
	inA(t, f, func(c *store.TenantTx) error {
		ids, err := c.ArchiveCandidates(store.ClassJobRuns, now.Add(-time.Hour), 10)
		if err != nil || len(ids) != 1 || ids[0] != "arch-job-a" {
			t.Errorf("A's job run candidates = %v, %v", ids, err)
		}
		ids, err = c.ArchiveCandidates(store.ClassCampaigns, now.Add(-time.Hour), 10)
		if err != nil || len(ids) != 1 || ids[0] != itoa(campaign) {
			t.Errorf("A's campaign candidates = %v, %v (want %d)", ids, err, campaign)
		}
		d, err := c.ArchiveDocument(store.ClassJobRuns, "arch-job-a")
		if err != nil || d.Record["id"] != "arch-job-a" {
			t.Errorf("A's document = %+v, %v", d, err)
		}
		// a delete before the segment is verified is refused for an append-only table,
		// and the status cannot skip a step or go back
		if err := c.MarkArchivePurged("seg-a", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a written segment was purged: %v", err)
		}
		if err := c.MarkArchiveVerified("seg-a", now); err != nil {
			return err
		}
		if err := c.MarkArchiveVerified("seg-a", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a segment was verified twice: %v", err)
		}
		return nil
	})
}
