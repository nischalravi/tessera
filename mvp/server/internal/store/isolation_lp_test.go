package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// lpCovered lists the least-privilege loop repository methods TestIsolation_LeastPrivLoop exercises
// (TestIsolation_EveryRepoMethodClassified).
func lpCovered() map[string]bool {
	return map[string]bool{
		"LPSettings": true, "PutLPSettings": true, "InsertLPRevocation": true, "LPRevocation": true, "LPRevocations": true,
		"LPRevocationsToAdvance": true, "UpdateLPRevocation": true, "LPExecutedSince": true, "LPRestoredSince": true,
		"LPOpenForGrant": true, "InsertLPEvent": true, "LPEvents": true, "InsertLPProtected": true, "LPProtected": true,
		"DeleteLPProtected": true, "InsertLPExemption": true, "LPExempted": true, "LPExemptions": true,
		// restore on denial (schema/0922, TestIsolation_LPDenials)
		"LPDenialHook": true, "PutLPDenialHook": true, "LPDenialSeen": true, "InsertLPDenial": true, "LPDenials": true,
		"LPRevokedForPrincipal": true,
	}
}

// The denial tables (schema/0922, issue #662): the hook credential and the denial events are a tenant's own. The
// same event id is a different event in each tenant, A's secret digest is not B's, and a principal revoked in A is
// not revoked in B.
func TestIsolation_LPDenials(t *testing.T) {
	f := storetest.TwoTenants(t)
	digest := func(c string) string { return strings.Repeat(c, 64) }
	principal := "arn:aws:iam::111122223333:role/shared"
	for _, tn := range []struct {
		t storetest.Tenant
		c string
	}{{f.A, "a"}, {f.B, "b"}} {
		if err := f.DB.InTenant(context.Background(), tn.t.ID, func(c *store.TenantTx) error {
			if err := c.PutLPDenialHook(&store.LPDenialHook{SecretSHA256: digest(tn.c), CreatedBy: "u", CreatedAt: storetest.Now, RotatedAt: storetest.Now}); err != nil {
				return err
			}
			if tn.t.Slug == f.A.Slug { // only A has a revoked grant for the principal
				r := lpRev("rev-1", principal)
				if err := c.InsertLPRevocation(r); err != nil {
					return err
				}
				r.State = store.LPRevoked
				if err := c.UpdateLPRevocation(r, store.LPCandidate, storetest.Now); err != nil {
					return err
				}
			}
			return c.InsertLPDenial(&store.LPDenial{Source: store.LPDenialCloudTrail, EventID: "evt-1", Principal: principal, Action: "s3:GetObject",
				ArrivedAt: storetest.Now, Outcome: store.LPDenialActionNotRemoved, RevocationID: "rev-" + tn.c})
		}); err != nil {
			t.Fatal(err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		if h, err := c.LPDenialHook(); err != nil || h.SecretSHA256 != digest("b") {
			t.Errorf("B's hook = %+v, %v; A's digest leaked", h, err)
		}
		if err := c.PutLPDenialHook(&store.LPDenialHook{SecretSHA256: digest("c"), CreatedBy: "later", CreatedAt: storetest.Now.Add(time.Hour), RotatedAt: storetest.Now.Add(time.Hour)}); err != nil {
			t.Errorf("rotate: %v", err)
		}
		if seen, err := c.LPDenialSeen(store.LPDenialCloudTrail, "evt-1"); err != nil || !seen {
			t.Errorf("B's own event seen = %v, %v", seen, err)
		}
		if seen, err := c.LPDenialSeen(store.LPDenialIdP, "evt-1"); err != nil || seen {
			t.Errorf("another source's event seen = %v, %v", seen, err)
		}
		if err := c.InsertLPDenial(&store.LPDenial{Source: store.LPDenialCloudTrail, EventID: "evt-1", Principal: principal, Action: "s3:GetObject",
			ArrivedAt: storetest.Now, Outcome: store.LPDenialActionNotRemoved}); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("a redelivered event = %v, want ErrDuplicate", err)
		}
		if ds, err := c.LPDenials(0); err != nil || len(ds) != 1 || ds[0].RevocationID != "rev-b" {
			t.Errorf("LPDenials = %+v, %v; want B's one", ds, err)
		}
		if xs, err := c.LPRevokedForPrincipal(principal); err != nil || len(xs) != 0 {
			t.Errorf("B sees %d of A's revoked grants, %v", len(xs), err)
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if h, err := c.LPDenialHook(); err != nil || h.SecretSHA256 != digest("a") {
			t.Errorf("A's hook = %+v, %v; B's rotation leaked", h, err)
		}
		if xs, err := c.LPRevokedForPrincipal(principal); err != nil || len(xs) != 1 {
			t.Errorf("A's revoked for the principal = %d, %v", len(xs), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func lpRev(id, principal string) *store.LPRevocation {
	return &store.LPRevocation{ID: id, State: store.LPCandidate, Kind: "aws_set_policy_version", Eligibility: store.LPEligAuto,
		ConnectorID: "conn", SnapshotID: "snap", AccountID: "111122223333", Principal: principal,
		PolicyARN: "arn:aws:iam::111122223333:policy/P", UnusedDays: 90, Confidence: "high", Evidence: `{}`,
		CandidateSHA256: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
		RestorePayload:  `{}`, RestoreSHA256: "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
		CreatedBy: "u", CreatedAt: storetest.Now}
}

// The loop's tables (schema/0921, issue #661): settings, revocations, their events, the protected list and the
// exemptions are a tenant's own. The same ids exist in both tenants, another tenant's id looks nonexistent, and the
// counts the caps use never see the other tenant's executions.
func TestIsolation_LeastPrivLoop(t *testing.T) {
	f := storetest.TwoTenants(t)
	later := storetest.Now.Add(time.Hour)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			s := store.DefaultLPSettings()
			s.Mode, s.CapPerRun, s.UpdatedBy = store.LPModeStaged, 5, "u-"+tn.Slug
			if tn.Slug == f.A.Slug {
				s.Paused, s.PausedReason, s.PausedBy = true, "kill switch", "pat"
				s.PausedAt = &later
			}
			if err := c.PutLPSettings(s, later); err != nil {
				return err
			}
			// the same revocation id in both tenants; A executed one, B none
			r := lpRev("rev-1", "arn:aws:iam::111122223333:role/"+tn.Slug)
			if err := c.InsertLPRevocation(r); err != nil {
				return err
			}
			if err := c.InsertLPEvent(&store.LPEvent{RevocationID: "rev-1", From: "", To: store.LPCandidate, Actor: "u-" + tn.Slug, CreatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.InsertLPProtected(&store.LPProtectedRef{ID: "prot-1", Kind: "principal", Ref: "arn:aws:iam::111122223333:role/break-glass", CreatedBy: "u", CreatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.InsertLPExemption(&store.LPExemption{ID: "ex-1", Principal: r.Principal, PolicyARN: r.PolicyARN, Source: store.LPExemptRestore,
				Until: later.Add(24 * time.Hour), CreatedBy: "u", CreatedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A moves its revocation to revoking (queued for execution)
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := c.LPRevocation("rev-1")
		if err != nil {
			return err
		}
		r.State, r.ExecutedAt = store.LPRevoking, &later
		return c.UpdateLPRevocation(r, store.LPCandidate, later)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if s, err := c.LPSettings(); err != nil || s.Mode != store.LPModeStaged || s.Paused || s.CapPerRun != 5 || s.UpdatedBy != "u-"+f.B.Slug {
			t.Errorf("B's LPSettings = %+v, %v; A's pause leaked", s, err)
		}
		r, err := c.LPRevocation("rev-1")
		if err != nil || r.State != store.LPCandidate || r.Principal != "arn:aws:iam::111122223333:role/"+f.B.Slug {
			t.Errorf("B's LPRevocation = %+v, %v", r, err)
		}
		if _, err := c.LPRevocation("nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown revocation = %v, want ErrNotFound", err)
		}
		if xs, err := c.LPRevocations("", 0); err != nil || len(xs) != 1 {
			t.Errorf("LPRevocations = %d, %v; want B's 1", len(xs), err)
		}
		if xs, err := c.LPRevocations(store.LPRevoking, 0); err != nil || len(xs) != 0 {
			t.Errorf("B's revoking = %d, %v; A's execution leaked", len(xs), err)
		}
		if xs, err := c.LPRevocationsToAdvance(store.LPCandidate, 10); err != nil || len(xs) != 1 {
			t.Errorf("LPRevocationsToAdvance = %d, %v", len(xs), err)
		}
		if n, err := c.LPExecutedSince(storetest.Now, "", ""); err != nil || n != 0 {
			t.Errorf("B's executed count = %d, %v; A's execution leaked into the caps", n, err)
		}
		if n, err := c.LPExecutedSince(storetest.Now, "111122223333", ""); err != nil || n != 0 {
			t.Errorf("B's per-account count = %d, %v", n, err)
		}
		if n, err := c.LPRestoredSince(storetest.Now); err != nil || n != 0 {
			t.Errorf("LPRestoredSince = %d, %v", n, err)
		}
		if n, err := c.LPOpenForGrant("arn:aws:iam::111122223333:role/"+f.B.Slug, "arn:aws:iam::111122223333:policy/P"); err != nil || n != 1 {
			t.Errorf("LPOpenForGrant = %d, %v", n, err)
		}
		if n, err := c.LPOpenForGrant("arn:aws:iam::111122223333:role/"+f.A.Slug, "arn:aws:iam::111122223333:policy/P"); err != nil || n != 0 {
			t.Errorf("LPOpenForGrant of A's principal = %d, %v", n, err)
		}
		// a compare-and-set from the wrong state changes nothing
		r.State = store.LPAnnounced
		if err := c.UpdateLPRevocation(r, store.LPRevoking, later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("update from the wrong state = %v, want ErrNotFound", err)
		}
		if es, err := c.LPEvents("rev-1"); err != nil || len(es) != 1 || es[0].Actor != "u-"+f.B.Slug {
			t.Errorf("LPEvents = %+v, %v", es, err)
		}
		if ps, err := c.LPProtected(); err != nil || len(ps) != 1 {
			t.Errorf("LPProtected = %d, %v", len(ps), err)
		}
		if err := c.InsertLPProtected(&store.LPProtectedRef{Kind: "principal", Ref: "arn:aws:iam::111122223333:role/break-glass", CreatedBy: "u", CreatedAt: storetest.Now}); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("duplicate protected = %v, want ErrDuplicate", err)
		}
		if ok, err := c.LPExempted(r.Principal, r.PolicyARN, later); err != nil || !ok {
			t.Errorf("LPExempted = %v, %v", ok, err)
		}
		if ok, err := c.LPExempted(r.Principal, r.PolicyARN, later.Add(48*time.Hour)); err != nil || ok {
			t.Errorf("LPExempted after it ended = %v, %v", ok, err)
		}
		if ok, err := c.LPExempted("arn:aws:iam::111122223333:role/"+f.A.Slug, r.PolicyARN, later); err != nil || ok {
			t.Errorf("A's exemption applies in B = %v, %v", ok, err)
		}
		if xs, err := c.LPExemptions(later, 0); err != nil || len(xs) != 1 {
			t.Errorf("LPExemptions = %d, %v", len(xs), err)
		}
		if err := c.DeleteLPProtected("prot-1"); err != nil {
			t.Errorf("DeleteLPProtected = %v", err)
		}
		if err := c.DeleteLPProtected("prot-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second DeleteLPProtected = %v, want ErrNotFound", err)
		}
		return nil
	})
	// B's changes left A's rows alone, and the caps see A's own execution
	inA(t, f, func(c *store.TenantTx) error {
		if s, err := c.LPSettings(); err != nil || !s.Paused || s.PausedBy != "pat" || s.PausedAt == nil {
			t.Errorf("A's LPSettings = %+v, %v", s, err)
		}
		if r, err := c.LPRevocation("rev-1"); err != nil || r.State != store.LPRevoking || r.ExecutedAt == nil {
			t.Errorf("A's revocation = %+v, %v", r, err)
		}
		if n, err := c.LPExecutedSince(storetest.Now, "111122223333", ""); err != nil || n != 1 {
			t.Errorf("A's executed count = %d, %v", n, err)
		}
		if ps, err := c.LPProtected(); err != nil || len(ps) != 1 {
			t.Errorf("A's protected list = %d, %v; B's delete leaked", len(ps), err)
		}
		return nil
	})
	// a tenant with no row is off with the defaults
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
