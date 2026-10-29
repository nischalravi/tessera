package lp_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// revokedRow puts a proposed candidate straight into the revoked state (what the engine's verified revoke does).
func revokedRow(t *testing.T, tx *store.TenantTx, n int, principal string) *store.LPRevocation {
	t.Helper()
	s := store.DefaultLPSettings()
	s.Mode, s.UpdatedBy = store.LPModeStaged, "u"
	must(t, tx.PutLPSettings(s, now))
	c := cand(n, principal, "111122223333")
	must(t, lp.Propose(tx, now, "alice", c))
	until := now.AddDate(0, 0, 30)
	c.State, c.RevokedAt, c.RestoreUntil = store.LPRevoked, &now, &until
	must(t, tx.UpdateLPRevocation(c, store.LPCandidate, now))
	return c
}

func removedIf(ids ...string) lp.Removed {
	return func(r *store.LPRevocation, _, _ string) (bool, error) { return slices.Contains(ids, r.ID), nil }
}

// A denial restores the revoked grants whose removal covers the call, once, with its trigger and audit events; it
// leaves no row when nothing is revoked for the principal, and a redelivery changes nothing.
func TestOnDenial(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		a := revokedRow(t, tx, 1, role(1))
		d := lp.Denial{Source: store.LPDenialCloudTrail, EventID: "evt-1", Principal: role(1), Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k"}
		at := now.Add(time.Hour)

		// nothing revoked for a stranger: no row, no restore
		res, err := lp.OnDenial(tx, at, lp.Denial{Source: d.Source, EventID: "evt-0", Principal: role(9), Action: d.Action}, removedIf(a.ID), ex)
		must(t, err)
		if res.Outcome != lp.OutcomeNoRevocation || res.Denial != nil || len(ex.restores) != 0 {
			t.Errorf("stranger: %+v", res)
		}
		if seen, err := tx.LPDenialSeen(d.Source, "evt-0"); err != nil || seen {
			t.Errorf("an event with no revoked grant was recorded: %v, %v", seen, err)
		}

		// a call the revocation did not remove: recorded, not restored
		res, err = lp.OnDenial(tx, at, lp.Denial{Source: d.Source, EventID: "evt-x", Principal: role(1), Action: "s3:PutObject"}, removedIf(), ex)
		must(t, err)
		if res.Outcome != store.LPDenialActionNotRemoved || len(res.Restored) != 0 || len(ex.restores) != 0 {
			t.Errorf("kept call: %+v", res)
		}
		if r, _ := tx.LPRevocation(a.ID); r.State != store.LPRevoked {
			t.Errorf("a kept call moved the revocation to %s", r.State)
		}

		// the removed call
		res, err = lp.OnDenial(tx, at, d, removedIf(a.ID), ex)
		must(t, err)
		if res.Outcome != store.LPDenialRestoreRequested || len(res.Restored) != 1 || !slices.Equal(ex.restores, []string{a.ID}) {
			t.Fatalf("removed call: %+v, restores %v", res, ex.restores)
		}
		r, err := tx.LPRevocation(a.ID)
		must(t, err)
		if r.State != store.LPRestoring || r.RestoreTrigger != "denial" || r.RestoreRequestedAt == nil || !r.RestoreRequestedAt.Equal(at) {
			t.Errorf("revocation = %+v", r)
		}
		evs, err := tx.LPEvents(a.ID)
		must(t, err)
		if last := evs[len(evs)-1]; last.To != store.LPRestoring || last.Actor != lp.ActorDenial || last.Detail == "" {
			t.Errorf("last event = %+v", last)
		}
		ds, err := tx.LPDenials(10)
		must(t, err)
		if len(ds) != 2 || ds[0].EventID != "evt-1" && ds[1].EventID != "evt-1" {
			t.Errorf("denials = %+v", ds)
		}
		got := auditActions(t, tx)
		for _, want := range []string{"lp.denial.restore_requested", "lp.denial.action_not_removed", "lp.revocation.restoring"} {
			if !slices.Contains(got, want) {
				t.Errorf("audit lacks %s: %v", want, got)
			}
		}

		// the same event again, and a second removed call on the revocation already restoring
		res, err = lp.OnDenial(tx, at.Add(time.Second), d, removedIf(a.ID), ex)
		must(t, err)
		if res.Outcome != lp.OutcomeDuplicate || len(ex.restores) != 1 {
			t.Errorf("redelivery: %+v, restores %v", res, ex.restores)
		}
		res, err = lp.OnDenial(tx, at.Add(time.Minute), lp.Denial{Source: d.Source, EventID: "evt-2", Principal: role(1), Action: d.Action}, removedIf(a.ID), ex)
		must(t, err)
		if res.Outcome != lp.OutcomeNoRevocation || len(ex.restores) != 1 {
			t.Errorf("a restoring grant is not restored twice: %+v, restores %v", res, ex.restores)
		}
	})
}

// Several revoked grants of one principal that all covered the call are all restored, under one denial row.
func TestOnDenial_RestoresEveryCoveringGrant(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		a := revokedRow(t, tx, 1, role(1))
		c := cand(2, role(1), "111122223333")
		must(t, lp.Propose(tx, now, "alice", c))
		until := now.AddDate(0, 0, 30)
		c.State, c.RevokedAt, c.RestoreUntil = store.LPRevoked, &now, &until
		must(t, tx.UpdateLPRevocation(c, store.LPCandidate, now))
		res, err := lp.OnDenial(tx, now.Add(time.Minute), lp.Denial{Source: store.LPDenialIdP, EventID: "e", Principal: role(1), Action: "s3:GetObject"}, removedIf(a.ID, c.ID), ex)
		must(t, err)
		if len(res.Restored) != 2 || len(ex.restores) != 2 || res.Denial.Detail == "" {
			t.Errorf("res = %+v, restores %v", res, ex.restores)
		}
	})
}
