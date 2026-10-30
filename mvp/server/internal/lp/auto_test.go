package lp_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/lpauto"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func autoPolicy(t *testing.T, tx *store.TenantTx, yaml string) {
	t.Helper()
	p, err := lpauto.Parse([]byte(yaml))
	must(t, err)
	must(t, tx.PutLPAutoPolicy(&store.LPAutoPolicy{Policy: p.Canonical(), PolicySHA256: p.Digest(), Commit: "c0ffee", AppliedBy: "a", ApprovedBy: "b"}, now))
}

func autoMode(t *testing.T, tx *store.TenantTx) {
	t.Helper()
	staged(t, tx, func(s *store.LPSettings) { s.Mode = store.LPModeAuto })
}

const policyYAML = "version: 1\nkinds: [aws_set_policy_version]\n"

// Auto is off by default: a tenant that never set anything has mode off, no policy, and the loop announces and
// revokes nothing, whatever candidates exist.
func TestAutoDisabledByDefault(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		s, err := tx.LPSettings()
		must(t, err)
		if s.Mode != store.LPModeOff || lp.Active(s) {
			t.Fatalf("default settings = %+v", s)
		}
		if p, _, err := lp.AutoPolicy(tx); err != nil || p != nil {
			t.Errorf("a default tenant has a policy: %v, %v", p, err)
		}
		tick, err := lp.Run(tx, now.AddDate(0, 0, 40), newExec(), false, nil)
		must(t, err)
		if tick.Announced+tick.Revoking != 0 {
			t.Errorf("the off loop acted: %+v", tick)
		}
	})
}

// Auto mode without an applied policy announces nothing; staged mode never announces by itself.
func TestAutoNeedsPolicyAndMode(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		staged(t, tx, nil)
		must(t, lp.Propose(tx, now, "alice", cand(1, role(1), "111122223333")))
		tick, err := lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		if tick.Announced != 0 {
			t.Errorf("staged mode announced by itself")
		}
		autoMode(t, tx)
		tick, err = lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		if tick.Announced != 0 || tick.Holds["no_auto_policy"] != 1 {
			t.Errorf("auto without a policy = %+v", tick)
		}
	})
}

// Silence is consent: the policy announces a covered candidate by itself, the owners have the announce period,
// and after it the loop revokes through the same recheck and caps as staged mode.
func TestAutoAnnouncesAndRevokes(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, policyYAML)
		c := cand(1, role(1), "111122223333")
		must(t, lp.Propose(tx, now, "alice", c))
		ex := newExec()
		tick, err := lp.Run(tx, now, ex, false, nil)
		must(t, err)
		r, err := tx.LPRevocation(c.ID)
		must(t, err)
		if tick.Announced != 1 || r.State != store.LPAnnounced || r.ApprovedBy != lp.ActorAuto || r.AnnounceUntil == nil ||
			!r.AnnounceUntil.Equal(now.AddDate(0, 0, 7)) {
			t.Fatalf("announce: %+v %+v", tick, r)
		}
		if !slices.Contains(auditActions(t, tx), "lp.revocation.announced") {
			t.Errorf("not audited: %v", auditActions(t, tx))
		}
		// nothing is revoked inside the announce period
		tick, err = lp.Run(tx, now.AddDate(0, 0, 3), ex, false, map[string]lp.Recheck{c.ID: {OK: true}})
		must(t, err)
		if tick.Revoking != 0 || len(ex.queued) != 0 {
			t.Errorf("revoked inside the announce period: %+v", tick)
		}
		// after it, revoked
		tick, err = lp.Run(tx, now.AddDate(0, 0, 8), ex, false, map[string]lp.Recheck{c.ID: {OK: true}})
		must(t, err)
		if tick.Revoking != 1 || !slices.Equal(ex.queued, []string{c.ID}) {
			t.Errorf("after the announce period: %+v %v", tick, ex.queued)
		}
	})
}

func TestAutoOwnerObjection(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, policyYAML)
		c := cand(1, role(1), "111122223333")
		must(t, lp.Propose(tx, now, "alice", c))
		ex := newExec()
		_, err := lp.Run(tx, now, ex, false, nil)
		must(t, err)
		_, err = lp.Object(tx, now.Add(time.Hour), "owner", c.ID, "we need it")
		must(t, err)
		tick, err := lp.Run(tx, now.AddDate(0, 0, 8), ex, false, map[string]lp.Recheck{c.ID: {OK: true}})
		must(t, err)
		if tick.Revoking != 0 || len(ex.queued) != 0 {
			t.Errorf("an objected grant was revoked: %+v", tick)
		}
	})
}

// What the policy does not cover stays a candidate: medium confidence, fewer than the policy's unused days,
// another kind, another account.
func TestAutoPolicyBounds(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, "version: 1\nkinds: [aws_set_policy_version]\nmin_unused_days: 100\naccounts: ['111122223333']\n")
		mk := func(n int, mut func(*store.LPRevocation)) *store.LPRevocation {
			c := cand(n, role(n), "111122223333")
			mut(c)
			must(t, lp.Propose(tx, now, "alice", c))
			return c
		}
		medium := mk(1, func(c *store.LPRevocation) { c.Confidence = "medium" })
		young := mk(2, func(c *store.LPRevocation) { c.UnusedDays = 95 })
		kind := mk(3, func(c *store.LPRevocation) { c.Kind = "aws_detach_policy" })
		acct := mk(4, func(c *store.LPRevocation) { c.AccountID = "999999999999" })
		covered := mk(5, func(c *store.LPRevocation) {})
		tick, err := lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		if tick.Announced != 1 {
			t.Fatalf("announced %d, want 1", tick.Announced)
		}
		for _, c := range []*store.LPRevocation{medium, young, kind, acct, covered} {
			r, _ := tx.LPRevocation(c.ID)
			want := store.LPCandidate
			if c.ID == covered.ID {
				want = store.LPAnnounced
			}
			if r.State != want {
				t.Errorf("%s is %s, want %s", c.ID, r.State, want)
			}
		}
	})
}

func TestAutoProtectedAndMaxPerDay(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, "version: 1\nkinds: [aws_set_policy_version]\nmax_per_day: 2\n")
		for n := 1; n <= 4; n++ {
			must(t, lp.Propose(tx, now, "alice", cand(n, role(n), "111122223333")))
		}
		// break-glass: listed after it was proposed, so the guard at announce time is what holds
		must(t, tx.InsertLPProtected(&store.LPProtectedRef{Kind: "principal", Ref: role(1), Reason: "break-glass", CreatedBy: "a", CreatedAt: now}))
		tick, err := lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		if tick.Announced != 2 || tick.Holds["auto_policy_max_per_day"] != 1 {
			t.Errorf("tick = %+v", tick)
		}
		if r, _ := tx.LPRevocation("rev-1"); r.State != store.LPCandidate {
			t.Errorf("a break-glass principal was announced: %s", r.State)
		}
		// the day passes: the rest follows
		tick, err = lp.Run(tx, now.Add(25*time.Hour), newExec(), false, nil)
		must(t, err)
		if tick.Announced != 1 {
			t.Errorf("next day announced %d, want 1", tick.Announced)
		}
	})
}

// A paused loop and the operator switch announce nothing.
func TestAutoPausedAndDisabled(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, policyYAML)
		must(t, lp.Propose(tx, now, "alice", cand(1, role(1), "111122223333")))
		tick, err := lp.Run(tx, now, newExec(), true, nil)
		must(t, err)
		if tick.Announced != 0 {
			t.Errorf("announced while disabled")
		}
		_, err = lp.Pause(tx, now, "alice", "stop", nil)
		must(t, err)
		tick, err = lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		if tick.Announced != 0 {
			t.Errorf("announced while paused")
		}
	})
}

// When the false-positive rate of high confidence is over 1 percent, auto pauses itself, with an audit event that
// names the trigger, and stays paused (resuming takes two people).
func TestAutoPausesOnCalibration(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, policyYAML)
		// one executed high-confidence revocation that turned out to be needed: 100 percent
		old := cand(9, role(9), "111122223333")
		must(t, lp.Propose(tx, now, "alice", old))
		old.State, old.ExecutedAt = store.LPRevoked, &now
		must(t, tx.UpdateLPRevocation(old, store.LPCandidate, now))
		must(t, tx.InsertLPFalsePositive(&store.LPFalsePositive{RevocationID: old.ID, Source: store.LPFPJIT, Principal: old.Principal,
			PolicyARN: old.PolicyARN, Confidence: "high", CreatedAt: now}))
		must(t, lp.Propose(tx, now, "alice", cand(1, role(1), "111122223333")))

		if why, err := lp.CalibrationReview(tx, now); err != nil || !strings.Contains(why, "over 1%") {
			t.Fatalf("CalibrationReview = %q, %v", why, err)
		}
		tick, err := lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		s, _ := tx.LPSettings()
		if !s.Paused || !strings.HasPrefix(s.PausedReason, "calibration:") || s.PausedBy != lp.ActorAuto || !strings.HasPrefix(tick.Paused, "calibration:") {
			t.Fatalf("not paused: %+v %+v", s, tick)
		}
		if tick.Announced != 0 {
			t.Errorf("announced in the pass that paused")
		}
		got := auditActions(t, tx)
		if !slices.Contains(got, "lp.auto_paused") || !slices.Contains(got, "lp.paused") {
			t.Errorf("pause not audited: %v", got)
		}
		// still paused on the next pass, and only one pause event
		_, err = lp.Run(tx, now.Add(time.Hour), newExec(), false, nil)
		must(t, err)
		n := 0
		for _, a := range auditActions(t, tx) {
			if a == "lp.auto_paused" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("lp.auto_paused audited %d times", n)
		}
	})
}

// With no revocations carried out there is nothing to calibrate: auto is not paused.
func TestAutoCalibrationBelowThreshold(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		autoMode(t, tx)
		autoPolicy(t, tx, policyYAML)
		tick, err := lp.Run(tx, now, newExec(), false, nil)
		must(t, err)
		if s, _ := tx.LPSettings(); s.Paused || tick.Paused != "" {
			t.Errorf("paused with no revocations: %+v", tick)
		}
	})
}
