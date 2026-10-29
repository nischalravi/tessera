package lp_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A JIT request for a revoked grant labels the revocation a false positive, once, and leaves it revoked (the JIT
// grant is time-bound and the standing grant stays revoked). Other requests label nothing.
func TestOnJITRequest(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		a := revokedRow(t, tx, 1, role(1))
		at := now.Add(time.Hour)
		for _, tc := range []struct {
			name string
			q    lp.JITRequest
			want int
		}{
			{"another group", lp.JITRequest{RequestID: 1, Principals: []string{role(1)}, Group: "arn:aws:iam::111122223333:policy/other"}, 0},
			{"another principal", lp.JITRequest{RequestID: 2, Principals: []string{role(2)}, Group: a.PolicyARN}, 0},
			{"no group id", lp.JITRequest{RequestID: 3, Principals: []string{role(1)}}, 0},
			{"the revoked grant", lp.JITRequest{RequestID: 4, Requester: "Ann", Principals: []string{"", role(2), role(1)}, Group: a.PolicyARN}, 1},
			{"a second request", lp.JITRequest{RequestID: 5, Principals: []string{role(1)}, Group: a.PolicyARN}, 0},
		} {
			got, err := lp.OnJITRequest(tx, at, tc.q)
			must(t, err)
			if len(got) != tc.want {
				t.Errorf("%s: labelled %d, want %d", tc.name, len(got), tc.want)
			}
		}
		if ok, err := tx.LPLabelled(a.ID); err != nil || !ok {
			t.Errorf("labelled = %v, %v", ok, err)
		}
		if r, _ := tx.LPRevocation(a.ID); r.State != store.LPRevoked {
			t.Errorf("a JIT request moved the revocation to %s: the standing grant stays revoked", r.State)
		}
		if got := auditActions(t, tx); !slices.Contains(got, "lp.jit.false_positive") {
			t.Errorf("not audited: %v", got)
		}
	})
}

// A finalized revocation is final: a JIT request for it is an ordinary request and labels nothing.
func TestOnJITRequestFinalized(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		a := revokedRow(t, tx, 1, role(1))
		a.State = store.LPFinalized
		must(t, tx.UpdateLPRevocation(a, store.LPRevoked, now))
		got, err := lp.OnJITRequest(tx, now, lp.JITRequest{RequestID: 1, Principals: []string{role(1)}, Group: a.PolicyARN})
		must(t, err)
		if len(got) != 0 {
			t.Errorf("labelled a final revocation: %d", len(got))
		}
	})
}

// The calibration counts revocations carried out and false positives per confidence level over 60 days, and flags
// a high level above 1 percent.
func TestCalibration(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		var rows []*store.LPRevocation
		for n := 1; n <= 3; n++ {
			r := revokedRow(t, tx, n, role(n))
			r.ExecutedAt = &now
			must(t, tx.UpdateLPRevocation(r, store.LPRevoked, now))
			rows = append(rows, r)
		}
		lv := func(at time.Time) map[string]lp.CalibrationLevel {
			cs, err := lp.Calibration(tx, at)
			must(t, err)
			m := map[string]lp.CalibrationLevel{}
			for _, c := range cs {
				m[c.Confidence] = c
			}
			return m
		}
		if c := lv(now)["high"]; c.Revocations != 3 || c.FalsePositives != 0 || c.Review {
			t.Errorf("before: %+v", c)
		}
		if _, err := lp.OnJITRequest(tx, now, lp.JITRequest{RequestID: 1, Principals: []string{role(1)}, Group: rows[0].PolicyARN}); err != nil {
			t.Fatal(err)
		}
		// a restore of an already labelled revocation does not count twice
		if ok, err := lp.LabelFalsePositive(tx, now, rows[0], "owner", "x"); err != nil || ok {
			t.Errorf("relabel = %v, %v", ok, err)
		}
		c := lv(now.Add(time.Hour))["high"]
		if c.Revocations != 3 || c.FalsePositives != 1 || !c.Review || c.Percent < 33 || c.Percent > 34 {
			t.Errorf("after: %+v", c)
		}
		if c := lv(now.Add(61 * 24 * time.Hour))["high"]; c.Revocations != 0 || c.FalsePositives != 0 {
			t.Errorf("outside the window: %+v", c)
		}
		if c := lv(now)["medium"]; c.Revocations != 0 || c.Review {
			t.Errorf("medium: %+v", c)
		}
	})
}
