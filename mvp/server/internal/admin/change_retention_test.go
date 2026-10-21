package admin_test

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/retention"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func days(t *testing.T, h *harness) map[string]int {
	t.Helper()
	out := map[string]int{}
	h.tx(func(tx *store.TenantTx) error {
		ss, err := retention.Effective(tx)
		for _, s := range ss {
			out[s.Name] = s.Days
		}
		return err
	})
	return out
}

// retention.update (issue #298): the floors hold whatever the payload says,
// the change needs two admins and a fresh step-up on each side, nothing
// changes before the approval, and the change is audited with the transaction
// that applies it.
func TestRetentionUpdate(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	if !slices.Contains(admin.Types(), admin.TypeRetentionUpdate) {
		t.Fatalf("the change types %v lack retention.update", admin.Types())
	}
	def := days(t, h)
	for _, c := range retention.Classes {
		if def[c.Name] != c.Default {
			t.Errorf("%s defaults to %d days, want %d", c.Name, def[c.Name], c.Default)
		}
	}

	// the floors are enforced on the server, class by class, before anyone is asked
	for name, payload := range map[string]string{
		"audit under a year":      `{"audit_days":364}`,
		"audit zero":              `{"audit_days":0}`,
		"audit negative":          `{"audit_days":-5}`,
		"campaigns under a year":  `{"review_campaigns_days":100}`,
		"requests under a year":   `{"requests_days":30}`,
		"job runs under 30":       `{"job_runs_days":29}`,
		"outbox under 30":         `{"notifications_days":1}`,
		"above the ceiling":       `{"audit_days":3651}`,
		"one good, one too short": `{"job_runs_days":60,"audit_days":10}`,
		"nothing named":           `{}`,
		"unchanged":               `{"audit_days":730}`,
		"unknown field":           `{"audit_days":800,"logs_days":9}`,
	} {
		if _, err := h.submit(h.as(a[0]), admin.TypeRetentionUpdate, payload); err == nil {
			t.Errorf("%s: filed", name)
		} else {
			wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		}
	}

	// a stale step-up cannot file it, and a requester cannot approve their own
	if _, err := h.submit(h.asAged(a[0], time.Hour), admin.TypeRetentionUpdate, `{"audit_days":900}`); err == nil {
		t.Error("filed without a fresh step-up")
	} else {
		wantStepUp(t, err)
	}
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRetentionUpdate, `{"audit_days":365,"job_runs_days":45}`)
	if ch.Status != store.ChangePendingApproval || !ch.TwoPerson || ch.CoolingOffSeconds != 0 {
		t.Fatalf("request = %+v", ch)
	}
	if got := days(t, h); got[store.ClassAudit] != 730 || got[store.ClassJobRuns] != 90 {
		t.Errorf("retention changed before approval: %v", got)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(a[0]), ch.ID, ch.PayloadHash); err == nil {
		t.Error("the requester approved their own change")
	}
	if _, err := h.svc.Approve(h.ctx, h.asAged(a[1], time.Hour), ch.ID, ch.PayloadHash); err == nil {
		t.Error("approved without a fresh step-up")
	} else {
		wantStepUp(t, err)
	}
	if got := days(t, h); got[store.ClassAudit] != 730 {
		t.Errorf("retention changed by a refused approval: %v", got)
	}
	done, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	if err != nil || done.Status != store.ChangeApplied {
		t.Fatalf("approve = %+v, %v", done, err)
	}
	got := days(t, h)
	if got[store.ClassAudit] != 365 || got[store.ClassJobRuns] != 45 || got[store.ClassCampaigns] != 730 || got[store.ClassOutbox] != 90 {
		t.Errorf("retention after the change = %v", got)
	}
	acts := h.audited(tenantID)
	for _, want := range []string{"admin.change.submitted", "admin.change.approved", "admin.change.applied", "retention.updated"} {
		if !slices.Contains(acts, want) {
			t.Errorf("audit lacks %s: %v", want, acts)
		}
	}
	// a floor raised after a setting was stored lifts the effective value to it
	h.tx(func(tx *store.TenantTx) error {
		return tx.SetRetentionPolicy(store.ClassRequests, 400, h.clk.now(), "")
	})
	if got := days(t, h); got[store.ClassRequests] != 400 {
		t.Errorf("requests = %d", got[store.ClassRequests])
	}
}
