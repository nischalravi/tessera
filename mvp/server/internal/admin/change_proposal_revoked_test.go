package admin_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A proposal whose client was revoked, lost config.propose or whose stored payload was altered never applies
// (issue #743).

func (h *harness) ruleThreshold() int {
	h.t.Helper()
	var th int
	h.tx(func(tx *store.TenantTx) error {
		r, err := alerts.EffectiveRule(tx, "signin_failures")
		th = r.Threshold
		return err
	})
	return th
}

func (h *harness) hasEvent(action string, id uuid.UUID, contains string) bool {
	h.t.Helper()
	found := false
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			found = found || e.Action == action && strings.Contains(string(e.Detail), id.String()) && strings.Contains(string(e.Detail), contains)
		}
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return found
}

func TestProposal_ProposerWithdrawnBeforeApproval(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw func(h *harness)
		cancel   bool // the withdrawal cancels the open proposal itself
	}{
		{"revoked, cancelled with it", func(h *harness) {
			h.tx(func(tx *store.TenantTx) error {
				if err := tx.SetAPIClientStatus(proposalClientID, store.ClientDisabled); err != nil {
					return err
				}
				_, err := h.svc.CancelProposalsOf(tx, proposalClientID, nil, "ivan")
				return err
			})
		}, true},
		{"scope removed, cancelled with it", func(h *harness) {
			h.tx(func(tx *store.TenantTx) error {
				return h.svc.SetClientScopes(tx, proposalClientID, []string{"tessera:read"}, nil, "ivan")
			})
		}, true},
		{"revoked, nothing cancelled", func(h *harness) {
			h.tx(func(tx *store.TenantTx) error { return tx.SetAPIClientStatus(proposalClientID, store.ClientDisabled) })
		}, false},
		{"scope removed, nothing cancelled", func(h *harness) {
			h.tx(func(tx *store.TenantTx) error {
				return tx.SetAPIClientScopes(proposalClientID, []string{"tessera:read"})
			})
		}, false},
		{"owner disabled, nothing cancelled", func(h *harness) {
			h.tx(func(tx *store.TenantTx) error {
				c, err := tx.APIClientByClientID(proposalClientID)
				if err != nil {
					return err
				}
				return tx.DisableUser(*c.OwnerUserID, "left", h.clk.now())
			})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ad := h.admins("adm1", "adm2")
			machine := h.machine(h.user("olu", store.RoleOperator), "config.propose")
			h.grantScope(ad[0], ad[1])
			before := h.ruleThreshold()
			ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
			if err != nil {
				t.Fatal(err)
			}
			tc.withdraw(h)

			_, err = h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
			got := h.change(ch.ID)
			if tc.cancel {
				wantErr(t, err, http.StatusConflict, "invalid_state")
				if got.Status != store.ChangeCancelled || got.Failure != admin.ReasonProposerRevoked {
					t.Fatalf("proposal = %s (%q), want cancelled with proposer_revoked", got.Status, got.Failure)
				}
				if !h.hasEvent("admin.change.cancelled", ch.ID, admin.ReasonProposerRevoked) {
					t.Error("the cancellation is not audited with its reason")
				}
			} else {
				wantErr(t, err, http.StatusConflict, "proposer_revoked")
				if got.Status != store.ChangeFailed || got.Failure != admin.ReasonProposerRevoked {
					t.Fatalf("proposal = %s (%q), want failed with proposer_revoked", got.Status, got.Failure)
				}
				if !h.hasEvent("admin.change.failed", ch.ID, admin.ReasonProposerRevoked) {
					t.Error("the failure is not audited with its reason")
				}
			}
			if got.ApprovedBy != nil {
				t.Error("an approval was recorded")
			}
			if h.ruleThreshold() != before {
				t.Error("the proposal of a withdrawn client was applied")
			}
		})
	}
}

// the proposer is withdrawn after approval, while the change cools off: apply refuses it
func TestProposal_ProposerWithdrawnBeforeApply(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	machine := h.machine(h.user("olu", store.RoleOperator), "config.propose")
	h.grantScope(ad[0], ad[1])
	before := h.ruleThreshold()
	ch := h.coolingProposal(machine, admin.KindAlertRule, "signin_failures", alertBody, nil, ad[0].ID)
	h.tx(func(tx *store.TenantTx) error { return tx.SetAPIClientStatus(proposalClientID, store.ClientDisabled) })
	h.advance(time.Hour)
	_, err := h.svc.Apply(h.ctx, h.as(ad[1]), ch.ID)
	wantErr(t, err, http.StatusConflict, "proposer_revoked")
	if got := h.change(ch.ID); got.Status != store.ChangeFailed || got.Failure != admin.ReasonProposerRevoked {
		t.Fatalf("proposal = %s (%q), want failed with proposer_revoked", got.Status, got.Failure)
	}
	if h.ruleThreshold() != before {
		t.Error("applied")
	}
}

// coolingProposal files an approved proposal in cooling_off. hash overrides the stored hash when set (a tampered row).
func (h *harness) coolingProposal(machine interface{}, kind, id, body string, hash *string, approver uuid.UUID) *store.AdminChange {
	h.t.Helper()
	payload, err := admin.ProposalPayload(kind, id, json.RawMessage(body))
	if err != nil {
		h.t.Fatal(err)
	}
	var owner uuid.UUID
	h.tx(func(tx *store.TenantTx) error {
		c, err := tx.APIClientByClientID(proposalClientID)
		owner = *c.OwnerUserID
		return err
	})
	now := h.clk.now()
	eff := now.Add(time.Minute)
	ch := &store.AdminChange{TenantID: tenantID, Type: admin.TypeConfigProposal, Payload: payload, PayloadHash: admin.HashPayload(payload),
		Status: store.ChangePendingApproval, TwoPerson: true, CoolingOffSeconds: 60, RequestedBy: owner, RequestedAt: now,
		ExpiresAt: now.Add(admin.ApprovalWindow)}
	if hash != nil {
		ch.PayloadHash = *hash
	}
	h.tx(func(tx *store.TenantTx) error {
		if err := tx.InsertAdminChange(ch); err != nil {
			return err
		}
		if err := tx.InsertAdminChangeProposal(ch.ID, proposalClientID, now); err != nil {
			return err
		}
		return tx.ApproveAdminChange(ch.ID, approver, now, eff) // cooling off, as if a person approved it
	})
	return ch
}

func TestProposal_TamperedPayloadFailsAndNeverApplies(t *testing.T) {
	bad := strings.Repeat("ab", 32)
	t.Run("at approve", func(t *testing.T) {
		h := newHarness(t)
		ad := h.admins("adm1", "adm2")
		machine := h.machine(h.user("olu", store.RoleOperator), "config.propose")
		h.grantScope(ad[0], ad[1])
		before := h.ruleThreshold()
		payload, err := admin.ProposalPayload(admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
		if err != nil {
			t.Fatal(err)
		}
		_ = machine
		now := h.clk.now()
		var owner uuid.UUID
		h.tx(func(tx *store.TenantTx) error {
			c, err := tx.APIClientByClientID(proposalClientID)
			owner = *c.OwnerUserID
			return err
		})
		// the stored payload does not hash to the stored hash, and the approver echoes the stored hash
		ch := &store.AdminChange{TenantID: tenantID, Type: admin.TypeConfigProposal, Payload: payload, PayloadHash: bad,
			Status: store.ChangePendingApproval, TwoPerson: true, RequestedBy: owner, RequestedAt: now, ExpiresAt: now.Add(admin.ApprovalWindow)}
		h.tx(func(tx *store.TenantTx) error {
			if err := tx.InsertAdminChange(ch); err != nil {
				return err
			}
			return tx.InsertAdminChangeProposal(ch.ID, proposalClientID, now)
		})
		_, err = h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, bad)
		wantErr(t, err, http.StatusConflict, admin.ReasonPayloadTampered)
		got := h.change(ch.ID)
		if got.Status != store.ChangeFailed || got.Failure != admin.ReasonPayloadTampered || got.ApprovedBy != nil {
			t.Fatalf("proposal = %s (%q) approved by %v, want failed with payload_tampered and no approval", got.Status, got.Failure, got.ApprovedBy)
		}
		if !h.hasEvent("admin.change.failed", ch.ID, admin.ReasonPayloadTampered) {
			t.Error("the failure is not audited")
		}
		if h.ruleThreshold() != before {
			t.Error("applied")
		}
	})
	t.Run("at apply", func(t *testing.T) {
		h := newHarness(t)
		ad := h.admins("adm1", "adm2")
		machine := h.machine(h.user("olu", store.RoleOperator), "config.propose")
		h.grantScope(ad[0], ad[1])
		before := h.ruleThreshold()
		ch := h.coolingProposal(machine, admin.KindAlertRule, "signin_failures", alertBody, &bad, ad[0].ID)
		h.advance(time.Hour)
		_, err := h.svc.Apply(h.ctx, h.as(ad[1]), ch.ID)
		wantErr(t, err, http.StatusConflict, admin.ReasonPayloadTampered)
		if got := h.change(ch.ID); got.Status != store.ChangeFailed || got.Failure != admin.ReasonPayloadTampered {
			t.Fatalf("proposal = %s (%q), want failed with payload_tampered", got.Status, got.Failure)
		}
		if !h.hasEvent("admin.change.failed", ch.ID, admin.ReasonPayloadTampered) {
			t.Error("the failure is not audited")
		}
		if h.ruleThreshold() != before {
			t.Error("applied")
		}
	})
}
