package admin

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Operator-assisted recovery (design §15.5): the tenant lost all its admins
// and break-glass keys. Two pre-registered security contacts ask support;
// two different Tessera operators run `tessera admin recover-tenant`, which
// moves the tenant to status recovery and creates a bootstrap invitation
// that works only after RecoveryDelay. Notifications go out immediately and
// any existing admin can cancel meanwhile. After the delay the invitation is
// redeemed like §15.3, with a phishing-resistant sign-in.

// RecoveryDelay is how long after the request the recovery invitation first
// works (not_before).
const RecoveryDelay = 72 * time.Hour

// recoveryInvitationTTL is how long the invitation stays valid after not_before.
const recoveryInvitationTTL = 24 * time.Hour

// Operator is a Tessera operator taking part in a recovery. PhishingResistant
// says the operator authenticated to the operator host with a phishing-
// resistant method (a hardware key); in Phase 0 the CLI on a hardened host
// attests it and the platform chain records the claim.
type Operator struct {
	ID                string
	PhishingResistant bool
}

// RecoveryRequest is what `tessera admin recover-tenant` asks for.
type RecoveryRequest struct {
	Tenant       tenancy.ID
	Operator     Operator
	CoOperator   Operator
	Ticket       string
	ConnectionID uuid.UUID // the IdP connection the invitee signs in through
	Email        string    // the invitee's address at that IdP
}

// RecoveryResult carries the one-time code, shown once to the operator.
type RecoveryResult struct {
	Recovery *store.TenantRecovery
	Code     string
}

func cleanOperator(o Operator) Operator {
	o.ID = strings.TrimSpace(o.ID)
	return o
}

// RequestRecovery starts a recovery. It refuses unless two different
// operators, each phishing-resistantly authenticated, take part, and writes
// the request to the tenant's chain and to the platform chain.
func (s *Service) RequestRecovery(ctx context.Context, r RecoveryRequest) (*RecoveryResult, error) {
	now := s.now()
	op, co := cleanOperator(r.Operator), cleanOperator(r.CoOperator)
	ticket := strings.TrimSpace(r.Ticket)
	switch {
	case op.ID == "" || co.ID == "" || len(op.ID) > 200 || len(co.ID) > 200:
		return nil, invalid("both operators are required (ids of at most 200 characters)")
	case strings.EqualFold(op.ID, co.ID):
		return nil, newErr(422, "two_operators_required", "recovery needs two different operators, not %q twice", op.ID)
	case !op.PhishingResistant || !co.PhishingResistant:
		return nil, newErr(422, "operator_phr_required", "both operators must authenticate with a phishing-resistant method")
	case ticket == "" || len(ticket) > 200:
		return nil, invalid("ticket is required (at most 200 characters)")
	}
	addr, err := mail.ParseAddress(r.Email)
	if err != nil || addr.Address != r.Email {
		return nil, invalid("email %q is not an address", r.Email)
	}
	notBefore := now.Add(RecoveryDelay)
	code := "tbi_" + seal.RandomSecret(32)
	var rec *store.TenantRecovery
	err = s.DB.InTenant(ctx, r.Tenant, func(tx *store.TenantTx) error {
		e := s.env(tx, now, uuid.Nil)
		t, err := e.tenantRecord()
		if err != nil {
			return err
		}
		if t.Status != "active" {
			return conflict("tenant_not_active", "the tenant is %s; only an active tenant can enter recovery", t.Status)
		}
		c, err := e.connection(r.ConnectionID)
		if err != nil {
			return err
		}
		if c.Status != "active" || (c.Protocol != "oidc" && c.Protocol != "saml") {
			return conflict("connection_unusable", "connection %s is not an active OIDC or SAML connection", c.ID)
		}
		inv := &store.BootstrapInvitation{CodeHash: seal.SHA256Hex([]byte(code)), IdPConnectionID: c.ID, Email: r.Email,
			CreatedBy: op.ID + "+" + co.ID, CreatedAt: now, ExpiresAt: notBefore.Add(recoveryInvitationTTL)}
		if err := tx.InsertBootstrapInvitation(inv); err != nil {
			return err
		}
		rec = &store.TenantRecovery{InvitationID: inv.ID, Operator: op.ID, CoOperator: co.ID, Ticket: ticket,
			NotBefore: notBefore, CreatedAt: now}
		if err := tx.InsertTenantRecovery(rec); errors.Is(err, store.ErrDuplicate) {
			return conflict("recovery_in_progress", "the tenant already has a recovery in progress")
		} else if err != nil {
			return err
		}
		if err := tx.UpdateTenantStatus("recovery"); err != nil {
			return err
		}
		if _, err := audit.Record(tx.Context(), tx, "recovery.requested", recoveryDetail(rec, c.ID), audit.At(now),
			audit.Target("tenant_recovery", rec.ID.String())); err != nil {
			return err
		}
		body := fmt.Sprintf("Operator-assisted recovery of this tenant was requested (ticket %s) and approved by two "+
			"Tessera operators.\nA one-time recovery invitation becomes usable at %s. Until then nothing changes.\n"+
			"If you did not expect this, sign in to Tessera now and cancel it: Admin > Recovery > Cancel. "+
			"Cancelling is audited and tells both operators.\n", ticket, notBefore.UTC().Format(time.RFC3339))
		return e.queueAll(nil, &rec.ID, "recovery.requested", "[Tessera] Operator recovery requested for your tenant", body,
			"recovery:"+rec.ID.String()+":requested")
	})
	if err != nil {
		return nil, mapStore(err)
	}
	// the platform chain records the request too (§15.5 step 2: logged to the platform chain)
	if err := s.DB.InTenant(ctx, tenancy.Platform, func(tx *store.TenantTx) error {
		_, err := audit.Record(tx.Context(), tx, "recovery.requested", ojson.Object{{Key: "tenant_id", Value: r.Tenant.String()},
			{Key: "recovery_id", Value: rec.ID.String()}, {Key: "operator", Value: op.ID}, {Key: "co_operator", Value: co.ID},
			{Key: "operators_phishing_resistant", Value: true}, {Key: "ticket", Value: ticket},
			{Key: "not_before", Value: notBefore.UTC().Format(time.RFC3339)}}, audit.At(now),
			audit.Target("tenant_recovery", rec.ID.String()))
		return err
	}); err != nil {
		return nil, fmt.Errorf("recovery %s was requested, but writing it to the platform audit chain failed: %w", rec.ID, err)
	}
	return &RecoveryResult{Recovery: rec, Code: code}, nil
}

func recoveryDetail(rec *store.TenantRecovery, conn uuid.UUID) ojson.Object {
	return ojson.Object{{Key: "recovery_id", Value: rec.ID.String()}, {Key: "invitation_id", Value: rec.InvitationID.String()},
		{Key: "connection_id", Value: conn.String()}, {Key: "operator", Value: rec.Operator},
		{Key: "co_operator", Value: rec.CoOperator}, {Key: "ticket", Value: rec.Ticket},
		{Key: "not_before", Value: rec.NotBefore.UTC().Format(time.RFC3339)}}
}

// CancelRecovery cancels a pending recovery: any signed-in tenant admin (or
// break-glass holder) may, while it is pending. The invitation is spent, the
// tenant returns to active, and both operators are told.
func (s *Service) CancelRecovery(ctx context.Context, p *auth.Principal, id uuid.UUID) (*store.TenantRecovery, error) {
	now := s.now()
	perms := auth.EffectivePermissions(p)
	if !perms.Has(auth.PermAdminChangeReq) && !perms.Has(auth.PermBreakGlassRecover) {
		d := auth.Check(p, auth.PermAdminChangeReq, nil, now)
		if d == nil {
			d = &auth.Denial{Status: 403, Error: "forbidden", Permission: auth.PermAdminChangeReq}
		}
		return nil, denied(d)
	}
	var rec *store.TenantRecovery
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		var err error
		if rec, err = tx.TenantRecovery(id); errors.Is(err, store.ErrNotFound) {
			return notFound("recovery")
		} else if err != nil {
			return err
		}
		if err := tx.CancelTenantRecovery(id, *p.UserID, now); errors.Is(err, store.ErrAdminChangeState) {
			return conflict("invalid_state", "the recovery is %s, not pending", rec.Status)
		} else if err != nil {
			return err
		}
		// spend the invitation (consumed_by names the canceller; the audit
		// event says why). It may already have expired: that is fine.
		if err := tx.ConsumeBootstrapInvitation(rec.InvitationID, *p.UserID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.UpdateTenantStatus("active"); err != nil {
			return err
		}
		if _, err := audit.Record(tx.Context(), tx, "recovery.cancelled", ojson.Object{{Key: "recovery_id", Value: id.String()},
			{Key: "invitation_id", Value: rec.InvitationID.String()}, {Key: "by", Value: p.Display},
			{Key: "operator", Value: rec.Operator}, {Key: "co_operator", Value: rec.CoOperator}},
			audit.At(now), audit.Target("tenant_recovery", id.String())); err != nil {
			return err
		}
		body := fmt.Sprintf("The operator recovery of this tenant (ticket %s) was cancelled by %s. The recovery invitation "+
			"no longer works.\n", rec.Ticket, p.Display)
		if err := e.queueAll(nil, &rec.ID, "recovery.cancelled", "[Tessera] Operator recovery cancelled", body,
			"recovery:"+id.String()+":cancelled", rec.Operator, rec.CoOperator); err != nil {
			return err
		}
		rec, err = tx.TenantRecovery(id)
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return rec, nil
}

// CompleteRecovery finishes a recovery when its invitation was redeemed: the
// tenant returns to active, the event is audited and a summary goes to all
// admins and contacts. The login flow calls it in the transaction that
// consumed the invitation.
func (s *Service) CompleteRecovery(tx *store.TenantTx, rec *store.TenantRecovery, userID uuid.UUID, now time.Time) error {
	e := s.env(tx, now, userID)
	if err := tx.CompleteTenantRecovery(rec.ID, userID, now); err != nil {
		return mapStore(err)
	}
	if err := tx.UpdateTenantStatus("active"); err != nil {
		return err
	}
	if _, err := audit.Record(tx.Context(), tx, "recovery.completed", ojson.Object{{Key: "recovery_id", Value: rec.ID.String()},
		{Key: "invitation_id", Value: rec.InvitationID.String()}, {Key: "user_id", Value: userID.String()},
		{Key: "operator", Value: rec.Operator}, {Key: "co_operator", Value: rec.CoOperator}},
		audit.At(now), audit.Target("tenant_recovery", rec.ID.String())); err != nil {
		return err
	}
	body := fmt.Sprintf("Operator recovery of this tenant (ticket %s) is complete: %s signed in with the recovery invitation "+
		"and is now a tenant admin. The tenant is active again.\n", rec.Ticket, e.name(userID))
	return e.queueAll(nil, &rec.ID, "recovery.completed", "[Tessera] Operator recovery completed", body,
		"recovery:"+rec.ID.String()+":completed", rec.Operator, rec.CoOperator)
}

// Redemption refusals (login failure reasons).
const (
	ReasonRecoveryNotYet = "recovery_not_yet_valid"
	ReasonRecoveryClosed = "recovery_not_pending"
	ReasonRecoveryPhr    = "recovery_requires_phr"
)

// RedemptionError is why a recovery invitation cannot be redeemed now.
type RedemptionError struct{ Reason string }

func (e *RedemptionError) Error() string { return "recovery invitation refused: " + e.Reason }

// CheckWindow refuses a recovery invitation before not_before and after the
// recovery was cancelled or completed.
func CheckWindow(rec *store.TenantRecovery, now time.Time) *RedemptionError {
	switch {
	case rec.Status != store.RecoveryPending:
		return &RedemptionError{ReasonRecoveryClosed}
	case now.Before(rec.NotBefore):
		return &RedemptionError{ReasonRecoveryNotYet}
	}
	return nil
}

// CheckRedemption is CheckWindow plus the phishing-resistance requirement:
// the sign-in that redeems a recovery invitation must be phishing-resistant
// (design §15.5 step 5), proved from acr/amr, never assumed.
func CheckRedemption(rec *store.TenantRecovery, phishingResistant bool, now time.Time) *RedemptionError {
	if err := CheckWindow(rec, now); err != nil {
		return err
	}
	if !phishingResistant {
		return &RedemptionError{ReasonRecoveryPhr}
	}
	return nil
}
