package oauthapps

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Revoke scopes.
const (
	ScopeGrant  = "grant"
	ScopeApp    = "app"
	ScopeVendor = "vendor"
)

// Per-grant revoke outcomes.
const (
	OutcomeRevoked = "revoked" // the provider confirmed and a re-read no longer finds the grant
	OutcomeFailed  = "failed"  // refused, unverifiable, or still there after the revoke
	OutcomeManual  = "manual"  // no API can do it: a person must (never reported as done)
	OutcomeSkipped = "skipped" // the time budget ended first; run it again
)

// ApprovalWindow is how long a first admin's four-eyes request waits for a second.
const ApprovalWindow = 24 * time.Hour

// ErrNothingToRevoke: the target holds no grant that still exists.
var ErrNothingToRevoke = errors.New("oauthapps: nothing to revoke: no live grant")

// ErrNotFound: no such app or grant in the tenant.
var ErrNotFound = errors.New("oauthapps: no such app or grant")

// PlanItem is one grant to revoke.
type PlanItem struct {
	App   *store.OAuthApp
	Grant *store.OAuthGrant
}

// Plan is what a revoke would touch.
type Plan struct {
	Scope  string
	Target string // the grant id, the app id, or the normalized vendor
	Items  []PlanItem
	Apps   int
	// HighRisk: some app in the plan holds a high or critical scope.
	HighRisk bool
}

// FourEyes reports whether the plan needs a second admin: more than one grant
// to revoke, at an app that holds a high or critical scope.
func (p *Plan) FourEyes() bool { return len(p.Items) > 1 && p.HighRisk }

// BuildPlan lists the live grants a revoke of the target would revoke. For
// ScopeGrant, appID names the app and target the grant; for ScopeApp, target is
// the app; for ScopeVendor, target is the vendor name.
func BuildPlan(tx *store.TenantTx, scope, appID, target string, now time.Time) (*Plan, error) {
	plan := &Plan{Scope: scope, Target: target}
	add := func(app *store.OAuthApp, only string) error {
		grants, err := tx.OAuthGrantsOf(app.ID)
		if err != nil {
			return err
		}
		as, n := AssessApp(app, grants, now)
		if n == 0 {
			return nil
		}
		took := false
		for _, g := range grants {
			if live(g) && (only == "" || g.ID == only) {
				plan.Items = append(plan.Items, PlanItem{App: app, Grant: g})
				took = true
			}
		}
		if took {
			plan.Apps++
			plan.HighRisk = plan.HighRisk || IsHighRisk(as.Severity)
		}
		return nil
	}
	switch scope {
	case ScopeGrant, ScopeApp:
		app, err := tx.OAuthApp(appID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		only := ""
		if scope == ScopeGrant {
			g, err := tx.OAuthGrant(target)
			if errors.Is(err, store.ErrNotFound) || (err == nil && g.AppID != app.ID) {
				return nil, ErrNotFound
			}
			if err != nil {
				return nil, err
			}
			only = g.ID
			plan.Target = g.ID
		} else {
			plan.Target = app.ID
		}
		if err := add(app, only); err != nil {
			return nil, err
		}
	case ScopeVendor:
		plan.Target = NormalizeVendor(target)
		apps, err := tx.OAuthApps()
		if err != nil {
			return nil, err
		}
		for _, app := range apps {
			if MatchesVendor(app, plan.Target) {
				if err := add(app, ""); err != nil {
					return nil, err
				}
			}
		}
		if plan.Apps == 0 {
			return nil, ErrNotFound
		}
	default:
		return nil, fmt.Errorf("oauthapps: unknown revoke scope %q", scope)
	}
	if len(plan.Items) == 0 {
		return nil, ErrNothingToRevoke
	}
	return plan, nil
}

// Gate decisions.
const (
	GateExecute      = "execute"        // go ahead (no second admin needed, or this one is the second)
	GatePending      = "pending"        // the first admin's request is recorded and waits
	GateSameApprover = "same_requester" // the same admin repeated a pending request
)

// Gate applies the four-eyes rule in the caller's write transaction. A plan
// that needs no second admin executes. Otherwise the first request is
// recorded and waits; the same admin repeating it is refused; a different
// admin repeating it (same scope and target) marks it executed and executes.
func Gate(tx *store.TenantTx, plan *Plan, by uuid.UUID, byName, reason string, now time.Time) (string, *store.OAuthRevokeRequest, error) {
	if !plan.FourEyes() || plan.Scope == ScopeGrant {
		return GateExecute, nil, nil
	}
	if err := tx.ExpireOAuthRevokeRequests(now); err != nil {
		return "", nil, err
	}
	pend, err := tx.PendingOAuthRevokeRequest(plan.Scope, plan.Target, now)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", nil, err
	}
	same := false
	if pend != nil {
		// People, not user ids: two users linked to one identity are one admin (#416, #402).
		if same, err = tx.SameActor(pend.RequestedByUserID.String(), by.String()); err != nil {
			return "", nil, err
		}
	}
	switch {
	case pend != nil && same:
		return GateSameApprover, pend, nil
	case pend != nil:
		if err := tx.ExecuteOAuthRevokeRequest(pend.ID, by, byName, now); err != nil {
			return "", nil, err
		}
		return GateExecute, pend, tx.Audit(now, byName, "oauthapps.revoke_approved", ojson.Object{{Key: "request_id", Value: pend.ID},
			{Key: "scope", Value: plan.Scope}, {Key: "target", Value: plan.Target}, {Key: "requested_by", Value: pend.RequestedBy},
			{Key: "approved_by", Value: byName}})
	}
	req := &store.OAuthRevokeRequest{Scope: plan.Scope, Target: plan.Target, Reason: reason, Apps: plan.Apps, Grants: len(plan.Items),
		RequestedByUserID: by, RequestedBy: byName, RequestedAt: now, ExpiresAt: now.Add(ApprovalWindow)}
	if err := tx.InsertOAuthRevokeRequest(req); err != nil {
		return "", nil, err
	}
	return GatePending, req, tx.Audit(now, byName, "oauthapps.revoke_requested", ojson.Object{{Key: "request_id", Value: req.ID},
		{Key: "scope", Value: plan.Scope}, {Key: "target", Value: plan.Target}, {Key: "apps", Value: plan.Apps},
		{Key: "grants", Value: len(plan.Items)}, {Key: "reason", Value: reason}})
}

// ItemResult is the outcome of one grant.
type ItemResult struct {
	AppID   string `json:"app_id"`
	App     string `json:"app"`
	GrantID string `json:"grant_id"`
	User    string `json:"user"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// RevokeReport is the result of a revoke.
type RevokeReport struct {
	Scope   string       `json:"scope"`
	Target  string       `json:"target"`
	Total   int          `json:"total"`
	Revoked int          `json:"revoked"`
	Failed  int          `json:"failed"`
	Manual  int          `json:"manual"`
	Skipped int          `json:"skipped"`
	OK      bool         `json:"ok"`
	Items   []ItemResult `json:"items"`
}

// maxAuditedItems bounds the per-grant list in the audit event.
const maxAuditedItems = 50

// Execute revokes the plan's grants at the providers, re-reads each to verify,
// and records the outcome. It never holds a transaction during a provider
// call. Before the first call a short transaction audits oauthapps.revoke_started,
// so a call that happened is in the ledger whatever follows; the outcome (grant
// statuses, app status and risk, and the oauthapps.revoked event) is one
// transaction. A grant is "revoked" only when the provider confirmed and a
// re-read no longer shows it; what no API can revoke is manual, never done.
func (s *Service) Execute(ctx context.Context, db *store.DB, tenant tenancy.ID, plan *Plan, by, reason string) (*RevokeReport, error) {
	rep := &RevokeReport{Scope: plan.Scope, Target: plan.Target, Total: len(plan.Items)}
	started := s.now()
	if err := db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		return tx.Audit(started, by, "oauthapps.revoke_started", ojson.Object{{Key: "scope", Value: plan.Scope},
			{Key: "target", Value: plan.Target}, {Key: "apps", Value: plan.Apps}, {Key: "grants", Value: len(plan.Items)},
			{Key: "reason", Value: reason}})
	}); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, s.budget())
	defer cancel()
	provs := map[string]Provider{}
	why := map[string]string{}
	for _, it := range plan.Items {
		res := ItemResult{AppID: it.App.ID, App: it.App.Name, GrantID: it.Grant.ID, User: userLabel(it.Grant)}
		prov, ok := provs[it.App.Provider]
		if !ok && why[it.App.Provider] == "" {
			cred, w, err := s.credential(ctx, db, tenant, it.App.Provider)
			if err != nil {
				return nil, err
			}
			if cred != nil {
				p, perr := s.provider(it.App.Provider, cred)
				if perr != nil {
					w = errText(perr)
				} else {
					provs[it.App.Provider], prov = p, p
				}
			}
			if prov == nil {
				why[it.App.Provider] = w
			}
		}
		switch {
		case prov == nil:
			res.Outcome, res.Detail = OutcomeManual, "no provider credential ("+why[it.App.Provider]+"): revoke it in the provider's console"
		case callCtx.Err() != nil:
			res.Outcome, res.Detail = OutcomeSkipped, "the time budget of this request ended; run the revoke again"
		default:
			res.Outcome, res.Detail = revokeOne(callCtx, prov, it)
		}
		rep.Items = append(rep.Items, res)
	}
	done := s.now()
	err := db.InTenant(ctx, tenant, func(tx *store.TenantTx) error { return s.record(tx, plan, rep, by, reason, done) })
	if err != nil {
		return nil, err
	}
	rep.OK = rep.Revoked == rep.Total
	return rep, nil
}

func revokeOne(ctx context.Context, prov Provider, it PlanItem) (outcome, detail string) {
	err := prov.RevokeGrant(ctx, it.App.ClientID, grantOf(it.Grant))
	var me *ManualError
	switch {
	case errors.As(err, &me):
		return OutcomeManual, me.Msg
	case err != nil:
		return OutcomeFailed, errText(err)
	}
	present, err := prov.Present(ctx, it.App.ClientID, grantOf(it.Grant))
	switch {
	case err != nil:
		return OutcomeFailed, "the provider accepted the revoke but the re-read failed: " + errText(err)
	case present:
		return OutcomeFailed, "the provider accepted the revoke but a re-read still shows the grant"
	}
	return OutcomeRevoked, ""
}

func grantOf(g *store.OAuthGrant) Grant {
	return Grant{Key: g.GrantKey, Ref: g.ProviderRef, Kind: g.Kind, UserRef: g.UserRef, Scopes: g.Scopes, Consent: g.ConsentType}
}

func userLabel(g *store.OAuthGrant) string {
	switch {
	case g.UserRef != "":
		return g.UserRef
	case g.ConsentType == ConsentAdmin:
		return "(tenant-wide)"
	}
	return ""
}

// record stores the outcome in one transaction.
func (s *Service) record(tx *store.TenantTx, plan *Plan, rep *RevokeReport, by, reason string, now time.Time) error {
	touched := map[string]*store.OAuthApp{}
	var order []string
	for i, res := range rep.Items {
		it := plan.Items[i]
		switch res.Outcome {
		case OutcomeRevoked:
			rep.Revoked++
			if err := tx.SetOAuthGrantStatus(it.Grant.ID, store.OAuthRevoked, &by, &now, ""); err != nil {
				return err
			}
		case OutcomeFailed, OutcomeManual:
			if res.Outcome == OutcomeFailed {
				rep.Failed++
			} else {
				rep.Manual++
			}
			if err := tx.SetOAuthGrantStatus(it.Grant.ID, store.OAuthRevokeFailed, &by, &now, res.Detail); err != nil {
				return err
			}
		default:
			rep.Skipped++
		}
		if touched[it.App.ID] == nil {
			touched[it.App.ID] = it.App
			order = append(order, it.App.ID)
		}
	}
	for _, id := range order {
		app, err := tx.OAuthApp(id)
		if err != nil {
			return err
		}
		grants, err := tx.OAuthGrantsOf(id)
		if err != nil {
			return err
		}
		anyLive := false
		for _, g := range grants {
			anyLive = anyLive || live(g)
		}
		if err := Refresh(tx, app, now); err != nil {
			return err
		}
		if !anyLive {
			if err := tx.MarkOAuthAppRevoked(id, by, now); err != nil {
				return err
			}
		}
	}
	closed := map[string]bool{}
	for _, id := range order { // a permission that was flagged as added is contained once it is revoked
		if p := touched[id].Provider; !closed[p] {
			closed[p] = true
			if err := resolveChanges(tx, p, now); err != nil {
				return err
			}
		}
	}
	items := rep.Items
	if len(items) > maxAuditedItems {
		items = items[:maxAuditedItems]
	}
	list := make([]ojson.Object, 0, len(items))
	for _, r := range items {
		list = append(list, ojson.Object{{Key: "app_id", Value: r.AppID}, {Key: "grant_id", Value: r.GrantID}, {Key: "outcome", Value: r.Outcome}})
	}
	return tx.Audit(now, by, "oauthapps.revoked", ojson.Object{{Key: "scope", Value: plan.Scope}, {Key: "target", Value: plan.Target},
		{Key: "reason", Value: reason}, {Key: "apps", Value: plan.Apps}, {Key: "total", Value: rep.Total}, {Key: "revoked", Value: rep.Revoked},
		{Key: "failed", Value: rep.Failed}, {Key: "manual", Value: rep.Manual}, {Key: "skipped", Value: rep.Skipped},
		{Key: "items", Value: list}})
}
