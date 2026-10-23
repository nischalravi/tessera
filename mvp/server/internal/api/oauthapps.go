package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Third-party OAuth apps and grants (issue #107):
//
//	GET  /api/oauth-apps?provider=&severity=&status=&flag=&vendor=&q=&unused_days=   the inventory with risk, flags, sync state
//	GET  /api/oauth-apps/{app_id}                                                    one app: its grants, each scope's risk
//	POST /api/oauth-apps/sync                       {provider?}: refresh from the providers now
//	PUT  /api/oauth-apps/{app_id}/owner             {identity_id|null}
//	POST /api/oauth-apps/{app_id}/revoke            {reason}: every live grant of the app
//	POST /api/oauth-apps/{app_id}/grants/{grant_id}/revoke   {reason}
//	POST /api/oauth-apps/revoke-vendor              {vendor, reason, dry_run?}: every app of a breached vendor
//	POST /api/oauth-apps/{app_id}/credentials/{credential_id}/remove   {reason}: remove a secret an attacker may have added (#474)
//	POST /api/oauth-apps/{app_id}/changes/{change_id}/resolve          {note}: acknowledge a detected change (#474)
//
// A sync also detects what an app gained since the last one: a new secret or
// certificate, a new application permission or tenant-wide consent, and an
// owner change (#474). They are listed as "changes" (open ones in the list, all
// of an app with its credentials in the app view), audited as
// oauthapps.change_detected, and raised by the oauth_app_change alert rule.
// Containment is the credential remove above or the grant revoke. A credential
// no API can remove (an Entra certificate) answers 502 oauth_credential_manual.
//

// Revoking needs oauthapps.revoke and a fresh phishing-resistant sign-in. A
// revoke that covers more than one grant of an app holding a high or critical
// scope, and every vendor revoke of such apps, needs two admins: the first
// request answers 202 pending_second_admin, the same admin repeating it is
// refused (four_eyes_required), and a second admin's identical request
// executes. A revoke calls the providers, so it is phased: it plans, then calls
// with no transaction open, then records grant statuses and the audit event in
// one transaction. Each grant is re-read at the provider; the answer is 200
// with the report, or 502 oauth_revoke_incomplete with the same report when a
// grant could not be revoked or verified (a grant no API can revoke is a
// manual task, never a success).

const (
	// oauthSyncEvery is how often each tenant's inventory is refreshed.
	oauthSyncEvery = time.Hour
	// maxOAuthSyncAttempts: a failed sync is retried once; the next window tries again anyway.
	maxOAuthSyncAttempts = 2
	oauthSyncActor       = "oauthapps.sync"
)

func (s *Server) registerOAuthAppsRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/oauth-apps", read, need(auth.PermGraphRead), s.listOAuthApps)
	s.handle(G, "/api/oauth-apps/{app_id}", read, need(auth.PermGraphRead), s.getOAuthApp)
	s.handle(P, "/api/oauth-apps/sync", phased, need(auth.PermOAuthAppsManage), s.syncOAuthApps)
	s.handle(http.MethodPut, "/api/oauth-apps/{app_id}/owner", write, need(auth.PermOAuthAppsManage), s.setOAuthAppOwner)
	s.handle(P, "/api/oauth-apps/revoke-vendor", phased, needStepUp(auth.PermOAuthAppsRevoke, auth.StepUpPolicy), s.revokeOAuthVendor)
	s.handle(P, "/api/oauth-apps/{app_id}/revoke", phased, needStepUp(auth.PermOAuthAppsRevoke, auth.StepUpPolicy), s.revokeOAuthApp)
	s.handle(P, "/api/oauth-apps/{app_id}/grants/{grant_id}/revoke", phased, needStepUp(auth.PermOAuthAppsRevoke, auth.StepUpPolicy), s.revokeOAuthGrant)
	s.handle(P, "/api/oauth-apps/{app_id}/credentials/{credential_id}/remove", phased, needStepUp(auth.PermOAuthAppsRevoke, auth.StepUpPolicy), s.removeOAuthCredential)
	s.handle(P, "/api/oauth-apps/{app_id}/changes/{change_id}/resolve", write, need(auth.PermOAuthAppsManage), s.resolveOAuthChange)
}

// queueOAuthSync is the queue handler of the inventory refresh. A tenant with
// no provider credential leaves no job run.
func (s *Server) queueOAuthSync(ctx context.Context, j queue.Job) (any, error) {
	ctx = audit.WithSystemActor(ctx, oauthSyncActor)
	rep, err := s.oauthapps.Sync(ctx, s.store, j.Tenant, oauthSyncActor)
	if err != nil {
		return nil, err
	}
	// the GitHub and CI token inventory (#476) refreshes with the OAuth app inventory; a failure is audited and shown in the UI
	if _, err := s.ghtokens.Sync(ctx, s.store, j.Tenant, oauthSyncActor); err != nil {
		return nil, err
	}
	if !rep.Changed() {
		return nil, nil
	}
	var failed []string
	for _, p := range rep.Providers {
		if p.Status == oauthapps.SyncFailed {
			failed = append(failed, p.Provider)
		}
	}
	if len(failed) > 0 {
		return rep, fmt.Errorf("oauth sync failed for %s", strings.Join(failed, ", "))
	}
	return rep, nil
}

// ---------------------------------------------------------------- views

type oauthOwnerView struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type oauthAppView struct {
	ID          string          `json:"id"`
	Provider    string          `json:"provider"`
	ClientID    string          `json:"client_id"`
	Name        string          `json:"name"`
	Publisher   string          `json:"publisher"`
	Verified    bool            `json:"verified"`
	Status      string          `json:"status"`
	RiskScore   int             `json:"risk_score"`
	Severity    string          `json:"severity"`
	RiskReasons []string        `json:"risk_reasons"`
	Flags       []string        `json:"flags"`
	Grants      int             `json:"grants"`
	Users       int             `json:"users"`
	Owner       *oauthOwnerView `json:"owner"`
	FirstSeen   string          `json:"first_seen"`
	LastSeen    string          `json:"last_seen"`
	LastUsed    *string         `json:"last_used"`
	RevokedAt   *string         `json:"revoked_at"`
	RevokedBy   *string         `json:"revoked_by"`
}

type oauthGrantView struct {
	ID          string                `json:"id"`
	Kind        string                `json:"kind"`
	User        string                `json:"user"`
	Identity    *oauthOwnerView       `json:"identity"`
	Admin       bool                  `json:"granter_admin"`
	Consent     string                `json:"consent_type"`
	Scopes      []oauthapps.ScopeView `json:"scopes"`
	GrantedAt   *string               `json:"granted_at"`
	LastUsed    *string               `json:"last_used"`
	Status      string                `json:"status"`
	RevokedAt   *string               `json:"revoked_at"`
	RevokedBy   *string               `json:"revoked_by"`
	RevokeError string                `json:"revoke_error,omitempty"`
}

type oauthChangeView struct {
	ID         string  `json:"id"`
	AppID      string  `json:"app_id"`
	App        string  `json:"app"`
	Kind       string  `json:"kind"`
	Summary    string  `json:"summary"`
	DetectedAt string  `json:"detected_at"`
	Status     string  `json:"status"`
	ResolvedAt *string `json:"resolved_at"`
	Resolution string  `json:"resolution,omitempty"`
	// CredentialID names the credential (remove it with .../credentials/{id}/remove); GrantID the permission (revoke it).
	CredentialID string `json:"credential_id,omitempty"`
	GrantID      string `json:"grant_id,omitempty"`
}

type oauthCredentialView struct {
	ID      string  `json:"id"`
	Kind    string  `json:"kind"`
	Label   string  `json:"label"`
	AddedAt *string `json:"added_at"`
	Status  string  `json:"status"`
}

func viewOAuthChange(c *store.OAuthChange, appName string) oauthChangeView {
	v := oauthChangeView{ID: c.ID, AppID: c.AppID, App: appName, Kind: c.Kind, Summary: c.Summary,
		DetectedAt: c.DetectedAt.UTC().Format(time.RFC3339), Status: c.Status, ResolvedAt: isoPtr(c.ResolvedAt), Resolution: c.Resolution}
	var d struct {
		FactID  string `json:"fact_id"`
		GrantID string `json:"grant_id"`
	}
	if json.Unmarshal(c.Detail, &d) == nil {
		v.CredentialID, v.GrantID = d.FactID, d.GrantID
	}
	return v
}

func viewOAuthApp(tx *store.TenantTx, a *store.OAuthApp, grants []*store.OAuthGrant, now time.Time, unusedDays int, names map[int64]string) (oauthAppView, error) {
	as, n := oauthapps.AssessApp(a, grants, now)
	users := map[string]bool{}
	for _, g := range grants {
		if (g.Status == store.OAuthActive || g.Status == store.OAuthRevokeFailed) && g.UserRef != "" {
			users[g.UserRef] = true
		}
	}
	v := oauthAppView{ID: a.ID, Provider: a.Provider, ClientID: a.ClientID, Name: a.Name, Publisher: a.Publisher, Verified: a.Verified,
		Status: a.Status, RiskScore: a.RiskScore, Severity: as.Severity, RiskReasons: a.RiskReasons,
		Flags: oauthapps.Flags(a, grants, now, unusedDays), Grants: n, Users: len(users),
		FirstSeen: a.FirstSeen.UTC().Format(time.RFC3339), LastSeen: a.LastSeen.UTC().Format(time.RFC3339), LastUsed: isoPtr(a.LastUsed),
		RevokedAt: isoPtr(a.RevokedAt), RevokedBy: a.RevokedBy}
	if a.Status == store.OAuthRevoked || a.Status == store.OAuthRemoved {
		v.Severity = "none"
	}
	if a.OwnerIdentityID != nil {
		name, ok := names[*a.OwnerIdentityID]
		if !ok {
			if id, err := tx.Identity(*a.OwnerIdentityID); err == nil {
				name = id.Name
			} else if !errors.Is(err, store.ErrNotFound) {
				return v, err
			}
			names[*a.OwnerIdentityID] = name
		}
		v.Owner = &oauthOwnerView{ID: *a.OwnerIdentityID, Name: name}
	}
	return v, nil
}

func viewOAuthGrant(tx *store.TenantTx, g *store.OAuthGrant, provider string) (oauthGrantView, error) {
	v := oauthGrantView{ID: g.ID, Kind: g.Kind, User: g.UserRef, Admin: g.GranterAdmin, Consent: g.ConsentType,
		Scopes: oauthapps.Scopes(provider, g.Scopes), GrantedAt: isoPtr(g.GrantedAt), LastUsed: isoPtr(g.LastUsed), Status: g.Status,
		RevokedAt: isoPtr(g.RevokedAt), RevokedBy: g.RevokedBy, RevokeError: g.RevokeError}
	if g.IdentityID != nil {
		if id, err := tx.Identity(*g.IdentityID); err == nil {
			v.Identity = &oauthOwnerView{ID: id.ID, Name: id.Name}
		} else if !errors.Is(err, store.ErrNotFound) {
			return v, err
		}
	}
	return v, nil
}

// ---------------------------------------------------------------- reads

var (
	oauthStatuses  = []string{"all", store.OAuthActive, store.OAuthRevoked, store.OAuthRemoved}
	oauthSeverties = []string{oauthapps.SevCritical, oauthapps.SevHigh, oauthapps.SevMedium, oauthapps.SevLow}
	oauthFlags     = []string{oauthapps.FlagHighRiskNonAdmin, oauthapps.FlagUnused, oauthapps.FlagUnverified}
)

func (s *Server) listOAuthApps(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	enum := func(name string, allowed []string) string {
		v, _ := p.query(name)
		if v != "" && !slices.Contains(allowed, v) {
			p.errs = append(p.errs, verr{Type: "enum", Loc: []any{"query", name}, Msg: "must be one of " + strings.Join(allowed, ", ")})
		}
		return v
	}
	provider := enum("provider", oauthapps.Providers)
	severity := enum("severity", oauthSeverties)
	status := enum("status", oauthStatuses)
	flag := enum("flag", oauthFlags)
	vendor, _ := p.query("vendor")
	q, _ := p.query("q")
	if len(vendor) > 200 || len(q) > 200 {
		p.errs = append(p.errs, verr{Type: "string_too_long", Loc: []any{"query", "q"}, Msg: "must be at most 200 characters"})
	}
	unusedDays := p.queryInt("unused_days", oauthapps.DefaultUnusedDays, ptr(int64(1)), ptr(int64(3650)))
	unused := oauthapps.DefaultUnusedDays
	if unusedDays >= 1 && unusedDays <= 3650 {
		unused = int(unusedDays)
	}
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if status == "" {
		status = store.OAuthActive
	}
	q = strings.ToLower(strings.TrimSpace(q))
	now := s.clock()
	c := store.TxFrom(r.Context())
	apps, err := c.OAuthApps()
	if err != nil {
		return nil, err
	}
	all, err := c.OAuthGrants()
	if err != nil {
		return nil, err
	}
	byApp := map[string][]*store.OAuthGrant{}
	for _, g := range all {
		byApp[g.AppID] = append(byApp[g.AppID], g)
	}
	names := map[int64]string{}
	out := []oauthAppView{}
	sum := map[string]int{"apps": 0, "high_risk": 0, "high_risk_non_admin": 0, "unused": 0, "grants": 0}
	for _, a := range apps {
		if a.Status != store.OAuthActive {
			continue // the summary counts what is live
		}
		v, err := viewOAuthApp(c, a, byApp[a.ID], now, unused, names)
		if err != nil {
			return nil, err
		}
		sum["apps"]++
		sum["grants"] += v.Grants
		if oauthapps.IsHighRisk(v.Severity) {
			sum["high_risk"]++
		}
		if slices.Contains(v.Flags, oauthapps.FlagHighRiskNonAdmin) {
			sum["high_risk_non_admin"]++
		}
		if slices.Contains(v.Flags, oauthapps.FlagUnused) {
			sum["unused"]++
		}
	}
	for _, a := range apps {
		switch {
		case status != "all" && a.Status != status,
			provider != "" && a.Provider != provider,
			vendor != "" && !oauthapps.MatchesVendor(a, vendor),
			q != "" && !strings.Contains(strings.ToLower(a.Name+" "+a.Publisher+" "+a.ClientID), q):
			continue
		}
		v, err := viewOAuthApp(c, a, byApp[a.ID], now, unused, names)
		if err != nil {
			return nil, err
		}
		if (severity != "" && v.Severity != severity) || (flag != "" && !slices.Contains(v.Flags, flag)) {
			continue
		}
		out = append(out, v)
	}
	states, err := c.OAuthSyncStates()
	if err != nil {
		return nil, err
	}
	type stateView struct {
		Provider    string  `json:"provider"`
		Status      string  `json:"status"`
		AttemptedAt string  `json:"attempted_at"`
		SucceededAt *string `json:"succeeded_at"`
		Apps        int     `json:"apps"`
		Grants      int     `json:"grants"`
		Error       string  `json:"error"`
	}
	sync := make([]stateView, 0, len(states))
	for _, st := range states {
		sync = append(sync, stateView{st.Provider, st.Status, st.AttemptedAt.UTC().Format(time.RFC3339), isoPtr(st.SucceededAt), st.Apps, st.Grants, st.Error})
	}
	pending, err := c.PendingOAuthRevokeRequests(now)
	if err != nil {
		return nil, err
	}
	type pendingView struct {
		ID          string `json:"id"`
		Scope       string `json:"scope"`
		Target      string `json:"target"`
		Apps        int    `json:"apps"`
		Grants      int    `json:"grants"`
		Reason      string `json:"reason"`
		RequestedBy string `json:"requested_by"`
		ExpiresAt   string `json:"expires_at"`
	}
	pv := make([]pendingView, 0, len(pending))
	for _, x := range pending {
		pv = append(pv, pendingView{x.ID, x.Scope, x.Target, x.Apps, x.Grants, x.Reason, x.RequestedBy, x.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	open, err := c.OpenOAuthChanges()
	if err != nil {
		return nil, err
	}
	appName := map[string]string{}
	for _, a := range apps {
		appName[a.ID] = a.Name
	}
	changes := make([]oauthChangeView, 0, len(open))
	for _, ch := range open {
		changes = append(changes, viewOAuthChange(ch, appName[ch.AppID]))
	}
	sum["open_changes"] = len(changes)
	return map[string]any{"apps": out, "summary": sum, "sync": sync, "pending_requests": pv, "changes": changes, "unused_days": unused,
		"catalog_version": oauthapps.CatalogVersion}, nil
}

func oauthAppID(p *params, name string) (string, error) {
	id := p.path[name]
	if !idRE.MatchString(id) {
		return "", errStatus(http.StatusNotFound, "no such app or grant")
	}
	return id, nil
}

func (s *Server) getOAuthApp(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := oauthAppID(p, "app_id")
	if err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	a, err := c.OAuthApp(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "no such app or grant")
	}
	if err != nil {
		return nil, err
	}
	grants, err := c.OAuthGrantsOf(id)
	if err != nil {
		return nil, err
	}
	v, err := viewOAuthApp(c, a, grants, s.clock(), oauthapps.DefaultUnusedDays, map[int64]string{})
	if err != nil {
		return nil, err
	}
	gv := make([]oauthGrantView, 0, len(grants))
	for _, g := range grants {
		x, err := viewOAuthGrant(c, g, a.Provider)
		if err != nil {
			return nil, err
		}
		gv = append(gv, x)
	}
	facts, err := c.OAuthFactsOf(id)
	if err != nil {
		return nil, err
	}
	creds := []oauthCredentialView{}
	for _, f := range facts {
		if f.Kind == store.OAuthFactSecret || f.Kind == store.OAuthFactCertificate {
			creds = append(creds, oauthCredentialView{ID: f.ID, Kind: f.Kind, Label: f.Label, AddedAt: isoPtr(f.AddedAt), Status: f.Status})
		}
	}
	chs, err := c.OAuthChangesOf(id)
	if err != nil {
		return nil, err
	}
	cv := make([]oauthChangeView, 0, len(chs))
	for _, ch := range chs {
		cv = append(cv, viewOAuthChange(ch, a.Name))
	}
	return map[string]any{"app": v, "grants": gv, "credentials": creds, "changes": cv}, nil
}

// ---------------------------------------------------------------- writes

func (s *Server) syncOAuthApps(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b struct {
		Provider string `json:"provider"`
	}
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	if b.Provider != "" && !slices.Contains(oauthapps.Providers, b.Provider) {
		return nil, badRequest("invalid_provider", "provider is google, entra, salesforce or github")
	}
	ctx, cancel := context.WithTimeout(r.Context(), containTimeout)
	defer cancel()
	var only []string
	if b.Provider != "" {
		only = []string{b.Provider}
	}
	return s.oauthapps.Sync(ctx, s.store, principal(r).TenantID, actor(r), only...)
}

func (s *Server) setOAuthAppOwner(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := oauthAppID(p, "app_id")
	if err != nil {
		return nil, err
	}
	var b struct {
		IdentityID *int64 `json:"identity_id"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.IdentityID != nil && *b.IdentityID < 1 {
		return nil, badRequest("invalid_identity", "identity_id is an identity id, or null to clear the owner")
	}
	c := store.TxFrom(r.Context())
	if b.IdentityID != nil {
		if _, err := c.Identity(*b.IdentityID); errors.Is(err, store.ErrNotFound) {
			return nil, badRequest("invalid_identity", "no such identity")
		} else if err != nil {
			return nil, err
		}
	}
	if err := c.SetOAuthAppOwner(id, b.IdentityID); errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "no such app or grant")
	} else if err != nil {
		return nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "oauthapps.owner_set", ojson.Object{{Key: "app_id", Value: id},
		{Key: "identity_id", Value: b.IdentityID}}); err != nil {
		return nil, err
	}
	return map[string]any{"app_id": echoSafe(id), "identity_id": b.IdentityID}, nil
}

func (s *Server) removeOAuthCredential(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := oauthAppID(p, "app_id")
	if err != nil {
		return nil, err
	}
	cid, err := oauthAppID(p, "credential_id")
	if err != nil {
		return nil, err
	}
	var b oauthRevokeBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), containTimeout)
	defer cancel()
	rep, err := s.oauthapps.RemoveCredential(ctx, s.store, principal(r).TenantID, id, cid, actor(r), strings.TrimSpace(b.Reason))
	switch {
	case errors.Is(err, oauthapps.ErrNotFound), errors.Is(err, oauthapps.ErrNoCredential):
		return nil, errStatus(http.StatusNotFound, "no such app or credential")
	case err != nil:
		return nil, err
	}
	if !rep.OK {
		code := "oauth_credential_failed"
		if rep.Outcome == oauthapps.OutcomeManual {
			code = "oauth_credential_manual"
		}
		return nil, &readiness.Error{Status: http.StatusBadGateway, Code: code, Msg: "the credential was not removed: " + rep.Detail,
			Extra: map[string]any{"report": rep}}
	}
	return rep, nil
}

func (s *Server) resolveOAuthChange(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := oauthAppID(p, "app_id")
	if err != nil {
		return nil, err
	}
	cid, err := oauthAppID(p, "change_id")
	if err != nil {
		return nil, err
	}
	var b struct {
		Note string `json:"note"`
	}
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	note := strings.TrimSpace(b.Note)
	if len(note) > 500 {
		return nil, badRequest("invalid_note", "note is at most 500 characters")
	}
	c := store.TxFrom(r.Context())
	ch, err := c.OAuthChange(cid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && ch.AppID != id) {
		return nil, errStatus(http.StatusNotFound, "no such change")
	}
	if err != nil {
		return nil, err
	}
	if err := c.ResolveOAuthChangeID(cid, "acknowledged by "+actor(r)+": "+note, s.clock()); errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusConflict, "the change is already closed")
	} else if err != nil {
		return nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "oauthapps.change_resolved", ojson.Object{{Key: "change_id", Value: cid},
		{Key: "app_id", Value: id}, {Key: "kind", Value: ch.Kind}, {Key: "note", Value: note}}); err != nil {
		return nil, err
	}
	return map[string]any{"change_id": echoSafe(cid), "status": store.OAuthChangeResolved}, nil
}

type oauthRevokeBody struct {
	Reason string `json:"reason"`
	Vendor string `json:"vendor"`
	DryRun bool   `json:"dry_run"`
}

func (s *Server) revokeOAuthApp(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := oauthAppID(p, "app_id")
	if err != nil {
		return nil, err
	}
	return s.revokeOAuth(r, p, oauthapps.ScopeApp, id, "", &oauthRevokeBody{})
}

func (s *Server) revokeOAuthGrant(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := oauthAppID(p, "app_id")
	if err != nil {
		return nil, err
	}
	gid, err := oauthAppID(p, "grant_id")
	if err != nil {
		return nil, err
	}
	return s.revokeOAuth(r, p, oauthapps.ScopeGrant, id, gid, &oauthRevokeBody{})
}

func (s *Server) revokeOAuthVendor(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	b := &oauthRevokeBody{}
	if err := decodeBody(r, b, false); err != nil {
		return nil, err
	}
	v := strings.TrimSpace(b.Vendor)
	if v == "" || len(v) > 200 {
		return nil, badRequest("invalid_vendor", "vendor is required: the publisher or app name, at most 200 characters")
	}
	return s.revokeOAuth(r, p, oauthapps.ScopeVendor, "", v, b)
}

// revokeOAuth is the shared flow: validate, plan, gate (four-eyes), execute.
func (s *Server) revokeOAuth(r *http.Request, p *params, scope, appID, target string, b *oauthRevokeBody) (any, error) {
	if scope != oauthapps.ScopeVendor {
		if err := decodeBody(r, b, false); err != nil {
			return nil, err
		}
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(b.Reason)
	ctx := r.Context()
	now := s.clock()
	var plan *oauthapps.Plan
	err := p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		plan, err = oauthapps.BuildPlan(c, scope, appID, target, now)
		return err
	})
	switch {
	case errors.Is(err, oauthapps.ErrNotFound):
		return nil, errStatus(http.StatusNotFound, "no such app, grant or vendor")
	case errors.Is(err, oauthapps.ErrNothingToRevoke):
		return nil, errStatus(http.StatusConflict, "nothing to revoke: no live grant")
	case err != nil:
		return nil, err
	}
	if b.DryRun {
		return map[string]any{"dry_run": true, "scope": plan.Scope, "target": echoSafe(plan.Target), "apps": plan.Apps, "grants": len(plan.Items),
			"four_eyes_required": plan.FourEyes()}, nil
	}
	by := principal(r).User()
	if plan.FourEyes() && by.ID == uuid.Nil {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden",
			Msg: "this revoke needs two admins; a signed-in admin user makes it"}
	}
	var decision string
	var req *store.OAuthRevokeRequest
	if err := p.scope.Write(ctx, func(c *store.TenantTx) error {
		var err error
		decision, req, err = oauthapps.Gate(c, plan, by.ID, actor(r), reason, now)
		return err
	}); err != nil {
		return nil, err
	}
	switch decision {
	case oauthapps.GateSameApprover:
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "four_eyes_required",
			Msg: "this revoke needs a second admin: another tenant admin must make the same request"}
	case oauthapps.GatePending:
		return statusBody{http.StatusAccepted, map[string]any{"status": "pending_second_admin", "request_id": req.ID, "scope": plan.Scope,
			"target": echoSafe(plan.Target), "apps": plan.Apps, "grants": len(plan.Items), "expires_at": req.ExpiresAt.UTC().Format(time.RFC3339)}}, nil
	}
	ectx, cancel := context.WithTimeout(ctx, containTimeout)
	defer cancel()
	rep, err := s.oauthapps.Execute(ectx, s.store, principal(r).TenantID, plan, actor(r), reason)
	if err != nil {
		return nil, err
	}
	rep.Target = echoSafe(rep.Target)
	if !rep.OK {
		return nil, &readiness.Error{Status: http.StatusBadGateway, Code: "oauth_revoke_incomplete",
			Msg: fmt.Sprintf("%d of %d grants revoked; %d failed, %d need a person, %d were not attempted", rep.Revoked, rep.Total,
				rep.Failed, rep.Manual, rep.Skipped), Extra: map[string]any{"report": rep}}
	}
	return rep, nil
}

// echoAlphabet is every character a response may repeat from a request
// value (an app id, a vendor name): letters, digits and a few separators.
const echoAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_&,"

// echoSafe copies s through echoAlphabet, so a value echoed in a response
// is built from constant characters and never carries markup.
func echoSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if i := strings.IndexRune(echoAlphabet, r); i >= 0 {
			b.WriteByte(echoAlphabet[i])
		}
	}
	return b.String()
}
