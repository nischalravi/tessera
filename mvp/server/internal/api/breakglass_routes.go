package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The break-glass routes (design §9.6, §15.4, §16.1):
//
//	POST /api/auth/break-glass/options                      public {tenant}: WebAuthn assertion options
//	POST /api/auth/break-glass/verify                       public {tenant, credential}: the break-glass session
//	GET  /api/admin/break-glass                             keys, open enrolments, uses of the last 30 days
//	POST /api/admin/break-glass/registration/options        {change_request_id}: STEP_UP_ADMIN
//	POST /api/admin/break-glass/registration/verify         {change_request_id, credential}: STEP_UP_ADMIN
//	POST /api/admin/break-glass/actions/{action}            break_glass role only (§15.4 actions)
//	POST /api/admin/break-glass/uses/{use_id}/attest        {reason}: why break-glass was used
//
// The mutating routes are phased: internal/admin opens its own tenant
// transactions (a refused ceremony still spends its challenge and is
// audited in a transaction of its own).

func (s *Server) registerBreakGlassRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(P, "/api/auth/break-glass/options", noTenant, publicRoute, s.bgSignInOptions)
	s.handle(P, "/api/auth/break-glass/verify", noTenant, publicRoute, s.bgSignInVerify)
	s.handle(G, "/api/admin/break-glass", read, need(auth.PermAdminRead), s.bgOverview)
	s.handle(P, "/api/admin/break-glass/registration/options", phased, needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin),
		s.bgRegistrationOptions)
	s.handle(P, "/api/admin/break-glass/registration/verify", phased, needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin),
		s.bgRegistrationVerify)
	s.handle(P, "/api/admin/break-glass/actions/{action}", phased, need(auth.PermBreakGlassRecover), s.bgAction)
	s.handle(P, "/api/admin/break-glass/uses/{use_id}/attest", phased, need(auth.PermAdminChangeReq), s.bgAttest)
}

// errBreakGlassUnavailable is the answer for an unknown tenant and for a
// tenant with no usable key alike.
var errBreakGlassUnavailable = &admin.Error{Status: http.StatusNotFound, Code: "break_glass_unavailable",
	Msg: "break-glass sign-in is not available for this tenant"}

// requireJSON refuses a public POST that is not declared JSON: a cross-site
// form cannot send it without a CORS preflight.
func requireJSON(r *http.Request) error {
	if !jsonContentType(r) {
		return &admin.Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type",
			Msg: "request bodies must be application/json"}
	}
	return nil
}

func marshalRaw(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return rawJSON(b), nil
}

// ---------------------------------------------------------------- public sign-in

func (s *Server) bgSignInOptions(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := requireJSON(r); err != nil {
		return nil, err
	}
	var b struct {
		Tenant string `json:"tenant"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	t, ok, err := s.activeTenant(r.Context(), b.Tenant)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errBreakGlassUnavailable
	}
	assertion, err := s.admin.BeginAssertion(r.Context(), t.ID)
	if err != nil {
		return nil, err
	}
	return marshalRaw(assertion)
}

func (s *Server) bgSignInVerify(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := requireJSON(r); err != nil {
		return nil, err
	}
	var b struct {
		Tenant     string          `json:"tenant"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if len(b.Credential) == 0 {
		return nil, badRequest("invalid_body", "credential is required")
	}
	t, ok, err := s.activeTenant(r.Context(), b.Tenant)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &admin.Error{Status: http.StatusUnauthorized, Code: "break_glass_failed", Msg: "break-glass sign-in failed"}
	}
	ctx := r.Context()
	res, err := s.admin.SignIn(ctx, t.ID, b.Credential, admin.ClientInfo{IP: clientAddr(r), UserAgent: userAgent(r)})
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	// Signing in again replaces the browser's previous session (§11).
	if prevTenant, prevSID, had, err := s.authn.RequestSession(r); err != nil {
		return nil, err
	} else if had {
		sys := audit.AsSystem(ctx, "auth.break_glass")
		if err := s.store.InTenant(sys, prevTenant, func(tx *store.TenantTx) error {
			_, err := auth.RevokeReplaced(sys, tx, prevSID, now)
			return err
		}); err != nil {
			return nil, err
		}
	}
	uid := res.User.ID
	p := &auth.Principal{Kind: auth.KindUser, UserID: &uid, Display: res.User.DisplayName,
		Authn: &auth.AuthnContext{ID: res.Authn.ID, AAL: 3, PhishingResistant: true, TesseraACR: auth.ACRPhrh, AuthTime: now}}
	sid := res.Issued.Session.ID.String()
	audit.SetPrincipal(ctx, audit.Principal{Tenant: t.ID, Actor: p.AuditActor(), SessionID: &sid, Authn: p.AuditAuthn(now)})
	http.SetCookie(w, s.authn.Cookies.Session(res.Issued.Secret))
	return ojson.Object{{Key: "ok", Value: true}, {Key: "redirect", Value: "/admin"},
		{Key: "expires_at", Value: rt3339(res.Issued.Session.AbsoluteExpiresAt)},
		{Key: "idle_timeout_s", Value: int(auth.BreakGlassIdle / time.Second)}}, nil
}

// ---------------------------------------------------------------- admin

func keyView(c *store.BreakGlassCredential, names map[uuid.UUID]string) ojson.Object {
	return ojson.Object{{Key: "id", Value: c.ID.String()}, {Key: "user_id", Value: c.UserID.String()},
		{Key: "user", Value: names[c.UserID]}, {Key: "label", Value: c.Label}, {Key: "custodian", Value: c.Custodian},
		{Key: "aaguid", Value: c.AAGUID}, {Key: "attestation_format", Value: c.AttestationFormat},
		{Key: "attestation_trust", Value: c.AttestationTrust}, {Key: "transports", Value: append([]string{}, c.Transports...)},
		{Key: "change_request_id", Value: c.ChangeRequestID.String()}, {Key: "created_at", Value: rt3339(c.CreatedAt)},
		{Key: "last_used_at", Value: opt(c.LastUsedAt)}, {Key: "revoked_at", Value: opt(c.RevokedAt)}}
}

func useView(u *store.BreakGlassUse, names map[uuid.UUID]string, labels map[uuid.UUID]string) ojson.Object {
	var by any
	if u.AnsweredBy != nil {
		by = ojson.Object{{Key: "id", Value: u.AnsweredBy.String()}, {Key: "display_name", Value: names[*u.AnsweredBy]}}
	}
	return ojson.Object{{Key: "id", Value: u.ID.String()}, {Key: "session_id", Value: u.SessionID.String()},
		{Key: "credential_id", Value: u.CredentialID.String()}, {Key: "key", Value: labels[u.CredentialID]},
		{Key: "used_at", Value: rt3339(u.UsedAt)}, {Key: "ip", Value: u.IP},
		{Key: "answered", Value: u.AnsweredAt != nil}, {Key: "answered_at", Value: opt(u.AnsweredAt)},
		{Key: "answered_by", Value: by}, {Key: "reason", Value: u.Reason}}
}

// bgOverview is what the admin Break-glass page and the dashboard show: the
// keys, the enrolments whose registration window is open, the uses of the
// last 30 days (and every use nobody explained yet), the AAGUID allowlist.
func (s *Server) bgOverview(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	now := s.clock()
	names, err := userNames(tx)
	if err != nil {
		return nil, err
	}
	keys, err := tx.BreakGlassCredentials()
	if err != nil {
		return nil, err
	}
	labels := map[uuid.UUID]string{}
	hasKey := map[uuid.UUID]bool{}
	keyViews := []ojson.Object{}
	for _, c := range keys {
		labels[c.ID] = c.Label
		hasKey[c.ChangeRequestID] = true
		keyViews = append(keyViews, keyView(c, names))
	}
	chs, err := tx.AdminChanges()
	if err != nil {
		return nil, err
	}
	open := []ojson.Object{}
	for _, ch := range chs {
		if ch.Type != admin.TypeBGRegister || ch.Status != store.ChangeApplied || ch.AppliedAt == nil || hasKey[ch.ID] ||
			!now.Before(ch.AppliedAt.Add(admin.RegistrationWindow)) {
			continue
		}
		var p struct {
			UserID    string `json:"user_id"`
			Label     string `json:"label"`
			Custodian string `json:"custodian"`
		}
		_ = json.Unmarshal(ch.Payload, &p)
		open = append(open, ojson.Object{{Key: "change_request_id", Value: ch.ID.String()}, {Key: "user_id", Value: p.UserID},
			{Key: "label", Value: p.Label}, {Key: "custodian", Value: p.Custodian},
			{Key: "requested_by", Value: ojson.Object{{Key: "id", Value: ch.RequestedBy.String()},
				{Key: "display_name", Value: names[ch.RequestedBy]}}},
			{Key: "window_closes_at", Value: rt3339(ch.AppliedAt.Add(admin.RegistrationWindow))}})
	}
	uses, err := tx.RecentBreakGlassUses(now.Add(-admin.UseReviewWindow))
	if err != nil {
		return nil, err
	}
	useViews, unanswered := []ojson.Object{}, 0
	for _, u := range uses {
		if u.AnsweredAt == nil {
			unanswered++
		}
		useViews = append(useViews, useView(u, names, labels))
	}
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "available", Value: s.admin.Available()}, {Key: "keys", Value: keyViews},
		{Key: "open_enrolments", Value: open}, {Key: "uses", Value: useViews}, {Key: "unanswered_uses", Value: unanswered},
		{Key: "aaguid_allowlist", Value: append([]string{}, admin.AAGUIDAllowlist(t)...)},
		{Key: "actions", Value: admin.Actions()}}, nil
}

func (s *Server) bgRegistrationOptions(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		ChangeRequestID string `json:"change_request_id"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(b.ChangeRequestID)
	if err != nil {
		return nil, badRequest("invalid_body", "change_request_id must be the id of an applied breakglass.register request")
	}
	creation, err := s.admin.BeginRegistration(r.Context(), principal(r), id)
	if err != nil {
		return nil, err
	}
	return marshalRaw(creation)
}

func (s *Server) bgRegistrationVerify(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		ChangeRequestID string          `json:"change_request_id"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(b.ChangeRequestID)
	if err != nil || len(b.Credential) == 0 {
		return nil, badRequest("invalid_body", "change_request_id and credential are required")
	}
	c, err := s.admin.FinishRegistration(r.Context(), principal(r), id, b.Credential)
	if err != nil {
		return nil, err
	}
	names, err := s.userNamesNow(r)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, keyView(c, names)}, nil
}

// userNamesNow reads the tenant's user names in a read transaction (phased
// routes have no request transaction).
func (s *Server) userNamesNow(r *http.Request) (map[uuid.UUID]string, error) {
	var names map[uuid.UUID]string
	err := s.store.ReadTenant(r.Context(), principal(r).TenantID, func(tx *store.TenantTx) error {
		var err error
		names, err = userNames(tx)
		return err
	})
	return names, err
}

func (s *Server) bgAction(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	action := p.path["action"]
	if !slices.Contains(admin.Actions(), action) {
		return nil, &admin.Error{Status: http.StatusNotFound, Code: "unknown_action", Msg: "unknown break-glass action"}
	}
	var payload json.RawMessage
	if err := decodeBody(r, &payload, true); err != nil {
		return nil, err
	}
	res, err := s.admin.BreakGlassAction(r.Context(), principal(r), action, payload)
	if err != nil {
		return nil, err
	}
	out := ojson.Object{{Key: "action", Value: res.Action}, {Key: "revoked_sessions", Value: res.RevokedSessions}}
	if res.Change != nil {
		cv, err := s.changeResponse(r, res.Change)
		if err != nil {
			return nil, err
		}
		out = append(out, ojson.KV{Key: "change_request", Value: cv})
	}
	return statusBody{http.StatusAccepted, out}, nil
}

func (s *Server) bgAttest(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "use_id")
	if err != nil {
		return nil, err
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	u, err := s.admin.AttestUse(r.Context(), principal(r), id, b.Reason)
	if err != nil {
		return nil, err
	}
	names, err := s.userNamesNow(r)
	if err != nil {
		return nil, err
	}
	return useView(u, names, map[uuid.UUID]string{}), nil
}
