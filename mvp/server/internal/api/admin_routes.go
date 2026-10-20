package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The admin routes of design §16.1 (all /api/admin/* except break-glass,
// which arrives in PR13):
//
//	GET  /api/admin/users                                   users and their roles
//	POST /api/admin/users/{user_id}/disable                 {reason}: disable now, revoke sessions
//	GET  /api/admin/idp-connections                         connections (never their secrets)
//	POST /api/admin/idp-connections/{connection_id}/activate  after the requester's test login
//	GET  /api/admin/change-requests[?status=open|<status>]  the workflow's requests
//	POST /api/admin/change-requests                         {type, payload, client_secret?}
//	GET  /api/admin/change-requests/{change_id}
//	POST /api/admin/change-requests/{change_id}/approve     {payload_hash}: a different admin, STEP_UP_ADMIN
//	POST /api/admin/change-requests/{change_id}/reject
//	POST /api/admin/change-requests/{change_id}/cancel
//	POST /api/admin/change-requests/{change_id}/apply       after the cooling-off (409 before)
//	GET  /api/admin/notifications                           queued admin notifications
//	GET  /api/admin/recovery                                operator recoveries
//	POST /api/admin/recovery/{recovery_id}/cancel           an existing admin cancels a recovery
//	GET  /api/admin/api-clients                             machine clients (admin_clients.go)
//
// The mutating routes are phased: internal/admin opens its own tenant
// transactions (an applier that fails is recorded as failed in a second
// one) and writes each transition's audit event and notification in the
// transaction that makes it.

func (s *Server) registerAdminRoutes() {
	G, P := http.MethodGet, http.MethodPost
	adm := auth.StepUpAdmin
	s.handle(G, "/api/admin/users", read, need(auth.PermAdminRead), s.adminUsers)
	s.handle(P, "/api/admin/users/{user_id}/disable", phased, needStepUp(auth.PermAdminUsersDisable, adm), s.adminDisableUser)
	s.handle(G, "/api/admin/idp-connections", read, need(auth.PermAdminRead), s.adminConnections)
	s.handle(P, "/api/admin/idp-connections/{connection_id}/activate", phased, needStepUp(auth.PermAdminChangeReq, adm),
		s.adminActivateConnection)
	s.handle(G, "/api/admin/change-requests", read, need(auth.PermAdminRead), s.adminChanges)
	s.handle(P, "/api/admin/change-requests", phased, needStepUp(auth.PermAdminChangeReq, adm), s.adminSubmit)
	s.handle(G, "/api/admin/change-requests/{change_id}", read, need(auth.PermAdminRead), s.adminChange)
	s.handle(P, "/api/admin/change-requests/{change_id}/approve", phased, needStepUp(auth.PermAdminChangeAppr, adm), s.adminApprove)
	s.handle(P, "/api/admin/change-requests/{change_id}/reject", phased, need(auth.PermAdminChangeAppr), s.adminReject)
	s.handle(P, "/api/admin/change-requests/{change_id}/cancel", phased, need(auth.PermAdminChangeReq), s.adminCancel)
	s.handle(P, "/api/admin/change-requests/{change_id}/apply", phased, needStepUp(auth.PermAdminChangeAppr, adm), s.adminApply)
	s.handle(G, "/api/admin/notifications", read, need(auth.PermAdminRead), s.adminNotifications)
	s.handle(G, "/api/admin/recovery", read, need(auth.PermAdminRead), s.adminRecoveries)
	s.handle(P, "/api/admin/recovery/{recovery_id}/cancel", phased, need(auth.PermAdminChangeReq), s.adminCancelRecovery)
}

// pathUUID reads a UUID path segment; anything else is the same 404 as a
// missing row.
func pathUUID(p *params, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(p.path[name])
	if err != nil {
		return uuid.Nil, errStatus(http.StatusNotFound, "Not Found")
	}
	return id, nil
}

// notFoundIf maps the store's ErrNotFound to the API's 404.
func notFoundIf(err error) error {
	if isNotFound(err) {
		return errStatus(http.StatusNotFound, "Not Found")
	}
	return err
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// ---------------------------------------------------------------- users

func opt(t *time.Time) any {
	if t == nil {
		return nil
	}
	return rt3339(*t)
}

func (s *Server) adminUsers(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	us, err := tx.PlatformUsers()
	if err != nil {
		return nil, err
	}
	as, err := tx.AllRoleAssignments()
	if err != nil {
		return nil, err
	}
	roles := map[uuid.UUID][]ojson.Object{}
	for _, a := range as {
		roles[a.UserID] = append(roles[a.UserID], ojson.Object{{Key: "role", Value: a.Role}, {Key: "source", Value: a.Source},
			{Key: "expires_at", Value: opt(a.ExpiresAt)}, {Key: "change_request_id", Value: a.ChangeRequestID}})
	}
	out := []ojson.Object{}
	for _, u := range us {
		rs := roles[u.ID]
		if rs == nil {
			rs = []ojson.Object{}
		}
		out = append(out, ojson.Object{{Key: "id", Value: u.ID.String()}, {Key: "email", Value: u.Email},
			{Key: "display_name", Value: u.DisplayName}, {Key: "status", Value: u.Status},
			{Key: "is_break_glass", Value: u.IsBreakGlass}, {Key: "roles", Value: rs},
			{Key: "created_at", Value: rt3339(u.CreatedAt)}, {Key: "last_login_at", Value: opt(u.LastLoginAt)},
			{Key: "disabled_at", Value: opt(u.DisabledAt)}, {Key: "disabled_reason", Value: u.DisabledReason}})
	}
	return ojson.Object{{Key: "users", Value: out}}, nil
}

func (s *Server) adminDisableUser(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "user_id")
	if err != nil {
		return nil, err
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	u, err := s.admin.DisableUser(r.Context(), principal(r), id, b.Reason)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "id", Value: u.ID.String()}, {Key: "status", Value: u.Status}}, nil
}

// ---------------------------------------------------------------- idp connections

func (s *Server) adminConnections(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	cs, err := tx.IdPConnections()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, c := range cs {
		var domains []string
		_ = json.Unmarshal(c.VerifiedDomains, &domains)
		if domains == nil {
			domains = []string{}
		}
		row := ojson.Object{{Key: "id", Value: c.ID.String()}, {Key: "name", Value: c.Name}, {Key: "protocol", Value: c.Protocol},
			{Key: "profile", Value: c.Profile}, {Key: "status", Value: c.Status}, {Key: "is_default", Value: c.IsDefault},
			{Key: "verified_domains", Value: domains},
			{Key: "issuer", Value: firstString(c.Issuer, c.IdPEntityID, c.UserinfoEndpoint)},
			{Key: "assume_phishing_resistant", Value: c.AssumePhishingResistant},
			{Key: "jit_provisioning", Value: c.JITProvisioning}, {Key: "default_role", Value: c.DefaultRole},
			{Key: "created_at", Value: rt3339(c.CreatedAt)}, {Key: "updated_at", Value: rt3339(c.UpdatedAt)},
			{Key: "last_change_request_id", Value: c.LastChangeRequestID}}
		// a pending connection created by a change request shows its activation state
		var act any
		if c.Status == "pending" {
			if ch, err := tx.AppliedConnectionCreate(c.ID); err == nil {
				act = ojson.Object{{Key: "change_request_id", Value: ch.ID.String()}, {Key: "requested_by", Value: ch.RequestedBy.String()},
					{Key: "test_login_at", Value: opt(ch.TestLoginAt)}, {Key: "ready", Value: ch.TestLoginAt != nil}}
			} else if !isNotFound(err) {
				return nil, err
			}
		}
		out = append(out, append(row, ojson.KV{Key: "activation", Value: act}))
	}
	return ojson.Object{{Key: "connections", Value: out}}, nil
}

func firstString(vs ...*string) any {
	for _, v := range vs {
		if v != nil && *v != "" {
			return *v
		}
	}
	return nil
}

func (s *Server) adminActivateConnection(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "connection_id")
	if err != nil {
		return nil, err
	}
	c, err := s.admin.ActivateConnection(r.Context(), principal(r), id)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "id", Value: c.ID.String()}, {Key: "status", Value: c.Status}}, nil
}

// ---------------------------------------------------------------- change requests

// adminChangeView renders a request for the API. names maps user ids to display
// names. The sealed secret and the payload's hash input are never included
// beyond the payload itself (which holds no secret).
func adminChangeView(tx *store.TenantTx, ch *store.AdminChange, names map[uuid.UUID]string, now time.Time) ojson.Object {
	who := func(id *uuid.UUID) any {
		if id == nil {
			return nil
		}
		return ojson.Object{{Key: "id", Value: id.String()}, {Key: "display_name", Value: names[*id]}}
	}
	var payload any
	dec := json.NewDecoder(bytes.NewReader(ch.Payload))
	if dec.Decode(&payload) != nil {
		payload = nil
	}
	var failure any
	if ch.Failure != "" {
		failure = ch.Failure
	}
	var target any
	if ch.TargetID != "" {
		target = ch.TargetID
	}
	return ojson.Object{{Key: "id", Value: ch.ID.String()}, {Key: "type", Value: ch.Type},
		{Key: "summary", Value: admin.Summarize(tx, ch, now)}, {Key: "status", Value: ch.Status},
		{Key: "target_id", Value: target}, {Key: "two_person", Value: ch.TwoPerson},
		{Key: "cooling_off_seconds", Value: ch.CoolingOffSeconds},
		{Key: "requested_by", Value: who(&ch.RequestedBy)}, {Key: "requested_at", Value: rt3339(ch.RequestedAt)},
		{Key: "expires_at", Value: rt3339(ch.ExpiresAt)}, {Key: "approved_by", Value: who(ch.ApprovedBy)},
		{Key: "approved_at", Value: opt(ch.ApprovedAt)}, {Key: "effective_at", Value: opt(ch.EffectiveAt)},
		{Key: "decided_by", Value: who(ch.DecidedBy)}, {Key: "decided_at", Value: opt(ch.DecidedAt)},
		{Key: "applied_at", Value: opt(ch.AppliedAt)}, {Key: "failure", Value: failure},
		{Key: "test_login_at", Value: opt(ch.TestLoginAt)}, {Key: "payload_hash", Value: ch.PayloadHash},
		{Key: "payload", Value: payload}}
}

func userNames(tx *store.TenantTx) (map[uuid.UUID]string, error) {
	us, err := tx.PlatformUsers()
	if err != nil {
		return nil, err
	}
	m := make(map[uuid.UUID]string, len(us))
	for _, u := range us {
		m[u.ID] = u.DisplayName
	}
	return m, nil
}

var changeStatuses = []string{store.ChangePendingApproval, store.ChangeCoolingOff, store.ChangeApplied, store.ChangeRejected,
	store.ChangeCancelled, store.ChangeExpired, store.ChangeFailed}

func (s *Server) adminChanges(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	status, _ := p.query("status")
	if status != "" && status != "open" && !slices.Contains(changeStatuses, status) {
		return nil, badRequest("invalid_status", "status must be open or one of "+strings.Join(changeStatuses, ", "))
	}
	tx := store.TxFrom(r.Context())
	var chs []*store.AdminChange
	var err error
	if status == "open" {
		chs, err = tx.OpenAdminChanges()
	} else {
		chs, err = tx.AdminChanges()
	}
	if err != nil {
		return nil, err
	}
	names, err := userNames(tx)
	if err != nil {
		return nil, err
	}
	now := s.clock()
	out := []ojson.Object{}
	for _, ch := range chs {
		if status != "" && status != "open" && ch.Status != status {
			continue
		}
		out = append(out, adminChangeView(tx, ch, names, now))
	}
	return ojson.Object{{Key: "change_requests", Value: out}, {Key: "types", Value: admin.Types()}}, nil
}

func (s *Server) adminChange(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "change_id")
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	ch, err := tx.AdminChange(id)
	if err != nil {
		return nil, notFoundIf(err)
	}
	names, err := userNames(tx)
	if err != nil {
		return nil, err
	}
	notifs, err := tx.AdminNotificationsForChange(id)
	if err != nil {
		return nil, err
	}
	v := adminChangeView(tx, ch, names, s.clock())
	return append(v, ojson.KV{Key: "notifications", Value: notificationViews(notifs, names)}), nil
}

// changeResponse renders a request after a transition, in a read transaction.
func (s *Server) changeResponse(r *http.Request, ch *store.AdminChange) (any, error) {
	var out ojson.Object
	err := s.store.ReadTenant(r.Context(), ch.TenantID, func(tx *store.TenantTx) error {
		names, err := userNames(tx)
		if err != nil {
			return err
		}
		out = adminChangeView(tx, ch, names, s.clock())
		return nil
	})
	return out, err
}

func (s *Server) adminSubmit(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		Type         string          `json:"type"`
		Payload      json.RawMessage `json:"payload"`
		ClientSecret string          `json:"client_secret"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	ch, err := s.admin.Submit(r.Context(), principal(r), admin.SubmitInput{Type: b.Type, Payload: b.Payload,
		ClientSecret: b.ClientSecret})
	if err != nil {
		return nil, err
	}
	out, err := s.changeResponse(r, ch)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, out}, nil
}

func (s *Server) adminApprove(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "change_id")
	if err != nil {
		return nil, err
	}
	var b struct {
		PayloadHash string `json:"payload_hash"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.PayloadHash == "" {
		return nil, badRequest("payload_hash_required", "payload_hash is required: the hash of the payload you reviewed")
	}
	ch, err := s.admin.Approve(r.Context(), principal(r), id, b.PayloadHash)
	if err != nil {
		return nil, err
	}
	return s.changeResponse(r, ch)
}

func (s *Server) adminReject(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.changeTransition(r, p, s.admin.Reject)
}

func (s *Server) adminCancel(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.changeTransition(r, p, s.admin.Cancel)
}

func (s *Server) adminApply(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.changeTransition(r, p, s.admin.Apply)
}

// changeTransition runs a body-less transition of the request in {change_id}.
func (s *Server) changeTransition(r *http.Request, p *params, fn func(ctx context.Context, p *auth.Principal, id uuid.UUID) (*store.AdminChange, error)) (any, error) {
	id, err := pathUUID(p, "change_id")
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	ch, err := fn(r.Context(), principal(r), id)
	if err != nil {
		return nil, err
	}
	return s.changeResponse(r, ch)
}

// ---------------------------------------------------------------- notifications, recovery, api clients

func notificationViews(ns []*store.AdminNotification, names map[uuid.UUID]string) []ojson.Object {
	out := []ojson.Object{}
	for _, n := range ns {
		var rcpt any = n.RecipientAddress
		if n.RecipientUserID != nil {
			rcpt = names[*n.RecipientUserID]
		}
		var change, recovery any
		if n.ChangeRequestID != nil {
			change = n.ChangeRequestID.String()
		}
		if n.RecoveryID != nil {
			recovery = n.RecoveryID.String()
		}
		out = append(out, ojson.Object{{Key: "id", Value: n.ID.String()}, {Key: "kind", Value: n.Kind},
			{Key: "recipient_type", Value: n.RecipientType}, {Key: "recipient", Value: rcpt}, {Key: "subject", Value: n.Subject},
			{Key: "change_request_id", Value: change}, {Key: "recovery_id", Value: recovery},
			{Key: "created_at", Value: rt3339(n.CreatedAt)}, {Key: "delivered_at", Value: opt(n.DeliveredAt)}})
	}
	return out
}

func (s *Server) adminNotifications(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	ns, err := tx.AdminNotifications()
	if err != nil {
		return nil, err
	}
	names, err := userNames(tx)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "notifications", Value: notificationViews(ns, names)}}, nil
}

func recoveryView(rec *store.TenantRecovery) ojson.Object {
	return ojson.Object{{Key: "id", Value: rec.ID.String()}, {Key: "status", Value: rec.Status}, {Key: "ticket", Value: rec.Ticket},
		{Key: "operator", Value: rec.Operator}, {Key: "co_operator", Value: rec.CoOperator},
		{Key: "not_before", Value: rt3339(rec.NotBefore)}, {Key: "created_at", Value: rt3339(rec.CreatedAt)},
		{Key: "cancelled_at", Value: opt(rec.CancelledAt)}, {Key: "completed_at", Value: opt(rec.CompletedAt)}}
}

func (s *Server) adminRecoveries(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	rs, err := store.TxFrom(r.Context()).TenantRecoveries()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, rec := range rs {
		out = append(out, recoveryView(rec))
	}
	return ojson.Object{{Key: "recoveries", Value: out}}, nil
}

func (s *Server) adminCancelRecovery(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := pathUUID(p, "recovery_id")
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	rec, err := s.admin.CancelRecovery(r.Context(), principal(r), id)
	if err != nil {
		return nil, err
	}
	return recoveryView(rec), nil
}
