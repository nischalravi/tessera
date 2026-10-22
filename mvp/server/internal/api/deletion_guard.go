package api

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The deletion threshold guard (internal/deleteguard).
//
//	GET  /api/admin/deletion-guard                     each category's threshold, window usage and the hold expiry
//	GET  /api/admin/deletion-holds[?status=&category=] held deletions, newest first
//	GET  /api/admin/deletion-holds/{id}                one hold with its items
//	POST /api/admin/deletion-holds/{id}/approve        release the held items (body {"items":[ords]} releases only those and discards the rest); a different admin than the actor; step-up
//	POST /api/admin/deletion-holds/{id}/discard        drop the held items (body {"note"})
//
//	GET  /api/admin/deletion-guard/sources/{kind}/{id}  one source's (connection, loader, vms_source) settings per category: the category's, its override, what applies, its last good record count and window use
//
// Per-source overrides and feed checks change through the same request type (payload "sources").
// The thresholds change through the admin change requests (POST /api/admin/change-requests, type
// deletion_guard.update): tightening takes one admin, loosening two.
//
// A deleting route (groups, folders, members) that the guard held part of answers 202 with
// {"applied", "held", "hold_id", "threshold", "message"} next to its usual fields.

func (s *Server) registerDeletionGuardRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/admin/deletion-guard", read, need(auth.PermAdminRead), s.rd(s.getDeletionGuard))
	s.handle(G, "/api/admin/deletion-guard/sources/{kind}/{id}", read, need(auth.PermAdminRead), s.rd(s.getDeletionGuardSource))
	s.handle(G, "/api/admin/deletion-holds", read, need(auth.PermAdminRead), s.rd(s.listDeletionHolds))
	s.handle(G, "/api/admin/deletion-holds/{id}", read, need(auth.PermAdminRead), s.rd(s.getDeletionHold))
	s.handle(P, "/api/admin/deletion-holds/{id}/approve", write, needStepUp(auth.PermAdminChangeAppr, auth.StepUpAdmin), s.rd(s.approveDeletionHold))
	s.handle(P, "/api/admin/deletion-holds/{id}/discard", write, needStepUp(auth.PermAdminChangeAppr, auth.StepUpAdmin), s.rd(s.discardDeletionHold))
}

// heldBody adds the guard's answer to a deleting route's body.
func heldBody(res *deleteguard.Result, base map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	base["status"] = "partially_applied"
	if res.Applied == 0 {
		base["status"] = "held"
	}
	base["applied"], base["held"], base["hold_id"] = res.Applied, res.Held, res.HoldID
	base["threshold"], base["message"] = res.Threshold, res.Message
	return base
}

// guardErr maps a guard refusal to the API's error.
func guardErr(err error) error {
	if ge, ok := err.(*deleteguard.Error); ok {
		return &readiness.Error{Status: ge.Status, Code: ge.Code, Msg: ge.Msg}
	}
	return err
}

type holdView struct {
	ID            string         `json:"id"`
	Category      string         `json:"category"`
	Status        string         `json:"status"`
	Mode          string         `json:"mode"`
	Reason        map[string]any `json:"reason"`
	Actor         string         `json:"actor"`
	ActorName     string         `json:"actor_name,omitempty"`
	Source        string         `json:"source"`
	SourceID      string         `json:"source_id"`
	CorrelationID string         `json:"correlation_id"`
	ItemCount     int            `json:"item_count"`
	CreatedAt     string         `json:"created_at"`
	ExpiresAt     string         `json:"expires_at"`
	ResolvedAt    *string        `json:"resolved_at"`
	ResolvedBy    *string        `json:"resolved_by"`
	Note          *string        `json:"note"`
	Items         []holdItemView `json:"items,omitempty"`
}

type holdItemView struct {
	Ord    int     `json:"ord"`
	Kind   string  `json:"kind"`
	Ref    string  `json:"ref"`
	Label  string  `json:"label"`
	Status string  `json:"status"`
	Note   *string `json:"note"`
}

func viewHold(tx *store.TenantTx, h *store.DeletionHold, items []*store.DeletionHoldItem) holdView {
	v := holdView{ID: h.ID, Category: h.Category, Status: h.Status, Mode: h.Mode, Actor: h.Actor, Source: h.Source, SourceID: h.SourceID,
		CorrelationID: h.CorrelationID, ItemCount: h.ItemCount, CreatedAt: store.RT(h.CreatedAt), ExpiresAt: store.RT(h.ExpiresAt),
		ResolvedAt: rtPtr(h.ResolvedAt), ResolvedBy: h.ResolvedBy, Note: h.Note, Reason: map[string]any{}}
	_ = json.Unmarshal([]byte(h.Reason), &v.Reason)
	if h.Actor != "" {
		v.ActorName = userName(tx, h.Actor)
	}
	for _, it := range items {
		v.Items = append(v.Items, holdItemView{Ord: it.Ord, Kind: it.Kind, Ref: it.Ref, Label: it.Label, Status: it.Status, Note: it.Note})
	}
	return v
}

func (s *Server) getDeletionGuard(r *http.Request, _ *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	us, err := deleteguard.UsageOf(tx, s.clock())
	if err != nil {
		return 0, nil, err
	}
	hours, err := deleteguard.HoldExpiryHours(tx)
	if err != nil {
		return 0, nil, err
	}
	open, err := tx.OpenDeletionHolds()
	if err != nil {
		return 0, nil, err
	}
	srcs, err := s.sourceOverrides(tx)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"categories": us, "hold_expiry_hours": hours, "open_holds": open,
		"defaults": deleteguard.Defaults(), "change_type": "deletion_guard.update", "sources": srcs,
		"feed_defaults": deleteguard.DefaultFeed()}, nil
}

// sourceOverrideView is one stored override with its source's name.
type sourceOverrideView struct {
	deleteguard.SourcePolicy
	Name string `json:"name"`
	// Effective is what applies to the source for the category.
	Effective deleteguard.Resolved `json:"effective"`
}

// sourceOverrides lists every override of the tenant, each with the name of its source.
func (s *Server) sourceOverrides(tx *store.TenantTx) ([]sourceOverrideView, error) {
	rows, err := tx.DeletionSourcePolicies()
	if err != nil {
		return nil, err
	}
	out := make([]sourceOverrideView, 0, len(rows))
	names := map[deleteguard.SourceRef]string{}
	for _, r := range rows {
		p := deleteguard.SourcePolicyFromRow(r)
		ref := p.Ref()
		name, ok := names[ref]
		if !ok {
			name = sourceName(tx, ref)
			names[ref] = name
		}
		res, err := deleteguard.ResolveFor(tx, ref, p.Category, true)
		if err != nil {
			return nil, err
		}
		out = append(out, sourceOverrideView{SourcePolicy: *p, Name: name, Effective: res})
	}
	return out, nil
}

// sourceName is the display name of a source ("" when it is gone).
func sourceName(tx *store.TenantTx, ref deleteguard.SourceRef) string {
	switch ref.Kind {
	case deleteguard.SrcConnection:
		if c, err := tx.Connection(ref.ID); err == nil {
			return c.Name
		}
	case deleteguard.SrcLoader:
		if l, err := tx.GrpLoader(ref.ID); err == nil {
			return l.Name
		}
	case deleteguard.SrcVMS:
		if v, err := tx.VmsSource(ref.ID); err == nil {
			return v.Name
		}
	}
	return ""
}

func (s *Server) getDeletionGuardSource(r *http.Request, p *params) (int, any, error) {
	ref := deleteguard.SourceRef{Kind: p.path["kind"], ID: p.path["id"]}
	if !ref.Valid() || len(ref.ID) > 128 || len(deleteguard.SourceCategories[ref.Kind]) == 0 {
		return 0, nil, notFound("not_found", "no such source")
	}
	tx := store.TxFrom(r.Context())
	name := sourceName(tx, ref)
	if name == "" {
		return 0, nil, notFound("not_found", "no such source")
	}
	cats, err := deleteguard.ViewSource(tx, ref, s.clock())
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"kind": ref.Kind, "source_id": ref.ID, "name": name, "categories": cats,
		"feed_defaults": deleteguard.DefaultFeed(), "change_type": "deletion_guard.update"}, nil
}

func (s *Server) listDeletionHolds(r *http.Request, p *params) (int, any, error) {
	status, _ := p.query("status")
	cat, _ := p.query("category")
	switch status {
	case "", "held", "released", "partially_released", "discarded", "expired":
	default:
		return 0, nil, badRequest("invalid_status", "status is held, released, partially_released, discarded or expired")
	}
	if cat != "" && !deleteguard.ValidCategory(cat) {
		return 0, nil, badRequest("invalid_category", "category is not a deletion category")
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	hs, err := tx.DeletionHolds(status, cat, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	out := make([]holdView, 0, len(hs))
	for _, h := range hs {
		out = append(out, viewHold(tx, h, nil))
	}
	return http.StatusOK, map[string]any{"holds": out, "limit": limit, "offset": offset}, nil
}

func (s *Server) getDeletionHold(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, notFound("not_found", "no such held deletion")
	}
	tx := store.TxFrom(r.Context())
	h, err := deleteguard.Load(tx, s.clock(), id)
	if err != nil {
		return 0, nil, guardErr(err)
	}
	return http.StatusOK, viewHold(tx, h.DeletionHold, h.Items), nil
}

type approveBody struct {
	// Items are the positions to release; the rest of the hold is discarded. Omitted: all of them.
	Items []int  `json:"items"`
	Note  string `json:"note"`
}

// deletionAppliers are the code that applies each kind of held item again. Every applier runs
// in the approving admin's transaction with the guard's override set.
func (s *Server) deletionAppliers(r *http.Request) deleteguard.Appliers {
	env := func(tx *store.TenantTx, now time.Time) model.Env {
		e := s.grpEnv(r, tx, now)
		e.Override = true
		return e
	}
	group := func(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (string, string, error) {
		return env(tx, now).ReleaseGroup(it)
	}
	return deleteguard.Appliers{
		// accounts and identities: provisioning, connector sync, imports, leavers
		provision.ItemOp:          provision.ReleaseHeld,
		ingest.ItemIdentityStatus: ingest.ReleaseIdentity,
		ingest.ItemAccountStatus:  ingest.ReleaseAccount,
		flatfile.ItemDropAccount:  flatfile.ReleaseDrop,
		jml.ItemLeaver:            jml.ReleaseLeaver,
		jml.ItemAccountDisable:    jml.ReleaseAccountDisable,
		model.ItemGroupDelete:     group, model.ItemGroupPurge: group, model.ItemGroupTree: group,
		model.ItemFolder: func(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (string, string, error) {
			return env(tx, now).ReleaseFolder(it)
		},
		model.ItemMember: func(tx *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (string, string, error) {
			return env(tx, now).ReleaseMember(it)
		},
	}
}

func (s *Server) approveDeletionHold(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, notFound("not_found", "no such held deletion")
	}
	var b approveBody
	if err := decodeBody(r, &b, true); err != nil {
		return 0, nil, err
	}
	pr := principal(r)
	if pr.UserID == nil {
		return 0, nil, errStatus(http.StatusForbidden, "a signed-in admin must release a held deletion")
	}
	if len(b.Items) > 100000 {
		return 0, nil, badRequest("invalid_items", "too many items")
	}
	var ords []int
	if b.Items != nil {
		ords = b.Items
	}
	tx := store.TxFrom(r.Context())
	res, err := deleteguard.Release(tx, s.clock(), id, pr.UserID.String(), ords, s.deletionAppliers(r))
	if err != nil {
		return 0, nil, guardErr(err)
	}
	return http.StatusOK, res, nil
}

func (s *Server) discardDeletionHold(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, notFound("not_found", "no such held deletion")
	}
	var b approveBody
	if err := decodeBody(r, &b, true); err != nil {
		return 0, nil, err
	}
	if len(b.Note) > 1000 {
		return 0, nil, badRequest("invalid_note", "note is at most 1000 characters")
	}
	pr := principal(r)
	if pr.UserID == nil {
		return 0, nil, errStatus(http.StatusForbidden, "a signed-in admin must discard a held deletion")
	}
	res, err := deleteguard.Discard(store.TxFrom(r.Context()), s.clock(), id, pr.UserID.String(), b.Note)
	if err != nil {
		return 0, nil, guardErr(err)
	}
	return http.StatusOK, res, nil
}

// userName is the display name of a platform user id ("" when it is not one).
func userName(tx *store.TenantTx, id string) string {
	u, err := uuid.Parse(id)
	if err != nil {
		return ""
	}
	pu, err := tx.PlatformUser(u)
	if err != nil {
		return ""
	}
	return pu.DisplayName
}
