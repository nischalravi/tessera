package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group privileges (issue #47, GR-4; design docs/design/groups-grouper-parity.md
// §7). Every group route is gated twice: the route's permission (groups.read,
// groups.write or groups.admin, by role and token scope) lets the request in,
// and the handler then asks the privilege checker whether the caller holds the
// privilege the folder or group requires. A caller's group privileges come from
// the identity its platform user is linked to; tenant_admin implicitly holds
// all of them, auditor the read ones and viewer (where the tenant allows it)
// the view ones. A refusal is 403 {"error":"privilege_required", ...}.
//
//	GET    /api/groups/folders/{id}/privileges                      the rows on the folder (stem_admin)
//	POST   /api/groups/folders/{id}/privileges                      grant (stem_admin)
//	DELETE /api/groups/folders/{id}/privileges/{privilege_id}       revoke (stem_admin)
//	GET    /api/groups/folders/{id}/privileges/effective[?identity=]  every path, per privilege
//	GET|POST /api/groups/{id}/privileges, DELETE .../privileges/{privilege_id}, GET .../privileges/effective   the same on a group (admin)
//	GET|PUT /api/groups/privileges/settings                         the everyone policy and default privileges (groups.admin)
//	PUT    /api/groups/users/{id}/identity                          {identity_id|null} link a platform user to an identity (groups.admin, step-up)
//
// A grant is {privilege, holder_type: identity|group|everyone, identity | group,
// applies_to: self|groups|folders|attr_defs, scope: self|one|sub}. Listing or
// explaining another identity's privileges needs admin on the object; one's
// own needs view. The design's DELETE /privileges takes the row in the path
// here, so a revoke names exactly one row.
func (s *Server) registerGroupsPrivilegeRoutes() {
	G, P, PU, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	canRead, canWrite := need(auth.PermGroupsRead), need(auth.PermGroupsWrite)
	admin := need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/privileges/settings", read, admin, s.rd(s.getGrpPrivSettings))
	s.handle(PU, "/api/groups/privileges/settings", write, admin, s.rd(s.putGrpPrivSettings))
	s.handle(PU, "/api/groups/users/{id}/identity", write, needStepUp(auth.PermGroupsAdmin, auth.StepUpPolicy), s.rd(s.linkGrpUserIdentity))
	for _, typ := range []privs.ObjectType{privs.Folder, privs.Group} {
		base := "/api/groups/{id}/privileges"
		if typ == privs.Folder {
			base = "/api/groups/folders/{id}/privileges"
		}
		h := s.privHandlers(typ)
		s.handle(G, base, read, canRead, s.rd(h.list))
		s.handle(P, base, write, canWrite, s.rd(h.grant))
		s.handle(G, base+"/effective", read, canRead, s.rd(h.effective))
		s.handle(D, base+"/{privilege_id}", write, canWrite, s.rd(h.revoke))
	}
}

// ---------------------------------------------------------------- the caller

// grpSubject is who the request's principal is for the privilege checker.
func (s *Server) grpSubject(r *http.Request) privs.Subject {
	pr := principal(r)
	return privs.Subject{Identity: pr.IdentityID, TenantAdmin: pr.ActiveRoles.Has(auth.RoleTenantAdmin),
		Auditor: pr.ActiveRoles.Has(auth.RoleAuditor), ViewerView: pr.ActiveRoles.Has(auth.RoleViewer) && pr.GroupsViewerView}
}

// grpChecker returns the request's privilege checker; its lookups are cached
// for the request, so a handler makes one and reuses it.
func (s *Server) grpChecker(r *http.Request) *privs.Checker {
	return privs.NewChecker(store.TxFrom(r.Context()), s.clock(), s.cfg.GroupsEngine, s.grpSubject(r))
}

// privilegeRequired is the 403 of a privilege the caller does not hold.
func privilegeRequired(d *privs.DeniedError) error {
	return &readiness.Error{Status: http.StatusForbidden, Code: "privilege_required",
		Msg:   "the " + string(d.Privilege) + " privilege is required on this " + string(d.Object.Type),
		Extra: map[string]any{"privilege": string(d.Privilege), "object_type": string(d.Object.Type), "object_id": d.Object.ID}}
}

// privErr maps the privilege model's refusals to JSON errors.
func privErr(err error) error {
	var d *privs.DeniedError
	var pe *privs.Error
	switch {
	case errors.As(err, &d):
		return privilegeRequired(d)
	case errors.As(err, &pe):
		status := map[privs.Kind]int{privs.NotFound: http.StatusNotFound, privs.Conflict: http.StatusConflict,
			privs.Invalid: http.StatusUnprocessableEntity, privs.Forbidden: http.StatusForbidden}[pe.Kind]
		return &readiness.Error{Status: status, Code: pe.Code, Msg: pe.Msg, Extra: pe.Extra}
	}
	return err
}

// grpFolderFor loads a folder (404) and requires the privilege on it (403).
func (s *Server) grpFolderFor(r *http.Request, ck *privs.Checker, id string, p privs.Privilege) (*store.Folder, error) {
	f, err := s.grpRead(r).Folder(store.FolderID(id))
	if err != nil {
		return nil, grpErr(err)
	}
	return f, grpErr(ck.Require(privs.FolderObject(f.ID), p))
}

// grpGroupFor loads a group of any status (404) and requires the privilege on it (403).
func (s *Server) grpGroupFor(r *http.Request, ck *privs.Checker, id string, p privs.Privilege) (*store.NativeGroup, error) {
	g, err := s.grpRead(r).Group(store.GroupID(id))
	if err != nil {
		return nil, grpErr(err)
	}
	return g, grpErr(ck.Require(privs.GroupObject(g.ID), p))
}

// grpAnyFolder resolves a body's folder field: the folder named, or the root
// when it is empty. Before the first folder exists there is no root: only a
// tenant admin may create the first folder or group (which creates it).
func (s *Server) grpFolderOrRoot(r *http.Request, ck *privs.Checker, id string, p privs.Privilege) (*store.Folder, error) {
	if id != "" {
		return s.grpFolderFor(r, ck, id, p)
	}
	root, err := store.TxFrom(r.Context()).GrpRootFolder()
	if errors.Is(err, store.ErrNotFound) {
		if ck.Subject().TenantAdmin {
			return nil, nil
		}
		return nil, privilegeRequired(&privs.DeniedError{Object: privs.Object{Type: privs.Folder, ID: "root"}, Privilege: p})
	}
	if err != nil {
		return nil, err
	}
	return root, grpErr(ck.Require(privs.FolderObject(root.ID), p))
}

// visible fetches a page of a listing and keeps what the caller may view
// (design §10.7, GRP-7387: browse and search are filtered by VIEW). A caller
// whose roles see everything gets the plain page; otherwise rows are read in
// chunks and filtered until offset and limit count visible rows.
func visible[T any](ck *privs.Checker, typ privs.ObjectType, limit, offset int,
	fetch func(limit, offset int) ([]T, error), object func(T) privs.Object, view privs.Privilege) ([]T, error) {
	if ck.Subject().SeesAll(typ) {
		return fetch(limit, offset)
	}
	const chunk = 500
	var out []T
	skip := offset
	for raw := 0; len(out) < limit; raw += chunk {
		rows, err := fetch(chunk, raw)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			ok, err := ck.Has(object(row), view)
			if err != nil {
				return nil, err
			}
			switch {
			case !ok:
			case skip > 0:
				skip--
			case len(out) < limit:
				out = append(out, row)
			}
		}
		if len(rows) < chunk {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- privilege rows

type privHandlers struct {
	s   *Server
	typ privs.ObjectType
}

func (s *Server) privHandlers(t privs.ObjectType) privHandlers { return privHandlers{s, t} }

// admin is the privilege that administers an object of the type.
func (h privHandlers) admin() privs.Privilege {
	if h.typ == privs.Folder {
		return privs.StemAdmin
	}
	return privs.Admin
}

func (h privHandlers) view() privs.Privilege {
	if h.typ == privs.Folder {
		return privs.StemView
	}
	return privs.View
}

// object loads the path's folder or group (404) and requires p on it (403).
func (h privHandlers) object(r *http.Request, p *params, ck *privs.Checker, need privs.Privilege) (privs.Object, error) {
	id, err := grpPathID(p, string(h.typ))
	if err != nil {
		return privs.Object{}, err
	}
	if h.typ == privs.Folder {
		f, err := h.s.grpFolderFor(r, ck, id, need)
		if err != nil {
			return privs.Object{}, err
		}
		return privs.FolderObject(f.ID), nil
	}
	g, err := h.s.grpGroupFor(r, ck, id, need)
	if err != nil {
		return privs.Object{}, err
	}
	return privs.GroupObject(g.ID), nil
}

type privList struct {
	ObjectType string           `json:"object_type"`
	ObjectID   string           `json:"object_id"`
	Items      []*privs.RowView `json:"items"`
}

func (h privHandlers) list(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.object(r, p, ck, h.admin())
	if err != nil {
		return 0, nil, err
	}
	rows, err := store.TxFrom(r.Context()).GrpPrivilegesOf(string(o.Type), o.ID)
	if err != nil {
		return 0, nil, err
	}
	out := privList{ObjectType: string(o.Type), ObjectID: o.ID, Items: make([]*privs.RowView, len(rows))}
	for i, row := range rows {
		out.Items[i] = ck.View(row)
	}
	return http.StatusOK, out, nil
}

func (h privHandlers) grant(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.object(r, p, ck, h.admin())
	if err != nil {
		return 0, nil, err
	}
	var in struct {
		Privilege  string `json:"privilege"`
		HolderType string `json:"holder_type"`
		Identity   *int64 `json:"identity"`
		Group      string `json:"group"`
		AppliesTo  string `json:"applies_to"`
		Scope      string `json:"scope"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	holder := privs.Holder{Type: in.HolderType}
	switch in.HolderType {
	case store.HolderIdentity:
		if in.Identity == nil || *in.Identity < 1 || in.Group != "" {
			return 0, nil, badRequest("invalid_holder", "an identity holder names identity (an identity id) and no group")
		}
		holder.Identity = *in.Identity
	case store.HolderGroup:
		if in.Identity != nil || !idRE.MatchString(in.Group) {
			return 0, nil, badRequest("invalid_holder", "a group holder names group (a group id) and no identity")
		}
		holder.Group = store.GroupID(in.Group)
		// naming a group in a grant shows it exists: the grantor must be able to see it
		if g, err := h.s.grpRead(r).Group(holder.Group); err != nil {
			return 0, nil, grpErr(err)
		} else if err := ck.Require(privs.GroupObject(g.ID), privs.View); err != nil {
			return 0, nil, grpErr(err)
		}
	case store.HolderEveryone:
		if in.Identity != nil || in.Group != "" {
			return 0, nil, badRequest("invalid_holder", "everyone names no identity or group")
		}
	default:
		return 0, nil, badRequest("invalid_holder", "holder_type is identity, group or everyone")
	}
	var row *store.GrpPrivilege
	var created bool
	err = h.s.grpWrite(r, func(e model.Env) error {
		var err error
		row, created, err = privs.Grant(e.Privs(), privs.GrantInput{Object: o, Privilege: privs.Privilege(in.Privilege),
			Holder: holder, AppliesTo: in.AppliesTo, Scope: in.Scope, Source: store.PrivSourceAPI})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return status, ck.View(row), nil
}

func (h privHandlers) revoke(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	o, err := h.object(r, p, ck, h.admin())
	if err != nil {
		return 0, nil, err
	}
	pid := p.path["privilege_id"]
	if !idRE.MatchString(pid) {
		return 0, nil, grpNotFound("privilege")
	}
	row, err := store.TxFrom(r.Context()).GrpPrivilege(pid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (row.ObjectType != string(o.Type) || row.ObjectID != o.ID)) {
		return 0, nil, grpNotFound("privilege") // another object's row is not this object's to revoke
	}
	if err != nil {
		return 0, nil, err
	}
	err = h.s.grpWrite(r, func(e model.Env) error {
		_, err := privs.Revoke(e.Privs(), pid)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"id": pid, "revoked": true}, nil
}

func (h privHandlers) effective(r *http.Request, p *params) (int, any, error) {
	ck := h.s.grpChecker(r)
	// one's own privileges need view on the object, another identity's need admin
	raw, other := p.query("identity")
	need := h.view()
	if other {
		need = h.admin()
	}
	o, err := h.object(r, p, ck, need)
	if err != nil {
		return 0, nil, err
	}
	target := ck
	var identity *int64
	if other {
		id, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || id < 1 {
			return 0, nil, badRequest("invalid_identity", "identity must be an identity id")
		}
		if _, err := store.TxFrom(r.Context()).Identity(id); errors.Is(err, store.ErrNotFound) {
			return 0, nil, &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such identity"}
		} else if err != nil {
			return 0, nil, err
		}
		// what the identity holds through its own rows and groups, not through the caller's roles
		target = privs.NewChecker(store.TxFrom(r.Context()), h.s.clock(), h.s.cfg.GroupsEngine, privs.Subject{Identity: &id})
		identity = &id
	} else {
		identity = ck.Subject().Identity
	}
	ex, err := target.Explain(o)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"object_type": string(o.Type), "object_id": o.ID, "identity_id": identity,
		"privileges": ex}, nil
}

// ---------------------------------------------------------------- settings and identity link

func (s *Server) getGrpPrivSettings(r *http.Request, _ *params) (int, any, error) {
	set, err := privs.LoadSettings(store.TxFrom(r.Context()))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, set, nil
}

func (s *Server) putGrpPrivSettings(r *http.Request, _ *params) (int, any, error) {
	var in privs.Settings
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out privs.Settings
	err := s.grpWrite(r, func(e model.Env) error {
		var err error
		out, err = privs.SaveSettings(e.Privs(), in)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

// identityLinkWindow is how long a link change waits for its second admin.
const identityLinkWindow = 72 * time.Hour

// linkGrpUserIdentity links a platform user to an identity of the tenant (or
// removes the link with null). The link decides which group privileges the
// user holds, whether sign-in is refused because the identity is inactive,
// and every self check (self-approval, SoD exemption, help-desk own
// identity), so it is a tenant admin's act, needs a fresh sign-in and
// (#357):
//
//   - nobody changes their own user's link (self_link_not_allowed);
//   - a user is linked only to an active identity (identity_not_active);
//   - a user whose identity is not active (terminated, disabled) keeps the
//     link, so their sign-in stays blocked (identity_inactive);
//   - linking a user that has no link applies at once, but changing or
//     removing an existing link needs two admins: the first admin's request
//     answers 202 and waits, the same admin repeating it is refused
//     (four_eyes_required), and a second admin's identical change applies it
//     and revokes the user's sessions and CLI refresh tokens.
func (s *Server) linkGrpUserIdentity(r *http.Request, p *params) (int, any, error) {
	uid, err := uuid.Parse(p.path["id"])
	if err != nil || !idRE.MatchString(p.path["id"]) {
		return 0, nil, grpNotFound("user")
	}
	var in struct {
		IdentityID *int64 `json:"identity_id"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if in.IdentityID != nil && *in.IdentityID < 1 {
		return 0, nil, badRequest("invalid_identity", "identity_id is an identity id, or null to remove the link")
	}
	by := principal(r).User()
	if by.ID == uuid.Nil {
		return 0, nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden", Msg: "a tenant admin's signed-in user changes identity links"}
	}
	status, out := http.StatusOK, map[string]any{"user_id": uid.String(), "identity_id": in.IdentityID}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		u, err := c.PlatformUser(uid)
		if errors.Is(err, store.ErrNotFound) {
			return grpNotFound("user")
		}
		if err != nil {
			return err
		}
		if u.ID == by.ID {
			return &readiness.Error{Status: http.StatusForbidden, Code: "self_link_not_allowed",
				Msg: "you cannot change your own user's identity link; another admin must"}
		}
		if in.IdentityID != nil {
			ident, err := c.Identity(*in.IdentityID)
			if errors.Is(err, store.ErrNotFound) {
				return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such identity"}
			} else if err != nil {
				return err
			}
			if ident.Status != "active" {
				return &readiness.Error{Status: http.StatusConflict, Code: "identity_not_active",
					Msg: "a user is linked only to an active identity; this one is " + ident.Status}
			}
		}
		was := u.IdentityID
		detail := ojson.Object{{Key: "user_id", Value: uid.String()}, {Key: "identity_id", Value: in.IdentityID},
			{Key: "previous_identity_id", Value: was}}
		action := "groups.user.identity_linked"
		if in.IdentityID == nil {
			action = "groups.user.identity_unlinked"
		}
		if was != nil && !sameLink(was, in.IdentityID) {
			// the user's current identity must be active: unlinking or
			// relinking a terminated or disabled person would give them
			// their sign-in back
			cur, err := c.Identity(*was)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if cur == nil || cur.Status != "active" {
				st := "missing"
				if cur != nil {
					st = cur.Status
				}
				return &readiness.Error{Status: http.StatusConflict, Code: "identity_inactive",
					Msg: "the user's identity is " + st + ", so their sign-in is blocked; the link stays until the identity is enabled again"}
			}
			pend, err := c.IdentityLinkRequest(uid)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			matches := pend != nil && now.Before(pend.ExpiresAt) && sameLink(pend.PreviousIdentityID, was) &&
				sameLink(pend.IdentityID, in.IdentityID)
			switch {
			case matches && pend.RequestedByUserID == by.ID:
				return &readiness.Error{Status: http.StatusForbidden, Code: "four_eyes_required",
					Msg: "changing an existing identity link needs a second admin: another tenant admin must make the same change"}
			case !matches:
				req := &store.IdentityLinkRequest{UserID: uid, IdentityID: in.IdentityID, PreviousIdentityID: was,
					RequestedByUserID: by.ID, RequestedBy: by.Display, RequestedAt: now, ExpiresAt: now.Add(identityLinkWindow)}
				if err := c.PutIdentityLinkRequest(req); err != nil {
					return err
				}
				status = http.StatusAccepted
				out = map[string]any{"user_id": uid.String(), "identity_id": in.IdentityID, "status": "pending_second_admin",
					"previous_identity_id": was, "expires_at": req.ExpiresAt}
				_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "groups.user.identity_change_requested", LegacyActor: "groups",
					TargetType: "platform_user", TargetID: uid.String(), Detail: append(detail, ojson.KV{Key: "expires_at", Value: req.ExpiresAt})})
				return err
			}
			// a second admin confirms the pending request
			detail = append(detail, ojson.KV{Key: "requested_by", Value: pend.RequestedBy},
				ojson.KV{Key: "requested_by_user_id", Value: pend.RequestedByUserID.String()})
		}
		if err := c.SetPlatformUserIdentity(uid, in.IdentityID); err != nil {
			return err
		}
		if err := c.DeleteIdentityLinkRequest(uid); err != nil {
			return err
		}
		if was != nil && !sameLink(was, in.IdentityID) {
			n, err := c.RevokeUserSessions(uid, auth.RevokedIdentityLinkChanged, now)
			if err != nil {
				return err
			}
			detail = append(detail, ojson.KV{Key: "sessions_revoked", Value: n})
		}
		_, err = c.RecordAudit(store.AuditRecord{At: now, Action: action, LegacyActor: "groups", TargetType: "platform_user",
			TargetID: uid.String(), Detail: detail})
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return status, out, nil
}

// sameLink reports whether two identity links are the same (nil is no link).
func sameLink(a, b *int64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
