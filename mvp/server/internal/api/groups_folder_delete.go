package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Deleting a folder (DELETE /api/groups/folders/{id}).
//
// Without recursive=true the folder must be empty (409 folder_not_empty, with
// the counts and how many of the groups are deleted). With recursive=true the
// whole tree goes in one transaction: groups are soft-deleted then purged,
// attribute definitions removed, folders deepest first. It needs stem_admin on
// every folder of the tree and a fresh STEP_UP_POLICY, and is refused with
// 409 recursive_delete_blocked (and the list of blockers) unless every item is
// UI-managed, no group is policy-managed or used by a group outside the tree
// and nothing outside names an attribute definition of it. A tree of more than
// model.RecursiveApprovalGroups groups, or one where any group has members,
// does not apply at once: the answer is 202 with an admin change request
// (groups.folder.delete_recursive) that a second admin approves (GRP-6311).

// deletePlanView is the answer of the plan route.
type deletePlanView struct {
	FolderID          string          `json:"folder_id"`
	Name              string          `json:"name"`
	Folders           int             `json:"folders"`
	Groups            int             `json:"groups"`
	ActiveGroups      int             `json:"active_groups"`
	DeletedGroups     int             `json:"deleted_groups"`
	AttrDefs          int             `json:"attr_defs"`
	GroupsWithMembers int             `json:"groups_with_members"`
	Memberships       int             `json:"memberships"`
	NeedsApproval     bool            `json:"needs_approval"`
	ApprovalReason    string          `json:"approval_reason,omitempty"`
	Blockers          []model.Blocker `json:"blockers"`
	BlockerCount      int             `json:"blocker_count"`
}

func viewDeletePlan(p *model.DeletePlan) deletePlanView {
	b := p.Blockers
	if b == nil {
		b = []model.Blocker{}
	}
	return deletePlanView{FolderID: string(p.Folder.ID), Name: p.Folder.Name, Folders: p.Folders, Groups: p.TotalGroups(),
		ActiveGroups: p.ActiveGroups, DeletedGroups: p.DeletedGroups, AttrDefs: p.AttrDefs, GroupsWithMembers: p.GroupsWithMembers,
		Memberships: p.Memberships, NeedsApproval: p.NeedsApproval, ApprovalReason: p.ApprovalReason, Blockers: b, BlockerCount: len(b)}
}

// planFolderDelete plans the delete in c and adds a blocker for every folder of
// the tree the caller does not hold stem_admin on.
func (s *Server) planFolderDelete(r *http.Request, c *store.TenantTx, id string) (*model.DeletePlan, error) {
	ck := privs.NewChecker(c, s.clock(), s.cfg.GroupsEngine, s.grpSubject(r))
	f, err := c.GrpFolder(store.FolderID(id))
	if err != nil {
		return nil, grpErr(wrapNotFound(err, "folder"))
	}
	if err := grpErr(ck.Require(privs.FolderObject(f.ID), privs.StemAdmin)); err != nil {
		return nil, err
	}
	p, err := s.grpEnv(r, c, s.clock()).PlanFolderDelete(f.ID)
	if err != nil {
		return nil, grpErr(err)
	}
	for _, sf := range p.Subtree {
		ok, err := ck.Has(privs.FolderObject(sf.ID), privs.StemAdmin)
		if err != nil {
			return nil, grpErr(err)
		}
		if !ok {
			p.Block("folder", string(sf.ID), sf.Name, "no_privilege", "you do not hold stem_admin on folder %q", sf.Name)
		}
	}
	return p, nil
}

func wrapNotFound(err error, what string) error {
	if err == store.ErrNotFound {
		return grpNotFound(what)
	}
	return err
}

func (s *Server) getGrpFolderDeletePlan(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	plan, err := s.planFolderDelete(r, store.TxFrom(r.Context()), id)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, viewDeletePlan(plan), nil
}

func (s *Server) deleteGrpFolder(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "folder")
	if err != nil {
		return 0, nil, err
	}
	recursive := false
	switch v, _ := p.query("recursive"); v {
	case "", "false":
	case "true":
		recursive = true
	default:
		return 0, nil, badRequest("invalid_recursive", "recursive is true or false")
	}
	ctx := r.Context()
	col := &deleteguard.Collector{}
	if !recursive {
		err := p.scope.Write(ctx, func(c *store.TenantTx) error {
			ck := privs.NewChecker(c, s.clock(), s.cfg.GroupsEngine, s.grpSubject(r))
			f, err := c.GrpFolder(store.FolderID(id))
			if err != nil {
				return grpErr(wrapNotFound(err, "folder"))
			}
			if err := grpErr(ck.Require(privs.FolderObject(f.ID), privs.StemAdmin)); err != nil {
				return err
			}
			e := s.grpEnv(r, c, s.clock())
			e.Held = col
			return grpErr(e.DeleteFolder(f.ID))
		})
		if err != nil {
			return 0, nil, err
		}
		if res := col.Result(); res != nil {
			return http.StatusAccepted, heldBody(res, map[string]any{"id": id, "deleted": false}), nil
		}
		return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
	}
	reason, err := deleteReason(r, true)
	if err != nil {
		return 0, nil, err
	}
	// destructive: a fresh phishing-resistant sign-in, like the other policy-level group changes
	if d := auth.Check(principal(r), auth.PermGroupsWrite, &auth.StepUpPolicy, s.clock()); d != nil {
		return 0, nil, denial{d}
	}
	var plan *model.DeletePlan
	err = p.scope.Read(ctx, func(c *store.TenantTx) error {
		var err error
		plan, err = s.planFolderDelete(r, c, id)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	if len(plan.Blockers) > 0 {
		return 0, nil, grpErr(plan.BlockedError())
	}
	if plan.NeedsApproval {
		ch, err := s.submitFolderDelete(ctx, r, plan, reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, map[string]any{"status": "pending_approval", "change_request_id": ch.ID.String(), "type": ch.Type,
			"folder_id": id, "expires_at": store.RT(ch.ExpiresAt), "reason": plan.ApprovalReason,
			"detail": "a second admin must approve this change (POST /api/admin/change-requests/{id}/approve) before the folder is deleted"}, nil
	}
	var res *model.DeleteResult
	err = p.scope.Write(ctx, func(c *store.TenantTx) error {
		// the plan is made again in the write transaction: nothing changed in between, or it is refused
		again, err := s.planFolderDelete(r, c, id)
		if err != nil {
			return err
		}
		if len(again.Blockers) > 0 {
			return grpErr(again.BlockedError())
		}
		if again.NeedsApproval {
			return grpErr(&model.Error{Kind: model.Conflict, Code: "folder_changed", Msg: "the folder changed while it was being deleted; try again"})
		}
		env := s.grpEnv(r, c, s.clock())
		env.Reason = reason
		env.Held = col
		_, res, err = env.DeleteFolderRecursive(store.FolderID(id))
		return grpErr(err)
	})
	if err != nil {
		return 0, nil, err
	}
	if held := col.Result(); held != nil {
		return http.StatusAccepted, heldBody(held, map[string]any{"id": id, "deleted": false, "recursive": true, "folders": res.Folders,
			"groups": res.Groups, "attr_defs": res.AttrDefs, "memberships": res.Memberships}), nil
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true, "recursive": true, "folders": res.Folders, "groups": res.Groups,
		"attr_defs": res.AttrDefs, "memberships": res.Memberships}, nil
}

// submitFolderDelete files the groups.folder.delete_recursive request.
func (s *Server) submitFolderDelete(ctx context.Context, r *http.Request, p *model.DeletePlan, reason string) (*store.AdminChange, error) {
	var by string
	if err := s.store.ReadTenant(ctx, principal(r).TenantID, func(c *store.TenantTx) error { by = s.actorLabel(r, c); return nil }); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{"folder_id": string(p.Folder.ID), "name": p.Folder.Name, "folders": p.Folders,
		"groups": p.TotalGroups(), "memberships": p.Memberships, "reason": reason, "by_display": by})
	if err != nil {
		return nil, err
	}
	return s.admin.SubmitChecked(ctx, principal(r), admin.SubmitInput{Type: admin.TypeGroupFolderDelete, Payload: payload})
}
