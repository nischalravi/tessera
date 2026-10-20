package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Role memberships in access reviews (issue #214):
//
//	GET  /api/roles/{role_id}/exclusions                       the birthright exclusion list, with its version history
//	POST /api/roles/{role_id}/exclusions/{identity_id}/remove  {reason}: take a person off the list
//	GET  /api/roles/{role_id}/flags                            review decisions that flagged the rule to the owner
//
// People are put on the list by a reviewer revoking a rule membership
// (POST /api/reviews/items/{item_id}/decision with rule_action "exclude");
// removing them needs roles.manage and a fresh sign-in, like any role change.

func (s *Server) registerRoleReviewRoutes() {
	s.handle(http.MethodGet, "/api/roles/{role_id}/exclusions", read, need(auth.PermGraphRead), s.roleExclusions)
	s.handle(http.MethodPost, "/api/roles/{role_id}/exclusions/{identity_id}/remove", write,
		needStepUp(auth.PermRolesManage, auth.StepUpPolicy), s.removeRoleExclusion)
	s.handle(http.MethodGet, "/api/roles/{role_id}/flags", read, need(auth.PermGraphRead), s.roleFlags)
}

// membershipViews returns, for the campaign's role membership items, the
// fields a membership adds to an item row (grant items add none).
func membershipViews(c *store.TenantTx, campaignID int64) (map[int64]ojson.Object, error) {
	irs, err := c.CampaignItemRoles(campaignID)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]ojson.Object, len(irs))
	names := map[string]string{}
	for _, ir := range irs {
		name, ok := names[ir.RoleID]
		if !ok {
			ro, err := c.BusinessRole(ir.RoleID)
			if err != nil {
				return nil, err
			}
			name = ro.Name
			names[ir.RoleID] = name
		}
		out[ir.ItemID] = ojson.Object{{Key: "kind", Value: "membership"},
			{Key: "role", Value: ojson.Object{{Key: "id", Value: ir.RoleID}, {Key: "name", Value: name}}},
			{Key: "member_source", Value: ir.MemberSource}, {Key: "resolution", Value: ir.Resolution}}
	}
	return out, nil
}

// roleScopeForAudit is the role scope a saved schedule has, for its audit event.
func roleScopeForAudit(tx *store.TenantTx, templateID string) []string {
	ids, err := tx.ReviewTemplateRoles(templateID)
	if err != nil {
		return []string{}
	}
	return ids
}

type exclusionView struct {
	Person         personRef  `json:"person"`
	Reason         string     `json:"reason"`
	Version        int        `json:"version"`
	ExcludedBy     string     `json:"excluded_by"`
	ExcludedAt     time.Time  `json:"excluded_at"`
	ReviewItemID   *int64     `json:"review_item_id"`
	Active         bool       `json:"active"`
	RemovedAt      *time.Time `json:"removed_at"`
	RemovedVersion *int       `json:"removed_version"`
	RemovedReason  *string    `json:"removed_reason"`
}

type exclusionList struct {
	Version int             `json:"version"` // the list's current version
	Items   []exclusionView `json:"items"`   // newest first, removed ones included
}

func (s *Server) roleExclusions(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	xs, err := tx.RoleExclusions(ro.ID)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := exclusionList{Items: make([]exclusionView, 0, len(xs))}
	for i := len(xs) - 1; i >= 0; i-- {
		x := xs[i]
		person, err := v.person(x.IdentityID)
		if err != nil {
			return nil, err
		}
		out.Version = max(out.Version, x.Version)
		if x.RemovedVersion != nil {
			out.Version = max(out.Version, *x.RemovedVersion)
		}
		out.Items = append(out.Items, exclusionView{person, x.Reason, x.Version, x.ExcludedActor, x.ExcludedAt, x.ReviewItemID,
			x.Active(), x.RemovedAt, x.RemovedVersion, x.RemovedReason})
	}
	return out, nil
}

func (s *Server) removeRoleExclusion(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	by, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	var b roleChangeBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	ver, err := roles.Unexclude(store.TxFrom(r.Context()), ro.ID, p.pathInt("identity_id"), b.Reason, by, s.clock().UTC())
	if err != nil {
		return nil, roleErr(err)
	}
	return ojson.Object{{Key: "role_id", Value: ro.ID}, {Key: "version", Value: ver}}, nil
}

type flagView struct {
	ItemID     int64      `json:"item_id"`
	CampaignID int64      `json:"campaign_id"`
	Person     personRef  `json:"person"`
	Comment    *string    `json:"comment"`
	DecidedAt  *time.Time `json:"decided_at"`
}

func (s *Server) roleFlags(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ro, err := s.loadRole(r, p)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	irs, err := tx.FlaggedRoleItems(ro.ID)
	if err != nil {
		return nil, err
	}
	v := newViewer(tx)
	out := make([]flagView, 0, len(irs))
	for _, ir := range irs {
		it, err := tx.Item(ir.ItemID)
		if err != nil {
			return nil, err
		}
		person, err := v.person(it.IdentityID)
		if err != nil {
			return nil, err
		}
		out = append(out, flagView{it.ID, it.CampaignID, person, it.Comment, it.DecidedAt})
	}
	return out, nil
}
