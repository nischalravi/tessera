package api

import (
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Guest access (guest accounts design §8.2 and §9.3, issue #75):
//
//	GET  /api/identities/{identity_id}/access-bundle   a person's bundle items with their state (guests.read)
//	GET  /api/refgroups                                the system-managed reference groups with their members (graph.read)
//	POST /api/refgroups/reconcile                      recompute them now (lifecycle.manage)
//
// A sponsorship's bundle with the state of each item is also in the
// sponsorship view (bundle[].state): pending (waiting for the guest to claim or
// for the target to confirm), granted, failed, removing, removed. Reference
// groups are Tessera-managed: their membership is derived from affiliations,
// status, assurance and sponsor eligibility and rewritten on every change and
// by the sweeper.

func (s *Server) registerGuestAccessRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/identities/{identity_id}/access-bundle", read, need(auth.PermGuestsRead), s.identityBundle)
	s.handle(G, "/api/refgroups", read, need(auth.PermGraphRead), s.listRefGroups)
	s.handle(P, "/api/refgroups/reconcile", write, need(auth.PermLifecycleManage), s.reconcileRefGroups)
}

// eligible is the sponsor policy's answer for ref:sponsor:eligible.
func (s *Server) eligible() access.Eligibility {
	if s.guests == nil {
		return nil
	}
	return s.guests.CanSponsor
}

// refreshRefGroups recomputes one person's reference groups after a change
// that concerns them (an affiliation added or ended).
func (s *Server) refreshRefGroups(tx *store.TenantTx, now time.Time, actor string, identityID int64) error {
	_, err := access.Recompute(tx, now, actor, identityID, s.eligible())
	return err
}

// bundleItemView is a sponsorship's bundle item with its state.
type bundleItemView struct {
	sponsorship.BundleItem
	State     string     `json:"state"`
	Detail    string     `json:"detail,omitempty"`
	OpID      *string    `json:"op_id"`
	OpStatus  *string    `json:"op_status"`
	ExpiresAt *time.Time `json:"expires_at"`
	GrantedAt *time.Time `json:"granted_at"`
}

// bundleViews is a sponsorship's chosen bundle with the state of each item.
func bundleViews(tx *store.TenantTx, ss *store.Sponsorship) ([]bundleItemView, error) {
	chosen := sponsorship.ParseBundle(ss.AccessBundle)
	rows, err := tx.BundleItems(store.BundleItemFilter{Sponsorship: ss.ID})
	if err != nil {
		return nil, err
	}
	views, err := access.Views(tx, rows)
	if err != nil {
		return nil, err
	}
	byGroup := map[int64]access.ItemView{}
	for _, v := range views {
		byGroup[v.GroupID] = v
	}
	out := make([]bundleItemView, 0, len(chosen))
	for _, c := range chosen {
		bv := bundleItemView{BundleItem: c}
		if v, ok := byGroup[c.GroupID]; ok {
			bv.State, bv.Detail, bv.OpID, bv.OpStatus = v.State, v.Detail, v.OpID, v.OpStatus
			e, g := v.ExpiresAt, v.GrantedAt
			bv.ExpiresAt, bv.GrantedAt = &e, g
		} else {
			switch ss.Status {
			case store.SponsorPendingApproval, store.SponsorRequested:
				bv.State, bv.Detail = access.StatePending, "waiting for the sponsorship to be approved"
			case store.SponsorRejected, store.SponsorRevoked, store.SponsorEnded:
				bv.State = access.StateRemoved
			default:
				bv.State, bv.Detail = access.StatePending, "waiting to be recorded"
			}
		}
		out = append(out, bv)
	}
	return out, nil
}

type identityBundleView struct {
	IdentityID int64             `json:"identity_id"`
	IAL        int               `json:"ial"`
	AAL        int               `json:"aal"`
	Items      []access.ItemView `json:"items"`
}

func (s *Server) identityBundle(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if _, err := person(tx, id); err != nil {
		return nil, err
	}
	rows, err := tx.BundleItems(store.BundleItemFilter{Guest: id})
	if err != nil {
		return nil, err
	}
	views, err := access.Views(tx, rows)
	if err != nil {
		return nil, err
	}
	out := identityBundleView{IdentityID: id, Items: views}
	if a, err := tx.IdentityAssurance(id); err == nil {
		out.IAL, out.AAL = a.IAL, a.AAL
	}
	return out, nil
}

type refGroupView struct {
	ID          int64       `json:"id"`
	Key         string      `json:"key"`
	System      string      `json:"system"`
	Description string      `json:"description"`
	Managed     bool        `json:"managed"`
	Members     []personRef `json:"members"`
	Count       int         `json:"count"`
}

type refGroupsView struct {
	Groups []refGroupView `json:"groups"`
}

func (s *Server) listRefGroups(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	v := newViewer(tx)
	edges, err := tx.EdgesBySource(store.EdgeSourceRefGroup)
	if err != nil {
		return nil, err
	}
	accts, err := tx.AccountsBySystemUsername(&refSystem)
	if err != nil {
		return nil, err
	}
	owner := map[int64]int64{}
	for _, a := range accts {
		if a.IdentityID != nil {
			owner[a.ID] = *a.IdentityID
		}
	}
	members := map[int64][]int64{}
	for _, e := range edges {
		if _, aid, err := graph.ParseKey(e.Src); err == nil {
			if _, gid, err := graph.ParseKey(e.Dst); err == nil && owner[aid] != 0 {
				members[gid] = append(members[gid], owner[aid])
			}
		}
	}
	out := refGroupsView{Groups: []refGroupView{}}
	for _, d := range access.RefGroups {
		g, err := tx.GroupByXID(access.RefSystem, d.Key)
		if err != nil {
			continue // not created yet: the first reconcile creates them
		}
		rv := refGroupView{ID: g.ID, Key: d.Key, System: g.System, Description: d.Description, Managed: true, Members: []personRef{}}
		for _, pid := range members[g.ID] {
			pr, err := v.person(pid)
			if err != nil {
				return nil, err
			}
			rv.Members = append(rv.Members, pr)
		}
		rv.Count = len(rv.Members)
		out.Groups = append(out.Groups, rv)
	}
	return out, nil
}

func (s *Server) reconcileRefGroups(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	a, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	res, err := access.Recompute(store.TxFrom(r.Context()), s.clock().UTC(), a.Display, 0, s.eligible())
	if err != nil {
		return nil, err
	}
	return map[string]any{"added": res.Added, "removed": res.Removed, "groups_created": res.GroupsCreated}, nil
}

var refSystem = access.RefSystem
