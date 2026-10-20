package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ownership"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Ownership (issue #167):
//
//	GET  /api/ownership?kind=&unowned=     objects of a kind with their owners, and counts per kind
//	PUT  /api/ownership/{kind}/{object_key} set one object's owners and purpose
//	POST /api/ownership/bulk               give several objects the same owners

func (s *Server) registerOwnershipRoutes() {
	manage := need(auth.PermOwnershipManage)
	s.handle(http.MethodGet, "/api/ownership", read, need(auth.PermGraphRead), s.listOwnership)
	s.handle(http.MethodPut, "/api/ownership/{kind}/{object_key}", write, manage, s.putOwnership)
	s.handle(http.MethodPost, "/api/ownership/bulk", write, manage, s.bulkOwnership)
}

type ownerBody struct {
	PrimaryOwnerID *int64 `json:"primary_owner_id"`
	BackupOwnerID  *int64 `json:"backup_owner_id"`
	OwnerGroupID   *int64 `json:"owner_group_id"`
	Purpose        string `json:"purpose"`
}

func (b ownerBody) spec() ownership.Spec {
	return ownership.Spec{PrimaryID: b.PrimaryOwnerID, BackupID: b.BackupOwnerID, GroupID: b.OwnerGroupID, Purpose: b.Purpose}
}

type ownedView struct {
	Kind       string    `json:"kind"`
	Key        string    `json:"key"`
	Label      string    `json:"label"`
	Primary    *namedRef `json:"primary_owner"`
	Backup     *namedRef `json:"backup_owner"`
	OwnerGroup *namedRef `json:"owner_group"`
	Purpose    string    `json:"purpose"`
	// Source is "tessera" when set here, "connector" when only the
	// connector names an owner, and null when there is none.
	Source    *string    `json:"source"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type ownershipCounts struct {
	Total   int `json:"total"`
	Unowned int `json:"unowned"`
}

type ownershipList struct {
	Kind   string                     `json:"kind"`
	Counts map[string]ownershipCounts `json:"counts"`
	Items  []ownedView                `json:"items"`
}

func ownershipErr(err error) error {
	var oe *ownership.Error
	if errors.As(err, &oe) {
		return &readiness.Error{Status: oe.Status, Code: oe.Code, Msg: oe.Msg}
	}
	return err
}

type briefs struct {
	tx    *store.TenantTx
	cache map[int64]*namedRef
}

func (b *briefs) identity(id *int64) (*namedRef, error) {
	if id == nil {
		return nil, nil
	}
	if v, ok := b.cache[*id]; ok {
		return v, nil
	}
	i, err := b.tx.Identity(*id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	v := &namedRef{i.ID, i.Name}
	b.cache[*id] = v
	return v, nil
}

func (b *briefs) group(id *int64) (*namedRef, error) {
	if id == nil {
		return nil, nil
	}
	g, err := b.tx.Group(*id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &namedRef{g.ID, g.System + ":" + g.Name}, nil
}

func (b *briefs) view(e ownership.Entry) (ownedView, error) {
	v := ownedView{Kind: e.Kind, Key: e.Key, Label: e.Label}
	var err error
	if v.Primary, err = b.identity(e.PrimaryID); err != nil {
		return v, err
	}
	if o := e.Ownership; o != nil {
		src := "tessera"
		v.Source, v.Purpose, v.UpdatedAt = &src, o.Purpose, &o.UpdatedAt
		if v.Backup, err = b.identity(o.BackupID); err != nil {
			return v, err
		}
		if v.OwnerGroup, err = b.group(o.GroupID); err != nil {
			return v, err
		}
	} else if e.PrimaryID != nil {
		src := "connector"
		v.Source = &src
	}
	return v, nil
}

func (s *Server) listOwnership(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	kind := store.OwnedGroup
	if k := p.queryOptLiteral("kind", ownership.Kinds); k != nil {
		kind = *k
	}
	unowned := p.queryOptBool("unowned")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	out := ownershipList{Kind: kind, Counts: map[string]ownershipCounts{}, Items: []ownedView{}}
	b := &briefs{tx, map[int64]*namedRef{}}
	for _, k := range ownership.Kinds {
		es, err := ownership.List(tx, k)
		if err != nil {
			return nil, err
		}
		c := ownershipCounts{Total: len(es)}
		for _, e := range es {
			if e.PrimaryID == nil {
				c.Unowned++
			}
			if k != kind || (unowned != nil && *unowned != (e.PrimaryID == nil)) {
				continue
			}
			v, err := b.view(e)
			if err != nil {
				return nil, err
			}
			out.Items = append(out.Items, v)
		}
		out.Counts[k] = c
	}
	return out, nil
}

func actorUser(r *http.Request) *string {
	if pr := principal(r); pr != nil && pr.UserID != nil {
		id := pr.UserID.String()
		return &id
	}
	return nil
}

func (s *Server) putOwnership(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	kind := p.pathLiteral("kind", ownership.Kinds)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b ownerBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	ref := ownership.Ref{Kind: kind, Key: p.path["object_key"]}
	if _, err := ownership.Set(tx, ref, b.spec(), principal(r).Display, actorUser(r), now); err != nil {
		return nil, ownershipErr(err)
	}
	o, err := tx.Ownership(ref.Kind, ref.Key)
	if err != nil {
		return nil, err
	}
	label, err := ownership.Label(tx, ref)
	if err != nil {
		return nil, ownershipErr(err)
	}
	return (&briefs{tx, map[int64]*namedRef{}}).view(ownership.Entry{Ref: ref, Label: label, Ownership: o, PrimaryID: o.PrimaryID})
}

type bulkOwnerBody struct {
	Objects        []ownership.Ref `json:"objects"`
	PrimaryOwnerID *int64          `json:"primary_owner_id"`
	BackupOwnerID  *int64          `json:"backup_owner_id"`
	OwnerGroupID   *int64          `json:"owner_group_id"`
}

func (s *Server) bulkOwnership(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b bulkOwnerBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	spec := ownership.Spec{PrimaryID: b.PrimaryOwnerID, BackupID: b.BackupOwnerID, GroupID: b.OwnerGroupID}
	n, err := ownership.SetMany(tx, b.Objects, spec, true, principal(r).Display, actorUser(r), now)
	if err != nil {
		return nil, ownershipErr(err)
	}
	return map[string]int{"updated": n}, nil
}

// namedRef is an object's id and display name.
type namedRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
