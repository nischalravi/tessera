package loaders

import (
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Resolver turns a SubjectRef into an identity (design §9.1, subject
// resolution): an exact match on an identifier of the given source, following
// merges to the surviving identity. There is no fuzzy matching and no guessing:
// a reference that matches nothing is unresolved.
//
//	"" or "identity"   the identity's external id
//	"email"            the identity's email (case-insensitive; two identities with it match nothing)
//	"tessera_id"       the identity's own id (what loaders fed by Tessera's data use)
//	anything else      an account of that system with that external id that belongs to an identity,
//	                   else an identity of that source (identities.source) with that external id
type Resolver struct {
	byXID     map[string]int64
	byEmail   map[string]int64
	dupEmail  map[string]bool
	byID      map[int64]bool
	bySource  map[string]map[string]int64
	byAccount map[string]map[string]int64
	survivor  map[int64]int64
}

// NewResolver loads the tenant's identities and accounts.
func NewResolver(tx *store.TenantTx) (*Resolver, error) {
	r := &Resolver{byXID: map[string]int64{}, byEmail: map[string]int64{}, dupEmail: map[string]bool{}, byID: map[int64]bool{},
		bySource: map[string]map[string]int64{}, byAccount: map[string]map[string]int64{}}
	idents, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	for _, i := range idents {
		r.byID[i.ID] = true
		r.byXID[i.ExternalID] = i.ID
		if i.Email != nil && *i.Email != "" {
			e := strings.ToLower(*i.Email)
			if _, dup := r.byEmail[e]; dup {
				r.dupEmail[e] = true
			}
			r.byEmail[e] = i.ID
		}
		if i.Source != nil && *i.Source != "" {
			s := strings.ToLower(*i.Source)
			if r.bySource[s] == nil {
				r.bySource[s] = map[string]int64{}
			}
			r.bySource[s][i.ExternalID] = i.ID
		}
	}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.IdentityID == nil {
			continue
		}
		s := strings.ToLower(a.System)
		if r.byAccount[s] == nil {
			r.byAccount[s] = map[string]int64{}
		}
		r.byAccount[s][a.ExternalID] = *a.IdentityID
	}
	if r.survivor, err = tx.MergeSurvivors(); err != nil {
		return nil, err
	}
	return r, nil
}

// Resolve returns the identity a reference names.
func (r *Resolver) Resolve(ref SubjectRef) (int64, bool) {
	id, ok := r.lookup(ref)
	if !ok {
		return 0, false
	}
	if s, merged := r.survivor[id]; merged {
		id = s
	}
	return id, r.byID[id]
}

func (r *Resolver) lookup(ref SubjectRef) (int64, bool) {
	ident := strings.TrimSpace(ref.Identifier)
	if ident == "" {
		return 0, false
	}
	src := strings.ToLower(strings.TrimSpace(ref.Source))
	switch src {
	case "", "identity":
		id, ok := r.byXID[ident]
		return id, ok
	case "email":
		e := strings.ToLower(ident)
		if r.dupEmail[e] {
			return 0, false
		}
		id, ok := r.byEmail[e]
		return id, ok
	case "tessera_id":
		n, err := strconv.ParseInt(ident, 10, 64)
		if err != nil || !r.byID[n] {
			return 0, false
		}
		return n, true
	}
	if id, ok := r.byAccount[src][ident]; ok {
		return id, true
	}
	id, ok := r.bySource[src][ident]
	return id, ok
}
