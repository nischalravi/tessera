package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A person's affiliations and identifiers (guest accounts design, issue #64):
//
//	GET  /api/identities/{identity_id}/affiliations   the person's lifecycle state and affiliations
//	GET  /api/identities/{identity_id}/identifiers    identifiers and how each was verified
//	GET  /api/affiliation-summary                       every person's lifecycle state and effective affiliation types (the People list filters)
//	GET  /api/identities/{identity_id}/guest-profile  source records (identifiers masked, attribute names only) and terms acceptances (guests.read)
//	POST /api/identities/{identity_id}/affiliations   {type, org_unit, population, starts_at, ends_at, reason}
//	POST /api/affiliations/{affiliation_id}/end       {reason}
//
// Reads need graph.read. Adding or ending an affiliation changes what a person
// is entitled to once the groups engine reads it, so it needs
// identities.affiliate and a fresh phishing-resistant sign-in, and a signed-in
// user: the actor is recorded. Identifier hashes are never returned.

func (s *Server) registerAffiliationRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	affiliate := needStepUp(auth.PermIdentitiesAffiliate, auth.StepUpPolicy)
	s.handle(G, "/api/identities/{identity_id}/affiliations", read, need(auth.PermGraphRead), s.listAffiliations)
	s.handle(G, "/api/identities/{identity_id}/identifiers", read, need(auth.PermGraphRead), s.listIdentifiers)
	s.handle(G, "/api/affiliation-summary", read, need(auth.PermGraphRead), s.affiliationSummary)
	s.handle(G, "/api/identities/{identity_id}/guest-profile", read, need(auth.PermGuestsRead), s.guestProfile)
	s.handle(P, "/api/identities/{identity_id}/affiliations", write, affiliate, s.addAffiliation)
	s.handle(P, "/api/affiliations/{affiliation_id}/end", write, affiliate, s.endAffiliation)
}

type affiliationView struct {
	ID         string     `json:"id"`
	IdentityID int64      `json:"identity_id"`
	Type       string     `json:"type"`
	Source     string     `json:"source"`
	SourceRef  *string    `json:"source_ref"`
	OrgUnit    *string    `json:"org_unit"`
	Population *string    `json:"population"`
	StartsAt   time.Time  `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at"`
	// Status is the stored status; Effective is what it is now (an active
	// affiliation past its end reads as ended until the lifecycle sweep runs).
	Status    string     `json:"status"`
	Effective string     `json:"effective_status"`
	CreatedAt time.Time  `json:"created_at"`
	EndedAt   *time.Time `json:"ended_at"`
	EndReason *string    `json:"end_reason"`
}

func viewAffiliation(a *store.Affiliation, now time.Time) affiliationView {
	v := affiliationView{ID: a.ID, IdentityID: a.IdentityID, Type: a.Type, Source: a.Source, SourceRef: a.SourceRef,
		OrgUnit: a.OrgUnit, Population: a.Population, StartsAt: a.StartsAt, EndsAt: a.EndsAt, Status: a.Status,
		Effective: affiliations.Effective(a, now), CreatedAt: a.CreatedAt, EndReason: a.EndReason}
	if a.Status == store.AffEnded || a.Status == store.AffRevoked {
		v.EndedAt = a.EndsAt
	}
	return v
}

type personAffiliationsView struct {
	IdentityID     int64             `json:"identity_id"`
	LifecycleState string            `json:"lifecycle_state"`
	Affiliations   []affiliationView `json:"affiliations"`
}

type identifierView struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Issuer     string     `json:"issuer"`
	Value      *string    `json:"value"` // nil for hashed-only types
	VerifiedAt *time.Time `json:"verified_at"`
	VerifiedBy *string    `json:"verified_by"`
	Status     string     `json:"status"`
	// SourceSystem names the system of record that supplied it, when there is one.
	SourceSystem *string `json:"source_system"`
}

// affErr maps a refused change to the readiness error body
// ({"error": code, "detail": msg}); returning it rolls the transaction back.
func affErr(err error) error {
	var ae *affiliations.Error
	if errors.As(err, &ae) {
		return &readiness.Error{Status: ae.Status, Code: ae.Code, Msg: ae.Msg}
	}
	return err
}

// person loads the identity or answers 404, like every cross-tenant id.
func person(c *store.TenantTx, id int64) (*store.Identity, error) {
	i, err := getOrNil(c.Identity(id))
	if err != nil {
		return nil, err
	}
	if i == nil {
		return nil, errStatus(http.StatusNotFound, "identity not found")
	}
	return i, nil
}

func (s *Server) listAffiliations(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	i, err := person(c, id)
	if err != nil {
		return nil, err
	}
	affs, err := c.AffiliationsFor(id)
	if err != nil {
		return nil, err
	}
	out := personAffiliationsView{IdentityID: id, Affiliations: make([]affiliationView, 0, len(affs)),
		LifecycleState: string(affiliations.Derive(i.Status, affs, now, affiliations.DefaultNotice))}
	for _, a := range affs {
		out.Affiliations = append(out.Affiliations, viewAffiliation(a, now))
	}
	return out, nil
}

func (s *Server) listIdentifiers(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := person(c, id); err != nil {
		return nil, err
	}
	xs, err := c.IdentifiersFor(id)
	if err != nil {
		return nil, err
	}
	srcs, err := c.SourceRecordsFor(id)
	if err != nil {
		return nil, err
	}
	sor := map[string]string{}
	for _, sr := range srcs {
		sor[sr.ID] = sr.SOR
	}
	out := make([]identifierView, 0, len(xs))
	for _, x := range xs {
		v := identifierView{ID: x.ID, Type: x.Type, Issuer: x.Issuer, Value: x.ValueNorm, VerifiedAt: x.VerifiedAt,
			VerifiedBy: x.VerifiedBy, Status: x.Status}
		if x.SourceRecordID != nil {
			if name, ok := sor[*x.SourceRecordID]; ok {
				v.SourceSystem = &name
			}
		}
		out = append(out, v)
	}
	return out, nil
}

type affiliationSummaryRow struct {
	IdentityID     int64    `json:"identity_id"`
	LifecycleState string   `json:"lifecycle_state"`
	Types          []string `json:"types"` // effective-active or pending affiliation types, sorted
}

// affiliationSummary is one read for the People list's affiliation and lifecycle filters, instead of
// one request per person. It carries no identifiers and nothing beyond what the per-person route returns.
func (s *Server) affiliationSummary(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	ids, err := c.Identities()
	if err != nil {
		return nil, err
	}
	all, err := c.Affiliations()
	if err != nil {
		return nil, err
	}
	by := map[int64][]*store.Affiliation{}
	for _, a := range all {
		by[a.IdentityID] = append(by[a.IdentityID], a)
	}
	out := make([]affiliationSummaryRow, 0, len(ids))
	for _, i := range ids {
		affs := by[i.ID]
		row := affiliationSummaryRow{IdentityID: i.ID, Types: []string{},
			LifecycleState: string(affiliations.Derive(i.Status, affs, now, affiliations.DefaultNotice))}
		seen := map[string]bool{}
		for _, a := range affs {
			if e := affiliations.Effective(a, now); (e == store.AffActive || e == store.AffPending) && !seen[a.Type] {
				seen[a.Type] = true
				row.Types = append(row.Types, a.Type)
			}
		}
		sort.Strings(row.Types)
		out = append(out, row)
	}
	return struct {
		People []affiliationSummaryRow `json:"people"`
	}{out}, nil
}

type sourceRecordView struct {
	ID         string    `json:"id"`
	System     string    `json:"system"`
	SystemID   string    `json:"system_id"` // masked
	Status     string    `json:"status"`
	ReceivedAt time.Time `json:"received_at"`
	// Attributes lists the names the record carries, never their values.
	Attributes []string `json:"attributes"`
}

type termsAcceptanceView struct {
	Key        string    `json:"key"`
	Version    int       `json:"version"`
	Context    string    `json:"context"`
	AcceptedAt time.Time `json:"accepted_at"`
}

type guestProfileView struct {
	IdentityID      int64                 `json:"identity_id"`
	SourceRecords   []sourceRecordView    `json:"source_records"`
	TermsAcceptance []termsAcceptanceView `json:"terms_acceptances"`
}

// guestProfile is the person page's "source records" and "terms accepted"
// sections. It returns no attribute values, no hashes and no session data.
func (s *Server) guestProfile(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if _, err := person(c, id); err != nil {
		return nil, err
	}
	srcs, err := c.SourceRecordsFor(id)
	if err != nil {
		return nil, err
	}
	acc, err := c.TermsAcceptancesFor(id)
	if err != nil {
		return nil, err
	}
	out := guestProfileView{IdentityID: id, SourceRecords: make([]sourceRecordView, 0, len(srcs)), TermsAcceptance: make([]termsAcceptanceView, 0, len(acc))}
	for _, sr := range srcs {
		names := []string{}
		var attrs map[string]json.RawMessage
		if json.Unmarshal([]byte(sr.Attributes), &attrs) == nil {
			for k := range attrs {
				names = append(names, k)
			}
			sort.Strings(names)
		}
		out.SourceRecords = append(out.SourceRecords, sourceRecordView{ID: sr.ID, System: sr.SOR, SystemID: match.MaskID(sr.SORID),
			Status: sr.Status, ReceivedAt: sr.ReceivedAt, Attributes: names})
	}
	for _, a := range acc {
		out.TermsAcceptance = append(out.TermsAcceptance, termsAcceptanceView{Key: a.Key, Version: a.Version, Context: a.Context, AcceptedAt: a.AcceptedAt})
	}
	return out, nil
}

type addAffiliationBody struct {
	Type       string     `json:"type"`
	OrgUnit    string     `json:"org_unit"`
	Population string     `json:"population"`
	StartsAt   *time.Time `json:"starts_at"`
	EndsAt     *time.Time `json:"ends_at"`
	Reason     string     `json:"reason"`
}

func (s *Server) addAffiliation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := decider(r)
	if err != nil {
		return nil, err
	}
	var b addAffiliationBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	in := affiliations.AddInput{IdentityID: id, Type: b.Type, OrgUnit: b.OrgUnit, Population: b.Population,
		EndsAt: b.EndsAt, Reason: b.Reason, By: actor}
	if b.StartsAt != nil {
		in.StartsAt = *b.StartsAt
	}
	a, err := affiliations.Add(c, in, now)
	if err != nil {
		return nil, affErr(err)
	}
	if err := c.Audit(now, principal(r).Display, "identity.affiliation.add", ojson.Object{
		{Key: "affiliation_id", Value: a.ID}, {Key: "identity_id", Value: a.IdentityID}, {Key: "type", Value: a.Type},
		{Key: "source", Value: a.Source}, {Key: "population", Value: a.Population},
		{Key: "starts_at", Value: a.StartsAt}, {Key: "ends_at", Value: a.EndsAt}, {Key: "reason", Value: b.Reason}}); err != nil {
		return nil, err
	}
	if err := s.refreshRefGroups(c, now, principal(r).Display, a.IdentityID); err != nil {
		return nil, err
	}
	return viewAffiliation(a, now), nil
}

func (s *Server) endAffiliation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	actor, err := decider(r)
	if err != nil {
		return nil, err
	}
	var b reasonBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(p.path["affiliation_id"]) // a parameterized lookup: anything unknown is "not found"
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	a, err := affiliations.End(c, id, b.Reason, actor, now)
	if err != nil {
		return nil, affErr(err)
	}
	if err := c.Audit(now, principal(r).Display, "identity.affiliation.end", ojson.Object{
		{Key: "affiliation_id", Value: a.ID}, {Key: "identity_id", Value: a.IdentityID}, {Key: "type", Value: a.Type},
		{Key: "status", Value: a.Status}, {Key: "ended_at", Value: a.EndsAt}, {Key: "reason", Value: b.Reason}}); err != nil {
		return nil, err
	}
	if err := s.refreshRefGroups(c, now, principal(r).Display, a.IdentityID); err != nil {
		return nil, err
	}
	return viewAffiliation(a, now), nil
}
