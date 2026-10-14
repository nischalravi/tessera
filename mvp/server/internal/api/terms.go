package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/terms"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Guest terms of use, recovery and recovery codes (guest accounts design §7.4,
// §7.5, issue #73):
//
//	GET  /api/admin/terms                          every document with its versions and assignments (guests.read)
//	POST /api/admin/terms                          {key, title, body, grace_days}: publish a new version (terms.manage)
//	PUT  /api/admin/terms/{key}/assignments        {populations, bundles}: where it applies (terms.manage)
//	GET  /api/me/terms                             the documents that apply to me, where each stands
//	POST /api/me/terms/accept                      {documents: [{id, sha256}]}: accept what I was shown
//	POST /api/me/recovery-codes                    new batch of 10 single-use codes, shown once (hosted identities)
//	POST /api/guests/{identity_id}/recovery        {reason}: issue a recovery link (guests.recover, or the guest's sponsor)
//	GET  /api/guest-recoveries                     recovery cases (guests.read)
//	POST /api/guest-recoveries/{case_id}/cancel    {reason} (guests.recover, or the guest's sponsor)
//
// The claim's step 5 (terms and the attribute-release consent) is in claim.go
// under /public/t/{slug}/claim/terms and /consent. A person whose grace period
// for a new version has passed is blocked from every route but /api/auth/* and
// /api/me/terms* until they accept (termsGate, called by authorize).

func (s *Server) registerTermsRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	sponsor := needStepUp(auth.PermGuestsSponsor, auth.StepUpPolicy)
	manage := needStepUp(auth.PermTermsManage, auth.StepUpPolicy)
	self := need(auth.PermAuthenticated)
	s.handle(G, "/api/admin/terms", read, need(auth.PermGuestsRead), s.listTerms)
	s.handle(P, "/api/admin/terms", write, manage, s.publishTerms)
	s.handle(http.MethodPut, "/api/admin/terms/{key}/assignments", write, manage, s.assignTerms)
	s.handle(G, "/api/me/terms", read, self, s.myTerms)
	s.handle(P, "/api/me/terms/accept", write, self, s.acceptMyTerms)
	s.handle(P, "/api/me/recovery-codes", write, self, s.myRecoveryCodes)
	s.handle(P, "/api/guests/{identity_id}/recovery", write, sponsor, s.issueRecovery)
	s.handle(G, "/api/guest-recoveries", read, need(auth.PermGuestsRead), s.listRecoveries)
	s.handle(P, "/api/guest-recoveries/{case_id}/cancel", write, sponsor, s.cancelRecovery)
}

// ---------------------------------------------------------------- the gate

// termsGate answers whether a signed-in user is blocked by a terms document
// whose grace period has passed. It reads nothing for a tenant without terms.
func (s *Server) termsGate(r *http.Request, p *auth.Principal, rt *route) (blocked bool, err error) {
	if p.Kind != "user" || p.UserID == nil || !strings.HasPrefix(rt.pattern, "/api/") ||
		strings.HasPrefix(rt.pattern, "/api/auth/") || strings.HasPrefix(rt.pattern, "/api/me/terms") {
		return false, nil
	}
	err = s.store.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		if has, err := tx.HasTermsDocuments(); err != nil || !has {
			return err
		}
		u, err := tx.PlatformUser(*p.UserID)
		if err != nil || u.IdentityID == nil {
			return err
		}
		blocked, err = terms.Blocked(tx, *u.IdentityID, s.clock().UTC())
		return err
	})
	return blocked, err
}

// ---------------------------------------------------------------- admin

type termsVersionView struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	SHA256    string `json:"sha256"`
	GraceDays int    `json:"grace_days"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

type termsBundleRef struct {
	GroupID int64  `json:"group_id"`
	System  string `json:"system"`
	Name    string `json:"name"`
}

type termsDocView struct {
	Key         string             `json:"key"`
	Title       string             `json:"title"`
	Latest      int                `json:"latest_version"`
	Body        string             `json:"body"`
	SHA256      string             `json:"sha256"`
	GraceDays   int                `json:"grace_days"`
	Versions    []termsVersionView `json:"versions"`
	Populations []string           `json:"populations"`
	Bundles     []termsBundleRef   `json:"bundles"`
}

func viewTerms(tx *store.TenantTx) ([]termsDocView, error) {
	all, err := tx.TermsDocuments()
	if err != nil {
		return nil, err
	}
	assigns, err := tx.TermsAssignments()
	if err != nil {
		return nil, err
	}
	out := []termsDocView{}
	idx := map[string]int{}
	for _, d := range all { // by key, then version
		i, ok := idx[d.Key]
		if !ok {
			i = len(out)
			idx[d.Key] = i
			out = append(out, termsDocView{Key: d.Key, Versions: []termsVersionView{}, Populations: []string{}, Bundles: []termsBundleRef{}})
		}
		v := &out[i]
		v.Title, v.Latest, v.Body, v.SHA256, v.GraceDays = d.Title, d.Version, d.Body, d.TextSHA256, d.GraceDays
		v.Versions = append(v.Versions, termsVersionView{d.ID, d.Version, d.TextSHA256, d.GraceDays, timeutil.ISO(d.CreatedAt), d.CreatedBy})
	}
	for _, a := range assigns {
		i, ok := idx[a.Key]
		if !ok {
			continue
		}
		switch {
		case a.Population != nil:
			out[i].Populations = append(out[i].Populations, *a.Population)
		case a.GroupID != nil:
			g, err := tx.Group(*a.GroupID)
			if err != nil {
				return nil, err
			}
			out[i].Bundles = append(out[i].Bundles, termsBundleRef{g.ID, g.System, g.Name})
		}
	}
	return out, nil
}

func (s *Server) listTerms(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	docs, err := viewTerms(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return struct {
		Documents []termsDocView `json:"documents"`
	}{docs}, nil
}

type publishTermsBody struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	GraceDays *int   `json:"grace_days"`
}

func (s *Server) publishTerms(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b publishTermsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	act, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	d, err := terms.Publish(store.TxFrom(r.Context()), act.UserID.String(),
		terms.Input{Key: b.Key, Title: b.Title, Body: b.Body, GraceDays: b.GraceDays}, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return statusBody{http.StatusCreated, termsVersionView{d.ID, d.Version, d.TextSHA256, d.GraceDays, timeutil.ISO(d.CreatedAt), d.CreatedBy}}, nil
}

type assignTermsBody struct {
	Populations []string `json:"populations"`
	Bundles     []int64  `json:"bundles"`
}

func (s *Server) assignTerms(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b assignTermsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if err := terms.Assign(tx, p.path["key"], b.Populations, b.Bundles, s.clock().UTC()); err != nil {
		if err == store.ErrNotFound {
			return nil, errStatus(http.StatusNotFound, "terms document not found")
		}
		return nil, reqErr(err)
	}
	docs, err := viewTerms(tx)
	if err != nil {
		return nil, err
	}
	for _, d := range docs {
		if d.Key == p.path["key"] {
			return d, nil
		}
	}
	return nil, errStatus(http.StatusNotFound, "terms document not found")
}

// ---------------------------------------------------------------- me

type myTermView struct {
	ID      string  `json:"id"`
	Key     string  `json:"key"`
	Version int     `json:"version"`
	Title   string  `json:"title"`
	Body    string  `json:"body"`
	SHA256  string  `json:"sha256"`
	State   string  `json:"state"`
	DueBy   *string `json:"due_by"`
	Prior   bool    `json:"previously_accepted"`
}

func viewRequirements(reqs []terms.Requirement, onlyOutstanding bool) []myTermView {
	out := []myTermView{}
	for _, q := range reqs {
		if onlyOutstanding && !q.Outstanding() {
			continue
		}
		v := myTermView{ID: q.Doc.ID, Key: q.Doc.Key, Version: q.Doc.Version, Title: q.Doc.Title, Body: q.Doc.Body,
			SHA256: q.Doc.TextSHA256, State: q.State, Prior: q.Prior}
		if q.Outstanding() {
			d := timeutil.ISO(q.DueBy)
			v.DueBy = &d
		}
		out = append(out, v)
	}
	return out
}

// myTermsIdentity is the person the signed-in user is.
func (s *Server) myTermsIdentity(r *http.Request) (int64, error) {
	pr := principal(r)
	if pr == nil || pr.UserID == nil {
		return 0, &readiness.Error{Status: http.StatusForbidden, Code: "user_required", Msg: "terms are accepted by a signed-in user"}
	}
	u, err := store.TxFrom(r.Context()).PlatformUser(*pr.UserID)
	if err != nil {
		return 0, err
	}
	if u.IdentityID == nil {
		return 0, &readiness.Error{Status: http.StatusConflict, Code: "no_identity", Msg: "this user is not linked to a person"}
	}
	return *u.IdentityID, nil
}

func (s *Server) myTermsView(r *http.Request, id int64) (any, error) {
	reqs, err := terms.Required(store.TxFrom(r.Context()), id, s.clock().UTC())
	if err != nil {
		return nil, err
	}
	return struct {
		Documents []myTermView `json:"documents"`
		Blocked   bool         `json:"blocked"`
	}{viewRequirements(reqs, false), terms.IsBlocked(reqs)}, nil
}

func (s *Server) myTerms(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	id, err := s.myTermsIdentity(r)
	var re *readiness.Error
	if errors.As(err, &re) && re.Code == "no_identity" {
		// a user who is not a person (a service sign-in) has no terms to accept
		return struct {
			Documents []myTermView `json:"documents"`
			Blocked   bool         `json:"blocked"`
		}{[]myTermView{}, false}, nil
	}
	if err != nil {
		return nil, err
	}
	return s.myTermsView(r, id)
}

type acceptTermsBody struct {
	Documents []terms.Shown `json:"documents"`
}

func (s *Server) acceptMyTerms(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b acceptTermsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id, err := s.myTermsIdentity(r)
	if err != nil {
		return nil, err
	}
	pr := principal(r)
	who := terms.Accepting{IdentityID: id, Context: store.TermsContextSignin,
		IPHash: s.claimSvc.ClientHash(pr.TenantID, "ip", s.rateKey(r)), UAHash: s.claimSvc.ClientHash(pr.TenantID, "ua", r.UserAgent())}
	if _, err := terms.Accept(store.TxFrom(r.Context()), who, b.Documents, s.clock().UTC()); err != nil {
		return nil, reqErr(err)
	}
	return s.myTermsView(r, id)
}

func (s *Server) myRecoveryCodes(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	// codes belong to identities the Tessera-hosted credential service signs in
	if s.cfg.Credential == nil || s.cfg.Credential.Kind() != "hosted" {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "not_hosted", Msg: "recovery codes are for identities signed in by the hosted credential service"}
	}
	if !s.claimReady() {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "claim_unavailable", Msg: "recovery codes need the identifier key"}
	}
	id, err := s.myTermsIdentity(r)
	if err != nil {
		return nil, err
	}
	codes, err := s.claimSvc.GenerateRecoveryCodes(store.TxFrom(r.Context()), id, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	// shown once: the response is never cached and the codes are not stored
	w.Header().Set("Cache-Control", "no-store")
	return struct {
		Codes []string `json:"codes"`
		Note  string   `json:"note"`
	}{codes, "These codes are shown once. Each works once. Making new codes voids these."}, nil
}

// ---------------------------------------------------------------- recovery

// recoveryVia decides in what capacity the caller may act on a guest's
// recovery: as the guest's live sponsor, or as the help desk (guests.recover).
func (s *Server) recoveryVia(r *http.Request, guest int64) (via string, err error) {
	tx := store.TxFrom(r.Context())
	act, err := s.requestActor(r)
	if err != nil {
		return "", err
	}
	if act.IdentityID != nil {
		all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guest, Sponsor: *act.IdentityID})
		if err != nil {
			return "", err
		}
		for _, x := range all {
			if x.Live() {
				return store.RecoveryViaSponsor, nil
			}
		}
	}
	if s.can(r, auth.PermGuestsRecover) {
		return store.RecoveryViaDesk, nil
	}
	return "", errStatus(http.StatusForbidden, "only the guest's sponsor or the help desk can recover this account")
}

type recoveryView struct {
	ID           string  `json:"id"`
	IdentityID   int64   `json:"identity_id"`
	Status       string  `json:"status"`
	Via          string  `json:"via"`
	Reason       string  `json:"reason"`
	RequiredIAL  int     `json:"required_ial"`
	Privileged   bool    `json:"privileged"`
	CoolingUntil *string `json:"cooling_until"`
	CreatedAt    string  `json:"created_at"`
	CompletedAt  *string `json:"completed_at"`
}

func viewRecovery(c *store.RecoveryCase) recoveryView {
	v := recoveryView{ID: c.ID, IdentityID: c.IdentityID, Status: c.Status, Via: c.Via, Reason: c.Reason, RequiredIAL: c.RequiredIAL,
		Privileged: c.Privileged, CreatedAt: timeutil.ISO(c.CreatedAt)}
	if c.CoolingUntil != nil {
		t := timeutil.ISO(*c.CoolingUntil)
		v.CoolingUntil = &t
	}
	if c.CompletedAt != nil {
		t := timeutil.ISO(*c.CompletedAt)
		v.CompletedAt = &t
	}
	return v
}

type recoveryBody struct {
	Reason string `json:"reason"`
}

func (s *Server) issueRecovery(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.pathInt("identity_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	var b recoveryBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	if !s.claimReady() {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "claim_unavailable", Msg: "recovery links need TESSERA_PUBLIC_URL and the identifier key"}
	}
	tx := store.TxFrom(r.Context())
	if _, err := person(tx, id); err != nil {
		return nil, err
	}
	via, err := s.recoveryVia(r, id)
	if err != nil {
		return nil, err
	}
	act, err := s.requestActor(r)
	if err != nil {
		return nil, err
	}
	rec, err := s.claimSvc.IssueRecovery(tx, claim.RecoveryInput{IdentityID: id, IssuedBy: act.UserID.String(), Via: via, Reason: b.Reason}, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return statusBody{http.StatusCreated, struct {
		recoveryView
		ExpiresAt string `json:"expires_at"`
	}{viewRecovery(rec.Case), timeutil.ISO(rec.ExpiresAt)}}, nil
}

func (s *Server) listRecoveries(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	status := qs(p, "status")
	cs, err := store.TxFrom(r.Context()).RecoveryCases(0, status)
	if err != nil {
		return nil, err
	}
	out := make([]recoveryView, 0, len(cs))
	for _, c := range cs {
		out = append(out, viewRecovery(c))
	}
	return struct {
		Recoveries []recoveryView `json:"recoveries"`
	}{out}, nil
}

func (s *Server) cancelRecovery(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b recoveryBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	c, err := getOrNil(tx.RecoveryCase(p.path["case_id"]))
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errStatus(http.StatusNotFound, "recovery not found")
	}
	if _, err := s.recoveryVia(r, c.IdentityID); err != nil {
		return nil, err
	}
	if !s.claimReady() {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "claim_unavailable", Msg: "recovery needs TESSERA_PUBLIC_URL and the identifier key"}
	}
	reason := strings.TrimSpace(b.Reason)
	if reason == "" {
		reason = "cancelled"
	}
	if len(reason) > 500 {
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_reason", Msg: "the reason is at most 500 characters"}
	}
	if err := s.claimSvc.CancelRecovery(tx, c.ID, reason, s.clock().UTC()); err != nil {
		return nil, reqErr(err)
	}
	got, err := tx.RecoveryCase(c.ID)
	if err != nil {
		return nil, err
	}
	return viewRecovery(got), nil
}
