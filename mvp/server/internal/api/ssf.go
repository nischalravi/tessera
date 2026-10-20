package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/ssf"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Shared Signals receiver (issue #114, package internal/ssf):
//
//	GET    /api/ssf/transmitters                  list (graph.read)
//	GET    /api/ssf/transmitters/{id}             one, with its recent events
//	GET    /api/ssf/events[?transmitter_id=&limit=] recent events of all streams
//	POST   /api/ssf/transmitters                  create (ssf.configure, step-up)
//	PUT    /api/ssf/transmitters/{id}             update
//	DELETE /api/ssf/transmitters/{id}             delete
//	POST   /api/ssf/transmitters/{id}/verify      ask the transmitter for a verification event
//	POST   /public/t/{slug}/ssf/{transmitter_id}/events   push delivery (RFC 8935), public
//
// The push endpoint is public but authenticated: the transmitter presents the
// stream's receiver secret as a bearer token, compared in constant time. An
// unknown tenant, an unknown transmitter and a wrong secret all get the same
// answer, so it reveals nothing about which tenants or streams exist. It is
// rate limited like every anonymous request (the per-IP anonymous bucket,
// ratelimit.go), before anything is written.

func (s *Server) registerSSFRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/ssf/transmitters", read, need(auth.PermGraphRead), s.listSSFTransmitters)
	s.handle(G, "/api/ssf/transmitters/{id}", read, need(auth.PermGraphRead), s.getSSFTransmitter)
	s.handle(G, "/api/ssf/events", read, need(auth.PermGraphRead), s.listSSFEvents)
	s.handle(P, "/api/ssf/transmitters", phased, needStepUp(auth.PermSSFConfigure, auth.StepUpPolicy), s.createSSFTransmitter)
	s.handle(http.MethodPut, "/api/ssf/transmitters/{id}", phased, needStepUp(auth.PermSSFConfigure, auth.StepUpPolicy), s.updateSSFTransmitter)
	s.handle(http.MethodDelete, "/api/ssf/transmitters/{id}", write, needStepUp(auth.PermSSFConfigure, auth.StepUpPolicy), s.deleteSSFTransmitter)
	s.handle(P, "/api/ssf/transmitters/{id}/verify", phased, needStepUp(auth.PermSSFConfigure, auth.StepUpPolicy), s.verifySSFTransmitter)
	s.handle(P, "/public/t/{slug}/ssf/{transmitter_id}/events", noTenant, publicRoute, s.ssfPush)
}

// ssfError maps an internal/ssf configuration error to the API's.
func ssfError(err error) error {
	var ce *ssf.ConfigError
	switch {
	case errors.Is(err, ssf.ErrNoSuchTransmitter):
		return &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such transmitter"}
	case errors.As(err, &ce):
		return badRequest("invalid_transmitter", ce.Msg)
	}
	return err
}

func ssfID(p *params) (string, error) {
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return "", ssfError(ssf.ErrNoSuchTransmitter)
	}
	return id, nil
}

// slugOf is the slug of the principal's tenant (it names the push URL).
func (s *Server) slugOf(r *http.Request, t tenancy.ID) (string, error) {
	var slug string
	err := s.store.ReadSystem(r.Context(), "ssf: tenant slug", func(st *store.SystemTx) error {
		tn, err := st.TenantByID(t)
		slug = tn.Slug
		return err
	})
	return slug, err
}

func (s *Server) listSSFTransmitters(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	slug, err := s.slugOf(r, principal(r).TenantID)
	if err != nil {
		return nil, err
	}
	xs, err := store.TxFrom(r.Context()).SSFTransmitters()
	if err != nil {
		return nil, err
	}
	out := make([]ssf.TransmitterView, len(xs))
	for i, x := range xs {
		out[i] = ssf.ViewTransmitter(x, slug)
	}
	return ojson.Object{{Key: "transmitters", Value: out}}, nil
}

func (s *Server) getSSFTransmitter(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := ssfID(p)
	if err != nil {
		return nil, err
	}
	slug, err := s.slugOf(r, principal(r).TenantID)
	if err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	x, err := c.SSFTransmitter(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ssfError(ssf.ErrNoSuchTransmitter)
	}
	if err != nil {
		return nil, err
	}
	evs, err := c.SSFEvents(id, 50)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "transmitter", Value: ssf.ViewTransmitter(x, slug)}, {Key: "events", Value: viewEvents(evs)}}, nil
}

func viewEvents(evs []*store.SSFEvent) []ssf.EventView {
	out := make([]ssf.EventView, len(evs))
	for i, e := range evs {
		out[i] = ssf.ViewEvent(e)
	}
	return out
}

func (s *Server) listSSFEvents(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tid, _ := p.query("transmitter_id")
	if tid != "" && !idRE.MatchString(tid) {
		return nil, badRequest("invalid_transmitter_id", "transmitter_id is not a transmitter id")
	}
	limit := 100
	if v, ok := p.query("limit"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			return nil, badRequest("invalid_limit", "limit is 1 to 500")
		}
		limit = n
	}
	evs, err := store.TxFrom(r.Context()).SSFEvents(tid, limit)
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "events", Value: viewEvents(evs)}}, nil
}

// discover fills the blank JWKS URL and verification endpoint of in from the
// transmitter's /.well-known/ssf-configuration, when in.Discover is set. It
// runs before any transaction opens (it makes a network call).
func (s *Server) discover(r *http.Request, in *ssf.TransmitterInput) error {
	if !in.Discover {
		return nil
	}
	m, err := s.ssf.Discover(r.Context(), in.Issuer)
	if err != nil {
		return badRequest("discovery_failed", err.Error())
	}
	ssf.ApplyDiscovery(in, m)
	return nil
}

func (s *Server) createSSFTransmitter(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var in ssf.TransmitterInput
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	if err := s.discover(r, &in); err != nil {
		return nil, err
	}
	slug, err := s.slugOf(r, p.scope.Tenant)
	if err != nil {
		return nil, err
	}
	var x *store.SSFTransmitter
	var secret string
	err = p.scope.Write(r.Context(), func(c *store.TenantTx) error {
		var err error
		x, secret, err = s.ssf.Create(c, in, actor(r), s.clock())
		return err
	})
	if err != nil {
		return nil, ssfError(err)
	}
	return statusBody{http.StatusCreated, transmitterBody(x, slug, secret)}, nil
}

// transmitterBody is the answer of a create or an update: the receiver secret
// of a push stream appears here once, when it was generated, and never again.
func transmitterBody(x *store.SSFTransmitter, slug, generated string) ojson.Object {
	out := ojson.Object{{Key: "transmitter", Value: ssf.ViewTransmitter(x, slug)}}
	if generated != "" {
		out = append(out, ojson.KV{Key: "receiver_secret", Value: generated})
	}
	return out
}

func (s *Server) updateSSFTransmitter(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := ssfID(p)
	if err != nil {
		return nil, err
	}
	var in ssf.TransmitterInput
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	if err := s.discover(r, &in); err != nil {
		return nil, err
	}
	slug, err := s.slugOf(r, p.scope.Tenant)
	if err != nil {
		return nil, err
	}
	var x *store.SSFTransmitter
	var secret string
	err = p.scope.Write(r.Context(), func(c *store.TenantTx) error {
		var err error
		x, secret, err = s.ssf.Update(c, id, in, actor(r), s.clock())
		return err
	})
	if err != nil {
		return nil, ssfError(err)
	}
	return transmitterBody(x, slug, secret), nil
}

func (s *Server) deleteSSFTransmitter(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := ssfID(p)
	if err != nil {
		return nil, err
	}
	if err := s.ssf.Delete(store.TxFrom(r.Context()), id, actor(r), s.clock()); err != nil {
		return nil, ssfError(err)
	}
	return ojson.Object{{Key: "deleted", Value: true}, {Key: "id", Value: id}}, nil
}

func (s *Server) verifySSFTransmitter(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := ssfID(p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	if err := s.ssf.RequestVerification(r.Context(), s.store, p.scope.Tenant, id, actor(r)); err != nil {
		return nil, ssfError(err)
	}
	return ojson.Object{{Key: "requested", Value: true}}, nil
}

// ---------------------------------------------------------------- push (RFC 8935)

// ssfRefusal is the RFC 8935 error answer: 400 {"err", "description"}.
func ssfRefusal(code, msg string) statusBody {
	return statusBody{http.StatusBadRequest, ojson.Object{{Key: "err", Value: code}, {Key: "description", Value: msg}}}
}

// dummyDigest stands in for the secret when the tenant or the stream does not
// exist, so the comparison runs either way.
var dummyDigest = sha256.Sum256(seal.RandomBytes(32))

func bearerOf(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) ssfPush(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ctx := r.Context()
	denied := ssfRefusal(ssf.ErrAuthenticationFailed, "authentication failed")
	slug, id := p.path["slug"], p.path["transmitter_id"]
	var tenant store.Tenant
	var tr *store.SSFTransmitter
	secret, found := "", false
	if store.ValidSlug(slug) && idRE.MatchString(id) {
		err := s.store.ReadSystem(ctx, "ssf push: tenant", func(st *store.SystemTx) error {
			var err error
			tenant, err = st.TenantBySlug(slug)
			return err
		})
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		case tenant.Status == "active" && tenant.ID != tenancy.Platform:
			err := s.store.ReadTenant(ctx, tenant.ID, func(c *store.TenantTx) error {
				x, err := c.SSFTransmitter(id)
				if errors.Is(err, store.ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				if secret, err = s.ssf.ReceiverSecret(c, x); err != nil {
					return nil // an unreadable secret authenticates nobody
				}
				tr, found = x, x.Delivery == store.SSFPush && secret != ""
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	want := dummyDigest
	if found {
		want = sha256.Sum256([]byte(secret))
	}
	got := sha256.Sum256([]byte(bearerOf(r)))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 || !found || bearerOf(r) == "" {
		return denied, nil
	}
	if tr.Status != store.SSFEnabled {
		return ssfRefusal(ssf.ErrAccessDenied, "this stream is "+tr.Status), nil
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/secevent+jwt" {
		return ssfRefusal(ssf.ErrInvalidRequest, "the content type must be application/secevent+jwt"), nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, ssf.MaxSETBytes+1))
	if err != nil {
		return ssfRefusal(ssf.ErrInvalidRequest, "the request body could not be read"), nil
	}
	if len(raw) > ssf.MaxSETBytes {
		return ssfRefusal(ssf.ErrInvalidRequest, "the SET is too large"), nil
	}
	_, err = s.ssf.Receive(audit.AsSystem(ctx, ssf.Actor), s.store, tenant.ID, tr, store.SSFPush, string(raw), "")
	var se *ssf.Error
	switch {
	case err == nil:
		return statusBody{http.StatusAccepted, ojson.Object{}}, nil
	case errors.As(err, &se):
		return ssfRefusal(se.Code, se.Msg), nil
	case errors.Is(err, ssf.ErrKeysUnavailable):
		return statusBody{http.StatusServiceUnavailable, ojson.Object{{Key: "err", Value: "unavailable"},
			{Key: "description", Value: "the transmitter's signing keys are unavailable; deliver again later"}}}, nil
	}
	return nil, err
}
