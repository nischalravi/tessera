package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/transport"
)

// Config transport (issue #170): a tenant exports its configuration as a
// signed bundle; another tenant (usually on another instance: dev -> test
// -> prod) that trusts the signer's key previews and applies it.
func (s *Server) registerTransportRoutes() {
	G, P, D := http.MethodGet, http.MethodPost, http.MethodDelete
	s.handle(G, "/api/config/signing-key", read, need(auth.PermAdminRead), s.rd(s.configSigningKey))
	s.handle(P, "/api/config/export", write, need(auth.PermConfigTransport), s.rd(s.configExport))
	s.handle(G, "/api/config/trusted-signers", read, need(auth.PermAdminRead), s.rd(s.listTrustedSigners))
	s.handle(P, "/api/config/trusted-signers", write, needStepUp(auth.PermConfigTransport, auth.StepUpPolicy), s.rd(s.addTrustedSigner))
	s.handle(D, "/api/config/trusted-signers/{kid}", write, needStepUp(auth.PermConfigTransport, auth.StepUpPolicy), s.rd(s.removeTrustedSigner))
	s.handle(P, "/api/config/import/plan", write, need(auth.PermConfigTransport), s.rd(s.importPlan)).answersRead = true
	s.handle(P, "/api/config/import/apply", write, needStepUp(auth.PermConfigTransport, auth.StepUpPolicy), s.rd(s.importApply))
	s.handle(G, "/api/config/imports", read, need(auth.PermAdminRead), s.rd(s.listImports))
}

type signingKeyView struct {
	transport.PublicKey
	CreatedAt *string `json:"created_at"`
}

// configSigningKey shows the tenant's public key, or null before the first
// export creates it.
func (s *Server) configSigningKey(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	k, err := c.ActiveConfigSigningKey()
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusOK, map[string]any{"key": nil}, nil
	} else if err != nil {
		return 0, nil, err
	}
	at := k.CreatedAt.UTC().Format(time.RFC3339)
	return http.StatusOK, map[string]any{"key": signingKeyView{transport.EncodeKey(k, c.Tenant().String()), &at}}, nil
}

func (s *Server) source(r *http.Request, c *store.TenantTx) (transport.Source, error) {
	var t store.Tenant
	if err := s.store.ReadSystem(r.Context(), "config export source", func(st *store.SystemTx) error {
		var err error
		t, err = st.TenantByID(c.Tenant())
		return err
	}); err != nil {
		return transport.Source{}, err
	}
	return transport.Source{TenantID: c.Tenant().String(), Tenant: t.Slug, Env: s.cfg.Env,
		Instance: s.cfg.PublicOrigin, ExportedBy: actor(r)}, nil
}

// configExport signs the tenant's configuration and returns the bundle,
// creating the signing key on first use.
func (s *Server) configExport(r *http.Request, _ *params) (int, any, error) {
	if s.cfg.Sealer == nil {
		return 0, nil, badRequest("export_unavailable", "this server has no key-encryption key, so it cannot sign bundles")
	}
	var out any
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		src, err := s.source(r, c)
		if err != nil {
			return err
		}
		signed, b, err := transport.Export(c, s.readiness, s.cfg.Sealer, src, now)
		if err != nil {
			return err
		}
		if err := c.Audit(now, actor(r), "config.exported", ojson.Object{{Key: "bundle_hash", Value: signed.Hash},
			{Key: "signer_kid", Value: signed.KID}, {Key: "connections", Value: len(b.Connections)},
			{Key: "overlays", Value: len(b.Overlays)}, {Key: "identity_providers", Value: len(b.IdentityProviders)}}); err != nil {
			return err
		}
		out = map[string]any{"hash": signed.Hash, "kid": signed.KID,
			"file_name": "tessera-config-" + s.cfg.Env + "-" + now.UTC().Format("20060102-150405") + ".json",
			"excluded":  b.Excluded, "bundle": json.RawMessage(signed.JWS)}
		return nil
	})
	return http.StatusOK, out, err
}

type trustedSignerView struct {
	KID       string  `json:"kid"`
	PublicKey string  `json:"public_key"`
	Label     string  `json:"label"`
	AddedBy   *string `json:"added_by"`
	AddedAt   string  `json:"added_at"`
}

func signerView(t *store.TrustedSigner) trustedSignerView {
	return trustedSignerView{t.KID, transport.EncodeKey(&store.ConfigSigningKey{KID: t.KID, PublicKey: t.PublicKey}, "").PublicKey,
		t.Label, t.AddedBy, t.AddedAt.UTC().Format(time.RFC3339)}
}

func (s *Server) listTrustedSigners(r *http.Request, _ *params) (int, any, error) {
	ts, err := store.TxFrom(r.Context()).TrustedSigners()
	if err != nil {
		return 0, nil, err
	}
	out := make([]trustedSignerView, 0, len(ts))
	for _, t := range ts {
		out = append(out, signerView(t))
	}
	return http.StatusOK, out, nil
}

var kidRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Server) addTrustedSigner(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		KID       string `json:"kid"`
		PublicKey string `json:"public_key"`
		Label     string `json:"label"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	in.Label = strings.TrimSpace(in.Label)
	if !kidRE.MatchString(in.KID) {
		return 0, nil, badRequest("invalid_kid", "kid must be 1-64 letters, digits, dots, dashes or underscores")
	}
	if in.Label == "" || len(in.Label) > 120 {
		return 0, nil, badRequest("invalid_label", "label is required (at most 120 characters)")
	}
	pub, err := transport.DecodeKey(in.PublicKey)
	if err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		if _, err := c.TrustedSigner(in.KID); err == nil {
			return &httpError{http.StatusConflict, "a signer with this kid is already trusted; remove it first to replace its key"}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		t := &store.TrustedSigner{KID: in.KID, PublicKey: pub, Label: in.Label, AddedBy: userIDOf(r), AddedAt: now}
		if err := c.InsertTrustedSigner(t); err != nil {
			return err
		}
		out = signerView(t)
		return c.Audit(now, actor(r), "config.signer.trusted", ojson.Object{{Key: "kid", Value: in.KID}, {Key: "label", Value: in.Label}})
	})
	return http.StatusCreated, out, err
}

func (s *Server) removeTrustedSigner(r *http.Request, p *params) (int, any, error) {
	kid := p.path["kid"]
	if !kidRE.MatchString(kid) {
		return 0, nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		if err := c.DeleteTrustedSigner(kid); errors.Is(err, store.ErrNotFound) {
			return &httpError{http.StatusNotFound, "Not Found"}
		} else if err != nil {
			return err
		}
		return c.Audit(now, actor(r), "config.signer.removed", ojson.Object{{Key: "kid", Value: kid}})
	})
	return http.StatusOK, map[string]any{"removed": kid}, err
}

// readBundle reads a raw bundle body (the exported file as is).
func readBundle(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	return raw, nil
}

func (s *Server) target() transport.Target { return transport.Target{Prod: s.cfg.Env == "prod"} }

func (s *Server) importPlan(r *http.Request, _ *params) (int, any, error) {
	raw, err := readBundle(r)
	if err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		v, err := transport.Verify(c, raw)
		if err != nil {
			return err
		}
		out, err = transport.MakePlan(c, s.readiness, v, s.target(), now)
		return err
	})
	return http.StatusOK, out, err
}

// importApply applies a bundle. ?prune=true also retires connections the
// bundle does not have; ?hash= must match the plan the admin reviewed.
func (s *Server) importApply(r *http.Request, _ *params) (int, any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, badRequest("invalid_query", "the query string is not valid")
	}
	prune := q.Get("prune") == "true"
	hash := q.Get("hash")
	if hash == "" {
		return 0, nil, badRequest("hash_required", "send ?hash=<the plan's hash> so the bundle applied is the one previewed")
	}
	raw, err := readBundle(r)
	if err != nil {
		return 0, nil, err
	}
	var out any
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		v, err := transport.Verify(c, raw)
		if err != nil {
			return err
		}
		if v.Hash != hash {
			return badRequest("hash_mismatch", "this bundle is not the one previewed; plan it again")
		}
		out, err = transport.Apply(c, s.readiness, v, s.target(), prune, actor(r), userIDOf(r), now)
		return err
	})
	return http.StatusOK, out, err
}

// userIDOf is the signed-in user's id, nil for an API client.
func userIDOf(r *http.Request) *string {
	if u := principal(r).UserID; u != nil {
		id := u.String()
		return &id
	}
	return nil
}

func (s *Server) listImports(r *http.Request, _ *params) (int, any, error) {
	imps, err := store.TxFrom(r.Context()).ConfigImports()
	if err != nil {
		return 0, nil, err
	}
	out := make([]map[string]any, 0, len(imps))
	for _, i := range imps {
		out = append(out, map[string]any{"id": i.ID, "bundle_hash": i.BundleHash, "signer_kid": i.SignerKID, "source": i.Source,
			"exported_at": i.ExportedAt.UTC().Format(time.RFC3339), "summary": json.RawMessage(i.Summary),
			"applied_by": i.AppliedBy, "applied_at": i.AppliedAt.UTC().Format(time.RFC3339)})
	}
	return http.StatusOK, out, nil
}
