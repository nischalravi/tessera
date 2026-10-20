package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/branding"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Branding (Admin > Branding & labels): the name, colours and logo a tenant shows on its sign-in page, the guest
// claim pages and in emails.
//
//	GET /api/admin/branding                      the saved branding with the limits
//	PUT /api/admin/branding                      {display_name, primary_color, on_primary_color?, logo?, remove_logo?}
//	GET /api/auth/branding?tenant=<slug>         PUBLIC: what the sign-in and claim pages show (the unbranded default for an unknown tenant)
//	GET /api/auth/branding/logo?tenant=<slug>    PUBLIC: the logo image, served with its own image content type and nosniff
//
// Reading needs admin.read and changing needs email.manage (the tenant admin's presentation setting) and a fresh
// sign-in: the sign-in page is what people trust before they authenticate. The colour pair must reach WCAG AA; a
// pair below it is refused with the contrast it has. The logo is a PNG or JPEG only, checked by decoding it.

const (
	defaultPrimary   = "#0f6cbd" // --accent
	defaultOnPrimary = "#ffffff" // --on-accent
	maxLogoBase64    = (branding.MaxLogoBytes+2)/3*4 + 8
)

func (s *Server) registerBrandingRoutes() {
	s.handle(http.MethodGet, "/api/admin/branding", read, need(auth.PermAdminRead), s.getBranding)
	s.handle(http.MethodPut, "/api/admin/branding", write, needStepUp(auth.PermEmailManage, auth.StepUpPolicy), s.putBranding)
	s.handle(http.MethodGet, "/api/auth/branding", noTenant, publicRoute, s.publicBranding)
	s.handle(http.MethodGet, "/api/auth/branding/logo", noTenant, publicRoute, s.publicBrandingLogo)
}

func brandErr(err error) error {
	var be *branding.Error
	if errors.As(err, &be) {
		return &readiness.Error{Status: be.Status, Code: be.Code, Msg: be.Msg}
	}
	return err
}

type logoView struct {
	ContentType string `json:"content_type"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	SHA256      string `json:"sha256"`
}

type brandingView struct {
	Configured     bool      `json:"configured"`
	DisplayName    string    `json:"display_name"`
	PrimaryColor   string    `json:"primary_color"`
	OnPrimaryColor string    `json:"on_primary_color"`
	Logo           *logoView `json:"logo"`
	UpdatedBy      *string   `json:"updated_by"`
	UpdatedAt      *string   `json:"updated_at"`
	Limits         struct {
		LogoMaxBytes int      `json:"logo_max_bytes"`
		LogoMinPx    int      `json:"logo_min_px"`
		LogoMaxPx    int      `json:"logo_max_px"`
		LogoTypes    []string `json:"logo_types"`
		MinContrast  float64  `json:"min_contrast"`
	} `json:"limits"`
}

func viewBranding(b *store.TenantBranding) brandingView {
	v := brandingView{DisplayName: branding.DefaultName, PrimaryColor: defaultPrimary, OnPrimaryColor: defaultOnPrimary}
	v.Limits.LogoMaxBytes, v.Limits.LogoMinPx, v.Limits.LogoMaxPx = branding.MaxLogoBytes, branding.MinDim, branding.MaxDim
	v.Limits.LogoTypes, v.Limits.MinContrast = []string{"image/png", "image/jpeg"}, branding.MinContrast
	if b == nil {
		return v
	}
	v.Configured, v.DisplayName, v.PrimaryColor, v.OnPrimaryColor = true, b.DisplayName, b.PrimaryColor, b.OnPrimaryColor
	by, at := b.UpdatedBy, b.UpdatedAt.UTC().Format(time.RFC3339)
	v.UpdatedBy, v.UpdatedAt = &by, &at
	if b.LogoType != "" {
		v.Logo = &logoView{b.LogoType, b.LogoWidth, b.LogoHeight, b.LogoSHA256}
	}
	return v
}

func currentBranding(tx *store.TenantTx) (*store.TenantBranding, error) {
	b, err := tx.Branding()
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return b, err
}

func (s *Server) getBranding(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	b, err := currentBranding(store.TxFrom(r.Context()))
	if err != nil {
		return nil, err
	}
	return viewBranding(b), nil
}

type logoBody struct {
	ContentType string `json:"content_type"`
	DataBase64  string `json:"data_base64"`
}

type putBrandingBody struct {
	DisplayName    string    `json:"display_name"`
	PrimaryColor   string    `json:"primary_color"`
	OnPrimaryColor string    `json:"on_primary_color"`
	Logo           *logoBody `json:"logo"`
	RemoveLogo     bool      `json:"remove_logo"`
}

func (s *Server) putBranding(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	pr := principal(r)
	if pr.UserID == nil {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "user_required", Msg: "only a signed-in user can do this"}
	}
	var body putBrandingBody
	if err := decodeBody(r, &body, false); err != nil {
		return nil, err
	}
	if body.Logo != nil && body.RemoveLogo {
		return nil, badRequest("invalid_body", "send a logo or remove_logo, not both")
	}
	name, err := branding.Name(body.DisplayName)
	if err != nil {
		return nil, brandErr(err)
	}
	primary, on, err := branding.Colors(body.PrimaryColor, body.OnPrimaryColor)
	if err != nil {
		return nil, brandErr(err)
	}
	var logo *branding.Logo
	if body.Logo != nil {
		if len(body.Logo.DataBase64) > maxLogoBase64 {
			return nil, brandErr(&branding.Error{Status: http.StatusRequestEntityTooLarge, Code: "logo_too_large",
				Msg: "the logo is at most " + strconv.Itoa(branding.MaxLogoBytes>>10) + " KiB"})
		}
		raw, err := base64.StdEncoding.DecodeString(body.Logo.DataBase64)
		if err != nil {
			return nil, badRequest("invalid_logo", "data_base64 is not base64")
		}
		if logo, err = branding.CheckLogo(raw, body.Logo.ContentType); err != nil {
			return nil, brandErr(err)
		}
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	old, err := currentBranding(tx)
	if err != nil {
		return nil, err
	}
	rec := &store.TenantBranding{DisplayName: name, PrimaryColor: primary, OnPrimaryColor: on, UpdatedBy: pr.Display, UpdatedAt: now}
	var stored *store.BrandingLogo
	if logo != nil {
		stored = &store.BrandingLogo{Data: logo.Data, Type: logo.ContentType, Width: logo.Width, Height: logo.Height, SHA256: logo.SHA256}
	}
	setLogo := logo != nil || body.RemoveLogo
	if err := tx.PutBranding(rec, stored, setLogo); err != nil {
		return nil, err
	}
	logoChange := "kept"
	switch {
	case logo != nil:
		logoChange = "replaced"
	case body.RemoveLogo:
		logoChange = "removed"
	}
	prev := ""
	if old != nil {
		prev = old.DisplayName
	}
	detail := ojson.Object{{Key: "display_name", Value: ojson.Object{{Key: "from", Value: prev}, {Key: "to", Value: name}}},
		{Key: "primary_color", Value: primary}, {Key: "on_primary_color", Value: on}, {Key: "logo", Value: logoChange}}
	if logo != nil {
		detail = append(detail, ojson.KV{Key: "logo_sha256", Value: logo.SHA256})
	}
	if err := tx.Audit(now, pr.Display, "branding.updated", detail); err != nil {
		return nil, err
	}
	saved, err := tx.Branding()
	if err != nil {
		return nil, err
	}
	return viewBranding(saved), nil
}

// publicBranding is what the sign-in and claim pages show for a tenant. An unknown tenant, or one without
// branding, gets the same unbranded answer, so the page cannot tell which tenants exist.
func (s *Server) publicBranding(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	slug := r.URL.Query().Get("tenant")
	b, _, err := s.tenantBranding(r, slug)
	if err != nil {
		return nil, err
	}
	w.Header().Set("Cache-Control", "no-cache")
	v := viewBranding(b)
	out := ojson.Object{{Key: "name", Value: v.DisplayName}, {Key: "configured", Value: v.Configured},
		{Key: "primary_color", Value: v.PrimaryColor}, {Key: "on_primary_color", Value: v.OnPrimaryColor}, {Key: "logo_url", Value: nil}}
	if v.Logo != nil {
		out[len(out)-1].Value = "/api/auth/branding/logo?tenant=" + url.QueryEscape(slug) + "&v=" + v.Logo.SHA256[:12]
		out = append(out, ojson.KV{Key: "logo_width", Value: v.Logo.Width}, ojson.KV{Key: "logo_height", Value: v.Logo.Height})
	}
	return out, nil
}

func (s *Server) tenantBranding(r *http.Request, slug string) (*store.TenantBranding, store.Tenant, error) {
	t, ok, err := s.activeTenant(r.Context(), slug)
	if err != nil || !ok {
		return nil, t, err
	}
	var b *store.TenantBranding
	err = s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		var err error
		b, err = currentBranding(tx)
		return err
	})
	return b, t, err
}

// publicBrandingLogo serves the stored logo. The content type is the one the image was checked as (PNG or JPEG),
// never sniffed, and the response cannot run anything: nosniff and a CSP that allows nothing.
func (s *Server) publicBrandingLogo(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	t, ok, err := s.activeTenant(r.Context(), r.URL.Query().Get("tenant"))
	if err != nil {
		return nil, err
	}
	var logo *store.BrandingLogo
	if ok {
		err = s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			var err error
			logo, err = tx.BrandingLogo()
			if errors.Is(err, store.ErrNotFound) {
				logo, err = nil, nil
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	if logo == nil {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	etag := `"` + logo.SHA256 + `"`
	h := w.Header()
	h.Set("Content-Type", logo.Type)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return nil, nil
	}
	h.Set("Content-Length", strconv.Itoa(len(logo.Data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(logo.Data) // #nosec G705 -- a decoded PNG or JPEG served with its own image type, nosniff and a CSP that allows nothing
	return nil, nil
}
