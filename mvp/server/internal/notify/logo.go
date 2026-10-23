package notify

import (
	"errors"
	"html"
	"net/url"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// emailLogo is the tenant's logo as an email carries it (Admin > Branding & labels, "Show the logo in emails"): the
// public logo URL and the size to show it at.
type emailLogo struct {
	URL           string
	Width, Height int
}

// maxLogoHeight is the height, in pixels, the logo is shown at in an email.
const maxLogoHeight = 48

// emailLogo returns the logo to put in this tenant's emails, or nil: the switch is off, the tenant has no logo, or there is
// no public address (TESSERA_PUBLIC_URL) to load it from.
func (d *Dispatcher) emailLogo(tx *store.TenantTx) (*emailLogo, error) {
	if d.BaseURL == "" {
		return nil, nil
	}
	row, err := tx.LabelSettings()
	if errors.Is(err, store.ErrNotFound) || err == nil && !row.EmailLogo {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	b, err := tx.Branding()
	if errors.Is(err, store.ErrNotFound) || err == nil && b.LogoType == "" {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	w, h := b.LogoWidth, b.LogoHeight
	if h > maxLogoHeight {
		w, h = w*maxLogoHeight/h, maxLogoHeight
	}
	return &emailLogo{URL: strings.TrimRight(d.BaseURL, "/") + "/api/auth/branding/logo?tenant=" + url.QueryEscape(t.Slug) + "&v=" + b.LogoSHA256[:12],
		Width: w, Height: h}, nil
}

// html is the HTML part of a message: the logo, then the plain text, escaped, with its line breaks. Nothing from the
// message is trusted as markup.
func (l *emailLogo) html(product, text string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><body style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1b1b1b">`)
	b.WriteString(`<p><img src="` + html.EscapeString(l.URL) + `" alt="` + html.EscapeString(product) + `" width="` + strconv.Itoa(l.Width) +
		`" height="` + strconv.Itoa(l.Height) + `" style="display:block;border:0"></p>`)
	b.WriteString(`<div style="white-space:pre-wrap">` + html.EscapeString(text) + `</div></body></html>`)
	return b.String()
}
