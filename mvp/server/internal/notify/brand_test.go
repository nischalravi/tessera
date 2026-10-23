package notify_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestDispatch_UsesTheTenantsBrandName: with branding set (Admin > Branding), the email names the tenant's product
// where it said Tessera, in the subject, the link line and the footer.
func TestDispatch_UsesTheTenantsBrandName(t *testing.T) {
	w := newWorld(t)
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(tx *store.TenantTx) error {
		return tx.PutBranding(&store.TenantBranding{DisplayName: "Larkspur Health", PrimaryColor: "#0f6cbd", OnPrimaryColor: "#ffffff",
			UpdatedBy: "admin", UpdatedAt: w.now}, nil, false)
	}); err != nil {
		t.Fatal(err)
	}
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	mail := &notify.MemorySender{}
	if st := w.run(w.dispatcher(mail, &clock{t: w.now})); st.Sent != 1 || mail.Count() != 1 {
		t.Fatalf("stats = %+v, %d emails", st, mail.Count())
	}
	e := mail.Sent[0]
	if e.Subject != "[Larkspur Health] subject k" || !strings.Contains(e.Body, "Open in Larkspur Health: https://tessera.example/inbox") ||
		!strings.Contains(e.Body, "settings in Larkspur Health.") || strings.Contains(e.Body, "Tessera") {
		t.Errorf("email = %+v", e)
	}
}

// With "Show the logo in emails" on and a logo saved, the email also carries an HTML part: the logo from the tenant's
// public logo URL, then the message, escaped. Switch off, no logo or no public address: plain text only.
func TestDispatch_ShowsTheLogoInEmailsWhenAsked(t *testing.T) {
	logo := &store.BrandingLogo{Data: []byte("png"), Type: "image/png", Width: 200, Height: 100, SHA256: strings.Repeat("ab", 32)}
	cases := []struct {
		name     string
		switchOn bool
		logo     bool
		baseURL  string
		want     bool
	}{
		{"on, with a logo", true, true, "https://tessera.example", true},
		{"switch off", false, true, "https://tessera.example", false},
		{"no logo", true, false, "https://tessera.example", false},
		{"no public address", true, true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(tx *store.TenantTx) error {
				var l *store.BrandingLogo
				if tc.logo {
					l = logo
				}
				if err := tx.PutBranding(&store.TenantBranding{DisplayName: `Larkspur <b>Health</b>`, PrimaryColor: "#0f6cbd", OnPrimaryColor: "#ffffff",
					UpdatedBy: "admin", UpdatedAt: w.now}, l, true); err != nil {
					return err
				}
				return tx.PutLabelSettings(&store.LabelSettingsRow{EmailLogo: tc.switchOn, Labels: "{}", UpdatedBy: "admin"}, w.now)
			}); err != nil {
				t.Fatal(err)
			}
			w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
			mail := &notify.MemorySender{}
			d := w.dispatcher(mail, &clock{t: w.now})
			d.BaseURL = tc.baseURL
			if st := w.run(d); st.Sent != 1 {
				t.Fatalf("stats = %+v", st)
			}
			e := mail.Sent[0]
			if !tc.want {
				if e.HTML != "" {
					t.Errorf("HTML part = %q", e.HTML)
				}
				return
			}
			slug := w.f.B.Slug
			if !strings.Contains(e.HTML, `src="https://tessera.example/api/auth/branding/logo?tenant=`+slug+`&amp;v=abababababab"`) ||
				!strings.Contains(e.HTML, `width="96" height="48"`) || strings.Contains(e.HTML, "<b>") || !strings.Contains(e.HTML, "&lt;b&gt;Health&lt;/b&gt;") ||
				!strings.Contains(e.HTML, "subject") && !strings.Contains(e.HTML, "settings in") {
				t.Errorf("HTML part = %s", e.HTML)
			}
			if !strings.Contains(e.Body, "settings in") || strings.Contains(e.Body, "<img") {
				t.Errorf("plain text part = %q", e.Body)
			}
		})
	}
}
