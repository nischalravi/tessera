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
