package notify_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The guest claim's emails carry a one-time secret that never reaches the
// database (issue #69): the notification row says an invitation is to be sent,
// the secret line comes from memory when the dispatcher sends.

const guestMail = "gwen@guest.example"

func (w *world) invitation() (id string) {
	w.t.Helper()
	w.tx(func(c *store.TenantTx) error {
		var err error
		id, err = notify.GuestInvitation(c, w.now, notify.GuestInvite{TokenID: "tok-1", IdentityID: w.f.B.IDs["dave"], Email: guestMail,
			Name: "Gwen", Tenant: "Bravo", Sponsor: "Carol", Population: "visitor", EndsAt: w.now.AddDate(0, 0, 10), Expires: w.now.AddDate(0, 0, 7)})
		return err
	})
	if id == "" {
		w.t.Fatal("no notification id")
	}
	return id
}

func TestClaimMail_SecretComesFromMemoryAndIsForgotten(t *testing.T) {
	w := newWorld(t)
	id := w.invitation()
	secrets := notify.NewSecrets()
	const secret = "Your one-time link:\nhttps://t.example/claim#t=SECRET-TOKEN-VALUE"
	secrets.Put(id, secret, w.now.Add(time.Hour))
	// the row holds no secret
	w.read(func(c *store.TenantTx) {
		ns, err := c.DueNotifications(w.now.Add(time.Hour), 10)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, n := range ns {
			if n.ID == id {
				found = true
				if n.Kind != notify.KindGuestInvitation || n.Delivery != store.DeliveryPending || n.UserID != nil || n.InApp ||
					strings.Contains(n.Body+n.Subject+n.Link, "SECRET-TOKEN-VALUE") || n.Email == nil || *n.Email != guestMail {
					t.Errorf("notification row = %+v", n)
				}
			}
		}
		if !found {
			t.Fatal("the invitation notification is not due")
		}
	})
	mail := &notify.MemorySender{}
	d := w.dispatcher(mail, &clock{t: w.now})
	d.Secrets = secrets
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("stats = %+v", st)
	}
	e := mail.Sent[0]
	if e.To != guestMail || !strings.Contains(e.Body, "SECRET-TOKEN-VALUE") || !strings.Contains(e.Subject, "invited") ||
		strings.Contains(e.Body, "notification settings") || strings.Contains(e.Subject, "SECRET") {
		t.Errorf("email = %+v", e)
	}
	if secrets.Len() != 0 {
		t.Error("the secret is still held after the mail was sent")
	}
	// the delivery log has the envelope, no body, no secret
	w.read(func(c *store.TenantTx) {
		m, err := c.EmailMessageForNotification(id)
		if err != nil || m.Status != store.EmailAccepted || strings.Contains(m.Subject+string(m.Attempts), "SECRET-TOKEN-VALUE") {
			t.Errorf("delivery record = %+v, %v", m, err)
		}
	})
}

func TestClaimMail_LostSecretIsADeadLetterNotAMailWithoutIt(t *testing.T) {
	w := newWorld(t)
	id := w.invitation()
	mail := &notify.MemorySender{}
	d := w.dispatcher(mail, &clock{t: w.now})
	d.Secrets = notify.NewSecrets() // as after a restart
	if st := w.run(d); st.Dead != 1 || st.Sent != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if mail.Count() != 0 {
		t.Errorf("a message without its link was sent: %+v", mail.Sent)
	}
	w.read(func(c *store.TenantTx) {
		m, err := c.EmailMessageForNotification(id)
		if err != nil || m.Status != store.EmailRejected || strings.Contains(m.Subject, "http") {
			t.Errorf("delivery record = %+v, %v", m, err)
		}
	})
	// no Secrets at all is the same
	id2 := func() string {
		var out string
		w.tx(func(c *store.TenantTx) error {
			var err error
			out, err = notify.ClaimCode(c, w.now, "code-1", w.f.B.IDs["dave"], guestMail, "Bravo", 10*time.Minute)
			return err
		})
		return out
	}()
	d.Secrets = nil
	if st := w.run(d); st.Dead != 1 || mail.Count() != 0 {
		t.Errorf("without a handoff: %+v, %d mails (notification %s)", st, mail.Count(), id2)
	}
}

func TestClaimMail_RetryKeepsTheSecret(t *testing.T) {
	w := newWorld(t)
	id := w.invitation()
	secrets := notify.NewSecrets()
	secrets.Put(id, "LINK-LINE-123", w.now.Add(time.Hour))
	mail := &notify.MemorySender{Errs: []error{errors.New("421 try later")}}
	clk := &clock{t: w.now}
	d := w.dispatcher(mail, clk)
	d.Secrets = secrets
	if st := w.run(d); st.Retried != 1 {
		t.Fatalf("first run = %+v", st)
	}
	if secrets.Len() != 1 {
		t.Fatal("the secret was dropped while the message is still to be retried")
	}
	clk.add(time.Minute)
	if st := w.run(d); st.Sent != 1 || !strings.Contains(mail.Sent[0].Body, "LINK-LINE-123") || secrets.Len() != 0 {
		t.Errorf("second run = %+v, %d held", st, secrets.Len())
	}
}

func TestSecrets_ExpireAndBound(t *testing.T) {
	s := notify.NewSecrets()
	now := time.Now()
	s.Put("a", "x", now.Add(time.Minute))
	if v, ok := s.Get("a", now); !ok || v != "x" {
		t.Error("a held secret is not returned")
	}
	if _, ok := s.Get("a", now.Add(2*time.Minute)); ok {
		t.Error("an expired secret is returned")
	}
	if s.Len() != 0 {
		t.Error("an expired secret is kept")
	}
	var nilS *notify.Secrets
	nilS.Put("a", "x", now)
	nilS.Drop("a")
	if _, ok := nilS.Get("a", now); ok {
		t.Error("a nil handoff returned a secret")
	}
}

func TestClaimKinds_AreNotPreferences(t *testing.T) {
	for _, k := range []string{notify.KindGuestInvitation, notify.KindClaimCode} {
		if _, ok := notify.KindByID(k); ok {
			t.Errorf("%s is a user preference", k)
		}
		if !notify.SecretKind(k) {
			t.Errorf("%s carries no secret", k)
		}
	}
	if _, ok := notify.KindByID(notify.KindGuestClaimed); !ok {
		t.Error("guest.claimed is not a preference kind")
	}
}
