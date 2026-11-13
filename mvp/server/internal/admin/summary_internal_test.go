package admin

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var summaryTenant = tenancy.MustParse("00000000-0000-4000-8000-0000000000c2")

func TestClipSummary(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		wantLen  int
		cut      bool
	}{
		{"short", "abc", 3, false},
		{"exactly 1000", strings.Repeat("a", 1000), 1000, false},
		{"1001 ascii", strings.Repeat("a", 1001), 1000, true},
		{"multibyte under the limit in runes", strings.Repeat("é", 1000), 1000, false},
		{"multibyte over the limit", strings.Repeat("→", 1500), 1000, true},
		{"4-byte runes", strings.Repeat("\U0001F600", 1200), 1000, true},
	} {
		got := clipSummary(tc.in)
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) != tc.wantLen {
			t.Errorf("%s: %d runes, valid=%v; want %d", tc.name, utf8.RuneCountInString(got), utf8.ValidString(got), tc.wantLen)
		}
		if tc.cut != strings.HasSuffix(got, "…") {
			t.Errorf("%s: ellipsis = %v, want %v", tc.name, !tc.cut, tc.cut)
		}
	}
}

// A request applied before summaries were kept has none stored: describe falls back to rendering it live.
func TestDescribeAppliedWithoutStoredSummary(t *testing.T) {
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, summaryTenant, "acme")
	svc := &Service{DB: db}
	chID := "ch-legacy"
	inTenant(t, db, func(tx *store.TenantTx) error {
		return tx.InsertAlertChannel(&store.AlertChannel{ID: chID, Name: "Legacy", Kind: "email", Target: "a@x.example",
			MinSeverity: "low", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	})
	ch := &store.AdminChange{ID: uuid.New(), Type: TypeAlertChannelDisable, Status: store.ChangeApplied,
		Payload: []byte(`{"channel_id":"` + chID + `"}`)}
	inTenant(t, db, func(tx *store.TenantTx) error {
		if _, err := tx.AdminChangeSummary(ch.ID); err != store.ErrNotFound {
			t.Fatalf("summary lookup = %v, want ErrNotFound", err)
		}
		got := svc.env(tx, time.Now(), uuid.Nil).describe(ch)
		if !strings.Contains(got, `"Legacy" (email`) || !strings.Contains(got, "enabled → disabled") {
			t.Errorf("describe = %q, want the live rendering", got)
		}
		return nil
	})
}

// A kept summary is stored and listed as written, so no keepSummary type may put a secret or a URL in it.
func TestKeepSummaryTypesLeakNothing(t *testing.T) {
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, summaryTenant, "acme")
	svc := &Service{DB: db}
	const tok, secret = "TOKENsummary9z", "whsec_guard_0123456789abcdef"
	hook := &store.AlertChannel{ID: "ch-hook", Name: "Hook", Kind: "webhook", Target: "https://hooks.slack.com/services/T0/B0/" + tok,
		SecretSealed: []byte(secret), MinSeverity: "high", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	mail := &store.AlertChannel{ID: "ch-mail", Name: "Mail", Kind: "email", Target: "a@x.example, b@x.example",
		MinSeverity: "low", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	inTenant(t, db, func(tx *store.TenantTx) error {
		if err := tx.InsertAlertChannel(hook); err != nil {
			return err
		}
		return tx.InsertAlertChannel(mail)
	})
	payloads := map[string]string{
		TypeAlertChannelTarget:   `{"channel_id":"%s","target":"new@x.example"}`,
		TypeAlertChannelSeverity: `{"channel_id":"%s","min_severity":"critical"}`,
	}
	var n int
	inTenant(t, db, func(tx *store.TenantTx) error {
		e := svc.env(tx, time.Now(), uuid.Nil)
		for name, typ := range changeTypes {
			if !typ.keepSummary {
				continue
			}
			n++
			for _, id := range []string{hook.ID, mail.ID, "ch-gone"} {
				raw := payloads[name]
				if raw == "" {
					raw = `{"channel_id":"%s"}`
				}
				v, _, err := typ.decode([]byte(strings.Replace(raw, "%s", id, 1)))
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				// the applied text (typ.summary) and the text kept at filing (what describe stores) both
				filed := &store.AdminChange{ID: uuid.New(), Type: name, Status: store.ChangePendingApproval, Payload: []byte(strings.Replace(raw, "%s", id, 1))}
				for what, got := range map[string]string{"applied": typ.summary(e, v), "filing": clipSummary(e.describe(filed))} {
					for _, bad := range []string{tok, secret, "hooks.slack.com", "https://", "http://", "/services/"} {
						if strings.Contains(got, bad) {
							t.Errorf("%s %s summary for %s leaks %q: %s", name, what, id, bad, got)
						}
					}
				}
			}
		}
		return nil
	})
	if n == 0 {
		t.Fatal("no keepSummary types found")
	}
}

func inTenant(t *testing.T, db *store.DB, fn func(tx *store.TenantTx) error) {
	t.Helper()
	if err := db.InTenant(context.Background(), summaryTenant, fn); err != nil {
		t.Fatal(err)
	}
}

// A request closed without being applied (or failed) keeps the channel name it had when filed. A channel renamed since
// then (no second admin needed) shows its current name alongside; a deleted channel keeps the stored text.
func TestClosedSummaryShowsCurrentChannelName(t *testing.T) {
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, summaryTenant, "acme")
	svc := &Service{DB: db}
	now := time.Now()
	email := "req@x.example"
	user := &store.PlatformUser{Email: &email, DisplayName: "req", CreatedAt: now}
	mkCh := func(id, name string) *store.AlertChannel {
		return &store.AlertChannel{ID: id, Name: name, Kind: "email", Target: "a@x.example", MinSeverity: "low", Enabled: true, CreatedAt: now, UpdatedAt: now}
	}
	inTenant(t, db, func(tx *store.TenantTx) error {
		if err := tx.InsertPlatformUser(user); err != nil {
			return err
		}
		if err := tx.InsertAlertChannel(mkCh("ch-ren", "Old name")); err != nil {
			return err
		}
		return tx.InsertAlertChannel(mkCh("ch-del", "Doomed"))
	})
	for _, status := range []string{store.ChangeRejected, store.ChangeCancelled, store.ChangeExpired, store.ChangeFailed} {
		t.Run(status, func(t *testing.T) {
			file := func(tx *store.TenantTx, id string) *store.AdminChange {
				ch := &store.AdminChange{Type: TypeAlertChannelDisable, Payload: []byte(`{"channel_id":"` + id + `"}`), PayloadHash: strings.Repeat("a", 64),
					Status: store.ChangePendingApproval, TwoPerson: true, RequestedBy: user.ID, RequestedAt: now, ExpiresAt: now.Add(time.Hour)}
				if err := tx.InsertAdminChange(ch); err != nil {
					t.Fatal(err)
				}
				if err := tx.SetAdminChangeSummary(ch.ID, clipSummary(svc.env(tx, now, uuid.Nil).describe(ch))); err != nil {
					t.Fatal(err)
				}
				ch.Status = status
				return ch
			}
			inTenant(t, db, func(tx *store.TenantTx) error {
				ren, del := file(tx, "ch-ren"), file(tx, "ch-del")
				e := svc.env(tx, now, uuid.Nil)
				if got := e.describe(ren); strings.Contains(got, "(now") || !strings.Contains(got, `"Old name"`) {
					t.Errorf("unrenamed: %q", got)
				}
				c, _ := tx.AlertChannel("ch-ren")
				c.Name = "New name"
				if err := tx.UpdateAlertChannel(c); err != nil {
					return err
				}
				got := e.describe(ren)
				if !strings.Contains(got, `"Old name"`) || !strings.HasSuffix(got, ` (now "New name")`) {
					t.Errorf("renamed: %q", got)
				}
				if err := tx.DeleteAlertChannel("ch-del"); err != nil {
					return err
				}
				if got := e.describe(del); !strings.Contains(got, `"Doomed"`) || strings.Contains(got, "(now") {
					t.Errorf("deleted: %q", got)
				}
				// reset for the next status
				c.Name = "Old name"
				if err := tx.UpdateAlertChannel(c); err != nil {
					return err
				}
				return tx.InsertAlertChannel(mkCh("ch-del", "Doomed"))
			})
		})
	}
}
