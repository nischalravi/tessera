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
				got := typ.summary(e, v)
				for _, bad := range []string{tok, secret, "hooks.slack.com", "https://", "http://", "/services/"} {
					if strings.Contains(got, bad) {
						t.Errorf("%s summary for %s leaks %q: %s", name, id, bad, got)
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
