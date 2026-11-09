package alerts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A channel saved before the ASCII-host rule (#939) can still be disabled and renamed: an update that keeps the stored
// target is not refused. A new or changed non-ASCII target still is (#943).
func TestUpdateChannel_LegacyNonASCIITarget(t *testing.T) {
	w := newWorld(t)
	var ch *store.AlertChannel
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		ch, _, err = alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Hook", Kind: "webhook", Target: "https://hooks.example.com/a",
			MinSeverity: "low", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	const legacy = "https://bücher.example/legacy"
	w.write(t, func(tx *store.TenantTx) error {
		c, err := tx.AlertChannel(ch.ID)
		if err != nil {
			return err
		}
		c.Target = legacy // as it was stored before the rule
		return tx.UpdateAlertChannel(c)
	})
	update := func(spec alerts.ChannelSpec) error {
		return w.st.InTenant(audit.WithSystemActor(context.Background(), "test"), w.st.Tenant, func(tx *store.TenantTx) error {
			_, _, err := alerts.UpdateChannel(tx, w.sealer, ch.ID, spec, true, alerts.Actor{Display: "test"}, w.now)
			return err
		})
	}
	if err := update(alerts.ChannelSpec{Name: "Hook", Target: legacy, MinSeverity: "low", Enabled: true}); err != nil {
		t.Errorf("rename an enabled channel with the stored legacy target: %v", err)
	}
	if err := update(alerts.ChannelSpec{Name: "Hook", Target: legacy, MinSeverity: "low", Enabled: false}); err != nil {
		t.Errorf("disable with the stored legacy target: %v", err)
	}
	if err := update(alerts.ChannelSpec{Name: "Renamed", Target: legacy, MinSeverity: "high", Enabled: false}); err != nil {
		t.Errorf("rename with the stored legacy target: %v", err)
	}
	// enabling the disabled legacy channel is refused: its host can never be dialed
	var ee *alerts.Error
	if err := update(alerts.ChannelSpec{Name: "Renamed", Target: legacy, MinSeverity: "high", Enabled: true}); !errors.As(err, &ee) || ee.Code != alerts.CodeURLNonASCIIAuthority {
		t.Errorf("enable with the stored legacy target: %v", err)
	}
	for _, target := range []string{"https://BÜCHER.example/legacy", "https://bücher.example:443/legacy", "https://bücher.example/other", "https://exämple.com/x", "https://h%E2%88%B6x.example/x"} {
		var e *alerts.Error
		if err := update(alerts.ChannelSpec{Name: "Hook", Target: target, MinSeverity: "low", Enabled: false}); !errors.As(err, &e) || e.Code != alerts.CodeURLNonASCIIAuthority {
			t.Errorf("a changed non-ASCII target %q: %v", target, err)
		}
	}
}
