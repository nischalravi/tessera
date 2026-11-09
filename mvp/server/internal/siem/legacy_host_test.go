package siem_test

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A sink saved before the ASCII-host rule (#939) can still be disabled and renamed: an update that keeps the stored
// target is not refused. A new or changed non-ASCII target still is (#943).
func TestUpdateSink_LegacyNonASCIITarget(t *testing.T) {
	w := newWorld(t)
	k := w.create(t, siem.SinkSpec{Name: "Hook", Kind: "webhook", Format: siem.FormatJSON, Flavor: siem.FlavorJSON,
		Target: "https://siem.example.com/in", Enabled: true})
	const legacy = "https://bücher.example/legacy"
	w.write(t, func(tx *store.TenantTx) error {
		s, err := tx.SiemSink(k.ID)
		if err != nil {
			return err
		}
		s.Target = legacy // as it was stored before the rule
		return tx.UpdateSiemSink(s)
	})
	spec := func(name, target string, enabled bool) siem.SinkSpec {
		return siem.SinkSpec{Name: name, Kind: "webhook", Format: siem.FormatJSON, Flavor: siem.FlavorJSON, Target: target, Enabled: enabled}
	}
	if _, err := w.update(k.ID, spec("Hook", legacy, false)); err != nil {
		t.Errorf("disable with the stored legacy target: %v", err)
	}
	if _, err := w.update(k.ID, spec("Renamed", legacy, false)); err != nil {
		t.Errorf("rename with the stored legacy target: %v", err)
	}
	for _, target := range []string{"https://bücher.example/other", "https://exämple.com/x", "https://h%E2%88%B6x.example/x"} {
		var e *siem.Error
		if _, err := w.update(k.ID, spec("Hook", target, false)); !errors.As(err, &e) || e.Code != siem.CodeURLNonASCIIAuthority {
			t.Errorf("a changed non-ASCII target %q: %v", target, err)
		}
	}
}
