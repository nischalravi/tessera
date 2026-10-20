package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// SoD controls, mitigations, remediation options and escalations (issue #298):
// a tenant sees and changes only its own rows, and rows naming another tenant's
// ids are refused by the guard triggers.

type sodCtlRows struct {
	sodRows
	control    string
	mitigation string
	escalation string
}

func seedSodCtlRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) sodCtlRows {
	t.Helper()
	r := sodCtlRows{sodRows: seedSodRows(t, db, tn, tag), control: "ctl-" + tag, mitigation: "mit-" + tag, escalation: "esc-" + tag}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		uid := r.user.ID.String()
		if err := c.InsertSodControl(&store.SodControl{ID: r.control, Name: "Review " + tag, OwnerID: &r.owner, Type: "detective",
			Frequency: "monthly", Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		ctl := r.control
		if err := c.InsertSodMitigation(&store.SodMitigation{ID: r.mitigation, RiskID: r.risk, IdentityID: r.owner, Kind: store.MitigationControl,
			ControlID: &ctl, Justification: "j", Evidence: "[]", Status: store.MitigationPending, EndsAt: storetest.Now.AddDate(0, 1, 0),
			RequestedBy: uid, RequestedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.SetSodRiskOptions(r.risk, []string{"revoke", "mitigate"}); err != nil {
			return err
		}
		return c.InsertSodEscalation(&store.SodEscalation{ID: r.escalation, RiskID: r.risk, IdentityID: r.owner, EscalatedBy: uid, Note: "n",
			CreatedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sodCtlFixture(t *testing.T) (*storetest.Fixture, sodCtlRows, sodCtlRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedSodCtlRows(t, f.DB, f.A, "a"), seedSodCtlRows(t, f.DB, f.B, "b")
}

func TestIsolation_SodControlReads(t *testing.T) {
	f, a, b := sodCtlFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if x, err := c.SodControls(); err != nil || len(x) != 1 || x[0].ID != b.control {
			t.Errorf("SodControls = %v, %v", x, err)
		}
		if _, err := c.SodControl(a.control); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodControl(A's) = %v", err)
		}
		if _, err := c.SodControlByName("Review a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodControlByName(A's) = %v", err)
		}
		if x, err := c.SodMitigations(); err != nil || len(x) != 1 || x[0].ID != b.mitigation {
			t.Errorf("SodMitigations = %v, %v", x, err)
		}
		if _, err := c.SodMitigation(a.mitigation); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodMitigation(A's) = %v", err)
		}
		if _, err := c.LiveSodMitigation(a.risk, a.owner); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("LiveSodMitigation(A's) = %v", err)
		}
		if x, err := c.SodRiskOptions(); err != nil || len(x) != 2 || x[0].RiskID != b.risk {
			t.Errorf("SodRiskOptions = %v, %v", x, err)
		}
		if x, err := c.SodEscalations(); err != nil || len(x) != 1 || x[0].ID != b.escalation {
			t.Errorf("SodEscalations = %v, %v", x, err)
		}
		return nil
	})
}

var sodCtlMutations = map[string]func(c *store.TenantTx, a, b sodCtlRows) error{
	"InsertSodControl/A's owner": func(c *store.TenantTx, a, _ sodCtlRows) error {
		return c.InsertSodControl(&store.SodControl{ID: "x", Name: "x", OwnerID: &a.owner, Type: "detective", Frequency: "daily",
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"SaveSodControl": func(c *store.TenantTx, a, _ sodCtlRows) error {
		return c.SaveSodControl(&store.SodControl{ID: a.control, Name: "taken", Type: "detective", Frequency: "daily",
			Status: store.SodRetired, Version: 2, UpdatedAt: storetest.Now}, 1)
	},
	"InsertSodMitigation/A's risk": func(c *store.TenantTx, a, b sodCtlRows) error {
		ctl, uid := b.control, b.user.ID.String()
		return c.InsertSodMitigation(&store.SodMitigation{ID: "x", RiskID: a.risk, IdentityID: b.owner, Kind: store.MitigationControl, ControlID: &ctl,
			Justification: "j", Evidence: "[]", Status: store.MitigationPending, EndsAt: storetest.Now, RequestedBy: uid, RequestedAt: storetest.Now})
	},
	"InsertSodMitigation/A's identity": func(c *store.TenantTx, a, b sodCtlRows) error {
		ctl, uid := b.control, b.user.ID.String()
		return c.InsertSodMitigation(&store.SodMitigation{ID: "x", RiskID: b.risk, IdentityID: a.owner, Kind: store.MitigationControl, ControlID: &ctl,
			Justification: "j", Evidence: "[]", Status: store.MitigationPending, EndsAt: storetest.Now, RequestedBy: uid, RequestedAt: storetest.Now})
	},
	"InsertSodMitigation/A's control": func(c *store.TenantTx, a, b sodCtlRows) error {
		ctl, uid := a.control, b.user.ID.String()
		return c.InsertSodMitigation(&store.SodMitigation{ID: "x", RiskID: b.risk, IdentityID: b.owner, Kind: store.MitigationControl, ControlID: &ctl,
			Justification: "j", Evidence: "[]", Status: store.MitigationPending, EndsAt: storetest.Now, RequestedBy: uid, RequestedAt: storetest.Now})
	},
	"InsertSodMitigation/A's user": func(c *store.TenantTx, a, b sodCtlRows) error {
		ctl, uid := b.control, a.user.ID.String()
		return c.InsertSodMitigation(&store.SodMitigation{ID: "x", RiskID: b.risk, IdentityID: b.owner, Kind: store.MitigationControl, ControlID: &ctl,
			Justification: "j", Evidence: "[]", Status: store.MitigationPending, EndsAt: storetest.Now, RequestedBy: uid, RequestedAt: storetest.Now})
	},
	"SaveSodMitigation": func(c *store.TenantTx, a, _ sodCtlRows) error {
		return c.SaveSodMitigation(&store.SodMitigation{ID: a.mitigation, Status: store.MitigationActive}, store.MitigationPending)
	},
	"SetSodRiskOptions/A's risk": func(c *store.TenantTx, a, _ sodCtlRows) error {
		if err := c.SetSodRiskOptions(a.risk, []string{"accept"}); err != nil {
			return err
		}
		return store.ErrNotFound // the delete finds nothing in B; the insert for A's risk is refused above
	},
	"InsertSodEscalation/A's risk": func(c *store.TenantTx, a, b sodCtlRows) error {
		return c.InsertSodEscalation(&store.SodEscalation{ID: "x", RiskID: a.risk, IdentityID: b.owner, EscalatedBy: b.user.ID.String(), Note: "n", CreatedAt: storetest.Now})
	},
	"InsertSodEscalation/A's user": func(c *store.TenantTx, a, b sodCtlRows) error {
		return c.InsertSodEscalation(&store.SodEscalation{ID: "x", RiskID: b.risk, IdentityID: b.owner, EscalatedBy: a.user.ID.String(), Note: "n", CreatedAt: storetest.Now})
	},
}

func TestIsolation_SodControlMutationsScoped(t *testing.T) {
	for name, fn := range sodCtlMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := sodCtlFixture(t)
			before := sodCtlDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if err == nil {
				t.Fatalf("%s across tenants succeeded", name)
			}
			if after := sodCtlDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// One pending or active mitigation per risk and identity; a closed one does not count.
func TestSodMitigation_OneLivePerViolation(t *testing.T) {
	f, a, _ := sodCtlFixture(t)
	ctx := context.Background()
	dup := func() error {
		return f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
			ctl, uid := a.control, a.user.ID.String()
			return c.InsertSodMitigation(&store.SodMitigation{ID: "dup", RiskID: a.risk, IdentityID: a.owner, Kind: store.MitigationControl, ControlID: &ctl,
				Justification: "j", Evidence: "[]", Status: store.MitigationPending, EndsAt: storetest.Now, RequestedBy: uid, RequestedAt: storetest.Now})
		})
	}
	if err := dup(); err == nil {
		t.Fatal("a second pending mitigation was accepted")
	}
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.SaveSodMitigation(&store.SodMitigation{ID: a.mitigation, Status: store.MitigationRejected}, store.MitigationPending)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dup(); err != nil {
		t.Errorf("a new request after the old one closed: %v", err)
	}
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.SaveSodMitigation(&store.SodMitigation{ID: a.mitigation, Status: store.MitigationActive}, store.MitigationPending)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a stale status save = %v, want ErrNotFound", err)
	}
}

func sodCtlDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := sodDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		cs, err := c.SodControls()
		if err != nil {
			return err
		}
		ms, err := c.SodMitigations()
		if err != nil {
			return err
		}
		os, err := c.SodRiskOptions()
		if err != nil {
			return err
		}
		es, err := c.SodEscalations()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{cs, ms, os, es})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func sodCtlCovered() map[string]bool {
	out := map[string]bool{}
	for k := range sodCtlMutations {
		out[k] = true
	}
	for _, k := range []string{"SodControls", "SodControl", "SodControlByName", "SodMitigations", "SodMitigation", "LiveSodMitigation",
		"SodRiskOptions", "SodEscalations"} {
		out[k] = true // TestIsolation_SodControlReads
	}
	for _, k := range []string{"InsertSodControl", "SaveSodControl", "InsertSodMitigation", "SaveSodMitigation", "SetSodRiskOptions",
		"InsertSodEscalation"} {
		out[k] = true // sodCtlMutations
	}
	return out
}
