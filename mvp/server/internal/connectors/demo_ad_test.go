package connectors

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"testing"
	"time"
)

var adNow = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func snapshot(t *testing.T, conns []Connector) string {
	t.Helper()
	var all []any
	for _, c := range conns {
		r, err := c.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var events []any
		if err := c.StreamEvents(context.Background(), nil, func(e Event) error { events = append(events, e); return nil }); err != nil {
			t.Fatal(err)
		}
		all = append(all, c.System(), r, events)
	}
	b, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDemoAD_DoesNotChangeDefaultSeed(t *testing.T) {
	company := NewDemoCompany(DemoSeed, adNow)
	before := snapshot(t, DemoConnectors(company))
	ad := NewDemoAD(company)
	if _, err := ad.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, DemoConnectors(company)); after != before {
		t.Fatal("building the simulated AD changed the demo connectors' output")
	}
	// A fresh company (what the default "demo" spec seeds) is identical too.
	if fresh := snapshot(t, DemoConnectors(NewDemoCompany(DemoSeed, adNow))); fresh != before {
		t.Fatal("demo company output is not deterministic")
	}
	conns, err := Load("demo", adNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range conns {
		if c.System() == DemoADSystem {
			t.Fatal("the default demo spec must not include the simulated AD (staging only)")
		}
	}
	if _, ok := Factories["demo-ad"]; ok {
		t.Fatal("demo-ad must not be selectable through TESSERA_CONNECTORS")
	}
	// The AD itself is deterministic.
	a, b := snapshot(t, []Connector{NewDemoAD(company)}), snapshot(t, []Connector{NewDemoAD(NewDemoCompany(DemoSeed, adNow))})
	if a != b {
		t.Fatal("simulated AD is not deterministic")
	}
}

func TestDemoAD_PlantedGaps(t *testing.T) {
	c := NewDemoCompany(DemoSeed, adNow)
	res, err := NewDemoAD(c).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	users, filled, unowned := 0, 0, 0
	sam := map[string]AccountRecord{}
	for _, a := range res.Accounts {
		sam[a.Username] = a
		if a.Kind == "user" {
			users++
			if a.Attributes["employeeID"] != "" {
				filled++
			}
		} else if a.Attributes["managedBy"] == "" {
			unowned++
		}
	}
	if pct := math.Floor(100 * float64(filled) / float64(users)); pct != 61 {
		t.Errorf("employeeID fill %d/%d = %v%%, want 61%%", filled, users, pct)
	}
	if unowned != 3 {
		t.Errorf("service accounts without owner: %d", unowned)
	}
	da := ""
	for _, g := range res.Groups {
		if g.Name == "Domain Admins" {
			da = g.ExternalID
			if !g.Privileged {
				t.Error("Domain Admins not privileged")
			}
		}
	}
	var members []string
	for _, e := range res.Edges {
		if e.Dst.ExternalID == da {
			for _, a := range res.Accounts {
				if a.ExternalID == e.Src.ExternalID {
					members = append(members, a.Username)
				}
			}
		}
	}
	slices.Sort(members)
	if !slices.Equal(members, []string{"callum.ferreira", "ingrid.lindqvist", "thandiwe.mokoena"}) {
		t.Errorf("Domain Admins: %v", members)
	}
	if a := sam["oren.whitlock"]; a.Status != "disabled" {
		t.Errorf("Oren's AD account: %s", a.Status)
	}
	// Only tier-1 identity references: never an email that ingest would auto-link.
	for _, a := range res.Accounts {
		if a.Identity != nil && (a.Identity.Email != "" || a.Identity.ExternalID != a.Attributes["employeeID"]) {
			t.Errorf("%s: identity ref %+v", a.Username, a.Identity)
		}
	}
	if res.Stats == nil || res.Stats.Classes["user"].Total != users || res.Stats.Classes["msDS-GroupManagedServiceAccount"] == nil {
		t.Errorf("stats: %+v", res.Stats)
	}
}
