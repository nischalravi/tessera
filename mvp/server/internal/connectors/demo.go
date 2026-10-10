package connectors

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Demo connectors backed by the fictional DemoCompany. Each implements the
// same Connector interface a real connector does: replace DemoOkta with an
// Okta connector that calls the Okta API and the rest of the platform does not
// change.

// DemoSeed is the RNG seed of the demo company.
const DemoSeed = 7

type demoConnector struct {
	system, display, typeName string
	company                   *DemoCompany
}

func (d *demoConnector) System() string      { return d.system }
func (d *demoConnector) DisplayName() string { return d.display }
func (d *demoConnector) TypeName() string    { return d.typeName }

func (d *demoConnector) Discover(context.Context) (*DiscoveryResult, error) {
	return d.company.R[d.system], nil
}

func (d *demoConnector) StreamEvents(ctx context.Context, since *time.Time, yield func(Event) error) error {
	for _, ev := range d.company.Usage[d.system] {
		if since == nil || ev.Day.After(*since) {
			if err := yield(ev); err != nil {
				return err
			}
		}
	}
	if d.system == "workday" {
		for _, ev := range d.company.HrisEvents {
			if err := yield(ev); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

var demoMeta = []struct{ system, display, typeName string }{
	{"workday", "Workday (HRIS) - demo", "DemoWorkdayConnector"},
	{"okta", "Okta - demo", "DemoOktaConnector"},
	{"aws", "AWS - demo", "DemoAWSConnector"},
	{"github", "GitHub - demo", "DemoGitHubConnector"},
	{"snowflake", "Snowflake - demo", "DemoSnowflakeConnector"},
}

func newDemo(system string, company *DemoCompany) Connector {
	for _, m := range demoMeta {
		if m.system == system {
			return &demoConnector{m.system, m.display, m.typeName, company}
		}
	}
	return nil
}

// DemoConnectors returns the five demo connectors over one company.
func DemoConnectors(company *DemoCompany) []Connector {
	out := make([]Connector, 0, len(demoMeta))
	for _, m := range demoMeta {
		out = append(out, newDemo(m.system, company))
	}
	return out
}

// Factory builds a connector. now is the current time (the demo company is
// generated relative to it).
type Factory func(now time.Time) (Connector, error)

// Factories maps TESSERA_CONNECTORS names to constructors. Register a real
// connector here, e.g.
//
//	Factories["okta"] = func(time.Time) (Connector, error) {
//		return NewOktaConnector(os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN"))
//	}
var Factories = map[string]Factory{}

func init() {
	for _, m := range demoMeta {
		system := m.system
		Factories["demo-"+system] = func(now time.Time) (Connector, error) {
			return newDemo(system, GetCompany(DemoSeed, now)), nil
		}
	}
}

// Load selects connectors from a spec such as "demo" (the default) or
// "demo-workday,okta". An empty spec reads TESSERA_CONNECTORS.
func Load(spec string, now time.Time) ([]Connector, error) {
	if spec == "" {
		spec = os.Getenv("TESSERA_CONNECTORS")
	}
	if spec == "" || spec == "demo" {
		return DemoConnectors(GetCompany(DemoSeed, now)), nil
	}
	var out []Connector
	for _, name := range strings.Split(spec, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		f, ok := Factories[name]
		if !ok {
			return nil, fmt.Errorf("connectors: unknown connector %q", name)
		}
		c, err := f(now)
		if err != nil {
			return nil, fmt.Errorf("connectors: %s: %w", name, err)
		}
		out = append(out, c)
	}
	return out, nil
}
