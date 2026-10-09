package connectors

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

// Simulated validation for the demo connectors (design §5.5). A scenario
// gives selected checks a result per template; every other check runs its
// real logic against a healthy simulated system. Nothing here touches the
// network.

//go:embed demo_readiness/*.yaml
var scenarioFS embed.FS

// DefaultScenario is used when TESSERA_READINESS_SCENARIO is unset.
const DefaultScenario = "gaps"

// Scenario is one demo_readiness/*.yaml file.
type Scenario struct {
	Name        string                          `yaml:"scenario"`
	Description string                          `yaml:"description"`
	Templates   map[string]map[string]SimResult `yaml:"templates"`
}

var (
	scenarioOnce sync.Once
	scenarios    map[string]*Scenario
	scenarioErr  error
)

// Scenarios returns the embedded scenarios by name.
func Scenarios() (map[string]*Scenario, error) {
	scenarioOnce.Do(func() {
		scenarios = map[string]*Scenario{}
		files, err := scenarioFS.ReadDir("demo_readiness")
		if err != nil {
			scenarioErr = err
			return
		}
		for _, f := range files {
			data, err := scenarioFS.ReadFile("demo_readiness/" + f.Name())
			if err != nil {
				scenarioErr = err
				return
			}
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			var s Scenario
			if err := dec.Decode(&s); err != nil {
				scenarioErr = fmt.Errorf("scenario %s: %w", f.Name(), err)
				return
			}
			for tid, checks := range s.Templates {
				for id, r := range checks {
					if !slices.Contains([]string{"pass", "warn", "fail", "error"}, r.Status) {
						scenarioErr = fmt.Errorf("scenario %s: %s.%s: bad status %q", s.Name, tid, id, r.Status)
						return
					}
				}
			}
			scenarios[s.Name] = &s
		}
	})
	return scenarios, scenarioErr
}

// ScenarioNames lists the available scenarios.
func ScenarioNames() []string {
	s, _ := Scenarios()
	var out []string
	for n := range s {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ScenarioProber is a simulated system for one template under one scenario.
type ScenarioProber struct {
	TemplateID string
	Scenario   string
	Now        time.Time
	BaseDNs    []string
	fixed      map[string]bool
	overrides  map[string]SimResult
}

// NewScenarioProber builds the simulated system. fixed lists check ids whose
// fixable scenario failure was "fixed" (the demo scenario toggle).
func NewScenarioProber(templateID, scenario string, now time.Time, baseDNs, fixed []string) (*ScenarioProber, error) {
	all, err := Scenarios()
	if err != nil {
		return nil, err
	}
	sc, ok := all[scenario]
	if !ok {
		return nil, fmt.Errorf("connectors: unknown readiness scenario %q (have %s)", scenario, strings.Join(ScenarioNames(), ", "))
	}
	p := &ScenarioProber{TemplateID: templateID, Scenario: scenario, Now: now, BaseDNs: baseDNs,
		fixed: map[string]bool{}, overrides: sc.Templates[templateID]}
	for _, f := range fixed {
		p.fixed[f] = true
	}
	return p, nil
}

// Override implements Simulator.
func (p *ScenarioProber) Override(checkID string) (SimResult, bool) {
	r, ok := p.overrides[checkID]
	if !ok || (r.Fixable && p.fixed[checkID]) {
		return SimResult{}, false
	}
	return r, true
}

// Connect implements Prober: TLS 1.3, a valid chain, 212 days to expiry.
func (p *ScenarioProber) Connect(ctx context.Context) (ConnInfo, error) {
	return ConnInfo{Reachable: true, TLSVersion: "1.3", ChainValid: true, HostnameMatch: true,
		NotAfter: p.Now.AddDate(0, 0, 212), Issuer: "Larkspur Labs Issuing CA 2"}, ctx.Err()
}

// Authenticate implements Prober with the least-privilege grant for the template.
func (p *ScenarioProber) Authenticate(ctx context.Context) (AuthInfo, error) {
	exp := p.Now.AddDate(0, 0, 212)
	a := AuthInfo{OK: true, ExpiresAt: &exp}
	switch p.TemplateID {
	case "ad":
		a.Identity, a.Mode = "CN=svc-tessera-read,OU=Service Accounts,DC=corp,DC=larkspur,DC=example", "simple_bind"
	case "ldap":
		a.Identity, a.Mode = "uid=tessera-read,ou=services,dc=larkspur,dc=example", "simple_bind"
	case "entra":
		a.Identity, a.Mode = "app:5f0c1e2a-tessera", "certificate"
		a.Roles = []string{"User.Read.All", "GroupMember.Read.All", "AuditLog.Read.All", "RoleManagement.Read.Directory"}
	case "okta":
		a.Identity, a.Mode = "0oa-tessera-service-app", "oauth_private_key_jwt"
		a.Scopes = []string{"okta.users.read", "okta.groups.read", "okta.apps.read", "okta.logs.read", "okta.roles.read"}
	case "google":
		a.Identity, a.Mode = "tessera-read@tessera-larkspur.iam.gserviceaccount.com", "federation"
		a.Scopes = []string{"admin.directory.user.readonly", "admin.directory.group.readonly",
			"admin.directory.group.member.readonly", "admin.reports.audit.readonly"}
		a.RefusedScopes = []string{"admin.directory.user"}
	case "workday":
		a.Identity, a.Mode = "ISU_Tessera", "basic"
	case "scim_app":
		a.Identity, a.Mode = "tessera-scim-client", "oauth_client_credentials"
	}
	return a, ctx.Err()
}

// RootInfo implements Prober.
func (p *ScenarioProber) RootInfo(ctx context.Context) (RootInfo, error) {
	return RootInfo{Servers: 2, Domains: []string{"corp.larkspur.example"}, ConfiguredDomains: []string{"corp.larkspur.example"},
		RecycleBin: true, Capabilities: []string{"paged_results", "filter", "etag", "patch"}, CustomAttributes: 3,
		OrgUnits: 12}, ctx.Err()
}

// ObjectExists implements Prober: every configured object exists.
func (p *ScenarioProber) ObjectExists(ctx context.Context, ref string) (bool, error) {
	return ref != "", ctx.Err()
}

// Sample implements Prober: every requested attribute is returned.
func (p *ScenarioProber) Sample(ctx context.Context, q SampleQuery) (SampleStats, error) {
	n := q.Limit
	if n <= 0 || n > MaxSample {
		n = MaxSample
	}
	s := SampleStats{Objects: n, PerClass: map[string]int{}, AttrFill: map[string]int{}, PagedBeyond: true,
		LargestGroup: "Engineering", RangedCount: 312, FullCount: 312, Available: true,
		Fields: []string{"worker_id", "worker_type", "legal_name", "preferred_name", "status", "hire_date",
			"termination_date", "manager", "supervisory_org", "cost_center", "location", "work_email"}}
	for _, c := range q.Classes {
		s.PerClass[c] = n / max(1, len(q.Classes))
	}
	for _, a := range q.Attrs {
		s.AttrFill[a] = n
	}
	return s, ctx.Err()
}

// EffectiveRights implements Prober: read-only, no privileged membership.
func (p *ScenarioProber) EffectiveRights(ctx context.Context, ref string) (Rights, error) {
	r := Rights{}
	switch p.TemplateID {
	case "okta":
		r.AdminRoles = []string{"READ_ONLY_ADMIN"}
	case "google":
		r.AdminRoles = []string{"Tessera read-only"}
	}
	return r, ctx.Err()
}

// ChangeFeed implements Prober.
func (p *ScenarioProber) ChangeFeed(ctx context.Context) (FeedInfo, error) {
	mech := map[string]string{"ad": "usn", "ldap": "syncrepl", "entra": "delta", "okta": "system_log",
		"google": "reports_api", "workday": "transaction_log"}[p.TemplateID]
	return FeedInfo{Supported: true, Mechanism: mech}, ctx.Err()
}

// RateLimits implements Prober.
func (p *ScenarioProber) RateLimits(ctx context.Context) (RateInfo, error) {
	return RateInfo{Limit: 1000, Remaining: 910}, ctx.Err()
}

// Time implements Prober: three seconds of skew.
func (p *ScenarioProber) Time(ctx context.Context) (time.Time, error) {
	return p.Now.Add(3 * time.Second), ctx.Err()
}
