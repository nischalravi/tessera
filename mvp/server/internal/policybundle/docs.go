package policybundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
)

// Schema tags of the YAML documents (design §3).
const (
	TagRepo = "tessera.repo/v1"
	TagRole = "tessera.role/v1"
	TagJit  = "tessera.jit/v1"
	TagSod  = "tessera.sod/v1" // reused unchanged from internal/sod
	TagTest = "tessera.test/v1"
)

// maxJitHours mirrors jit.MaxHours (72); a test keeps them equal.
const maxJitHours = 72

var (
	keyRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	entRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*:[^\s:][^\s]*$`)
	slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// decode reads one YAML document into v, refusing unknown fields, an empty file
// and a second document. Anchors and aliases are refused: a repository file has
// no use for them and they are how a small file expands into a large value.
func decode(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("the file is empty")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if hasAlias(&root, 0) {
		return errors.New("YAML anchors and aliases are not accepted")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("the file holds more than one document")
	}
	return nil
}

func hasAlias(n *yaml.Node, depth int) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return true
	}
	if depth > 64 {
		return true // deeper than any bundle file needs
	}
	for _, c := range n.Content {
		if hasAlias(c, depth+1) {
			return true
		}
	}
	return false
}

// Config is tessera.yaml.
type Config struct {
	Schema string            `yaml:"schema"`
	Tenant string            `yaml:"tenant"`
	Manage map[string]string `yaml:"manage"`
}

var manageKinds = []string{"roles", "sod", "jit", "invariants", "agents", "birthright"}

func (l *loader) loadConfig() {
	data, ok := l.files[ConfigFile]
	if !ok {
		l.add(ConfigFile, 0, "missing", "the repository root needs tessera.yaml (schema: %s)", TagRepo)
		return
	}
	var c Config
	if err := decode(data, &c); err != nil {
		l.addErr(ConfigFile, err)
		return
	}
	if c.Schema != TagRepo {
		l.add(ConfigFile, 0, "invalid_schema", "schema is %q; this CLI reads %q", c.Schema, TagRepo)
	}
	if !slugRE.MatchString(c.Tenant) {
		l.add(ConfigFile, 0, "invalid_tenant", "tenant must be the tenant slug (lower-case letters, digits, '-')")
	}
	for k, m := range c.Manage {
		if !contains(manageKinds, k) {
			l.add(ConfigFile, 0, "invalid_manage", "unknown kind %q under manage (one of %s)", k, strings.Join(manageKinds, ", "))
		}
		if m != "full" && m != "partial" {
			l.add(ConfigFile, 0, "invalid_manage", "manage.%s is %q; use full or partial", k, m)
		}
	}
	l.b.Config = c
}

// Role is roles/<key>.yaml.
type Role struct {
	Path         string   `yaml:"-"`
	Schema       string   `yaml:"schema"`
	Key          string   `yaml:"key"`
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Owner        string   `yaml:"owner"`
	Risk         string   `yaml:"risk"`
	Requestable  bool     `yaml:"requestable"`
	Entitlements []string `yaml:"entitlements"`
}

// Jit is jit/<key>.yaml.
type Jit struct {
	Path         string   `yaml:"-"`
	Schema       string   `yaml:"schema"`
	Key          string   `yaml:"key"`
	Principals   []string `yaml:"principals"`
	Entitlements []string `yaml:"entitlements"`
	MaxHours     int      `yaml:"max_hours"`
	Approvers    []string `yaml:"approvers"`
	MinApprovals int      `yaml:"min_approvals"`
	StepUp       bool     `yaml:"step_up"`
}

var roleRisks = []string{"low", "medium", "high"} // requests.Risks

const maxList = 200

func (l *loader) yamlFiles(dir string) []string {
	var out []string
	for _, p := range l.paths(dir) {
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			l.add(p, 0, "unexpected_file", "%s/ holds .yaml files only", dir)
			continue
		}
		out = append(out, p)
	}
	return out
}

func (l *loader) refList(p, what string, list []string, nonEmpty bool) {
	if nonEmpty && len(list) == 0 {
		l.add(p, 0, "invalid_"+what, "%s must not be empty", what)
	}
	if len(list) > maxList {
		l.add(p, 0, "invalid_"+what, "%s lists %d entries; at most %d", what, len(list), maxList)
		return
	}
	seen := map[string]bool{}
	for _, e := range list {
		switch {
		case !entRE.MatchString(e) || len(e) > 256:
			l.add(p, 0, "invalid_"+what, "%q is not a system:name reference", e)
		case seen[e]:
			l.add(p, 0, "invalid_"+what, "%q is listed twice", e)
		}
		seen[e] = true
	}
}

func (l *loader) loadRoles() {
	keys := map[string]string{}
	for _, p := range l.yamlFiles(DirRoles) {
		var r Role
		if err := decode(l.files[p], &r); err != nil {
			l.addErr(p, err)
			continue
		}
		r.Path = p
		if r.Schema != TagRole {
			l.add(p, 0, "invalid_schema", "schema is %q; expected %q", r.Schema, TagRole)
		}
		if !keyRE.MatchString(r.Key) {
			l.add(p, 0, "invalid_key", "key is 1 to 64 letters, digits, '.', '_', ':' or '-'")
		} else if q := keys[r.Key]; q != "" {
			l.add(p, 0, "duplicate_key", "role %q is also defined in %s", r.Key, q)
		} else {
			keys[r.Key] = p
		}
		if n := strings.TrimSpace(r.Name); n == "" || len(n) > 120 {
			l.add(p, 0, "invalid_name", "name is 1 to 120 characters")
		}
		if !contains(roleRisks, r.Risk) {
			l.add(p, 0, "invalid_risk", "risk is one of %s", strings.Join(roleRisks, ", "))
		}
		l.refList(p, "entitlements", r.Entitlements, false)
		l.b.Roles = append(l.b.Roles, r)
	}
}

func (l *loader) loadJit() {
	keys := map[string]string{}
	for _, p := range l.yamlFiles(DirJit) {
		var j Jit
		if err := decode(l.files[p], &j); err != nil {
			l.addErr(p, err)
			continue
		}
		j.Path = p
		if j.Schema != TagJit {
			l.add(p, 0, "invalid_schema", "schema is %q; expected %q", j.Schema, TagJit)
		}
		if !keyRE.MatchString(j.Key) {
			l.add(p, 0, "invalid_key", "key is 1 to 64 letters, digits, '.', '_', ':' or '-'")
		} else if q := keys[j.Key]; q != "" {
			l.add(p, 0, "duplicate_key", "eligibility %q is also defined in %s", j.Key, q)
		} else {
			keys[j.Key] = p
		}
		l.refList(p, "principals", j.Principals, true)
		l.refList(p, "entitlements", j.Entitlements, true)
		l.refList(p, "approvers", j.Approvers, false)
		if j.MaxHours < 1 || j.MaxHours > maxJitHours {
			l.add(p, 0, "invalid_max_hours", "max_hours is 1 to %d", maxJitHours)
		}
		if j.MinApprovals < 0 || j.MinApprovals > len(j.Approvers) {
			l.add(p, 0, "invalid_min_approvals", "min_approvals is 0 to the number of approvers (%d)", len(j.Approvers))
		}
		l.b.Jit = append(l.b.Jit, j)
	}
	l.buildEntities()
}

// SodFile is sod/<ruleset-key>.yaml: internal/sod's tessera.sod/v1 document. The
// types mirror sod.Bundle's YAML so this package stays free of the database
// layer that internal/sod links; a test round-trips the two.
type SodFile struct {
	Path      string        `yaml:"-"`
	Schema    string        `yaml:"schema"`
	Ruleset   SodRuleset    `yaml:"ruleset"`
	Functions []SodFunction `yaml:"functions"`
	Risks     []SodRisk     `yaml:"risks"`
}

// SodRuleset is the ruleset of a SodFile.
type SodRuleset struct {
	Key         string `yaml:"key"`
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Enabled     *bool  `yaml:"enabled"`
}

// SodFunction is a function of a SodFile.
type SodFunction struct {
	Key         string        `yaml:"key"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description,omitempty"`
	Owner       string        `yaml:"owner,omitempty"`
	Selectors   []SodSelector `yaml:"selectors"`
}

// SodSelector matches entitlements.
type SodSelector struct {
	System        string `yaml:"system,omitempty"`
	EntitlementID *int64 `yaml:"entitlement_id,omitempty"`
	NamePattern   string `yaml:"name_pattern,omitempty"`
	Attribute     string `yaml:"attribute,omitempty"`
	Value         string `yaml:"value,omitempty"`
}

// SodRisk is a risk of a SodFile.
type SodRisk struct {
	Key             string    `yaml:"key"`
	Name            string    `yaml:"name"`
	Description     string    `yaml:"description,omitempty"`
	Priority        string    `yaml:"priority"`
	BusinessProcess string    `yaml:"business_process,omitempty"`
	Owner           string    `yaml:"owner,omitempty"`
	Functions       []string  `yaml:"functions"`
	Subjects        *struct { // opaque here; the server checks it on apply
		IdentityTypes []string `yaml:"identity_types,omitempty"`
		Statuses      []string `yaml:"statuses,omitempty"`
		Condition     any      `yaml:"condition,omitempty"`
	} `yaml:"subjects,omitempty"`
	Remediation []string `yaml:"remediation,omitempty"`
}

var (
	priorities  = []string{"critical", "high", "medium", "low"}
	remediation = []string{"revoke", "mitigate", "accept", "escalate"}
)

const (
	maxSodItems     = 500
	maxRiskFunction = 10
)

func (l *loader) loadSod() {
	keys := map[string]string{}
	for _, p := range l.yamlFiles(DirSod) {
		var s SodFile
		if err := decode(l.files[p], &s); err != nil {
			l.addErr(p, err)
			continue
		}
		s.Path = p
		if s.Schema != TagSod {
			l.add(p, 0, "invalid_schema", "schema is %q; expected %q", s.Schema, TagSod)
		}
		if !keyRE.MatchString(s.Ruleset.Key) {
			l.add(p, 0, "invalid_key", "ruleset.key is 1 to 64 letters, digits, '.', '_', ':' or '-'")
		} else if q := keys[s.Ruleset.Key]; q != "" {
			l.add(p, 0, "duplicate_key", "ruleset %q is also defined in %s", s.Ruleset.Key, q)
		} else {
			keys[s.Ruleset.Key] = p
		}
		l.checkSod(&s)
		l.b.Sod = append(l.b.Sod, s)
	}
}

func (l *loader) checkSod(s *SodFile) {
	p := s.Path
	if len(s.Functions) > maxSodItems || len(s.Risks) > maxSodItems {
		l.add(p, 0, "invalid_document", "at most %d functions and %d risks per ruleset", maxSodItems, maxSodItems)
		return
	}
	fns := map[string]bool{}
	for _, f := range s.Functions {
		switch {
		case !keyRE.MatchString(f.Key):
			l.add(p, 0, "invalid_key", "function key %q is not a valid key", f.Key)
		case fns[f.Key]:
			l.add(p, 0, "duplicate_key", "function %q is listed twice", f.Key)
		}
		fns[f.Key] = true
		if len(f.Selectors) == 0 || len(f.Selectors) > 50 {
			l.add(p, 0, "invalid_selectors", "function %s needs 1 to 50 selectors", f.Key)
		}
	}
	risks := map[string]bool{}
	for _, r := range s.Risks {
		switch {
		case !keyRE.MatchString(r.Key):
			l.add(p, 0, "invalid_key", "risk key %q is not a valid key", r.Key)
		case risks[r.Key]:
			l.add(p, 0, "duplicate_key", "risk %q is listed twice", r.Key)
		}
		risks[r.Key] = true
		if !contains(priorities, r.Priority) {
			l.add(p, 0, "invalid_priority", "risk %s: priority is one of %s", r.Key, strings.Join(priorities, ", "))
		}
		if len(r.Functions) < 2 || len(r.Functions) > maxRiskFunction {
			l.add(p, 0, "invalid_functions", "risk %s needs 2 to %d functions", r.Key, maxRiskFunction)
		}
		seen := map[string]bool{}
		for _, k := range r.Functions {
			switch {
			case !fns[k]:
				l.add(p, 0, "invalid_functions", "risk %s names function %q, which the file does not define", r.Key, k)
			case seen[k]:
				l.add(p, 0, "invalid_functions", "risk %s names function %q twice", r.Key, k)
			}
			seen[k] = true
		}
		for _, o := range r.Remediation {
			if !contains(remediation, o) {
				l.add(p, 0, "invalid_remediation", "risk %s: remediation options are %s", r.Key, strings.Join(remediation, ", "))
			}
		}
	}
}

// buildEntities makes the Role and JitEligibility entities of the bundle, and
// the Group entities they name, and checks them against the schema.
func (l *loader) buildEntities() {
	groups := map[string]bool{}
	var ents []map[string]any
	ref := func(typ, id string) map[string]any {
		return map[string]any{"__entity": map[string]any{"type": "Tessera::" + typ, "id": id}}
	}
	refs := func(list []string) []any {
		out := []any{}
		for _, g := range list {
			if !groups[g] && entRE.MatchString(g) {
				groups[g] = true
				sys, name, _ := strings.Cut(g, ":")
				ents = append(ents, map[string]any{
					"uid":   map[string]any{"type": "Tessera::Group", "id": g},
					"attrs": map[string]any{"system": sys, "name": name, "privileged": false, "requestable": false}, "parents": []any{},
				})
			}
			out = append(out, ref("Group", g))
		}
		return out
	}
	for _, r := range l.b.Roles {
		ents = append(ents, map[string]any{
			"uid": map[string]any{"type": "Tessera::Role", "id": r.Key}, "parents": []any{},
			"attrs": map[string]any{"key": r.Key, "name": r.Name, "risk": r.Risk, "requestable": r.Requestable, "entitlements": refs(r.Entitlements)},
		})
	}
	for _, j := range l.b.Jit {
		ents = append(ents, map[string]any{
			"uid": map[string]any{"type": "Tessera::JitEligibility", "id": j.Key}, "parents": []any{},
			"attrs": map[string]any{"key": j.Key, "principals": refs(j.Principals), "entitlements": refs(j.Entitlements),
				"max_hours": j.MaxHours, "approvers": refs(j.Approvers), "min_approvals": j.MinApprovals, "step_up": j.StepUp},
		})
	}
	sort.Slice(ents, func(a, b int) bool {
		return fmt.Sprint(ents[a]["uid"]) < fmt.Sprint(ents[b]["uid"])
	})
	raw, err := json.Marshal(ents)
	if err != nil {
		l.add(".", 0, "internal", "%v", err)
		return
	}
	set, err := cedarx.ParseEntities(raw)
	if err == nil && len(l.diags) == 0 { // type errors of a file already refused would only repeat
		err = l.b.Schema.ValidateSet(set)
	}
	if err != nil {
		l.addErr("roles", err)
		return
	}
	l.b.entities = set
}
