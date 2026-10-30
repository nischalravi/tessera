// Package policybundle loads an access-as-code policy repository (design
// access-as-code-repo.md §3, §4) from bytes into a validated bundle, and runs
// the repository's test files against it. It is the offline half of AC-2: the
// package is pure (no file system, network, database or clock; internal/archtest
// enforces it), so a caller reads the directory and hands over Files. Every
// Cedar parse goes through internal/cedarx and its limits.
package policybundle

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
)

// Limits of a bundle (design §9). A file is at most cedarx.MaxFileBytes.
const (
	MaxFiles = 2000
	MaxBytes = 4 << 20
)

// Folders of the repository that hold bundle files (design §4). groups/ is the
// policy-group repository (GR-9), read by `tessera groups policy validate`.
const (
	DirRoles      = "roles"
	DirBirthright = "birthright"
	DirJit        = "jit"
	DirSod        = "sod"
	DirAgents     = "agents"
	DirInvariants = "invariants"
	DirTests      = "tests"
	SchemaFile    = "schema/tessera.cedarschema"
	ConfigFile    = "tessera.yaml"
)

var bundleDirs = []string{DirRoles, DirBirthright, DirJit, DirSod, DirAgents, DirInvariants, DirTests}

// Files is a repository checkout: slash-separated paths relative to its root.
type Files map[string][]byte

// Diag is one finding, at a file and, when known, a line.
type Diag struct {
	Path string
	Line int
	Code string
	Msg  string
}

func (d Diag) String() string {
	if d.Line > 0 {
		return fmt.Sprintf("%s:%d: %s: %s", d.Path, d.Line, d.Code, d.Msg)
	}
	return fmt.Sprintf("%s: %s: %s", d.Path, d.Code, d.Msg)
}

// Bundle is a loaded repository. Objects are in path order.
type Bundle struct {
	Config     Config
	Schema     *cedarx.Schema
	Roles      []Role
	Jit        []Jit
	Sod        []SodFile
	Birthright []PolicyFile
	Agents     []PolicyFile
	// AgentScopes are the agents/<key>.yaml documents (AC-7); Agents are the Cedar files of the same folder.
	AgentScopes []AgentScopeFile
	Invariants  []PolicyFile
	Tests       []TestFile
	entities    *cedarx.Entities // roles and eligibilities as entities
}

// PolicyFile is a Cedar file of a folder.
type PolicyFile struct {
	Path     string
	Policies *cedarx.Policies
}

// Load reads, parses and validates the bundle. It returns every finding it can
// find, in path order, never stopping at the first; the bundle is usable only
// when there are none. attrs are extra identity attribute names for the
// generated schema, used only when the repository has no schema file.
func Load(files Files, attrs []string) (*Bundle, []Diag) {
	l := &loader{files: files}
	l.run(attrs)
	sort.SliceStable(l.diags, func(i, j int) bool {
		if l.diags[i].Path != l.diags[j].Path {
			return l.diags[i].Path < l.diags[j].Path
		}
		return l.diags[i].Line < l.diags[j].Line
	})
	return &l.b, l.diags
}

type loader struct {
	files Files
	b     Bundle
	diags []Diag
}

func (l *loader) add(p string, line int, code, format string, args ...any) {
	l.diags = append(l.diags, Diag{Path: p, Line: line, Code: code, Msg: fmt.Sprintf(format, args...)})
}

// addErr reports an error from cedarx or the YAML decoder with its code and line.
func (l *loader) addErr(p string, err error) {
	if e, ok := err.(*cedarx.Error); ok {
		l.add(p, e.Line, e.Code, "%s", e.Msg)
		return
	}
	l.add(p, 0, "invalid", "%v", err)
}

func (l *loader) paths(dir string) []string {
	var out []string
	for p := range l.files {
		if strings.HasPrefix(p, dir+"/") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (l *loader) run(attrs []string) {
	if len(l.files) > MaxFiles {
		l.add(".", 0, "too_many_files", "%d files; a bundle is at most %d", len(l.files), MaxFiles)
		return
	}
	total := 0
	for p, data := range l.files {
		total += len(data)
		if len(data) > cedarx.MaxFileBytes {
			l.add(p, 0, cedarx.CodeTooLarge, "%d bytes; a file is at most %d", len(data), cedarx.MaxFileBytes)
		}
		if badPath(p) {
			l.add(p, 0, "bad_path", "path is not a clean relative path")
		}
	}
	if total > MaxBytes {
		l.add(".", 0, cedarx.CodeTooLarge, "%d bytes; a bundle is at most %d", total, MaxBytes)
		return
	}
	if len(l.diags) > 0 {
		return
	}
	l.loadConfig()
	l.loadSchema(attrs)
	if l.b.Schema == nil {
		return
	}
	l.loadRoles()
	l.loadJit()
	l.loadSod()
	l.b.Birthright = l.loadCedar(DirBirthright, "permit")
	l.b.Agents = l.loadCedar(DirAgents, "permit")
	l.loadAgentScopes()
	l.b.Invariants = l.loadCedar(DirInvariants, "forbid")
	l.crossCheck()
	l.loadTests()
}

// badPath is a path that is not a clean path inside the repository.
func badPath(p string) bool {
	c := path.Clean(p)
	return p != c || path.IsAbs(p) || c == ".." || strings.HasPrefix(c, "../")
}

func (l *loader) loadSchema(attrs []string) {
	if data, ok := l.files[SchemaFile]; ok {
		s, err := cedarx.ParseSchema(SchemaFile, data)
		if err != nil {
			l.addErr(SchemaFile, err)
			return
		}
		l.b.Schema = s
		return
	}
	s, err := cedarx.Generate(cedarx.Facts{IdentityAttrs: attrs})
	if err != nil {
		l.addErr(SchemaFile, err)
		return
	}
	l.b.Schema = s
}

// loadCedar parses and type-checks every *.cedar file of a folder, and requires
// each policy to have the effect the folder is for and a unique @id.
func (l *loader) loadCedar(dir, effect string) []PolicyFile {
	var out []PolicyFile
	ids := map[string]string{}
	holds := ".cedar files"
	if dir == DirAgents {
		holds = ".cedar files and .yaml agent scopes"
	}
	for _, p := range l.paths(dir) {
		if dir == DirAgents && isYAML(p) {
			continue // an agent scope document (loadAgentScopes)
		}
		if !strings.HasSuffix(p, ".cedar") {
			l.add(p, 0, "unexpected_file", "%s/ holds %s only", dir, holds)
			continue
		}
		ps, err := l.b.Schema.Check(p, l.files[p])
		if err != nil {
			l.addErr(p, err)
			continue
		}
		for _, id := range ps.IDs() {
			line := ps.Line(id)
			if got := ps.Effect(id); got != effect {
				l.add(p, line, "wrong_effect", "%s/ holds %s policies, not %s", dir, effect, got)
			}
			key, ok := ps.Annotation(id, "id")
			switch {
			case !ok || !idRE.MatchString(key):
				l.add(p, line, "missing_id", "every policy needs an @id(\"...\") of letters, digits, '.', '_', ':' or '-' (at most 64)")
			case ids[key] != "":
				l.add(p, line, "duplicate_id", "@id %q is also in %s", key, ids[key])
			default:
				ids[key] = p
			}
		}
		out = append(out, PolicyFile{Path: p, Policies: ps})
	}
	return out
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

var severities = []string{"critical", "high", "medium", "low"}

// crossCheck holds the references between kinds: a birthright rule names an
// existing role, at most one per role (decision 3); an agent scope names its
// agent or blueprint; an invariant has a severity.
func (l *loader) crossCheck() {
	roles := map[string]bool{}
	for _, r := range l.b.Roles {
		roles[r.Key] = true
	}
	perRole := map[string]string{}
	for _, f := range l.b.Birthright {
		for _, id := range f.Policies.IDs() {
			line := f.Policies.Line(id)
			role, ok := f.Policies.Annotation(id, "role")
			switch {
			case !ok:
				l.add(f.Path, line, "missing_role", "a birthright rule needs @role(\"<role key>\")")
			case !roles[role]:
				l.add(f.Path, line, "unknown_role", "@role %q is not a role of this bundle", role)
			case perRole[role] != "":
				l.add(f.Path, line, "duplicate_birthright", "role %q already has a birthright rule in %s; v1 allows one", role, perRole[role])
			default:
				perRole[role] = f.Path
			}
		}
	}
	for _, f := range l.b.Agents {
		for _, id := range f.Policies.IDs() {
			_, a := f.Policies.Annotation(id, "agent")
			_, b := f.Policies.Annotation(id, "blueprint")
			if a == b {
				l.add(f.Path, f.Policies.Line(id), "missing_agent", "an agent scope needs exactly one of @agent(\"...\") or @blueprint(\"...\")")
			}
		}
	}
	for _, f := range l.b.Invariants {
		for _, id := range f.Policies.IDs() {
			if sev, ok := f.Policies.Annotation(id, "severity"); ok && !contains(severities, sev) {
				l.add(f.Path, f.Policies.Line(id), "invalid_severity", "@severity is one of %s", strings.Join(severities, ", "))
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
