package policygroups

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SourceFile is a policy file as it arrives: its path in the repository (or a
// label, for the UI) and its Cedar text.
type SourceFile struct {
	Path  string `json:"path"`
	Cedar string `json:"cedar"`
}

// Limits of one change.
const (
	MaxFiles = 1000
	MaxPath  = 512
)

var (
	pathRE   = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	commitRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// ValidCommit reports whether s is acceptable as a repository commit reference.
func ValidCommit(s string) bool { return commitRE.MatchString(s) }

// ParseAll parses and validates a set of files against the schema: each file by
// ParseFile, and across files that no two define the same group or share a path.
// The files come back in path order.
func ParseAll(schema Schema, files []SourceFile) ([]*File, []Diagnostic) {
	if len(files) > MaxFiles {
		return nil, []Diagnostic{{Code: CodeTooManyFiles, Msg: fmt.Sprintf("a change has at most %d policy files", MaxFiles)}}
	}
	sorted := append([]SourceFile(nil), files...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var diags []Diagnostic
	var out []*File
	paths := map[string]bool{}
	groups := map[string]string{} // lower-cased group name -> path
	for _, sf := range sorted {
		switch {
		case sf.Path == "" || len(sf.Path) > MaxPath || !pathRE.MatchString(sf.Path) || strings.Contains(sf.Path, "..") ||
			strings.HasPrefix(sf.Path, "/"):
			diags = append(diags, Diagnostic{Path: sf.Path, Line: 1, Col: 1, Code: CodeInvalidPath,
				Msg: "a path is relative, at most 512 characters of letters, digits, '.', '_', '-' and '/', without '..'"})
			continue
		case paths[sf.Path]:
			diags = append(diags, Diagnostic{Path: sf.Path, Line: 1, Col: 1, Code: CodeDuplicatePath, Msg: "the path is given twice"})
			continue
		}
		paths[sf.Path] = true
		f, ds := ParseFile(sf.Path, sf.Cedar, schema)
		if len(ds) > 0 {
			diags = append(diags, ds...)
			continue
		}
		k := strings.ToLower(f.Group)
		if other, dup := groups[k]; dup {
			diags = append(diags, Diagnostic{Path: sf.Path, Line: 1, Col: 1, Code: CodeDuplicateGroup,
				Msg: fmt.Sprintf("group %q is also defined in %s", f.Group, other)})
			continue
		}
		groups[k] = sf.Path
		out = append(out, f)
	}
	if len(diags) > 0 {
		return nil, diags
	}
	return out, nil
}

// resolver maps a group name to the id of the group (a live one, by name or by
// an old name). A name in batch is a group the change itself defines: it need
// not exist yet.
func resolver(tx *store.TenantTx, batch map[string]bool, hidden func(store.GroupID) bool) func(string) (string, error) {
	return func(name string) (string, error) {
		k := strings.ToLower(name)
		g, err := tx.GrpGroupByName(name)
		if errors.Is(err, store.ErrNotFound) {
			var a *store.GrpAlias
			if a, err = tx.GrpAliasByName(name); err == nil && a.ObjectType == store.AliasGroup {
				g, err = tx.GrpGroup(store.GroupID(a.ObjectID))
			} else if err == nil {
				err = store.ErrNotFound
			}
		}
		if err == nil && !batch[k] && hidden != nil && hidden(g.ID) {
			// a group the caller may not view looks as if there were none
			return "", fmt.Errorf("no group named %q", name)
		}
		switch {
		case err == nil && g.Status == store.GroupDeleted:
			if batch[k] {
				return string(g.ID), nil // the change defines it again
			}
			return "", fmt.Errorf("group %q is deleted", name)
		case err == nil:
			return string(g.ID), nil
		case errors.Is(err, store.ErrNotFound) && batch[k]:
			return "new:" + k, nil
		case errors.Is(err, store.ErrNotFound):
			return "", fmt.Errorf("no group named %q", name)
		}
		return "", err
	}
}

// FindGroup returns the live or deleted group with the name or an old name of it,
// and whether there is one.
func FindGroup(tx *store.TenantTx, name string) (store.GroupID, bool, error) {
	g, err := tx.GrpGroupByName(name)
	if errors.Is(err, store.ErrNotFound) {
		a, aerr := tx.GrpAliasByName(name)
		if errors.Is(aerr, store.ErrNotFound) || (aerr == nil && a.ObjectType != store.AliasGroup) {
			return "", false, nil
		}
		if aerr != nil {
			return "", false, aerr
		}
		return store.GroupID(a.ObjectID), true, nil
	}
	if err != nil {
		return "", false, err
	}
	return g.ID, true, nil
}

// Validation is what a dry check of a change found.
type Validation struct {
	Valid       bool         `json:"valid"`
	Groups      []string     `json:"groups"`
	References  []string     `json:"references"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// Validate checks a set of files without changing anything: the fragment, the
// schema, that the groups they name exist and that no condition is unbounded.
// Cycles between policy groups are found when a change is applied.
func Validate(env model.Env, schema Schema, files []SourceFile) (*Validation, []*File, error) {
	if err := schema.Validate(); err != nil {
		return nil, nil, err
	}
	fs, diags := ParseAll(schema, files)
	v := &Validation{Groups: []string{}, References: []string{}}
	if len(diags) == 0 {
		batch := map[string]bool{}
		for _, f := range fs {
			batch[strings.ToLower(f.Group)] = true
			v.Groups = append(v.Groups, f.Group)
		}
		refs := map[string]bool{}
		c := NewCompiler()
		for _, f := range fs {
			if _, ds := c.Compile(f, resolver(env.Tx, batch, env.GroupHidden)); len(ds) > 0 {
				diags = append(diags, ds...)
			}
			names, _ := f.Groups()
			for _, n := range names {
				refs[n] = true
			}
		}
		for n := range refs {
			v.References = append(v.References, n)
		}
		sort.Strings(v.References)
	}
	v.Valid = len(diags) == 0
	v.Diagnostics = append([]Diagnostic{}, diags...)
	if !v.Valid {
		return v, nil, nil
	}
	return v, fs, nil
}
