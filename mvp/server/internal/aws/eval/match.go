package eval

import (
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/glob"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// ActionMatcher is action_match for one statement (§8.2): Action or NotAction
// patterns, matched raw and ASCII-case-insensitively. The catalog is never
// consulted, so actions launched after the catalog snapshot still match (which
// matters for NotAction with Allow).
type ActionMatcher struct {
	pats   []*glob.Pattern
	negate bool // NotAction
}

// CompileActions compiles a statement's Action or NotAction. Exactly one must
// be non-nil (the parser guarantees it).
func CompileActions(actions, notActions *model.PatternSet) (*ActionMatcher, error) {
	var set *model.PatternSet
	m := &ActionMatcher{}
	switch {
	case actions != nil && notActions == nil:
		set = actions
	case notActions != nil && actions == nil:
		set, m.negate = notActions, true
	default:
		return nil, errors.New("eval: a statement needs exactly one of Action and NotAction")
	}
	for _, s := range set.Patterns {
		p, err := glob.Compile(s, true)
		if err != nil {
			return nil, fmt.Errorf("eval: action pattern %q: %w", clip(s), err)
		}
		m.pats = append(m.pats, p)
	}
	return m, nil
}

// Match reports whether the statement applies to action ("s3:GetObject").
func (m *ActionMatcher) Match(action string) bool {
	hit := false
	for _, p := range m.pats {
		if p.Match(action) {
			hit = true
			break
		}
	}
	return hit != m.negate
}

// ResourceMatcher is resource_match for one statement (§8.3), without policy
// variables: the caller substitutes variables (PR-4) and compiles the result
// with CompileARN. Patterns are the completed form where the parser set one.
type ResourceMatcher struct {
	implied bool // resource policy with no Resource: "this resource"
	negate  bool // NotResource
	pats    []*ARNPattern
}

// CompileResources compiles a statement's Resource or NotResource. When both
// are nil the statement is "implied this resource" and is valid only in a
// resource-based policy (resourceBased).
func CompileResources(resources, notResources *model.PatternSet, resourceBased bool) (*ResourceMatcher, error) {
	m := &ResourceMatcher{}
	var set *model.PatternSet
	switch {
	case resources != nil && notResources == nil:
		set = resources
	case notResources != nil && resources == nil:
		set, m.negate = notResources, true
	case resources == nil && notResources == nil && resourceBased:
		m.implied = true
		return m, nil
	default:
		return nil, errors.New("eval: a statement needs exactly one of Resource and NotResource")
	}
	for _, s := range set.MatchPatterns() {
		p, err := CompileARN(s)
		if err != nil {
			return nil, fmt.Errorf("eval: resource pattern %q: %w", clip(s), err)
		}
		m.pats = append(m.pats, p)
	}
	return m, nil
}

// Match reports whether the statement applies to the resource. An empty arn or
// "*" means an action without resource-level permissions: only a pattern "*"
// matches it, so Resource "arn:aws:s3:::x" does not match it and NotResource
// "arn:aws:s3:::x" does.
func (m *ResourceMatcher) Match(arn string) bool {
	if m.implied {
		return true
	}
	hit := false
	for _, p := range m.pats {
		if arn == "" || arn == "*" {
			if p.IsStar() {
				hit = true
				break
			}
		} else if p.Match(arn) {
			hit = true
			break
		}
	}
	return hit != m.negate
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
