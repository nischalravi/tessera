package index

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/glob"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// refs is what the policies of a snapshot refer to. Atoms are only sound if
// their signature covers every fact a policy can test, so the signature builders
// ask refs which tag keys, identity keys and patterns exist at all (§12.2).
type refs struct {
	// actionPats are the distinct lower-cased Action/NotAction patterns.
	actionPats []string
	// resPats are the distinct resource patterns as matched against ARNs. A
	// pattern with a policy variable appears as its skeleton (each ${...} turned
	// into '*'), which matches a superset of what any substitution can match;
	// resVar marks those.
	resPats []string
	resVar  map[string]bool
	// principalTagKeys and resourceTagKeys are the lower-cased tag keys that a
	// condition key or a variable names. allPrincipalTags and allResourceTags
	// say a key name itself was dynamic, so every tag counts.
	principalTagKeys, resourceTagKeys map[string]bool
	allPrincipalTags, allResourceTags bool
	// identityVars: a variable names an identity key (aws:username, aws:userid,
	// aws:PrincipalArn, ...), so a substituted value can be any identity string.
	identityVars bool
	// probes are the strings an identity attribute of a requester can be compared
	// with: the values of Principal and NotPrincipal elements, KMS grantees, and
	// the values of conditions on identity keys. Sorted and distinct.
	probes []string
	// badDocs are documents the engine cannot fully read (§3.3): they fail to
	// parse, or a pattern in them fails to compile.
	badDocs map[string]bool

	hasKMSGrants bool
	hasACLs      bool
}

// identityKeys are the condition keys whose value is a string about the caller
// itself. Their condition values become probes.
var identityKeys = map[string]bool{
	"aws:principalarn": true, "aws:userid": true, "aws:username": true, "aws:sourceidentity": true,
	"aws:federatedprovider": true, "aws:principalservicename": true, "aws:principalservicenameslist": true,
}

// identityVarNames are the variable names that read those keys.
var identityVarNames = identityKeys

func scanRefs(snap *model.Snapshot) *refs {
	r := &refs{
		resVar: map[string]bool{}, principalTagKeys: map[string]bool{}, resourceTagKeys: map[string]bool{},
		badDocs: map[string]bool{},
	}
	act, res, probes := map[string]bool{}, map[string]bool{}, map[string]bool{}

	ids := make([]string, 0, len(snap.Policies))
	for id := range snap.Policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := snap.Policies[id]
		if d.Unparseable != "" {
			r.badDocs[id] = true
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			for _, ps := range []*model.PatternSet{st.Actions, st.NotActions} {
				if ps == nil {
					continue
				}
				for _, p := range ps.Patterns {
					lp := asciiLower(p)
					if _, err := glob.Compile(lp, true); err != nil {
						r.badDocs[id] = true
						continue
					}
					act[lp] = true
				}
			}
			for _, ps := range []*model.PatternSet{st.Resources, st.NotResources} {
				if ps == nil {
					continue
				}
				for _, p := range append(append([]string(nil), ps.Patterns...), ps.Completed...) {
					r.noteVariables(p)
					key := p
					if strings.Contains(p, "${") {
						key = skeleton(p)
						r.resVar[key] = true
					}
					if _, err := eval.CompileARN(key); err != nil {
						r.badDocs[id] = true
						continue
					}
					res[key] = true
				}
			}
			for _, ps := range []*model.PrincipalSet{st.Principals, st.NotPrincipals} {
				if ps == nil {
					continue
				}
				for _, e := range ps.Entries {
					if e.Value != "" && e.Value != "*" {
						probes[e.Value] = true
					}
				}
			}
			for _, a := range st.Condition {
				r.noteKey(a.Key)
				for _, v := range a.Values {
					r.noteVariables(v)
					if identityKeys[a.Key] {
						probes[v] = true
					}
				}
			}
		}
	}
	for _, gs := range snap.KMSGrants {
		for _, g := range gs {
			r.hasKMSGrants = true
			for _, s := range []string{g.GranteePrincipal, g.GranteeServicePrincipal, g.RetiringPrincipal} {
				if s != "" {
					probes[s] = true
				}
			}
		}
	}
	for _, st := range snap.S3 {
		if len(st.BucketACL) > 0 {
			r.hasACLs = true
		}
		for _, g := range st.ObjectACLs {
			if len(g) > 0 {
				r.hasACLs = true
			}
		}
	}
	r.actionPats, r.resPats, r.probes = keys(act), keys(res), keys(probes)
	return r
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// noteKey records a condition key.
func (r *refs) noteKey(k string) {
	if rest, ok := strings.CutPrefix(k, "aws:principaltag/"); ok {
		r.noteTag(rest, r.principalTagKeys, &r.allPrincipalTags)
	} else if rest, ok := strings.CutPrefix(k, "aws:resourcetag/"); ok {
		r.noteTag(rest, r.resourceTagKeys, &r.allResourceTags)
	}
}

func (r *refs) noteTag(k string, set map[string]bool, all *bool) {
	if k == "" || strings.Contains(k, "${") {
		*all = true
		return
	}
	set[k] = true
}

// noteVariables records the policy variables in s.
func (r *refs) noteVariables(s string) {
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			return
		}
		s = s[i+2:]
		end := strings.IndexByte(s, '}')
		if end < 0 {
			end = len(s)
		}
		name := strings.TrimSpace(strings.SplitN(s[:end], ",", 2)[0])
		name = asciiLower(name)
		switch {
		case name == "*" || name == "?" || name == "$":
		case strings.HasPrefix(name, "aws:principaltag/"):
			r.noteTag(strings.TrimPrefix(name, "aws:principaltag/"), r.principalTagKeys, &r.allPrincipalTags)
		case strings.HasPrefix(name, "aws:resourcetag/"):
			r.noteTag(strings.TrimPrefix(name, "aws:resourcetag/"), r.resourceTagKeys, &r.allResourceTags)
		case identityVarNames[name]:
			r.identityVars = true
		}
		if end >= len(s) {
			return
		}
		s = s[end+1:]
	}
}

// skeleton turns every ${...} of a pattern into '*'.
func skeleton(p string) string {
	var b strings.Builder
	for {
		i := strings.Index(p, "${")
		if i < 0 {
			b.WriteString(p)
			return b.String()
		}
		b.WriteString(p[:i])
		b.WriteByte('*')
		end := strings.IndexByte(p[i:], '}')
		if end < 0 {
			return b.String()
		}
		p = p[i+end+1:]
	}
}

// literalPrefix is the part of a pattern before its first wildcard or variable.
// Every string the pattern matches starts with it.
func literalPrefix(p string) string {
	for i := 0; i < len(p); i++ {
		if p[i] == '*' || p[i] == '?' || (p[i] == '$' && i+1 < len(p) && p[i+1] == '{') {
			return p[:i]
		}
	}
	return p
}

func hasWildcard(p string) bool { return strings.ContainsAny(p, "*?") }

// asciiLower lower-cases A-Z only, as the engine does (§8.1).
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
