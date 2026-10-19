package index

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/glob"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// The identity attributes of a requester a policy can compare with a string.
const (
	attrARN = iota // the requester's ARN (the session template's for a role)
	attrEntity
	attrUniqueID
	attrFederated
	attrCtxARN // aws:PrincipalArn
	attrUserID
	attrUserName
	attrSourceIdentity
	numAttrs
)

// PrinAtomInfo is what the queries need to know about a principal atom.
type PrinAtomInfo struct {
	// P is the representative as the engine sees it (see eval.ResolveRequester).
	P     *model.Principal
	Class eval.RequesterClass
	// Docs are the identity, boundary and session documents that apply, sorted.
	Docs []string
	// IdentityDocs are the identity documents alone.
	IdentityDocs []string
	// Unprunable: a document that gates this requester cannot be trusted
	// (§3.3), so every decision is UNSUPPORTED and nothing can be pruned.
	Unprunable bool
	// SCPApplies is whether SCPs gate the requester.
	SCPApplies bool
}

// Principals are the requester atoms: the principals of the snapshot grouped by
// what a policy can tell about them.
type Principals struct {
	ARNs      []string // the universe, sorted
	AtomOf    []int32
	Atoms     []Atom
	Info      []PrinAtomInfo
	byARN     map[string]int32
	byKey     map[string]int32
	byDoc     map[string][]int32 // identity document to atoms
	byAccount map[string][]int32
	byKind    map[model.PrincipalKind][]int32
}

// probeSet compares identity attribute values with the strings policies name.
type probeSet struct {
	texts   []string
	exact   map[string]int32
	fold    map[string][]int32
	globs   []int32 // probes with a wildcard
	compile []*glob.Pattern
}

func newProbeSet(texts []string) *probeSet {
	ps := &probeSet{texts: texts, exact: map[string]int32{}, fold: map[string][]int32{}, compile: make([]*glob.Pattern, len(texts))}
	for i, t := range texts {
		id := int32(i)
		ps.exact[t] = id
		l := asciiLower(t)
		ps.fold[l] = append(ps.fold[l], id)
		if hasWildcard(t) {
			if p, err := glob.Compile(t, false); err == nil {
				ps.compile[i] = p
				ps.globs = append(ps.globs, id)
			}
		}
	}
	return ps
}

// describe lists, for each value of one attribute, the probes it matches.
func (ps *probeSet) describe(values []string) []string {
	out := make([]string, len(values))
	if len(ps.texts) == 0 {
		return out
	}
	// Distinct sorted values, to range-scan the glob probes.
	idx := map[string]int{}
	var distinct []string
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := idx[v]; !ok {
			idx[v] = 0
			distinct = append(distinct, v)
		}
	}
	sort.Strings(distinct)
	globHits := make([][]int32, len(distinct))
	for _, id := range ps.globs {
		p := ps.compile[id]
		scanPrefix(distinct, literalPrefix(ps.texts[id]), func(i int) {
			if p.Match(distinct[i]) {
				globHits[i] = append(globHits[i], id)
			}
		})
	}
	for i, v := range distinct {
		idx[v] = i
	}
	for n, v := range values {
		if v == "" {
			continue
		}
		var b strings.Builder
		if id, ok := ps.exact[v]; ok {
			b.WriteString("e=" + ps.texts[id] + ";")
		}
		for _, id := range ps.fold[asciiLower(v)] {
			b.WriteString("f=" + ps.texts[id] + ";")
		}
		for _, id := range globHits[idx[v]] {
			b.WriteString("g=" + ps.texts[id] + ";")
		}
		out[n] = b.String()
	}
	return out
}

// attrValues returns the identity attributes of an effective principal. The
// derived ones come from the engine's own context derivation.
func attrValues(p *model.Principal) [numAttrs]string {
	var v [numAttrs]string
	v[attrARN], v[attrEntity], v[attrUniqueID], v[attrFederated] = p.ARN, p.EntityARN, p.UniqueID, p.FederatedProvider
	c := eval.DeriveContext(eval.DeriveInput{Principal: p, DirectCall: true})
	first := func(k string) string {
		if cv := c.Values[k]; cv.State == eval.Present && len(cv.Values) > 0 {
			return cv.Values[0]
		}
		return ""
	}
	v[attrCtxARN], v[attrUserID], v[attrUserName] = first("aws:principalarn"), first("aws:userid"), first("aws:username")
	v[attrSourceIdentity] = first("aws:sourceidentity")
	return v
}

func (f *factEnv) principalFacts(p *model.Principal, class eval.RequesterClass, attrs [numAttrs]string, matches [numAttrs]string) string {
	var b strings.Builder
	usesIdentity := class == eval.RequesterIAM &&
		(p.Kind == model.IAMUser || p.Kind == model.RoleSession || p.Kind == model.FederatedUserSession)
	b.WriteString(p.Kind.String() + "|" + string(rune('0'+class)) + "|" + p.AccountID + "|" + boolStr(p.IsServiceLinked) + "|")
	if usesIdentity {
		b.WriteString(strings.Join(uniqueSorted(p.IdentityPolicyIDs), ",") + "|" + p.BoundaryPolicyID + "|" +
			strings.Join(uniqueSorted(p.SessionPolicyIDs), ",") + "|")
	}
	applies := f.snap.Org != nil && eval.SCPApplies(f.snap, p, class)
	b.WriteString(boolStr(applies) + f.scpKey[p.AccountID] + "|")
	// Tags: the effective values of the keys a policy names.
	switch {
	case f.r.allPrincipalTags:
		b.WriteString("tags:")
		writeTags(&b, mergedTags(p), nil)
	case len(f.r.principalTagKeys) > 0:
		b.WriteString("tags:")
		writeTags(&b, mergedTags(p), f.r.principalTagKeys)
	}
	// Presence matters to Null conditions even when no value is compared.
	b.WriteString("|has:" + boolStr(p.UniqueID != "") + boolStr(p.FederatedProvider != "") + boolStr(p.SourceIdentity != "") + boolStr(p.EntityARN != ""))
	for k := 0; k < numAttrs; k++ {
		if matches[k] != "" {
			b.WriteString("|a" + string(rune('0'+k)) + ":" + matches[k])
		}
	}
	if f.r.identityVars || class != eval.RequesterIAM {
		b.WriteString("|raw:" + strings.Join(attrs[:], "\x1f"))
	}
	return b.String()
}

// mergedTags overlays session tags on entity tags, as the context derivation does.
func mergedTags(p *model.Principal) map[string]string {
	if len(p.SessionTags) == 0 {
		return p.Tags
	}
	m := make(map[string]string, len(p.Tags)+len(p.SessionTags))
	for k, v := range p.Tags {
		m[k] = v
	}
	for k, v := range p.SessionTags {
		m[k] = v
	}
	return m
}

func uniqueSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	w := 0
	for i, s := range out {
		if i == 0 || s != out[w-1] {
			out[w] = s
			w++
		}
	}
	return out[:w]
}

type resolved struct {
	arn   string
	p     *model.Principal
	class eval.RequesterClass
}

func buildPrincipals(snap *model.Snapshot, r *refs, f *factEnv) *Principals {
	ps := &Principals{byARN: map[string]int32{}, byDoc: map[string][]int32{}, byAccount: map[string][]int32{},
		byKind: map[model.PrincipalKind][]int32{}}
	arns := make([]string, 0, len(snap.Principals))
	for a := range snap.Principals {
		arns = append(arns, a)
	}
	sort.Strings(arns)
	var all []resolved
	for _, a := range arns {
		p, class, err := eval.ResolveRequester(snap, a)
		if err != nil {
			continue // not a requester the engine can answer for
		}
		all = append(all, resolved{a, p, class})
	}
	ps.ARNs = make([]string, len(all))
	for i, x := range all {
		ps.ARNs[i] = x.arn
		ps.byARN[x.arn] = int32(i)
	}

	probes := newProbeSet(r.probes)
	attrs := make([][numAttrs]string, len(all))
	var matched [][numAttrs]string
	matched = make([][numAttrs]string, len(all))
	for i, x := range all {
		attrs[i] = attrValues(x.p)
	}
	for k := 0; k < numAttrs; k++ {
		col := make([]string, len(all))
		for i := range all {
			col[i] = attrs[i][k]
		}
		for i, m := range probes.describe(col) {
			matched[i][k] = m
		}
	}
	facts := func(i int) string {
		return f.principalFacts(all[i].p, all[i].class, attrs[i], matched[i])
	}
	ps.AtomOf, ps.Atoms, ps.byKey = group(len(all),
		func(i int) string { return facts(i) },
		func(i int) string { return shortHash(facts(i)) })
	ps.Info = make([]PrinAtomInfo, len(ps.Atoms))
	for _, at := range ps.Atoms {
		x := all[at.Rep]
		info := PrinAtomInfo{P: x.p, Class: x.class}
		bad := func(id string) bool { return snap.Policies[id] == nil || r.badDocs[id] }
		if x.class == eval.RequesterIAM && (x.p.Kind == model.IAMUser || x.p.Kind == model.RoleSession || x.p.Kind == model.FederatedUserSession) {
			info.IdentityDocs = uniqueSorted(x.p.IdentityPolicyIDs)
			info.Docs = append(info.Docs, info.IdentityDocs...)
			if x.p.BoundaryPolicyID != "" {
				info.Docs = append(info.Docs, x.p.BoundaryPolicyID)
			}
			info.Docs = append(info.Docs, uniqueSorted(x.p.SessionPolicyIDs)...)
		}
		info.SCPApplies = snap.Org != nil && eval.SCPApplies(snap, x.p, x.class)
		for _, d := range info.Docs {
			info.Unprunable = info.Unprunable || bad(d)
		}
		if info.SCPApplies {
			for _, n := range snap.Org.PathTo(x.p.AccountID) {
				for _, id := range n.SCPIDs {
					info.Unprunable = info.Unprunable || bad(id)
				}
			}
		}
		ps.Info[at.ID] = info
		for _, d := range info.IdentityDocs {
			ps.byDoc[d] = append(ps.byDoc[d], at.ID)
		}
		ps.byAccount[x.p.AccountID] = append(ps.byAccount[x.p.AccountID], at.ID)
		ps.byKind[x.p.Kind] = append(ps.byKind[x.p.Kind], at.ID)
	}
	return ps
}

// Lookup returns the atom of a principal of the snapshot, or -1.
func (ps *Principals) Lookup(arn string) int32 {
	if i, ok := ps.byARN[arn]; ok {
		return ps.AtomOf[i]
	}
	return -1
}

// RepARN is the representative principal of an atom.
func (ps *Principals) RepARN(id int32) string { return ps.ARNs[ps.Atoms[id].Rep] }

// MemberARNs lists the principals of an atom.
func (ps *Principals) MemberARNs(id int32) []string {
	out := make([]string, len(ps.Atoms[id].Members))
	for i, m := range ps.Atoms[id].Members {
		out[i] = ps.ARNs[m]
	}
	return out
}
