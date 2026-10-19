package index

import (
	"encoding/binary"
	"hash/fnv"
	"maps"
	"reflect"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// noneARN stands for an action without resource-level permissions ("" and "*").
const noneARN = "*"

// factEnv is what the facts of requesters and resources are computed from.
type factEnv struct {
	snap *model.Snapshot
	r    *refs
	// scpKey and rcpKey map an account of the organization to a string naming its
	// path and the policies attached along it.
	scpKey, rcpKey map[string]string
}

func newFactEnv(snap *model.Snapshot, r *refs) *factEnv {
	f := &factEnv{snap: snap, r: r, scpKey: map[string]string{}, rcpKey: map[string]string{}}
	if snap.Org == nil {
		return f
	}
	for id, n := range snap.Org.Nodes {
		if n == nil || n.Kind != model.OrgAccount {
			continue
		}
		path := snap.Org.PathTo(id)
		if path == nil {
			continue
		}
		var scp, rcp strings.Builder
		for _, p := range path {
			scp.WriteString(p.ID + "=" + strings.Join(p.SCPIDs, ",") + ";")
			rcp.WriteString(p.ID + "=" + strings.Join(p.RCPIDs, ",") + ";")
		}
		m := ""
		if id == snap.Org.ManagementAccountID {
			m = "M"
		}
		f.scpKey[id], f.rcpKey[id] = shortHash(scp.String(), m), shortHash(rcp.String(), m)
	}
	return f
}

// resFacts are the non-pattern facts of a resource (§12.2): service, type,
// account, region, the resource policies and KMS grants and S3 state that apply,
// the RCP chain of its account, and the values of the tag keys a policy names.
func (f *factEnv) resFacts(arn string, rf eval.ResourceFacts) string {
	if rf.None {
		return "none"
	}
	var b strings.Builder
	b.WriteString(serviceOf(arn) + "|" + rf.Account + "|" + boolStr(rf.AccountKnown) + "|" + rf.Type + "|" + rf.Region + "|")
	b.WriteString(f.rcpKey[rf.Account])
	b.WriteString("|rbp:")
	for _, k := range rf.PolicyKeys {
		for _, rp := range f.snap.ResourcePolicies[k] {
			b.WriteString(rp.PolicyID + "/" + rp.Kind.String() + "/" + boolStr(rp.RequiresExplicitAllow) + ",")
		}
		b.WriteByte(';')
	}
	if gs := f.snap.KMSGrants[arn]; len(gs) > 0 {
		b.WriteString("|kms:" + grantsHash(gs))
	}
	if bucket, isObj, ok := eval.S3Resource(arn); ok {
		b.WriteString("|s3:" + boolStr(isObj) + ":" + f.s3Hash(bucket, arn))
	}
	if f.r.allResourceTags {
		b.WriteString("|tags:")
		writeTags(&b, rf.Tags, nil)
	} else if len(f.r.resourceTagKeys) > 0 {
		b.WriteString("|tags:")
		writeTags(&b, rf.Tags, f.r.resourceTagKeys)
	}
	return b.String()
}

// serviceOf is the service segment of an ARN, or "".
func serviceOf(arn string) string {
	parts := strings.SplitN(arn, ":", 4)
	if len(parts) < 4 || parts[0] != "arn" {
		return ""
	}
	return parts[2]
}

// writeTags writes the tags whose lower-cased key is in only (all when nil),
// keyed by lower-cased key, the way the engine folds them into the context.
func writeTags(b *strings.Builder, tags map[string]string, only map[string]bool) {
	if len(tags) == 0 {
		return
	}
	ks := make([]string, 0, len(tags))
	for k := range tags {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	folded := map[string]string{}
	for _, k := range ks {
		l := asciiLower(k)
		if only == nil || only[l] {
			folded[l] = tags[k]
		}
	}
	fk := make([]string, 0, len(folded))
	for k := range folded {
		fk = append(fk, k)
	}
	sort.Strings(fk)
	for _, k := range fk {
		b.WriteString(k + "=" + folded[k] + ",")
	}
}

func grantsHash(gs []model.KMSGrant) string {
	parts := make([]string, len(gs))
	for i, g := range gs {
		var b strings.Builder
		b.WriteString(g.GranteePrincipal + "|" + g.GranteeServicePrincipal + "|" + g.RetiringPrincipal + "|" + g.ConstraintSourceARN + "|")
		b.WriteString(strings.Join(g.Operations, ",") + "|")
		writeMap(&b, g.ConstraintsECEquals, g.ConstraintsECEquals != nil)
		writeMap(&b, g.ConstraintsECSubset, g.ConstraintsECSubset != nil)
		parts[i] = b.String()
	}
	sort.Strings(parts)
	return shortHash(parts...)
}

func writeMap(b *strings.Builder, m map[string]string, present bool) {
	if !present {
		b.WriteString("-;")
		return
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		b.WriteString(k + "=" + m[k] + ",")
	}
	b.WriteByte(';')
}

// s3Hash covers everything the engine reads from the bucket's S3 state and from
// the object's ACLs (§7.6.2).
func (f *factEnv) s3Hash(bucket, arn string) string {
	st := f.snap.S3[bucket]
	if st == nil {
		return "nostate"
	}
	var b strings.Builder
	b.WriteString(st.OwnerAccount + "|" + st.ObjectOwnership + "|")
	acl := func(gs []model.ACLGrant) {
		parts := make([]string, len(gs))
		for i, g := range gs {
			acct := ""
			if g.GranteeType == "CanonicalUser" {
				acct = f.snap.CanonicalIDs[g.Grantee]
			}
			parts[i] = g.GranteeType + "/" + g.Grantee + "/" + g.Permission + "/" + acct
		}
		sort.Strings(parts)
		b.WriteString(strings.Join(parts, ",") + "|")
	}
	acl(st.BucketACL)
	acl(st.ObjectACLs[arn])
	bpa := func(x model.BPA) {
		b.WriteString(boolStr(x.BlockPublicAcls) + boolStr(x.IgnorePublicAcls) + boolStr(x.BlockPublicPolicy) + boolStr(x.RestrictPublicBuckets) + "|")
	}
	bpa(st.BPABucket)
	bpa(st.BPAAccount)
	switch {
	case st.BPAOrg == nil:
		b.WriteString("?")
	case *st.BPAOrg:
		b.WriteString("t")
	default:
		b.WriteString("f")
	}
	b.WriteString(boolStr(st.PolicyIsPublic))
	return shortHash(b.String())
}

// ResAtomInfo is what the queries need to know about a resource atom beyond its members.
type ResAtomInfo struct {
	None    bool
	Account string
	// Service is the service segment of the ARN; "" for the no-resource atom.
	Service string
	// Poisoned: a document the evaluation of this resource reads cannot be
	// trusted (§3.3), so every decision about it is UNSUPPORTED and none can be
	// pruned.
	Poisoned bool
	HasACL   bool
	// RBPDocs are the resource-policy documents that apply (the resource's own
	// and, for an S3 object, its bucket's).
	RBPDocs []string
	// KMSKey: the resource has KMS grants.
	KMSKey bool
	// VarSensitive: a policy variable can decide whether a pattern matches it,
	// so the atom is a single resource.
	VarSensitive bool
}

// Resources are the resource atoms.
type Resources struct {
	ARNs     []string // the universe, sorted; includes "*" (no resource)
	pats     patTable
	compile  []*eval.ARNPattern
	match    [][]int32
	AtomOf   []int32
	Atoms    []Atom
	Info     []ResAtomInfo
	byARN    map[string]int32
	byKey    map[string]int32
	patAtoms [][]int32
	rbpAtoms map[string][]int32
	// patIsVar marks the patterns that stand for a variable pattern's skeleton.
	patIsVar []bool
	// acctKeys and acctOrd are the universe sorted by service and account, built
	// when a pattern needs them (see scan); acctOrd maps back to ARNs indexes.
	acctKeys []string
	acctOrd  []int32
	// f and fk are the fact environment and the facts hash of every item.
	f  *factEnv
	fk [][2]uint64
}

func (f *factEnv) newResInfo(arn string, rf eval.ResourceFacts, varSens bool) ResAtomInfo {
	info := ResAtomInfo{None: rf.None, Account: rf.Account, VarSensitive: varSens, Service: serviceOf(arn)}
	if rf.None {
		return info
	}
	bad := func(id string) bool {
		d := f.snap.Policies[id]
		return d == nil || f.r.badDocs[id]
	}
	seen := map[string]bool{}
	for _, k := range rf.PolicyKeys {
		for _, rp := range f.snap.ResourcePolicies[k] {
			if !seen[rp.PolicyID] {
				seen[rp.PolicyID] = true
				info.RBPDocs = append(info.RBPDocs, rp.PolicyID)
			}
			if bad(rp.PolicyID) {
				info.Poisoned = true
			}
		}
	}
	sort.Strings(info.RBPDocs)
	if org := f.snap.Org; org != nil && eval.RCPApplies(org, rf.Account, false) {
		for _, n := range org.PathTo(rf.Account) {
			for _, id := range n.RCPIDs {
				if bad(id) {
					info.Poisoned = true
				}
			}
		}
	}
	info.KMSKey = len(f.snap.KMSGrants[arn]) > 0
	if bucket, _, ok := eval.S3Resource(arn); ok {
		if st := f.snap.S3[bucket]; st != nil {
			info.HasACL = len(st.BucketACL) > 0 || len(st.ObjectACLs[arn]) > 0
		}
	}
	return info
}

// universeResources lists the resources the index covers: everything the
// snapshot knows a resource policy, grant, bucket or inventory entry for, plus
// extra, plus the "no resource" pseudo-resource.
func universeResources(snap *model.Snapshot, extra []string) []string {
	set := map[string]bool{noneARN: true}
	for k := range snap.Resources {
		set[k] = true
	}
	for k := range snap.ResourcePolicies {
		set[k] = true
	}
	for k := range snap.KMSGrants {
		set[k] = true
	}
	for k := range snap.S3 {
		set[k] = true
	}
	for _, k := range extra {
		if k == "" {
			k = noneARN
		}
		set[k] = true
	}
	return keys(set)
}

func buildResources(arns []string, r *refs, f *factEnv, prev *Resources) (*Resources, RefineStats) {
	var st RefineStats
	rs := &Resources{ARNs: arns, byARN: make(map[string]int32, len(arns)), rbpAtoms: map[string][]int32{}}
	for i, a := range arns {
		rs.byARN[a] = int32(i)
	}
	if prev != nil {
		rs.pats = prev.pats.clone()
		rs.compile = append([]*eval.ARNPattern(nil), prev.compile...)
		rs.patIsVar = append([]bool(nil), prev.patIsVar...)
		for id := range rs.pats.live {
			rs.pats.live[id] = false
		}
	} else {
		rs.pats = newPatTable()
	}
	var added []int32
	for _, t := range r.resPats {
		if t == "*" {
			continue // matches every resource and nothing else; see noneARN
		}
		_, had := rs.pats.ids[t]
		id := rs.pats.add(t)
		if !had {
			// A pattern with a variable is matched by its literal prefix alone:
			// a substituted value can add colons, so the skeleton's segment rules
			// do not bound it. That only makes the atoms finer, never wrong.
			var p *eval.ARNPattern
			if !r.resVar[t] {
				var err error
				if p, err = eval.CompileARN(t); err != nil {
					rs.pats.live[id] = false
					p = nil
				}
			}
			rs.compile = append(rs.compile, p)
			rs.patIsVar = append(rs.patIsVar, r.resVar[t])
			added = append(added, id)
			st.PatternsAdded++
		} else if prev != nil && !prev.pats.live[id] {
			added = append(added, id)
			st.PatternsAdded++
		}
		rs.patIsVar[id] = r.resVar[t]
	}
	var gone []int32
	if prev != nil {
		for id, live := range prev.pats.live {
			if live && !rs.pats.live[id] {
				gone = append(gone, int32(id))
				st.PatternsGone++
			}
		}
	}

	rs.match = make([][]int32, len(arns))
	fresh := make([]bool, len(arns))
	for i, a := range arns {
		if prev != nil {
			if pi, ok := prev.byARN[a]; ok {
				rs.match[i] = prev.match[pi]
				st.ItemsReused++
				continue
			}
		}
		// With no previous index every pattern is "added" and scanned below; only
		// a new item of a refinement is tested against all the patterns.
		fresh[i] = prev != nil
		st.ItemsRebuilt++
	}
	if len(gone) > 0 {
		goneSet := map[int32]bool{}
		for _, id := range gone {
			goneSet[id] = true
		}
		for i, ids := range rs.match {
			hit := false
			for _, id := range ids {
				if goneSet[id] {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			kept := make([]int32, 0, len(ids))
			for _, id := range ids {
				if !goneSet[id] {
					kept = append(kept, id)
				}
			}
			rs.match[i] = kept
		}
	}
	for i, a := range arns {
		if !fresh[i] || a == noneARN {
			continue
		}
		rs.match[i] = rs.matchAll(a)
	}
	for _, id := range added {
		if !rs.pats.live[id] {
			continue
		}
		rs.scan(rs.pats.text[id], rs.patIsVar[id], func(i int) {
			if fresh[i] || arns[i] == noneARN || !rs.testPat(id, arns[i]) {
				return
			}
			if n := len(rs.match[i]); n == 0 || rs.match[i][n-1] < id {
				rs.match[i] = append(rs.match[i], id) // the usual case: ids arrive in order
			} else {
				rs.match[i] = insertSorted(rs.match[i], id)
			}
		})
	}

	// The facts of an item are hashed (128 bits) once and kept, so a refinement
	// over a snapshot whose resource side did not change reuses them instead of
	// resolving four million resources again.
	rs.f = f
	rs.fk = make([][2]uint64, len(arns))
	reuse := prev != nil && sameResourceWorld(prev.f, f)
	for i, a := range arns {
		if reuse {
			if pi, ok := prev.byARN[a]; ok {
				rs.fk[i] = prev.fk[pi]
				continue
			}
		}
		rs.fk[i] = hash128(f.resFacts(a, eval.ResolveResource(f.snap, a)))
	}
	factsOf := func(i int) string { return factsText(rs.fk[i], rs.varSensitive(rs.match[i]), arns[i]) }
	rs.AtomOf, rs.Atoms, rs.byKey = group(len(arns),
		func(i int) string { return matchKey(factsOf(i), rs.match[i]) },
		func(i int) string { return sigOf(factsOf(i), &rs.pats, rs.match[i]) })
	rs.Info = make([]ResAtomInfo, len(rs.Atoms))
	rs.patAtoms = make([][]int32, len(rs.pats.text))
	for _, at := range rs.Atoms {
		rep := arns[at.Rep]
		rf := eval.ResolveResource(f.snap, rep)
		rs.Info[at.ID] = f.newResInfo(rep, rf, rs.varSensitive(rs.match[at.Rep]))
		for _, id := range rs.match[at.Rep] {
			rs.patAtoms[id] = append(rs.patAtoms[id], at.ID)
		}
		for _, d := range rs.Info[at.ID].RBPDocs {
			rs.rbpAtoms[d] = append(rs.rbpAtoms[d], at.ID)
		}
	}
	if prev != nil {
		st.PreviousAtoms, st.AtomsSplit, st.AtomsMerged = refineCounts(prev.Atoms, prev.ARNs, rs.AtomOf, rs.byARN, len(rs.Atoms))
		st.AtomsAfter = len(rs.Atoms)
	}
	return rs, st
}

// scan calls fn for every universe item that might match the pattern: those that
// share its literal prefix, or, when a wildcard comes before the account but the
// service and account are literal ("arn:aws:sqs:*:123456789012:*"), those of
// that service and account. Either way the caller still tests the match.
func (rs *Resources) scan(text string, isVar bool, fn func(i int)) {
	prefix := literalPrefix(text)
	// A variable pattern is matched by prefix alone (see testPat), so only the
	// prefix range is a safe superset for it.
	if !isVar && strings.Count(prefix, ":") < 5 {
		segs := strings.SplitN(text, ":", 6)
		if len(segs) >= 5 && segs[2] != "" && segs[4] != "" && !hasWildcard(segs[2]) && !hasWildcard(segs[4]) &&
			!strings.Contains(segs[2], "${") && !strings.Contains(segs[4], "${") {
			if rs.acctKeys == nil {
				rs.buildAcctView()
			}
			scanPrefix(rs.acctKeys, segs[2]+":"+segs[4]+":", func(k int) { fn(int(rs.acctOrd[k])) })
			return
		}
	}
	scanPrefix(rs.ARNs, prefix, fn)
}

// buildAcctView sorts the universe by service, account, region and the rest.
func (rs *Resources) buildAcctView() {
	type kv struct {
		k string
		i int32
	}
	var all []kv
	for i, a := range rs.ARNs {
		if p := strings.SplitN(a, ":", 6); len(p) == 6 {
			all = append(all, kv{p[2] + ":" + p[4] + ":" + p[3] + ":" + p[5], int32(i)})
		}
	}
	sort.Slice(all, func(x, y int) bool { return all[x].k < all[y].k })
	rs.acctKeys, rs.acctOrd = make([]string, len(all)), make([]int32, len(all))
	for n, e := range all {
		rs.acctKeys[n], rs.acctOrd[n] = e.k, e.i
	}
}

// matchAll tests an ARN against every live pattern.
func (rs *Resources) matchAll(arn string) []int32 {
	var out []int32
	for id := range rs.compile {
		if rs.pats.live[id] && rs.testPat(int32(id), arn) {
			out = append(out, int32(id))
		}
	}
	return out
}

// testPat reports whether pattern id matches arn (a variable pattern: shares its
// literal prefix).
func (rs *Resources) testPat(id int32, arn string) bool {
	if rs.patIsVar[id] {
		return strings.HasPrefix(arn, literalPrefix(rs.pats.text[id]))
	}
	p := rs.compile[id]
	return p != nil && p.Match(arn)
}

func (rs *Resources) varSensitive(ids []int32) bool {
	for _, id := range ids {
		if rs.patIsVar[id] {
			return true
		}
	}
	return false
}

// Lookup returns the atom of a universe resource, or -1. "" and "*" are the
// no-resource atom.
func (rs *Resources) Lookup(arn string) int32 {
	if arn == "" {
		arn = noneARN
	}
	if i, ok := rs.byARN[arn]; ok {
		return rs.AtomOf[i]
	}
	return -1
}

// RepARN is the representative resource of an atom.
func (rs *Resources) RepARN(id int32) string { return rs.ARNs[rs.Atoms[id].Rep] }

// MemberARNs lists the member resources of an atom.
func (rs *Resources) MemberARNs(id int32) []string {
	out := make([]string, len(rs.Atoms[id].Members))
	for i, m := range rs.Atoms[id].Members {
		out[i] = rs.ARNs[m]
	}
	return out
}

// hash128 is a 128-bit hash of a facts string: two FNV-1a runs with different
// prefixes. Equal hashes stand for equal facts; a collision would merge two
// atoms, which at a few million distinct facts has odds around 10^-25.
func hash128(s string) [2]uint64 {
	a, b := fnv.New64a(), fnv.New64a()
	_, _ = a.Write([]byte(s))
	_, _ = b.Write([]byte{0xff})
	_, _ = b.Write([]byte(s))
	return [2]uint64{a.Sum64(), b.Sum64()}
}

// factsText is the grouping text of an item: its facts hash, and for an item a
// policy variable can single out, the item itself.
func factsText(fk [2]uint64, varSensitive bool, arn string) string {
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], fk[0])
	binary.LittleEndian.PutUint64(buf[8:], fk[1])
	if varSensitive {
		return string(buf[:]) + "|arn:" + arn
	}
	return string(buf[:])
}

// sameResourceWorld reports whether everything resFacts reads is equal in two
// fact environments, so the facts of an item present in both are equal too.
func sameResourceWorld(a, b *factEnv) bool {
	if a == nil || b == nil || a.r.allResourceTags != b.r.allResourceTags ||
		!maps.Equal(a.r.resourceTagKeys, b.r.resourceTagKeys) || !maps.Equal(a.rcpKey, b.rcpKey) {
		return false
	}
	sa, sb := a.snap, b.snap
	return reflect.DeepEqual(sa.ResourcePolicies, sb.ResourcePolicies) && reflect.DeepEqual(sa.KMSGrants, sb.KMSGrants) &&
		reflect.DeepEqual(sa.S3, sb.S3) && reflect.DeepEqual(sa.CanonicalIDs, sb.CanonicalIDs) &&
		reflect.DeepEqual(sa.Resources, sb.Resources)
}

// AtomOfARN is Lookup for any ARN: one outside the universe gets its atom
// computed on the fly. The id is -1 when no atom has its signature, and then
// the returned info and sig describe the resource alone.
func (rs *Resources) atomOfARN(f *factEnv, arn string) (id int32, sig string, info ResAtomInfo) {
	if arn == "" {
		arn = noneARN
	}
	if id := rs.Lookup(arn); id >= 0 {
		return id, rs.Atoms[id].Sig, rs.Info[id]
	}
	rf := eval.ResolveResource(f.snap, arn)
	var ids []int32
	if !rf.None {
		ids = rs.matchAll(arn)
	}
	vs := rs.varSensitive(ids)
	facts := factsText(hash128(f.resFacts(arn, rf)), vs, arn)
	if id, ok := rs.byKey[matchKey(facts, ids)]; ok {
		return id, rs.Atoms[id].Sig, rs.Info[id]
	}
	return -1, sigOf(facts, &rs.pats, ids), f.newResInfo(arn, rf, vs)
}
