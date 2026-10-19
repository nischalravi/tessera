// Package catalog is the AWS action, resource-type and condition-key catalog
// (design §10). It is built offline from a pinned snapshot of the AWS Service
// Reference JSON, the pinned iam-dataset extract and Tessera's curated
// overlays (compile.go), stored as one deterministic artifact, and loaded
// read-only by the evaluator (loader.go).
//
// A loaded *Catalog is immutable and safe for concurrent use. It does no I/O
// and reads no clock: evaluation always matches the raw policy pattern, and
// the catalog only pre-expands wildcards for indexing (§8.2, §12).
package catalog

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// ActionID identifies one action of one catalog version. IDs are dense, start
// at 0 and are ordered by service prefix, then by lower-cased action name, so
// the actions of a service form one contiguous range.
type ActionID uint32

// ResourceType names a resource type as "<service>:<name>", for example
// "s3:bucket".
type ResourceType string

// AccessLevel is an action's access level.
type AccessLevel uint8

const (
	AccessUnknown AccessLevel = iota
	AccessList
	AccessRead
	AccessWrite
	AccessPermissionsManagement
	AccessTagging
)

var accessLevelNames = []string{"unknown", "list", "read", "write", "permissions_management", "tagging"}

func (l AccessLevel) String() string {
	if int(l) < len(accessLevelNames) {
		return accessLevelNames[l]
	}
	return "unknown"
}

// MarshalText encodes the level as its lower-case name.
func (l AccessLevel) MarshalText() ([]byte, error) {
	if int(l) >= len(accessLevelNames) {
		return nil, fmt.Errorf("catalog: access level %d out of range", l)
	}
	return []byte(accessLevelNames[l]), nil
}

// UnmarshalText decodes a level name.
func (l *AccessLevel) UnmarshalText(b []byte) error {
	for i, n := range accessLevelNames {
		if n == string(b) {
			*l = AccessLevel(i)
			return nil
		}
	}
	return fmt.Errorf("catalog: unknown access level %q", b)
}

// ActionSet is a set of ActionIDs (a plain bitset; the catalog has about
// 18,000 actions, so a set costs a few KiB).
type ActionSet struct{ words []uint64 }

func newActionSet(n int) *ActionSet { return &ActionSet{words: make([]uint64, (n+63)/64)} }

func (s *ActionSet) add(id ActionID) { s.words[id>>6] |= 1 << (id & 63) }

// Has reports whether id is in the set.
func (s *ActionSet) Has(id ActionID) bool {
	w := int(id >> 6)
	return w < len(s.words) && s.words[w]&(1<<(id&63)) != 0
}

// Len returns the number of actions in the set.
func (s *ActionSet) Len() int {
	n := 0
	for _, w := range s.words {
		n += bits.OnesCount64(w)
	}
	return n
}

// IDs returns the members in ascending order.
func (s *ActionSet) IDs() []ActionID {
	out := make([]ActionID, 0, s.Len())
	for i, w := range s.words {
		for w != 0 {
			b := bits.TrailingZeros64(w)
			out = append(out, ActionID(i*64+b)) // #nosec G115 -- set size ≤ maxActions
			w &= w - 1
		}
	}
	return out
}

// KeyInfo describes a condition key.
type KeyInfo struct {
	Name        string // as published, for example "aws:ResourceTag/${TagKey}"
	Type        model.KeyType
	Multivalued bool
}

type actionRec struct {
	name      string // canonical, "s3:GetObject"
	level     AccessLevel
	keys      []string // sorted
	rtypes    []ResourceType
	dependent []string
}

type rtRec struct {
	rt      ResourceType
	formats []string
	keys    []string
	tmpl    []template
}

// Catalog is a loaded, immutable catalog version.
type Catalog struct {
	version  string
	snapshot string
	actions  []actionRec
	byLower  map[string]ActionID
	svcRange map[string][2]ActionID // prefix -> [lo, hi)
	keys     map[string]KeyInfo     // normKey -> info
	rtypes   map[ResourceType]*rtRec
	rtBySvc  map[string][]*rtRec
	rcp      map[string]bool
	overlays Overlays
	dataset  string
}

// Version is the catalog version (snapshot date plus a content hash prefix).
func (c *Catalog) Version() string { return c.version }

// Snapshot is the date of the Service Reference snapshot the catalog was built from.
func (c *Catalog) Snapshot() string { return c.snapshot }

// IAMDatasetCommit is the pinned iam-dataset commit, or "" if none was used.
func (c *Catalog) IAMDatasetCommit() string { return c.dataset }

// Overlays returns the curated overlay data compiled into the catalog. The
// result shares storage with the catalog and must not be modified.
func (c *Catalog) Overlays() *Overlays { return &c.overlays }

// NumActions is the number of actions (ActionIDs are 0..NumActions()-1).
func (c *Catalog) NumActions() int { return len(c.actions) }

// Services returns the service prefixes in ascending order.
func (c *Catalog) Services() []string {
	out := make([]string, 0, len(c.svcRange))
	for s := range c.svcRange {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// asciiLower lower-cases ASCII A-Z only (design §8.1).
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
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

// CanonicalAction returns the published spelling of an action, matched
// case-insensitively (ASCII). ok is false for an action the catalog lacks.
func (c *Catalog) CanonicalAction(a string) (string, bool) {
	id, ok := c.byLower[asciiLower(a)]
	if !ok {
		return "", false
	}
	return c.actions[id].name, true
}

// ActionID returns the id of an action (case-insensitive).
func (c *Catalog) ActionID(a string) (ActionID, bool) {
	id, ok := c.byLower[asciiLower(a)]
	return id, ok
}

// ActionName returns the canonical name of id, or "" if out of range.
func (c *Catalog) ActionName(id ActionID) string {
	if int(id) >= len(c.actions) {
		return ""
	}
	return c.actions[id].name
}

// maxPatternLen bounds Expand's input; longer patterns match nothing.
const maxPatternLen = 512

// Expand returns the actions matching an IAM action pattern ("*" and "?"
// wildcards, ASCII case-insensitive). It is for indexing only: evaluation
// matches the raw pattern, so actions newer than this catalog still match.
func (c *Catalog) Expand(pattern string) *ActionSet {
	set := newActionSet(len(c.actions))
	if len(pattern) > maxPatternLen || len(c.actions) == 0 {
		return set
	}
	p := asciiLower(pattern)
	lo, hi := ActionID(0), ActionID(len(c.actions)) // #nosec G115 -- len(actions) ≤ maxActions
	if i := strings.IndexByte(p, ':'); i > 0 && !strings.ContainsAny(p[:i], "*?") {
		r, ok := c.svcRange[p[:i]]
		if !ok {
			return set
		}
		lo, hi = r[0], r[1]
	}
	for id := lo; id < hi; id++ {
		if globMatch(p, asciiLower(c.actions[id].name)) {
			set.add(id)
		}
	}
	return set
}

// globMatch matches s against pat ("*" any run, "?" any one byte), both
// already lower-cased. It is iterative with a single backtrack point, so it
// takes O(len(pat)*len(s)) time at worst and never recurses.
func globMatch(pat, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pat) && pat[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pat) && (pat[px] == '?' || pat[px] == s[sx]):
			px++
			sx++
		case star >= 0:
			mark++
			px, sx = star+1, mark
		default:
			return false
		}
	}
	for px < len(pat) && pat[px] == '*' {
		px++
	}
	return px == len(pat)
}

// ResourceTypes returns the resource types an action can authorize, sorted.
// It is empty for an unknown action and for one that supports only "*".
func (c *Catalog) ResourceTypes(action string) []ResourceType {
	id, ok := c.byLower[asciiLower(action)]
	if !ok {
		return nil
	}
	return append([]ResourceType(nil), c.actions[id].rtypes...)
}

// SupportsResourceLevel reports whether the action can be limited to
// resources (it lists at least one resource type).
func (c *Catalog) SupportsResourceLevel(action string) bool {
	id, ok := c.byLower[asciiLower(action)]
	return ok && len(c.actions[id].rtypes) > 0
}

// ConditionKeys returns the sorted condition keys that apply to the action,
// plus, when rt is not empty, the keys of that resource type. An unknown
// action returns nil.
func (c *Catalog) ConditionKeys(action string, rt ResourceType) []string {
	id, ok := c.byLower[asciiLower(action)]
	if !ok {
		return nil
	}
	keys := c.actions[id].keys
	if r := c.rtypes[rt]; rt != "" && r != nil {
		merged := make(map[string]bool, len(keys)+len(r.keys))
		for _, k := range keys {
			merged[k] = true
		}
		for _, k := range r.keys {
			merged[k] = true
		}
		out := make([]string, 0, len(merged))
		for k := range merged {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return append([]string(nil), keys...)
}

// normKey is the index form of a condition key: ASCII lower case, and for a
// key with a variable suffix only the part through the delimiter that starts
// it: "/" for tag keys ("aws:ResourceTag/Env", "s3:RequestObjectTag/<key>"),
// or a second ":" ("kms:EncryptionContext:project"), whichever comes first.
func normKey(k string) string {
	k = asciiLower(k)
	first := strings.IndexByte(k, ':')
	if first < 0 {
		return k
	}
	cut := -1
	if i := strings.IndexByte(k[first+1:], '/'); i >= 0 {
		cut = first + 1 + i
	}
	if i := strings.IndexByte(k[first+1:], ':'); i >= 0 && (cut < 0 || first+1+i < cut) {
		cut = first + 1 + i
	}
	if cut >= 0 {
		return k[:cut+1]
	}
	return k
}

// LookupKey finds a condition key (case-insensitive, tag suffix ignored).
func (c *Catalog) LookupKey(key string) (KeyInfo, bool) {
	ki, ok := c.keys[normKey(key)]
	return ki, ok
}

// KeyType is the key's declared type; a key the catalog does not list is a
// String (the AWS default for unknown keys).
func (c *Catalog) KeyType(key string) model.KeyType {
	if ki, ok := c.LookupKey(key); ok {
		return ki.Type
	}
	return model.KeyString
}

// IsMultivalued reports whether the key is an ArrayOf* key.
func (c *Catalog) IsMultivalued(key string) bool {
	ki, ok := c.LookupKey(key)
	return ok && ki.Multivalued
}

// MultivaluedKey has the signature of policy.Options.MultivaluedKey: it takes
// a lower-cased key.
func (c *Catalog) MultivaluedKey(lowerKey string) bool { return c.IsMultivalued(lowerKey) }

// RCPSupported reports whether RCPs apply to the service prefix.
func (c *Catalog) RCPSupported(service string) bool { return c.rcp[asciiLower(service)] }

// AccessLevel returns the action's access level (AccessUnknown if unknown).
func (c *Catalog) AccessLevel(action string) AccessLevel {
	id, ok := c.byLower[asciiLower(action)]
	if !ok {
		return AccessUnknown
	}
	return c.actions[id].level
}

// DependentActions returns the actions iam-dataset lists as also required.
func (c *Catalog) DependentActions(action string) []string {
	id, ok := c.byLower[asciiLower(action)]
	if !ok {
		return nil
	}
	return append([]string(nil), c.actions[id].dependent...)
}

// ARNFormats returns the ARN templates of a resource type.
func (c *Catalog) ARNFormats(rt ResourceType) []string {
	r := c.rtypes[rt]
	if r == nil {
		return nil
	}
	return append([]string(nil), r.formats...)
}

// maxARNLen bounds MatchResourceType's input.
const maxARNLen = 2048

// MatchResourceType finds the resource type whose ARN format matches arn. If
// several do, a resource type of the ARN's own service wins, then the one with
// the most literal text (so an S3 object ARN is not a bucket), then the fewest
// variables, then the lower name.
func (c *Catalog) MatchResourceType(arn string) (ResourceType, bool) {
	if len(arn) > maxARNLen {
		return "", false
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return "", false
	}
	var best *rtRec
	bestOwner, bestLit, bestVars := false, -1, 0
	for _, r := range c.rtBySvc[parts[2]] {
		// a service's own resource types win: other services reuse ARNs
		// (ec2 lists a "role" type with an IAM ARN)
		owner := strings.HasPrefix(string(r.rt), parts[2]+":")
		for _, t := range r.tmpl {
			if !t.match(arn) {
				continue
			}
			lit, nv := t.literalLen(), t.numVars()
			better := false
			switch {
			case best == nil || owner != bestOwner:
				better = best == nil || owner
			case lit != bestLit:
				better = lit > bestLit
			case nv != bestVars:
				better = nv < bestVars
			default:
				better = r.rt < best.rt
			}
			if better {
				best, bestOwner, bestLit, bestVars = r, owner, lit, nv
			}
		}
	}
	if best == nil {
		return "", false
	}
	return best.rt, true
}

// template is a parsed ARN format: literal text and ${Variable} holes.
type template struct{ toks []tok }

type tok struct {
	lit string
	v   string // variable name; "" for literal
}

func parseTemplate(f string) template {
	var t template
	for len(f) > 0 {
		i := strings.Index(f, "${")
		if i < 0 {
			t.toks = append(t.toks, tok{lit: f})
			break
		}
		j := strings.IndexByte(f[i:], '}')
		if j < 0 {
			t.toks = append(t.toks, tok{lit: f})
			break
		}
		if i > 0 {
			t.toks = append(t.toks, tok{lit: f[:i]})
		}
		t.toks = append(t.toks, tok{v: f[i+2 : i+j]})
		f = f[i+j+1:]
	}
	return t
}

func (t template) literalLen() int {
	n := 0
	for _, k := range t.toks {
		n += len(k.lit)
	}
	return n
}

func (t template) numVars() int {
	n := 0
	for _, k := range t.toks {
		if k.v != "" {
			n++
		}
	}
	return n
}

// match reports whether s fits the template. Variables match one or more
// bytes; Partition, Region and Account do not span a ":". It is a dynamic
// program over (token, position), so it is O(tokens*len(s)) and never
// backtracks exponentially.
func (t template) match(s string) bool {
	n := len(s)
	cur := make([]bool, n+1) // cur[p]: tokens[:i] can consume s[:p]
	cur[0] = true
	for _, k := range t.toks {
		next := make([]bool, n+1)
		if k.v == "" {
			for p := 0; p+len(k.lit) <= n; p++ {
				if cur[p] && s[p:p+len(k.lit)] == k.lit {
					next[p+len(k.lit)] = true
				}
			}
		} else {
			noColon := k.v == "Partition" || k.v == "Region" || k.v == "Account"
			active := false // some start p <= q has cur[p] and no ":" in s[p:q]
			for q := 0; q < n; q++ {
				if noColon && s[q] == ':' {
					active = false
					continue
				}
				if cur[q] {
					active = true
				}
				if active {
					next[q+1] = true
				}
			}
		}
		cur = next
	}
	return cur[n]
}
