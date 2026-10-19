// Package index precomputes the structures that make effective-permission
// queries cheap (design §12): equivalence classes ("atoms") of actions,
// resources and requesters, per-requester action envelopes, inverted indexes and
// a decision memo. It is pure: no I/O, no clock, no SQL.
//
// The one soundness rule is that an atom's members are interchangeable for the
// engine: evaluating the representative gives the decision of every member. The
// signature of an atom therefore covers everything internal/aws/eval can read
// about its items; see Actions, Resources and Principals for the lists, and
// internal/aws/query's equivalence test for the check against the engine.
package index

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// Config says what the index covers.
type Config struct {
	// Catalog is the engine's catalog view.
	Catalog eval.Catalog
	// Actions is the action universe: the catalog's actions (§10). Every query
	// answers over exactly these actions.
	Actions []string
	// Resources are resources to cover beyond those the snapshot names (its
	// inventory, resource policies, KMS grants and S3 buckets).
	Resources []string
	// Applies, when set, says whether an action of a service prefix can be asked
	// of a resource of a service ("sqs", "s3", ...). A cell for which it is false
	// is not part of the answer: it is never evaluated and never listed. The
	// catalog's resource types (§10) will supply the real rule; a same-service
	// rule with a few exceptions (sts on iam roles) is what keeps a principal
	// with "Resource": "*" from being asked about every resource of every
	// service. A resource with no service (the no-resource pseudo-resource)
	// always applies. It must be a pure function.
	Applies func(actionPrefix, resourceService string) bool
}

// ErrConfig is returned for an unusable Config.
var ErrConfig = errors.New("index: invalid config")

// Index is the precomputed state for one snapshot. It is immutable once built,
// except for caches that fill lazily under their own locks, so any number of
// goroutines can query it.
type Index struct {
	Snap       *model.Snapshot
	Cat        eval.Catalog
	cfg        Config
	r          *refs
	f          *factEnv
	aenv       *actionEnv
	Actions    *Actions
	Resources  *Resources
	Principals *Principals
	inv        *inverted

	// Global is a hash of the facts that every decision depends on but no atom
	// signature carries: the organization's switches, the canonical-id map, VPC
	// endpoint policies, the catalog and the engine version. Equal Global and
	// equal atom signatures mean equal decisions, in this snapshot or another.
	Global string

	// Stats of the build or refinement that produced this index.
	ActionStats, ResourceStats RefineStats

	mu       sync.Mutex
	docAct   map[string]*docAct
	docGrant map[string][]Grant
	appRes   map[string]Bitset // action prefix to the resource atoms it applies to
	envSlots []envSlot
	whoOnce  sync.Once
	whoIndex []Bitset // action atom to the principal atoms whose envelope holds it
}

// Build indexes a snapshot.
func Build(snap *model.Snapshot, cfg Config) (*Index, error) {
	return build(snap, cfg, nil)
}

// Refine indexes next, reusing what it can of ix (§12.5): pattern ids, and the
// pattern match lists of every action and resource that is in both. Only the
// patterns that were added or removed are scanned; every other atom keeps its
// members. Patterns that no longer occur stay in the pattern tables, dead, until
// the next full Build, so atoms are split locally and merged back lazily.
//
// next may be any snapshot, not only a small change of ix.Snap: the cost is
// proportional to the patterns and items that differ.
func (ix *Index) Refine(next *model.Snapshot, cfg Config) (*Index, error) {
	return build(next, cfg, ix)
}

func build(snap *model.Snapshot, cfg Config, prev *Index) (*Index, error) {
	if snap == nil || cfg.Catalog == nil {
		return nil, ErrConfig
	}
	// Atom and pattern ids are int32.
	const maxItems = 1 << 30
	if len(cfg.Actions) > maxItems || len(cfg.Resources) > maxItems || len(snap.Resources) > maxItems ||
		len(snap.Principals) > maxItems || len(snap.Policies) > maxItems {
		return nil, ErrConfig
	}
	r := scanRefs(snap)
	f := newFactEnv(snap, r)
	ix := &Index{Snap: snap, Cat: cfg.Catalog, cfg: cfg, r: r, f: f,
		aenv:   &actionEnv{cat: cfg.Catalog, hasKMSGrants: r.hasKMSGrants, acl: aclBits(cfg.Catalog)},
		docAct: map[string]*docAct{}, docGrant: map[string][]Grant{}, appRes: map[string]Bitset{}}
	var pa *Actions
	var pr *Resources
	if prev != nil {
		pa, pr = prev.Actions, prev.Resources
	}
	ix.Actions, ix.ActionStats = buildActions(cfg.Actions, r, ix.aenv, pa)
	ix.Resources, ix.ResourceStats = buildResources(universeResources(snap, cfg.Resources), r, f, pr)
	ix.Principals = buildPrincipals(snap, r, f)
	ix.Global = globalSig(snap, cfg.Catalog)
	ix.inv = buildInverted(ix)
	ix.envSlots = make([]envSlot, len(ix.Principals.Atoms))
	return ix, nil
}

func globalSig(snap *model.Snapshot, cat eval.Catalog) string {
	var b strings.Builder
	b.WriteString(eval.EngineVersion + "|" + cat.Version() + "|")
	if o := snap.Org; o != nil {
		b.WriteString(o.OrgID + "|" + o.ManagementAccountID + "|" + boolStr(o.SCPEnabled) + boolStr(o.RCPEnabled))
	}
	b.WriteString("|canon:")
	b.WriteString(sortedPairs(snap.CanonicalIDs))
	b.WriteString("|vpce:")
	b.WriteString(sortedPairs(snap.VPCEPolicies))
	return shortHash(b.String())
}

func sortedPairs(m map[string]string) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k + "=" + m[k] + ";")
	}
	return b.String()
}

// ActionAtom returns the atom id and signature of any action name. The id is -1
// for an action outside the universe whose signature no atom has.
func (ix *Index) ActionAtom(name string) (id int32, sig string) {
	return ix.Actions.AtomOfAction(ix.aenv, name)
}

// ResourceAtom returns the atom id, signature and info of any resource ARN ("" or
// "*" is the no-resource atom). The id is -1 for a resource whose signature no
// atom has.
func (ix *Index) ResourceAtom(arn string) (id int32, sig string, info ResAtomInfo) {
	return ix.Resources.atomOfARN(ix.f, arn)
}

// PrincipalAtom returns the atom id of a principal of the snapshot, or -1.
func (ix *Index) PrincipalAtom(arn string) int32 { return ix.Principals.Lookup(arn) }

// Counts summarizes the index for logs and benchmarks.
type Counts struct {
	Actions, ActionAtoms        int
	Resources, ResourceAtoms    int
	Principals, PrincipalAtoms  int
	ActionPatterns, ResPatterns int
	IdentityProbes              int
	PoisonedResourceAtoms       int
	UnprunablePrincipalAtoms    int
}

// Counts reports sizes.
func (ix *Index) Counts() Counts {
	c := Counts{
		Actions: len(ix.Actions.Names), ActionAtoms: len(ix.Actions.Atoms),
		Resources: len(ix.Resources.ARNs), ResourceAtoms: len(ix.Resources.Atoms),
		Principals: len(ix.Principals.ARNs), PrincipalAtoms: len(ix.Principals.Atoms),
		ActionPatterns: len(ix.r.actionPats), ResPatterns: len(ix.r.resPats), IdentityProbes: len(ix.r.probes),
	}
	for _, i := range ix.Resources.Info {
		if i.Poisoned {
			c.PoisonedResourceAtoms++
		}
	}
	for _, i := range ix.Principals.Info {
		if i.Unprunable {
			c.UnprunablePrincipalAtoms++
		}
	}
	return c
}
