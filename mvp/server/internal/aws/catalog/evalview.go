package catalog

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
)

// EvalView is a Catalog as the engine sees it (eval.Catalog): the compiled
// action list, the condition keys' types and the reviewed overlays (RCP
// services, the KMS cross-account allowlist, the S3 ACL map, explicit-allow
// rules and the public-policy key rules).
type EvalView struct {
	C *Catalog

	kms map[string]bool
	pub map[string]eval.S3PublicKeyRule
	rbp map[string]RBPRule
}

var _ eval.Catalog = (*EvalView)(nil)

// NewEvalView builds the view; it indexes the overlays once.
func NewEvalView(c *Catalog) *EvalView {
	v := &EvalView{C: c, kms: map[string]bool{}, pub: map[string]eval.S3PublicKeyRule{}, rbp: map[string]RBPRule{}}
	o := c.Overlays()
	for _, a := range o.KMSXacct.Actions {
		v.kms[asciiLower(a)] = true
	}
	for _, k := range o.S3Public.Keys {
		r := eval.S3PublicKeyRule{ExceptPatterns: k.ExceptPatterns, IPv4MaxCIDR: k.IPv4MaxCIDRSize, IPv6MaxCIDR: k.IPv6MaxCIDRSize,
			BucketPoliciesOnly: k.BucketPoliciesOnly}
		if k.Rule == "ip_range" {
			r.Kind = eval.S3IPRange
		}
		v.pub[asciiLower(k.Name)] = r
	}
	for _, r := range o.RBP.Rules {
		v.rbp[r.Service] = r
	}
	return v
}

// Version implements eval.Catalog.
func (v *EvalView) Version() string { return v.C.Version() }

// CanonicalAction implements eval.Catalog.
func (v *EvalView) CanonicalAction(a string) (string, bool) { return v.C.CanonicalAction(a) }

// RCPSupportedService implements eval.Catalog.
func (v *EvalView) RCPSupportedService(prefix string) bool { return v.C.RCPSupported(prefix) }

// MultivaluedKey implements eval.Catalog.
func (v *EvalView) MultivaluedKey(lowerKey string) bool { return v.C.MultivaluedKey(lowerKey) }

// ResourceTagsSupported implements eval.Catalog: the action lists
// aws:ResourceTag/${TagKey} among the condition keys of its action or of a
// resource type it authorizes (§9.2). The engine asks by action alone, so an
// action counts as supporting resource tags when any of its resource types does.
func (v *EvalView) ResourceTagsSupported(action string) bool {
	has := func(keys []string) bool {
		for _, k := range keys {
			if normKey(k) == "aws:resourcetag/" {
				return true
			}
		}
		return false
	}
	rts := v.C.ResourceTypes(action)
	if len(rts) == 0 {
		return has(v.C.ConditionKeys(action, ""))
	}
	for _, rt := range rts {
		if has(v.C.ConditionKeys(action, rt)) {
			return true
		}
	}
	return false
}

// RequiresExplicitRBP implements eval.Catalog from rbp_rules.yaml: a service
// with no rule uses the union rule and is unverified.
func (v *EvalView) RequiresExplicitRBP(servicePrefix string) (explicit, verified bool) {
	r, ok := v.rbp[asciiLower(servicePrefix)]
	if !ok {
		return false, false
	}
	return r.RequiresExplicitAllow, r.Verified
}

// KMSCrossAccountOp implements eval.Catalog.
func (v *EvalView) KMSCrossAccountOp(action string) bool { return v.kms[asciiLower(action)] }

// S3ACLActions implements eval.Catalog.
func (v *EvalView) S3ACLActions(scope eval.S3ACLScope, permission string) []string {
	m := v.C.Overlays().S3ACL.Bucket
	if scope == eval.S3ACLObject {
		m = v.C.Overlays().S3ACL.Object
	}
	return m[permission]
}

// S3ACLGroup implements eval.Catalog.
func (v *EvalView) S3ACLGroup(uri string) (eval.S3ACLGroup, bool) {
	for _, g := range v.C.Overlays().S3ACL.Groups {
		if g.URI == uri {
			return eval.S3ACLGroup{Name: g.Name, Public: g.Public}, true
		}
	}
	return eval.S3ACLGroup{}, false
}

// S3PublicFixedKey implements eval.Catalog.
func (v *EvalView) S3PublicFixedKey(lowerKey string) (eval.S3PublicKeyRule, bool) {
	r, ok := v.pub[lowerKey]
	return r, ok
}

// Actions lists every action of the catalog, the action universe of an index
// (design §12): the answer to "what can X do" covers exactly these.
func (v *EvalView) Actions() []string {
	out := make([]string, 0, v.C.NumActions())
	for id := 0; id < v.C.NumActions(); id++ {
		out = append(out, v.C.ActionName(ActionID(id))) // #nosec G115 -- NumActions is bounded by maxActions
	}
	return out
}

// SameServiceRule is the index's rule for which (action, resource) cells are
// asked: an action applies to resources of its own service, and sts actions
// to IAM roles and users (the principals that are assumed or tagged). It keeps
// a principal with "Resource": "*" from being asked about every resource of
// every service.
func SameServiceRule(actionPrefix, resourceService string) bool {
	actionPrefix, resourceService = strings.ToLower(actionPrefix), strings.ToLower(resourceService)
	return actionPrefix == resourceService || (actionPrefix == "sts" && resourceService == "iam")
}
