package harness

import (
	"context"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

// World is the engine's view of a spec: a snapshot plus the document ids the
// comparator needs to map an oracle's statement positions back to ours.
type World struct {
	Snapshot *model.Snapshot
	// IdentityDocIDs and ResourceDocID map the oracle's "PolicyInputList.N" and
	// "ResourcePolicy" source ids to PolicyDoc ids.
	IdentityDocIDs []string
	ResourceDocID  string
}

const syntheticRootAllow = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// BuildWorld turns a spec into a snapshot. The SCP levels run root to account:
// the last level belongs to the account node and the first to the root. With a
// single level the root gets a synthetic allow-all SCP, because the engine (like
// Organizations) needs an Allow at every level of the path.
func BuildWorld(s *RequestSpec) (*World, error) {
	acct, kind, err := principalParts(s.PrincipalARN)
	if err != nil {
		return nil, err
	}
	b := snapshot.NewBuilder()
	w := &World{}
	add := func(k model.PolicyKind, src string, raw string) string {
		d := b.AddPolicy(policy.Options{Kind: k, SourceARN: src}, []byte(raw))
		return d.ID
	}
	var identityIDs []string
	for i, p := range s.Identity {
		id := add(model.PolicyIdentity, fmt.Sprintf("arn:aws:iam::%s:policy/%s-id%d", acct, s.ID, i), p)
		identityIDs = append(identityIDs, id)
	}
	w.IdentityDocIDs = identityIDs
	boundaryID := ""
	if len(s.Boundary) == 1 {
		boundaryID = add(model.PolicyBoundary, fmt.Sprintf("arn:aws:iam::%s:policy/%s-pb", acct, s.ID), s.Boundary[0])
	}
	pk, uid := model.IAMUser, "AIDAHARNESS"
	if kind == "role" {
		pk, uid = model.IAMRole, "AROAHARNESS"
	}
	b.AddPrincipal(&model.Principal{ARN: s.PrincipalARN, Kind: pk, AccountID: acct, UniqueID: uid, Path: "/",
		IdentityPolicyIDs: identityIDs, BoundaryPolicyID: boundaryID})

	if s.ResourcePolicy != "" {
		target := s.Resource
		if rest, ok := strings.CutPrefix(s.Resource, "arn:aws:s3:::"); ok {
			bucket := "arn:aws:s3:::" + strings.SplitN(rest, "/", 2)[0]
			target = bucket
			b.AddS3Bucket(&model.S3BucketState{BucketARN: bucket, OwnerAccount: s.ResourceOwner, ObjectOwnership: "BucketOwnerEnforced"})
		}
		if target == "" || target == "*" {
			return nil, fmt.Errorf("harness: spec %s: a resource policy needs a resource ARN", s.ID)
		}
		id := add(model.PolicyResource, target+"#policy0", s.ResourcePolicy)
		w.ResourceDocID = id
		b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: target, Kind: model.PolicyResource, PolicyID: id})
	} else if rest, ok := strings.CutPrefix(s.Resource, "arn:aws:s3:::"); ok {
		bucket := "arn:aws:s3:::" + strings.SplitN(rest, "/", 2)[0]
		b.AddS3Bucket(&model.S3BucketState{BucketARN: bucket, OwnerAccount: acct, ObjectOwnership: "BucketOwnerEnforced"})
	}

	if n := len(s.SCPLevels); n > 0 {
		nodes := map[string]*model.OrgNode{}
		levelIDs := func(i int) []string {
			var ids []string
			for j, p := range s.SCPLevels[i] {
				ids = append(ids, add(model.PolicySCP, fmt.Sprintf("arn:aws:organizations::999999999999:policy/o-harness/service_control_policy/p-%s-l%d-%d", s.ID, i, j), p))
			}
			return ids
		}
		parent := ""
		if n == 1 {
			nodes["r-h"] = &model.OrgNode{ID: "r-h", Kind: model.OrgRoot, Name: "Root",
				SCPIDs: []string{add(model.PolicySCP, "arn:aws:organizations::aws:policy/service_control_policy/p-HarnessRootAllow", syntheticRootAllow)}}
			parent = "r-h"
		}
		for i := 0; i < n; i++ {
			id, k := fmt.Sprintf("ou-h%d", i), model.OrgOU
			switch {
			case i == 0 && n > 1:
				id, k = "r-h", model.OrgRoot
			case i == n-1:
				id, k = acct, model.OrgAccount
			}
			nodes[id] = &model.OrgNode{ID: id, Kind: k, ParentID: parent, Name: id, SCPIDs: levelIDs(i)}
			parent = id
		}
		b.SetOrg(&model.Organization{OrgID: "o-harness", ManagementAccountID: "999999999999", Nodes: nodes, SCPEnabled: true})
	}
	snap, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("harness: spec %s: %w", s.ID, err)
	}
	w.Snapshot = snap
	return w, nil
}

// engineContext is the context both the engine and the simulator receive: the
// spec's explicit keys, plus aws:PrincipalArn, which the simulator does not
// fill in by itself (§13.2).
func engineContext(s *RequestSpec) map[string]eval.ContextValue {
	out := map[string]eval.ContextValue{}
	for _, k := range s.contextKeys() {
		out[strings.ToLower(k)] = eval.PresentValues(s.Context[k].Values...)
	}
	if _, ok := out["aws:principalarn"]; !ok {
		out["aws:principalarn"] = eval.PresentValues(s.PrincipalARN)
	}
	return out
}

// Decide evaluates the spec with the engine in concrete mode.
func Decide(ctx context.Context, cat eval.Catalog, s *RequestSpec) (*authz.Decision, *World, error) {
	if err := s.CheckIngest(); err != nil {
		return nil, nil, err
	}
	w, err := BuildWorld(s)
	if err != nil {
		return nil, nil, err
	}
	res := s.Resource
	if res == "*" {
		res = ""
	}
	req := &eval.EvaluationRequest{PrincipalARN: s.PrincipalARN, Action: s.Action, ResourceARN: res, Context: engineContext(s)}
	d, err := eval.Evaluate(ctx, w.Snapshot, cat, req, eval.Options{})
	if err != nil {
		return nil, w, err
	}
	return d, w, nil
}
