package snapshot_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

func sp(s string) *string { return &s }

const v2012 = `"Version":"2012-10-17"`

func estate(t *testing.T) *model.Snapshot {
	t.Helper()
	s, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ch(op snapshot.PolicyChangeOp, target string, doc, pol *string) snapshot.PolicyChange {
	return snapshot.PolicyChange{Op: op, TargetARN: target, Document: doc, PolicyARN: pol}
}

func apply(t *testing.T, base *model.Snapshot, cs ...snapshot.PolicyChange) *model.Snapshot {
	t.Helper()
	out, err := snapshot.Apply(base, cs, snapshot.ApplyOptions{FetchedAt: awstest.EstateTime})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return out
}

func docsOf(s *model.Snapshot, p *model.Principal) []string {
	var out []string
	for _, id := range p.IdentityPolicyIDs {
		out = append(out, s.Policies[id].SourceARN)
	}
	return out
}

func TestApplyNoChangesIsTheSameContent(t *testing.T) {
	base := estate(t)
	got := apply(t, base)
	if got.ID != base.ID {
		t.Errorf("Apply with no changes has id %s, base %s", got.ID, base.ID)
	}
}

// Apply never changes the snapshot it is given: its content hash is the same
// after every op, and the result has a hash of its own.
func TestApplyDoesNotMutateBase(t *testing.T) {
	base := estate(t)
	before, err := snapshot.Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	allow := `{` + v2012 + `,"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	seen := map[snapshot.PolicyChangeOp]bool{}
	for _, seq := range okChanges(allow) {
		got := apply(t, base, seq...)
		for _, c := range seq {
			seen[c.Op] = true
		}
		// clearing a boundary that is not set changes nothing
		noop := seq[0].Op == snapshot.OpDeleteBoundary
		if (got.ID == base.ID) != noop {
			t.Errorf("%s: result id %s, base %s; a no-op is %v", seq[0].Op, got.ID, base.ID, noop)
		}
		if h, _ := snapshot.Hash(base); h != before {
			t.Fatalf("%s mutated the base snapshot", seq[0].Op)
		}
	}
	for _, op := range snapshot.PolicyChangeOps() {
		if !seen[op] {
			t.Errorf("op %s is not exercised", op)
		}
	}
}

// okChanges is a valid change sequence for every op against Estate.
func okChanges(allow string) [][]snapshot.PolicyChange {
	grant := `{"grant_id":"g1","grantee_principal":"` + awstest.EstateDevUser + `","operations":["Decrypt"]}`
	const newSCP = "arn:aws:organizations::aws:policy/service_control_policy/p-new"
	const newRCP = "arn:aws:organizations::aws:policy/resource_control_policy/p-new"
	one := func(c snapshot.PolicyChange) []snapshot.PolicyChange { return []snapshot.PolicyChange{c} }
	return [][]snapshot.PolicyChange{
		one(ch(snapshot.OpPutPolicyVersion, awstest.EstateS3Read, &allow, nil)),
		one(ch(snapshot.OpAttach, awstest.EstateDevUser, nil, sp(awstest.EstateS3Read))),
		one(ch(snapshot.OpDetach, awstest.EstateAlice, nil, sp(awstest.EstateS3Read))),
		one(ch(snapshot.OpPutInline, awstest.EstateDevUser, &allow, sp("extra"))),
		one(ch(snapshot.OpDeleteInline, awstest.EstateAlice, nil, sp("assume"))),
		one(ch(snapshot.OpPutBoundary, awstest.EstateAlice, &allow, nil)),
		one(ch(snapshot.OpDeleteBoundary, awstest.EstateAlice, nil, nil)), // a no-op for an entity with no boundary
		one(ch(snapshot.OpPutResourcePolicy, awstest.EstateBucket, &allow, nil)),
		one(ch(snapshot.OpPutTrustPolicy, awstest.EstateEngineer, &allow, nil)),
		{ch(snapshot.OpPutSCP, newSCP, &allow, nil), ch(snapshot.OpAttachSCP, awstest.EstateOUProd, nil, sp(newSCP))},
		one(ch(snapshot.OpDetachSCP, awstest.EstateProd, nil, sp(awstest.EstateFullSCP))),
		one(ch(snapshot.OpPutSCP, awstest.EstateFullSCP, &allow, nil)),
		{ch(snapshot.OpPutRCP, newRCP, &allow, nil), ch(snapshot.OpAttachRCP, awstest.EstateOUProd, nil, sp(newRCP))},
		one(ch(snapshot.OpDetachRCP, awstest.EstateProd, nil, sp(awstest.EstateFullRCP))),
		one(ch(snapshot.OpMoveAccount, awstest.EstateDev, nil, sp(awstest.EstateOUProd))),
		one(ch(snapshot.OpCreateGrant, awstest.EstateKey, &grant, nil)),
		{ch(snapshot.OpCreateGrant, awstest.EstateKey, &grant, nil), ch(snapshot.OpRetireGrant, awstest.EstateKey, nil, sp("g1")), ch(snapshot.OpPutBPA, awstest.EstateBucket, sp(`{"block_public_acls":true}`), nil)},
		one(ch(snapshot.OpPutBPA, awstest.EstateBucket, sp(`{"block_public_acls":true,"restrict_public_buckets":true}`), nil)),
		one(ch(snapshot.OpPutOwnershipControl, awstest.EstateBucket, sp(`"ObjectWriter"`), nil)),
	}
}

func TestApplyEveryOpChangesTheSnapshotAsDocumented(t *testing.T) {
	base := estate(t)
	allow := `{` + v2012 + `,"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

	t.Run("put_policy_version replaces the document wherever the policy is used", func(t *testing.T) {
		got := apply(t, base, ch(snapshot.OpPutPolicyVersion, awstest.EstateS3Read, &allow, nil))
		alice := got.Principals[awstest.EstateAlice]
		if !slices.Contains(docsOf(got, alice), awstest.EstateS3Read) {
			t.Fatalf("alice has %v", docsOf(got, alice))
		}
		for _, id := range alice.IdentityPolicyIDs {
			d := got.Policies[id]
			if d.SourceARN == awstest.EstateS3Read && (string(d.RawJSON) != allow || d.Unparseable != "") {
				t.Errorf("the new document is %q (%q)", d.RawJSON, d.Unparseable)
			}
		}
		// the old document is gone from the snapshot, and the attachment follows the new one
		for id, d := range got.Policies {
			if d.SourceARN == awstest.EstateS3Read && string(d.RawJSON) != allow {
				t.Errorf("old document %s is still in the snapshot", id)
			}
		}
		for _, a := range got.Attachments {
			if got.Policies[a.PolicyID] == nil {
				t.Errorf("attachment %+v names a document that is not in the snapshot", a)
			}
		}
	})

	t.Run("attach and detach a managed policy", func(t *testing.T) {
		got := apply(t, base, ch(snapshot.OpAttach, awstest.EstateDevUser, nil, sp(awstest.EstateS3Read)))
		if d := docsOf(got, got.Principals[awstest.EstateDevUser]); !slices.Equal(d, []string{awstest.EstateS3Read}) {
			t.Errorf("dev has %v", d)
		}
		got = apply(t, base, ch(snapshot.OpDetach, awstest.EstateAlice, nil, sp(awstest.EstateS3Read)))
		if d := docsOf(got, got.Principals[awstest.EstateAlice]); slices.Contains(d, awstest.EstateS3Read) {
			t.Errorf("alice still has %v", d)
		}
	})

	t.Run("an inline policy on a group reaches its members", func(t *testing.T) {
		got := apply(t, base, ch(snapshot.OpPutInline, awstest.EstateGroup, &allow, sp("list")))
		bob := got.Principals[awstest.EstateBob]
		n := 0
		for _, id := range bob.IdentityPolicyIDs {
			if got.Policies[id].SourceARN == awstest.EstateGroup+"#inline/list" {
				n++
				if string(got.Policies[id].RawJSON) != allow {
					t.Errorf("bob's group policy is %q", got.Policies[id].RawJSON)
				}
			}
		}
		if n != 1 {
			t.Errorf("bob has %d copies of the group policy, want the replaced one", n)
		}
		if len(got.Principals[awstest.EstateAlice].IdentityPolicyIDs) != 2 {
			t.Error("a group change reached a user outside the group")
		}
		got = apply(t, base, ch(snapshot.OpDeleteInline, awstest.EstateGroup, nil, sp("list")))
		if d := docsOf(got, got.Principals[awstest.EstateBob]); len(d) != 0 {
			t.Errorf("bob still has %v", d)
		}
	})

	t.Run("a boundary is set and cleared, with its attachment", func(t *testing.T) {
		got := apply(t, base, ch(snapshot.OpPutBoundary, awstest.EstateAlice, &allow, sp("arn:aws:iam::111111111111:policy/Boundary")))
		a := got.Principals[awstest.EstateAlice]
		if d := got.Policies[a.BoundaryPolicyID]; d == nil || d.Kind != model.PolicyBoundary || d.SourceARN != "arn:aws:iam::111111111111:policy/Boundary" {
			t.Fatalf("boundary = %+v", d)
		}
		got = apply(t, got, ch(snapshot.OpDeleteBoundary, awstest.EstateAlice, nil, nil))
		if got.Principals[awstest.EstateAlice].BoundaryPolicyID != "" {
			t.Error("the boundary was not cleared")
		}
		for _, at := range got.Attachments {
			if at.AttachmentType == model.AttachBoundary {
				t.Errorf("boundary attachment %+v is left", at)
			}
		}
	})

	t.Run("a resource policy and a trust policy replace the old ones", func(t *testing.T) {
		got := apply(t, base,
			ch(snapshot.OpPutResourcePolicy, awstest.EstateBucket, &allow, nil),
			ch(snapshot.OpPutResourcePolicy, awstest.EstateBucket, &allow, nil), // twice: still one
			ch(snapshot.OpPutTrustPolicy, awstest.EstateEngineer, &allow, nil))
		rp := got.ResourcePolicies[awstest.EstateBucket]
		if len(rp) != 1 || rp[0].Kind != model.PolicyResource || rp[0].RequiresExplicitAllow {
			t.Errorf("bucket policies = %+v", rp)
		}
		tr := got.ResourcePolicies[awstest.EstateEngineer]
		if len(tr) != 1 || tr[0].Kind != model.PolicyTrust || !tr[0].RequiresExplicitAllow || string(got.Policies[tr[0].PolicyID].RawJSON) != allow {
			t.Errorf("trust policies = %+v", tr)
		}
		key := apply(t, base, ch(snapshot.OpPutResourcePolicy, awstest.EstateKey, &allow, nil)).ResourcePolicies[awstest.EstateKey]
		if len(key) != 1 || key[0].Kind != model.PolicyKMSKey || !key[0].RequiresExplicitAllow {
			t.Errorf("key policies = %+v", key)
		}
	})

	t.Run("organization policies", func(t *testing.T) {
		got := apply(t, base, ch(snapshot.OpDetachSCP, awstest.EstateRoot, nil, sp(awstest.EstateFullSCP)))
		if n := got.Org.Nodes[awstest.EstateRoot].SCPIDs; len(n) != 0 {
			t.Errorf("root still has SCPs %v", n)
		}
		if len(got.Policies) != len(base.Policies) {
			t.Errorf("the SCP is still attached below the root, yet %d policies, base %d", len(got.Policies), len(base.Policies))
		}
		// detached everywhere, the SCP is pruned
		var all []snapshot.PolicyChange
		for _, node := range []string{awstest.EstateRoot, awstest.EstateOUProd, awstest.EstateProd, awstest.EstateDev} {
			all = append(all, ch(snapshot.OpDetachSCP, node, nil, sp(awstest.EstateFullSCP)))
		}
		if got = apply(t, base, all...); len(got.Policies) != len(base.Policies)-1 {
			t.Errorf("the detached SCP is not pruned: %d policies, base %d", len(got.Policies), len(base.Policies))
		}
		// put then attach in one request
		deny := `{` + v2012 + `,"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
		const arn = "arn:aws:organizations::aws:policy/service_control_policy/p-new"
		got = apply(t, base, ch(snapshot.OpPutSCP, arn, &deny, nil), ch(snapshot.OpAttachSCP, awstest.EstateOUProd, nil, sp(arn)))
		if n := got.Org.Nodes[awstest.EstateOUProd].SCPIDs; len(n) != 2 || !slices.ContainsFunc(n, func(id string) bool { return got.Policies[id].SourceARN == arn }) {
			t.Errorf("OU SCPs = %v", n)
		}
		// replacing an attached SCP changes it at every node
		got = apply(t, base, ch(snapshot.OpPutSCP, awstest.EstateFullSCP, &deny, nil))
		if n := got.Org.Nodes[awstest.EstateRoot].SCPIDs; len(n) != 1 || string(got.Policies[n[0]].RawJSON) != deny {
			t.Errorf("root SCPs = %v", n)
		}
		got = apply(t, base, ch(snapshot.OpMoveAccount, awstest.EstateDev, nil, sp(awstest.EstateOUProd)))
		if p := got.Org.PathTo(awstest.EstateDev); len(p) != 3 || p[1].ID != awstest.EstateOUProd {
			t.Errorf("path of the moved account = %v", p)
		}
	})

	t.Run("KMS grants and S3 state", func(t *testing.T) {
		grant := `{"grant_id":"g1","grantee_principal":"` + awstest.EstateDevUser + `","operations":["Decrypt","Encrypt"]}`
		got := apply(t, base, ch(snapshot.OpCreateGrant, awstest.EstateKey, &grant, nil))
		if gs := got.KMSGrants[awstest.EstateKey]; len(gs) != 1 || gs[0].KeyARN != awstest.EstateKey || gs[0].GrantID != "g1" {
			t.Fatalf("grants = %+v", gs)
		}
		got = apply(t, got, ch(snapshot.OpRetireGrant, awstest.EstateKey, nil, sp("g1")))
		if len(got.KMSGrants) != 0 {
			t.Errorf("grants after retire = %+v", got.KMSGrants)
		}
		got = apply(t, base, ch(snapshot.OpPutBPA, awstest.EstateProd, sp(`{"block_public_acls":true}`), nil))
		if !got.S3[awstest.EstateBucket].BPAAccount.BlockPublicAcls || got.S3[awstest.EstateBucket].BPABucket.BlockPublicAcls {
			t.Errorf("account BPA = %+v", got.S3[awstest.EstateBucket])
		}
		got = apply(t, base, ch(snapshot.OpPutBPA, awstest.EstateBucket, sp(`{"restrict_public_buckets":true}`), nil),
			ch(snapshot.OpPutOwnershipControl, awstest.EstateBucket, sp(`"ObjectWriter"`), nil))
		if s := got.S3[awstest.EstateBucket]; !s.BPABucket.RestrictPublicBuckets || s.ObjectOwnership != "ObjectWriter" {
			t.Errorf("bucket state = %+v", s)
		}
	})
}

// A document that does not parse is kept as unparseable, never skipped (§3.3).
func TestApplyUnparseableDocumentFailsClosed(t *testing.T) {
	base := estate(t)
	got := apply(t, base, ch(snapshot.OpPutPolicyVersion, awstest.EstateS3Read, sp(`{"Version":`), nil))
	found := false
	for _, id := range got.Principals[awstest.EstateAlice].IdentityPolicyIDs {
		if d := got.Policies[id]; d.SourceARN == awstest.EstateS3Read {
			found = true
			if d.Unparseable == "" {
				t.Error("an unparseable document is not flagged")
			}
		}
	}
	if !found {
		t.Error("the unparseable document was skipped")
	}
}

func TestApplyOrderOfIndependentChangesDoesNotMatter(t *testing.T) {
	base := estate(t)
	allow := `{` + v2012 + `,"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	a := ch(snapshot.OpPutPolicyVersion, awstest.EstateS3Read, &allow, nil)
	b := ch(snapshot.OpPutBPA, awstest.EstateBucket, sp(`{"restrict_public_buckets":true}`), nil)
	c := ch(snapshot.OpAttach, awstest.EstateDevUser, nil, sp(awstest.EstateS3Read))
	if x, y := apply(t, base, a, b, c), apply(t, base, c, b, a); x.ID != y.ID {
		// attach needs the policy in the snapshot, which it is already; the order of independent changes is free
		t.Errorf("ids differ: %s and %s", x.ID, y.ID)
	}
}

func TestApplyRefusesBadChanges(t *testing.T) {
	base := estate(t)
	allow := `{` + v2012 + `,"Statement":[]}`
	for name, tc := range map[string]snapshot.PolicyChange{
		"no target":                    ch(snapshot.OpAttach, "", nil, sp(awstest.EstateS3Read)),
		"an unknown op":                ch("explode", awstest.EstateAlice, nil, nil),
		"put without document":         ch(snapshot.OpPutResourcePolicy, awstest.EstateBucket, nil, nil),
		"attach without a policy":      ch(snapshot.OpAttach, awstest.EstateAlice, nil, nil),
		"unknown principal":            ch(snapshot.OpAttach, "arn:aws:iam::111111111111:user/nobody", nil, sp(awstest.EstateS3Read)),
		"unknown policy":               ch(snapshot.OpAttach, awstest.EstateAlice, nil, sp("arn:aws:iam::111111111111:policy/Nope")),
		"detach what is not attached":  ch(snapshot.OpDetach, awstest.EstateDevUser, nil, sp(awstest.EstateS3Read)),
		"bad inline name":              ch(snapshot.OpPutInline, awstest.EstateAlice, &allow, sp("../x")),
		"delete a missing inline":      ch(snapshot.OpDeleteInline, awstest.EstateAlice, nil, sp("nope")),
		"unknown resource":             ch(snapshot.OpPutResourcePolicy, "arn:aws:s3:::nope", &allow, nil),
		"trust policy on a user":       ch(snapshot.OpPutTrustPolicy, awstest.EstateAlice, &allow, nil),
		"boundary on a group":          ch(snapshot.OpPutBoundary, awstest.EstateGroup, &allow, nil),
		"attach SCP to an unknown OU":  ch(snapshot.OpAttachSCP, "ou-nope", nil, sp(awstest.EstateFullSCP)),
		"detach an SCP not attached":   ch(snapshot.OpDetachSCP, awstest.EstateOUProd, nil, sp("arn:aws:organizations::aws:policy/service_control_policy/p-nope")),
		"move an OU":                   ch(snapshot.OpMoveAccount, awstest.EstateOUProd, nil, sp(awstest.EstateRoot)),
		"move under an account":        ch(snapshot.OpMoveAccount, awstest.EstateDev, nil, sp(awstest.EstateProd)),
		"grant with unknown field":     ch(snapshot.OpCreateGrant, awstest.EstateKey, sp(`{"grant_id":"g","grantee_principal":"x","evil":1}`), nil),
		"grant without a grantee":      ch(snapshot.OpCreateGrant, awstest.EstateKey, sp(`{"grant_id":"g"}`), nil),
		"retire a missing grant":       ch(snapshot.OpRetireGrant, awstest.EstateKey, nil, sp("nope")),
		"BPA of a missing bucket":      ch(snapshot.OpPutBPA, "arn:aws:s3:::nope", sp(`{}`), nil),
		"BPA with trailing data":       ch(snapshot.OpPutBPA, awstest.EstateBucket, sp(`{} {}`), nil),
		"unknown ownership mode":       ch(snapshot.OpPutOwnershipControl, awstest.EstateBucket, sp(`"Anyone"`), nil),
		"SCP policy without a node id": ch(snapshot.OpAttachSCP, "", nil, sp(awstest.EstateFullSCP)),
	} {
		_, err := snapshot.Apply(base, []snapshot.PolicyChange{tc}, snapshot.ApplyOptions{})
		var ce *snapshot.ChangeError
		if !errors.As(err, &ce) || ce.Index != 0 {
			t.Errorf("%s: err = %v, want a *ChangeError for change 0", name, err)
		}
	}
	// the index names the failing change
	_, err := snapshot.Apply(base, []snapshot.PolicyChange{
		ch(snapshot.OpPutBPA, awstest.EstateBucket, sp(`{}`), nil),
		ch(snapshot.OpDetach, awstest.EstateDevUser, nil, sp(awstest.EstateS3Read))}, snapshot.ApplyOptions{})
	var ce *snapshot.ChangeError
	if !errors.As(err, &ce) || ce.Index != 1 || !strings.Contains(ce.Error(), "change 1") {
		t.Errorf("err = %v, want change 1", err)
	}
	// an organization-less snapshot refuses organization ops
	flat := apply(t, base)
	flat.Org = nil
	if _, err := snapshot.Apply(flat, []snapshot.PolicyChange{ch(snapshot.OpPutSCP, awstest.EstateFullSCP, &allow, nil)}, snapshot.ApplyOptions{}); err == nil {
		t.Error("an SCP change on a snapshot with no organization was accepted")
	}
}

// The op set is closed and validated when the request is decoded.
func TestPolicyChangeDecodeRejectsUnknownOps(t *testing.T) {
	for _, op := range snapshot.PolicyChangeOps() {
		var c snapshot.PolicyChange
		if err := json.Unmarshal([]byte(`{"op":"`+string(op)+`","target_arn":"x"}`), &c); err != nil || c.Op != op {
			t.Errorf("op %q: %v", op, err)
		}
	}
	if len(snapshot.PolicyChangeOps()) != 20 {
		t.Errorf("%d ops, the design lists 20", len(snapshot.PolicyChangeOps()))
	}
	var c snapshot.PolicyChange
	if err := json.Unmarshal([]byte(`{"op":"drop_table","target_arn":"x"}`), &c); err == nil {
		t.Error("an unknown op decoded")
	}
}
