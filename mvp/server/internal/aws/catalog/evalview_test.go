package catalog

import (
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
)

// The compiled catalog, seen through the engine's interface: its answers come
// from the compiled actions and the reviewed overlays.
func TestEvalView(t *testing.T) {
	c := fixtureCatalog(t)
	v := NewEvalView(c)

	if v.Version() != c.Version() {
		t.Errorf("Version = %q, want %q", v.Version(), c.Version())
	}
	if a, ok := v.CanonicalAction("S3:GETOBJECT"); !ok || a != "s3:GetObject" {
		t.Errorf("CanonicalAction = %q, %v", a, ok)
	}
	if !v.RCPSupportedService("s3") || v.RCPSupportedService("iam") {
		t.Error("RCPSupportedService does not follow the overlay")
	}

	// resource tags: s3:PutBucketPolicy lists aws:ResourceTag/${TagKey} for its bucket; s3:GetObject for its
	// access point object type only (supported means any type of the action does); s3:ListAllMyBuckets for none
	if !v.ResourceTagsSupported("s3:PutBucketPolicy") || !v.ResourceTagsSupported("s3:GetObject") ||
		v.ResourceTagsSupported("s3:ListAllMyBuckets") || v.ResourceTagsSupported("s3:Nope") {
		t.Error("ResourceTagsSupported")
	}

	// explicit allow rules: the overlay lists iam and kms; every other service uses the union rule, unverified
	for svc, want := range map[string][2]bool{"iam": {true, true}, "KMS": {true, true}, "s3": {false, false}, "sqs": {false, false}} {
		if e, ver := v.RequiresExplicitRBP(svc); e != want[0] || ver != want[1] {
			t.Errorf("RequiresExplicitRBP(%s) = %v, %v; want %v", svc, e, ver, want)
		}
	}

	for _, a := range []string{"kms:Decrypt", "KMS:DESCRIBEKEY", "kms:CreateGrant"} {
		if !v.KMSCrossAccountOp(a) {
			t.Errorf("KMSCrossAccountOp(%s) = false", a)
		}
	}
	if v.KMSCrossAccountOp("kms:ScheduleKeyDeletion") || v.KMSCrossAccountOp("s3:GetObject") {
		t.Error("KMSCrossAccountOp admits a non-listed action")
	}

	if got := v.S3ACLActions(eval.S3ACLObject, "READ"); !slices.Contains(got, "s3:GetObject") {
		t.Errorf("object READ = %v", got)
	}
	if got := v.S3ACLActions(eval.S3ACLBucket, "WRITE"); !slices.Contains(got, "s3:PutObject") || slices.Contains(got, "s3:GetObject") {
		t.Errorf("bucket WRITE = %v", got)
	}
	if g, ok := v.S3ACLGroup("http://acs.amazonaws.com/groups/global/AllUsers"); !ok || g.Name != "AllUsers" || !g.Public {
		t.Errorf("AllUsers = %+v, %v", g, ok)
	}
	if g, ok := v.S3ACLGroup("http://acs.amazonaws.com/groups/s3/LogDelivery"); !ok || g.Public {
		t.Errorf("LogDelivery = %+v, %v", g, ok)
	}
	if _, ok := v.S3ACLGroup("http://example.com/groups/x"); ok {
		t.Error("an unknown ACL group resolved")
	}

	if r, ok := v.S3PublicFixedKey("aws:sourceip"); !ok || r.Kind != eval.S3IPRange || r.IPv4MaxCIDR != 8 || r.IPv6MaxCIDR != 32 {
		t.Errorf("aws:sourceip = %+v, %v", r, ok)
	}
	if r, ok := v.S3PublicFixedKey("aws:userid"); !ok || r.Kind != eval.S3FixedValue || !slices.Contains(r.ExceptPatterns, "AROLEID:*") {
		t.Errorf("aws:userid = %+v, %v", r, ok)
	}
	if r, ok := v.S3PublicFixedKey("s3:dataaccesspointarn"); !ok || !r.BucketPoliciesOnly {
		t.Errorf("s3:dataaccesspointarn = %+v, %v", r, ok)
	}
	if _, ok := v.S3PublicFixedKey("aws:nothing"); ok {
		t.Error("an unknown key is a fixed key")
	}

	// the action universe is the catalog's, in id order
	acts := v.Actions()
	if len(acts) != c.NumActions() || !slices.Contains(acts, "s3:GetObject") || acts[0] != c.ActionName(0) {
		t.Errorf("Actions has %d entries, catalog %d", len(acts), c.NumActions())
	}
}

func TestSameServiceRule(t *testing.T) {
	for _, tc := range []struct {
		action, resource string
		want             bool
	}{
		{"s3", "s3", true}, {"S3", "s3", true}, {"s3", "kms", false}, {"sts", "iam", true}, {"iam", "sts", false},
		{"sqs", "sqs", true}, {"lambda", "s3", false},
	} {
		if got := SameServiceRule(tc.action, tc.resource); got != tc.want {
			t.Errorf("SameServiceRule(%s, %s) = %v, want %v", tc.action, tc.resource, got, tc.want)
		}
	}
}
