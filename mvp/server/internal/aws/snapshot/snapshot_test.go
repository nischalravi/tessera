package snapshot

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

func build(t *testing.T, reverse bool) *model.Snapshot {
	t.Helper()
	b := NewBuilder()
	docs := []struct{ src, raw string }{
		{"arn:aws:iam::1:policy/a", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`},
		{"arn:aws:iam::1:policy/b", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`},
	}
	if reverse {
		docs[0], docs[1] = docs[1], docs[0]
	}
	var ids []string
	for _, d := range docs {
		ids = append(ids, b.AddPolicy(policy.Options{Kind: model.PolicyIdentity, SourceARN: d.src}, []byte(d.raw)).ID)
	}
	b.AddPrincipal(&model.Principal{ARN: "arn:aws:iam::1:user/u", Kind: model.IAMUser, IdentityPolicyIDs: ids})
	s, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildIsOrderIndependent(t *testing.T) {
	a, b := build(t, false), build(t, true)
	if a.ID == "" || a.ID != b.ID {
		t.Fatalf("ids %q and %q", a.ID, b.ID)
	}
	if h, _ := Hash(a); h != a.ID {
		t.Fatal("ID is not the content hash")
	}
	// The principal's policy list is sorted by source ARN, not insertion order.
	ids := b.Principals["arn:aws:iam::1:user/u"].IdentityPolicyIDs
	if b.Policies[ids[0]].SourceARN != "arn:aws:iam::1:policy/a" {
		t.Fatalf("policy order %v", ids)
	}
}

func TestUnparseableIsKept(t *testing.T) {
	b := NewBuilder()
	d := b.AddPolicy(policy.Options{Kind: model.PolicyIdentity, SourceARN: "x"}, []byte("{"))
	s, err := b.Build()
	if err != nil || s.Policies[d.ID] == nil || s.Policies[d.ID].Unparseable == "" {
		t.Fatalf("%v %v", s, err)
	}
}
