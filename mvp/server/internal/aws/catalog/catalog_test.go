package catalog

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

var _ func(string) bool = (*Catalog)(nil).MultivaluedKey // policy.Options.MultivaluedKey

func TestExpand(t *testing.T) {
	c := fixtureCatalog(t)
	tests := []struct {
		pattern string
		want    []string
	}{
		{"s3:GetObject", []string{"s3:GetObject"}},
		{"S3:getobject", []string{"s3:GetObject"}},
		{"s3:Get*", []string{"s3:GetObject", "s3:GetObjectAcl"}},
		{"s3:?utObject", []string{"s3:PutObject"}},
		{"s3:*Object", []string{"s3:GetObject", "s3:PutObject"}},
		{"s3:*Object*", []string{"s3:GetObject", "s3:GetObjectAcl", "s3:PutObject", "s3:PutObjectTagging"}},
		{"kms:*Grant", []string{"kms:CreateGrant"}},
		{"sqs:*", []string{"sqs:SendMessage"}},
		{"nosuch:*", nil},
		{"s3:", nil},
		{"s3:Nope*", nil},
		{"s3:GetObject?", nil},
		{"s3*:GetObject", []string{"s3:GetObject"}}, // wildcard in the service part scans everything
		{strings.Repeat("*", maxPatternLen+1), nil}, // over the cap matches nothing
	}
	for _, tc := range tests {
		got := names(c, c.Expand(tc.pattern))
		if !equalStrings(got, tc.want) {
			t.Errorf("Expand(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
	if n := c.Expand("*").Len(); n != c.NumActions() || n != 11 {
		t.Errorf("Expand(*) = %d actions, NumActions = %d, want 11", n, c.NumActions())
	}
	if n := c.Expand("s3:*").Len(); n != 7 {
		t.Errorf("Expand(s3:*) = %d, want 7", n)
	}
	// IDs are dense and ordered by service then action, so a service is one range
	ids := c.Expand("kms:*").IDs()
	for i := 1; i < len(ids); i++ {
		if ids[i] != ids[i-1]+1 {
			t.Errorf("kms ids not contiguous: %v", ids)
		}
	}
	if s := c.Expand("s3:GetObject"); !s.Has(mustID(t, c, "s3:getobject")) || s.Has(mustID(t, c, "s3:PutObject")) || s.Has(1<<20) {
		t.Error("ActionSet.Has")
	}
}

func mustID(t *testing.T, c *Catalog, a string) ActionID {
	t.Helper()
	id, ok := c.ActionID(a)
	if !ok {
		t.Fatalf("no action %s", a)
	}
	return id
}

func TestGlobMatchIsLinearEnough(t *testing.T) {
	// the classic exponential pattern for a backtracking matcher
	pat := strings.Repeat("*a", 40) + "b"
	s := strings.Repeat("a", 400)
	start := time.Now()
	if globMatch(pat, s) {
		t.Error("must not match")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("pathological glob took %v", d)
	}
	for _, tc := range []struct {
		pat, s string
		want   bool
	}{
		{"*", "", true}, {"", "", true}, {"", "a", false}, {"a*", "a", true}, {"a?c", "abc", true},
		{"a?c", "ac", false}, {"*b*", "abc", true}, {"*b", "abcb", true}, {"*b", "abca", false}, {"**", "x", true},
	} {
		if got := globMatch(tc.pat, tc.s); got != tc.want {
			t.Errorf("globMatch(%q,%q) = %v", tc.pat, tc.s, got)
		}
	}
}

func TestCanonicalAndMetadata(t *testing.T) {
	c := fixtureCatalog(t)
	if got, ok := c.CanonicalAction("S3:GETOBJECT"); !ok || got != "s3:GetObject" {
		t.Errorf("CanonicalAction = %q, %v", got, ok)
	}
	if _, ok := c.CanonicalAction("s3:Nope"); ok {
		t.Error("unknown action must not resolve")
	}
	if c.ActionName(1<<30) != "" {
		t.Error("ActionName out of range")
	}
	levels := map[string]AccessLevel{
		"s3:GetObject": AccessRead, "s3:ListBucket": AccessList, "s3:PutObject": AccessWrite,
		"s3:PutBucketPolicy": AccessPermissionsManagement, "s3:PutObjectTagging": AccessTagging,
		"kms:CreateGrant": AccessPermissionsManagement, "s3:Nope": AccessUnknown,
	}
	for a, want := range levels {
		if got := c.AccessLevel(a); got != want {
			t.Errorf("AccessLevel(%s) = %v, want %v", a, got, want)
		}
	}
	if got := c.ResourceTypes("s3:GetObject"); fmt.Sprint(got) != "[s3:accesspointobject s3:object]" {
		t.Errorf("ResourceTypes = %v", got)
	}
	if c.ResourceTypes("s3:Nope") != nil {
		t.Error("ResourceTypes of an unknown action")
	}
	if !c.SupportsResourceLevel("s3:GetObject") || c.SupportsResourceLevel("s3:ListAllMyBuckets") || c.SupportsResourceLevel("x:y") {
		t.Error("SupportsResourceLevel")
	}
	if got := c.ConditionKeys("s3:GetObject", ""); fmt.Sprint(got) != "[s3:ResourceAccount s3:TlsVersion]" {
		t.Errorf("ConditionKeys = %v", got)
	}
	if got := c.ConditionKeys("s3:PutObject", "s3:object"); fmt.Sprint(got) != "[s3:RequestObjectTag/<key> s3:TlsVersion s3:x-amz-acl]" {
		t.Errorf("ConditionKeys with resource type = %v", got)
	}
	if got := c.ConditionKeys("s3:PutBucketPolicy", "s3:bucket"); fmt.Sprint(got) != "[aws:ResourceTag/${TagKey}]" {
		t.Errorf("deduplicated ConditionKeys = %v", got)
	}
	if c.ConditionKeys("s3:Nope", "") != nil {
		t.Error("ConditionKeys of an unknown action")
	}
	if got := c.DependentActions("s3:PutObject"); fmt.Sprint(got) != "[kms:Decrypt s3:PutObjectTagging]" {
		t.Errorf("DependentActions = %v", got)
	}
	if c.DependentActions("s3:GetObject") != nil || c.DependentActions("x:y") != nil {
		t.Error("no dependent actions expected")
	}
	if c.IAMDatasetCommit() != fixtureCommit || c.Snapshot() != "2026-10-01" || !strings.HasPrefix(c.Version(), "2026-10-01-") {
		t.Errorf("version info: %s %s %s", c.IAMDatasetCommit(), c.Snapshot(), c.Version())
	}
	if got := c.Services(); fmt.Sprint(got) != "[kms s3 sqs]" {
		t.Errorf("Services = %v", got)
	}
}

func TestKeys(t *testing.T) {
	c := fixtureCatalog(t)
	tests := []struct {
		key   string
		typ   model.KeyType
		multi bool
	}{
		{"s3:TlsVersion", model.KeyNumeric, false},
		{"S3:TLSVERSION", model.KeyNumeric, false},
		{"aws:ResourceTag/Env", model.KeyString, false}, // tag-key suffix
		{"aws:resourcetag/${TagKey}", model.KeyString, false},
		{"s3:RequestObjectTag/owner", model.KeyString, false},
		{"aws:TagKeys", model.KeyString, true}, // from the service file
		{"AWS:TAGKEYS", model.KeyString, true},
		{"kms:EncryptionContext:project", model.KeyString, false}, // ":"-suffixed key family
		{"kms:GranteePrincipal", model.KeyARN, false},
		{"kms:GrantOperations", model.KeyString, true},
		{"aws:SourceIp", model.KeyIP, false}, // from the global overlay
		{"aws:PrincipalArn", model.KeyARN, false},
		{"aws:SecureTransport", model.KeyBool, false},
		{"aws:CurrentTime", model.KeyDate, false},
		{"aws:PrincipalOrgPaths", model.KeyString, true},
		{"aws:MultiFactorAuthAge", model.KeyNumeric, false},
		{"vendor:unknown", model.KeyString, false}, // unlisted keys are Strings
	}
	for _, tc := range tests {
		if got := c.KeyType(tc.key); got != tc.typ {
			t.Errorf("KeyType(%q) = %v, want %v", tc.key, got, tc.typ)
		}
		if got := c.IsMultivalued(tc.key); got != tc.multi {
			t.Errorf("IsMultivalued(%q) = %v, want %v", tc.key, got, tc.multi)
		}
	}
	if !c.MultivaluedKey("aws:tagkeys") || c.MultivaluedKey("aws:username") {
		t.Error("MultivaluedKey takes lower-cased keys")
	}
	if _, ok := c.LookupKey("vendor:unknown"); ok {
		t.Error("LookupKey of an unlisted key")
	}
	if ki, ok := c.LookupKey("KMS:EncryptionContext:project"); !ok || ki.Name != "kms:EncryptionContext:${EncryptionContextKey}" {
		t.Errorf("LookupKey(encryption context) = %+v, %v", ki, ok)
	}
	for in, want := range map[string]string{
		"aws:SourceIp": "aws:sourceip", "aws:ResourceTag/a:b": "aws:resourcetag/", "kms:EncryptionContext:a/b": "kms:encryptioncontext:",
		"nocolon": "nocolon", "s3:x-amz-acl": "s3:x-amz-acl",
	} {
		if got := normKey(in); got != want {
			t.Errorf("normKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchResourceType(t *testing.T) {
	c := fixtureCatalog(t)
	long := "arn:aws:s3:::" + strings.Repeat("a", maxARNLen)
	tests := []struct {
		arn  string
		want ResourceType
		ok   bool
	}{
		{"arn:aws:s3:::my-bucket", "s3:bucket", true},
		{"arn:aws:s3:::my-bucket/key/with/slashes", "s3:object", true}, // more literal text than the bucket format
		{"arn:aws-cn:s3:::my-bucket/k", "s3:object", true},
		{"arn:aws:s3:us-east-1:123456789012:accesspoint/ap1/object/k", "s3:accesspointobject", true},
		{"arn:aws:kms:eu-west-1:123456789012:key/1234abcd", "kms:key", true},
		{"arn:aws:sqs:us-east-1:123456789012:queue1", "sqs:queue", true},
		{"arn:aws:kms:eu-west-1:123456789012:alias/x", "", false},
		{"arn:aws:kms:eu-west-1:123456789012:key/", "", false}, // a variable needs at least one character
		{"arn:aws:nosuch:::x", "", false},
		{"arn:aws:s3", "", false},
		{"not-an-arn", "", false},
		{"arn:aws:kms:a:b:c:key/1", "", false}, // Region and Account never contain ":"
		{long, "", false},
	}
	for _, tc := range tests {
		got, ok := c.MatchResourceType(tc.arn)
		if got != tc.want || ok != tc.ok {
			t.Errorf("MatchResourceType(%.60q) = %q, %v; want %q, %v", tc.arn, got, ok, tc.want, tc.ok)
		}
	}
	if got := c.ARNFormats("s3:object"); fmt.Sprint(got) != "[arn:${Partition}:s3:::${BucketName}/${ObjectName}]" {
		t.Errorf("ARNFormats = %v", got)
	}
	if c.ARNFormats("s3:nothing") != nil {
		t.Error("ARNFormats of an unknown type")
	}
}

func TestMatchResourceTypePrefersOwningService(t *testing.T) {
	const f = "arn:${Partition}:iam::${Account}:role/${RoleName}"
	c, err := New(&Compiled{Schema: SchemaVersion, Snapshot: "2026-10-01", Services: []CService{
		{Prefix: "ec2", Resources: []CResource{{Name: "role", ARNFormats: []string{f}}}},
		{Prefix: "iam", Resources: []CResource{{Name: "role", ARNFormats: []string{f + "/x"}}, {Name: "rolepath", ARNFormats: []string{f}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// ec2:role sorts before iam:rolepath and matches with the same literal
	// text, but the IAM ARN belongs to iam
	if got, ok := c.MatchResourceType("arn:aws:iam::123456789012:role/r"); !ok || got != "iam:rolepath" {
		t.Errorf("got %q, %v", got, ok)
	}
	// with no owning match, another service's type still answers
	only, err := New(&Compiled{Schema: SchemaVersion, Snapshot: "2026-10-01", Services: []CService{
		{Prefix: "ec2", Resources: []CResource{{Name: "role", ARNFormats: []string{f}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := only.MatchResourceType("arn:aws:iam::123456789012:role/r"); !ok || got != "ec2:role" {
		t.Errorf("fallback got %q, %v", got, ok)
	}
}

func TestTemplateMatchIsPolynomial(t *testing.T) {
	tm := parseTemplate("arn:${Partition}:x:${Region}:${Account}:${A}/${B}/${C}/${D}/${E}")
	arn := "arn:aws:x:r:a:" + strings.Repeat("/", 1500)
	start := time.Now()
	_ = tm.match(arn)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("template match took %v", d)
	}
}

func TestRCPSupportedFromOverlay(t *testing.T) {
	c := fixtureCatalog(t)
	if !c.RCPSupported("s3") || !c.RCPSupported("S3") || c.RCPSupported("iam") || c.RCPSupported("") {
		t.Error("RCPSupported with the narrowed test list")
	}
	if c.Overlays().KMSXacct.Actions[0] == "" || len(c.Overlays().RBP.Rules) == 0 {
		t.Error("overlays are part of the catalog")
	}
}

func TestConcurrentUse(t *testing.T) {
	c := fixtureCatalog(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.Expand("s3:*Object*")
				c.MatchResourceType("arn:aws:s3:::b/k")
				c.ConditionKeys("s3:PutObject", "s3:object")
				c.KeyType("aws:ResourceTag/x")
			}
		}()
	}
	wg.Wait()
}
