package catalog

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// ---------------------------------------------------------------- overlays (real files)

func TestRealOverlaysRCPList(t *testing.T) {
	ov, err := LoadOverlays(realOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ov.RCP.Services); got != 62 {
		t.Fatalf("RCP overlay has %d service prefixes, want 62 (list of 2026-10-15)", got)
	}
	if !sort.StringsAreSorted(ov.RCP.Services) {
		t.Error("RCP services must be sorted")
	}
	in := map[string]bool{}
	for _, s := range ov.RCP.Services {
		in[s] = true
	}
	for _, s := range []string{"s3", "kms", "sts", "sqs", "dynamodb", "secretsmanager", "ecr", "logs", "cognito-idp", "wafv2", "xray", "aoss", "dsql", "signin"} {
		if !in[s] {
			t.Errorf("%s must be RCP-supported", s)
		}
	}
	// services AWS documents as not supported by RCPs
	for _, s := range []string{"ec2", "iam", "sns", "lambda", "rds", "organizations", "cloudformation"} {
		if in[s] {
			t.Errorf("%s must not be RCP-supported", s)
		}
	}
	if ov.RCP.FetchedOn == "" || !strings.HasPrefix(ov.RCP.Source, "https://docs.aws.amazon.com/organizations/") {
		t.Errorf("RCP overlay must cite its source and fetch date: %+v", ov.RCP)
	}
}

func TestRealOverlaysContent(t *testing.T) {
	ov, err := LoadOverlays(realOverlays)
	if err != nil {
		t.Fatal(err)
	}
	has := func(list []string, s string) bool {
		i := sort.SearchStrings(list, s)
		return i < len(list) && list[i] == s
	}
	for _, a := range []string{"kms:Decrypt", "kms:CreateGrant", "kms:DescribeKey", "kms:RevokeGrant"} {
		if !has(ov.KMSXacct.Actions, a) {
			t.Errorf("kms_xacct_ops lacks %s", a)
		}
	}
	for _, a := range []string{"kms:CreateKey", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:ListKeys"} {
		if has(ov.KMSXacct.Actions, a) {
			t.Errorf("kms_xacct_ops must not list %s", a)
		}
	}
	if got := ov.S3ACL.Bucket["READ"]; !equalStrings(got, []string{"s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions"}) {
		t.Errorf("bucket READ = %v", got)
	}
	if got := ov.S3ACL.Object["READ_ACP"]; !equalStrings(got, []string{"s3:GetObjectAcl", "s3:GetObjectVersionAcl"}) {
		t.Errorf("object READ_ACP = %v", got)
	}
	if len(ov.S3ACL.Object["WRITE"]) != 0 || len(ov.S3ACL.Bucket["FULL_CONTROL"]) != 7 {
		t.Error("S3 ACL map: object WRITE is empty, bucket FULL_CONTROL is the union")
	}
	var public []string
	for _, g := range ov.S3ACL.Groups {
		if g.Public {
			public = append(public, g.Name)
		}
	}
	if !equalStrings(public, []string{"AllUsers", "AuthenticatedUsers"}) {
		t.Errorf("public ACL groups = %v", public)
	}
	if len(ov.RBP.Rules) != 2 || ov.RBP.Rules[0].Service != "iam" || ov.RBP.Rules[1].Service != "kms" || ov.RBP.Default != "union" {
		t.Errorf("rbp_rules = %+v", ov.RBP)
	}
	for _, r := range ov.RBP.Rules {
		if r.Source == "" || !r.RequiresExplicitAllow {
			t.Errorf("rbp rule %+v must cite a source", r)
		}
	}
	regions := map[string]bool{}
	for _, r := range ov.OptInRegion.Regions {
		regions[r.Name] = true
	}
	for _, r := range []string{"ap-east-1", "me-south-1", "af-south-1", "eu-south-1"} {
		if !regions[r] {
			t.Errorf("opt-in regions lack %s", r)
		}
	}
	if regions["us-east-1"] || regions["eu-west-1"] {
		t.Error("default-enabled regions are not opt-in")
	}
	keys := map[string]S3PublicKey{}
	for _, k := range ov.S3Public.Keys {
		keys[strings.ToLower(k.Name)] = k
	}
	if len(keys) != 12 || keys["aws:sourceip"].IPv4MaxCIDRSize != 8 || keys["aws:sourceip"].IPv6MaxCIDRSize != 32 ||
		keys["aws:userid"].ExceptPatterns[0] != "AROLEID:*" || !keys["s3:dataaccesspointarn"].BucketPoliciesOnly {
		t.Errorf("s3_public_fixed_keys = %+v", keys)
	}
	gk := map[string]GlobalKey{}
	for _, k := range ov.GlobalKeys.Keys {
		gk[strings.ToLower(k.Name)] = k
	}
	if gk["aws:sourceip"].Type != model.KeyIP || !gk["aws:tagkeys"].Multivalued || !gk["aws:calledvia"].Multivalued ||
		gk["aws:multifactorauthage"].Type != model.KeyNumeric || gk["aws:principalarn"].Type != model.KeyARN {
		t.Error("global_keys types")
	}
	// the multivalued set must agree with the parser's built-in global list
	for _, k := range []string{"aws:tagkeys", "aws:calledvia", "aws:principalorgpaths", "aws:resourceorgpaths", "aws:sourceorgpaths", "aws:principalservicenameslist"} {
		if !gk[k].Multivalued {
			t.Errorf("%s must be multivalued", k)
		}
	}
}

func copyOverlays(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(realOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(realOverlays, e.Name())) // #nosec G304 -- test fixture
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestLoadOverlaysRejects(t *testing.T) {
	tests := []struct {
		name, file, content, want string
	}{
		{"duplicate prefix", fileRCP, "source: x\nfetched_on: y\nservices: [s3, s3]\n", "duplicate"},
		{"bad prefix", fileRCP, "source: x\nfetched_on: y\nservices: [S3]\n", "invalid"},
		{"empty list", fileRCP, "source: x\nfetched_on: y\nservices: []\n", "empty"},
		{"unknown field", fileRCP, "source: x\nfetched_on: y\nservices: [s3]\nextra: 1\n", "extra"},
		{"not yaml", fileRCP, "services: [", ""},
		{"kms action outside kms", fileKMS, "source: x\nactions: [s3:GetObject]\n", "not a kms action"},
		{"bad action", fileKMS, "source: x\nactions: ['kms:Decrypt*']\n", "invalid"},
		{"bad availability", fileGlobal, "keys:\n  - {name: 'aws:X', type: string, availability: sometimes}\n", "availability"},
		{"global key outside aws", fileGlobal, "keys:\n  - {name: 'x:X', type: string, availability: always}\n", "bad or duplicate"},
		{"bad key type", fileGlobal, "keys:\n  - {name: 'aws:X', type: integer, availability: always}\n", "key type"},
		{"rbp without source", fileRBP, "default: union\nrules:\n  - {service: iam, resource: r, requires_explicit_allow: true}\n", "source"},
		{"rbp default", fileRBP, "default: intersection\nrules: []\n", "union"},
		{"region format", fileOptIn, "principal_format: x\nregions: []\n", "principal_format"},
		{"s3 public rule", fileS3Public, "keys:\n  - {name: 'aws:X', rule: maybe}\n", "bad or duplicate"},
		{"s3 acl empty", fileS3ACL, "bucket: {}\nobject: {}\n", "bucket and object"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyOverlays(t)
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadOverlays(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadOverlays = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// a missing file and an oversized file
	dir := copyOverlays(t)
	if err := os.Remove(filepath.Join(dir, fileOptIn)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlays(dir); err == nil {
		t.Error("a missing overlay must fail")
	}
	dir = copyOverlays(t)
	if err := os.WriteFile(filepath.Join(dir, fileRCP), bytes.Repeat([]byte("#"), maxOverlayBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlays(dir); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized overlay: %v", err)
	}
}

// ---------------------------------------------------------------- compile

func TestCompileFixture(t *testing.T) {
	res := compileFixture(t, "upstream-v1", "2026-10-01", true)
	c := res.Compiled
	if c.Schema != SchemaVersion || c.Snapshot != "2026-10-01" || c.IAMDatasetCommit != fixtureCommit || !validVersion(c.Version) {
		t.Errorf("header: %+v", c)
	}
	var prefixes []string
	total := 0
	for _, s := range c.Services {
		prefixes = append(prefixes, s.Prefix)
		total += len(s.Actions)
		if !sort.SliceIsSorted(s.Actions, func(i, j int) bool { return strings.ToLower(s.Actions[i].Name) < strings.ToLower(s.Actions[j].Name) }) {
			t.Errorf("%s actions not sorted", s.Prefix)
		}
	}
	if !equalStrings(prefixes, []string{"kms", "s3", "sqs"}) || total != 11 {
		t.Errorf("services %v, %d actions", prefixes, total)
	}
	if len(res.RCPDrift.PageOnly) != 0 || len(res.RCPDrift.OverlayOnly) != 0 {
		t.Errorf("v1 page equals the test overlay: %+v", res.RCPDrift)
	}
	if !sort.StringsAreSorted(res.Warnings) {
		t.Error("warnings must be sorted")
	}
	// the invalid prefix on the fixture RCP page was dropped at fetch time
	snap, _ := readFixture(t, "upstream-v1", "2026-10-01", true)
	if !equalStrings(snap.RCPPage.Services, []string{"kms", "s3", "sqs"}) {
		t.Errorf("scraped RCP list = %v", snap.RCPPage.Services)
	}
}

func TestCompileSkipsAndReconciles(t *testing.T) {
	svc := func(body string) []byte { return []byte(body) }
	snap := &Snapshot{
		Date:  "2026-10-01",
		Index: []string{"aa", "bb"},
		Services: map[string][]byte{
			"aa": svc(`{"Name":"zz","Version":"v1","Actions":[
				{"Name":"Good","ActionConditionKeys":["aa:k","aa:k",""],"Resources":[{"Name":"res"},{"Name":"res"},{"Name":"bad\u0000name"},{"Name":"two words"}]},
				{"Name":"good","ActionConditionKeys":[]},
				{"Name":"Bad Name!"}],
				"ConditionKeys":[{"Name":"aa:k","Types":["Weird"]},{"Name":"shared:k","Types":["String"]},{"Name":"aa:fam/<a>","Types":["String"]},{"Name":"aa:fam/<b>","Types":["Numeric"]},{"Name":"aws:SourceIp","Types":["String"]},{"Name":""}],
				"Resources":[{"Name":"res","ARNFormats":["arn:${Partition}:aa:::${X}","not-an-arn"]},{"Name":"bad\u0000res"},{"Name":"two words"}]}`),
			"bb": svc(`{"Name":"bb","Actions":[{"Name":"Act","Annotations":{"Properties":{"IsWrite":true}}}],
				"ConditionKeys":[{"Name":"shared:k","Types":["ArrayOfNumeric"]}]}`),
		},
		Dataset: func() *DatasetExtract {
			d := &DatasetExtract{Commit: "c", Actions: []DatasetAction{{Action: "aa:Good", AccessLevel: "Permissions management", Dependent: []string{"bb:Act", "junk", "zz:NotAnAction"}}}}
			d.index()
			return d
		}(),
	}
	res, err := Compile(snap, testOverlays(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`global key aws:SourceIp: overlay says ip/false, aa says string/false; keeping the overlay`,
		`key shared:k is typed differently in aa and bb; keeping aa`,
		`service aa: key aa:k has unknown type "Weird"`,
		`service aa: duplicate action good`,
		`service aa: file names itself "zz"`,
		`service aa: resource res: skipped ARN format "not-an-arn"`,
		`service aa: skipped action "Bad Name!"`,
		`service aa: skipped condition key ""`,
		`service aa: skipped resource type "bad\x00res"`,
	}
	joined := strings.Join(res.Warnings, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing warning %q in:\n%s", w, joined)
		}
	}
	if strings.Contains(joined, "aa:fam/") {
		t.Errorf("a key family inside one service must not warn:\n%s", joined)
	}
	aa := res.Compiled.Services[0]
	if len(aa.Actions) != 1 || aa.Actions[0].Name != "aa:Good" {
		t.Fatalf("aa actions = %+v", aa.Actions)
	}
	g := aa.Actions[0]
	if !equalStrings(g.Keys, []string{"aa:k"}) || !equalStrings(g.Resources, []string{"res", "two words"}) || !equalStrings(g.Dependent, []string{"bb:Act"}) {
		t.Errorf("aa:Good = %+v", g)
	}
	// no Annotations: the iam-dataset access level is used
	if g.Level != AccessPermissionsManagement {
		t.Errorf("level = %v", g.Level)
	}
	if bb := res.Compiled.Services[1].Actions[0]; bb.Level != AccessWrite {
		t.Errorf("bb level = %v", bb.Level)
	}
	if len(aa.Resources) != 2 || aa.Resources[0].Name != "res" || aa.Resources[1].Name != "two words" ||
		!equalStrings(aa.Resources[0].ARNFormats, []string{"arn:${Partition}:aa:::${X}"}) {
		t.Errorf("aa resources = %+v", aa.Resources)
	}
	types := map[string]CKey{}
	for _, k := range res.Compiled.Keys {
		types[strings.ToLower(k.Name)] = k
	}
	if types["aws:sourceip"].Type != model.KeyIP || types["aa:k"].Type != model.KeyString || types["shared:k"].Multivalued {
		t.Errorf("keys = %+v", types)
	}

	// failures
	if _, err := Compile(nil, testOverlays(t)); err == nil {
		t.Error("nil snapshot")
	}
	bad := &Snapshot{Date: "2026-10-01", Index: []string{"aa"}, Services: map[string][]byte{"aa": []byte(`{"Actions": 5}`)}}
	if _, err := Compile(bad, testOverlays(t)); err == nil {
		t.Error("malformed service file must fail")
	}
}

func TestCompileLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Actions":[`)
	for i := 0; i < maxActionsPerSvc+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"Name":"A"}`)
	}
	b.WriteString(`]}`)
	snap := &Snapshot{Date: "2026-10-01", Index: []string{"aa"}, Services: map[string][]byte{"aa": []byte(b.String())}}
	if _, err := Compile(snap, testOverlays(t)); err == nil || !strings.Contains(err.Error(), "size limits") {
		t.Errorf("too many actions: %v", err)
	}
	keys := `"` + strings.Repeat(`k","`, maxKeysPerAction) + `k"`
	snap.Services["aa"] = []byte(`{"Actions":[{"Name":"A","ActionConditionKeys":[` + keys + `]}]}`)
	if _, err := Compile(snap, testOverlays(t)); err == nil || !strings.Contains(err.Error(), "too many condition keys") {
		t.Errorf("too many keys: %v", err)
	}
}

// ---------------------------------------------------------------- determinism

func TestDeterminism(t *testing.T) {
	encode := func(res *Result) []byte {
		b, err := Encode(res.Compiled)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// independent fetches, writes, reads and compiles of the same upstream
	a := compileFixture(t, "upstream-v2", "2026-10-08", false)
	b := compileFixture(t, "upstream-v2", "2026-10-08", false)
	ba, bb := encode(a), encode(b)
	if !bytes.Equal(ba, bb) {
		t.Error("same inputs gave different compiled bytes")
	}
	if a.Compiled.Version != b.Compiled.Version {
		t.Errorf("versions differ: %s %s", a.Compiled.Version, b.Compiled.Version)
	}
	if !bytes.Equal(ba, encode(a)) {
		t.Error("Encode is not repeatable")
	}
	// the v2 fixture index is not sorted: input order must not matter
	snap, _ := readFixture(t, "upstream-v2", "2026-10-08", false)
	snap.Index = []string{"sns", "kms", "sqs", "s3"}
	c, err := Compile(snap, testOverlays(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.Compiled.Version != a.Compiled.Version {
		t.Errorf("index order changed the version: %s vs %s", c.Compiled.Version, a.Compiled.Version)
	}
	// the same overlay content gives the same version; a content change gives another
	d, err := Compile(snap, testOverlays(t, "kms", "s3", "sqs"))
	if err != nil || d.Compiled.Version != a.Compiled.Version {
		t.Errorf("same overlay content: %v %v", err, d)
	}
	e, err := Compile(snap, testOverlays(t, "kms", "s3", "sqs", "sns"))
	if err != nil || e.Compiled.Version == a.Compiled.Version {
		t.Error("an overlay change must change the catalog version")
	}
	// version = snapshot date + prefix of the content hash
	h, err := contentHash(a.Compiled)
	if err != nil || a.Compiled.Version != "2026-10-08-"+h[:16] {
		t.Errorf("version %s does not match content hash %s", a.Compiled.Version, h)
	}
	// the iam-dataset input is part of the content
	withDS := compileFixture(t, "upstream-v2", "2026-10-08", true)
	if withDS.Compiled.Version == a.Compiled.Version {
		t.Error("the iam-dataset input must change the version")
	}
}

func TestEncodedGzipHeaderIsDeterministic(t *testing.T) {
	res := compileFixture(t, "upstream-v1", "2026-10-01", true)
	b, err := Encode(res.Compiled)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 1952: ID1 ID2 CM FLG MTIME(4) XFL OS
	if len(b) < 10 || b[0] != 0x1f || b[1] != 0x8b || b[3] != 0 || !bytes.Equal(b[4:8], []byte{0, 0, 0, 0}) || b[9] != 255 {
		t.Errorf("gzip header %x: want no flags, zero mtime, unknown OS", b[:10])
	}
	raw, _ := gunzip(t, b)
	if again, err := jcs.Transform(raw); err != nil || !bytes.Equal(again, raw) {
		t.Errorf("payload must be canonical JSON (RFC 8785): %v", err)
	}
}

func gunzip(t *testing.T, b []byte) ([]byte, error) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeVerifies(t *testing.T) {
	res := compileFixture(t, "upstream-v1", "2026-10-01", true)
	enc, err := Encode(res.Compiled)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(enc)
	if err != nil || got.Version != res.Compiled.Version {
		t.Fatalf("Decode: %v", err)
	}
	// the decoded catalog re-encodes to the same bytes
	if again, _ := Encode(got); !bytes.Equal(again, enc) {
		t.Error("Decode then Encode changed the bytes")
	}
	raw, _ := gunzip(t, enc)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"edited content", gzipBytes(t, bytes.Replace(raw, []byte(`"s3:GetObject"`), []byte(`"s3:GetObjecT"`), 1)), "content hash"},
		{"edited version", gzipBytes(t, bytes.Replace(raw, []byte(res.Compiled.Version), []byte("2026-10-01-0000000000000000"), 1)), "content hash"},
		{"schema", gzipBytes(t, bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":2`), 1)), "schema"},
		{"unknown field", gzipBytes(t, bytes.Replace(raw, []byte(`"schema":1`), []byte(`"extra":1,"schema":1`), 1)), "unknown field"},
		{"trailing data", gzipBytes(t, append(append([]byte(nil), raw...), []byte(" {}")...)), "trailing"},
		{"not gzip", []byte("this is plainly not gzip data"), "gzip"},
		{"truncated", enc[:len(enc)/2], ""},
		{"not json", gzipBytes(t, []byte("nope")), ""},
		{"too large", make([]byte, maxCompiledBytes+1), "too large"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Decode = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestAccessLevelText(t *testing.T) {
	for l := AccessUnknown; l <= AccessTagging; l++ {
		b, err := l.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back AccessLevel
		if err := back.UnmarshalText(b); err != nil || back != l || l.String() != string(b) {
			t.Errorf("level %d: %s %v", l, b, err)
		}
	}
	var l AccessLevel
	if l.UnmarshalText([]byte("root")) == nil || AccessLevel(99).String() != "unknown" {
		t.Error("bad level names must fail")
	}
	if _, err := AccessLevel(99).MarshalText(); err == nil {
		t.Error("out-of-range level must not marshal")
	}
}
