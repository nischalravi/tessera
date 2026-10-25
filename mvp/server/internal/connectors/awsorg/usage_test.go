package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// ---------------------------------------------------------------- mapping

func TestActionMapper(t *testing.T) {
	cat := readerCatalog(t, map[string]catalog.AccessLevel{
		"cloudwatch:PutMetricData": catalog.AccessWrite, "ses:SendEmail": catalog.AccessWrite, "ec2:RunInstances": catalog.AccessWrite,
		"s3:PutObject": catalog.AccessWrite, "s3:DeleteObject": catalog.AccessWrite,
	})
	m := ActionMapper{Canonical: cat.CanonicalAction}
	for _, c := range []struct {
		source, name, want string
		ok                 bool
	}{
		{"s3.amazonaws.com", "GetObject", "s3:GetObject", true},
		{"s3.amazonaws.com", "HeadObject", "s3:GetObject", true},
		{"s3.amazonaws.com", "ListBuckets", "s3:ListAllMyBuckets", true},
		{"s3.amazonaws.com", "ListObjectsV2", "s3:ListBucket", true},
		{"s3.amazonaws.com", "CompleteMultipartUpload", "s3:PutObject", true},
		{"s3.amazonaws.com", "DeleteObjects", "s3:DeleteObject", true},
		{"monitoring.amazonaws.com", "PutMetricData", "cloudwatch:PutMetricData", true},
		{"email.amazonaws.com", "SendEmail", "ses:SendEmail", true},
		{"ec2.amazonaws.com", "RunInstances", "ec2:RunInstances", true},
		{"ec2.amazonaws.com", "runinstances", "ec2:RunInstances", true}, // the catalog's spelling
		{"s3.amazonaws.com", "GetNothing", "", false},                   // not in the catalog: never guessed
		{"nope.amazonaws.com", "DoIt", "", false},
		{"evil.example.com", "GetObject", "", false},
		{"s3.amazonaws.com", "Get Object", "", false},
		{"", "", "", false},
	} {
		got, ok := m.Map(c.source, c.name)
		if got != c.want || ok != c.ok {
			t.Errorf("Map(%q, %q) = %q, %v; want %q, %v", c.source, c.name, got, ok, c.want, c.ok)
		}
	}
	// with no catalog the name is used as it is
	if got, ok := (ActionMapper{}).Map("sqs.amazonaws.com", "SendMessage"); !ok || got != "sqs:SendMessage" {
		t.Errorf("no catalog: %q, %v", got, ok)
	}
	if a, ok := ServiceAction("S3"); !ok || a != "s3:*" {
		t.Errorf("ServiceAction = %q, %v", a, ok)
	}
	if _, ok := ServiceAction("s3:*"); ok {
		t.Error("ServiceAction accepted a malformed namespace")
	}
}

func TestPrincipalARN(t *testing.T) {
	role := func(issuerType, arn string) ctIdentity {
		id := ctIdentity{Type: "AssumedRole"}
		id.SessionContext.SessionIssuer.Type, id.SessionContext.SessionIssuer.ARN = issuerType, arn
		return id
	}
	for _, c := range []struct {
		name string
		id   ctIdentity
		want string
	}{
		{"user", ctIdentity{Type: "IAMUser", ARN: userAl}, userAl},
		{"role session is filed under the role", role("Role", roleDE), roleDE},
		{"role with a path", role("Role", "arn:aws:iam::222222222222:role/svc/Deploy"), "arn:aws:iam::222222222222:role/svc/Deploy"},
		{"root", ctIdentity{Type: "Root", ARN: "arn:aws:iam::111111111111:root"}, "arn:aws:iam::111111111111:root"},
		{"a session of a user is no role", role("User", "arn:aws:iam::222222222222:user/bob"), ""},
		{"service", ctIdentity{Type: "AWSService", ARN: "ec2.amazonaws.com"}, ""},
		{"federated user", ctIdentity{Type: "FederatedUser", ARN: "arn:aws:sts::111111111111:federated-user/x"}, ""},
		{"a forged issuer", role("Role", "arn:aws:iam::222222222222:role/x\nInjected"), ""},
		{"not an iam arn", ctIdentity{Type: "IAMUser", ARN: "arn:aws:s3:::bucket"}, ""},
	} {
		got, ok := principalARN(c.id)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s: principalARN = %q, %v; want %q", c.name, got, ok, c.want)
		}
	}
}

// ---------------------------------------------------------------- config

func TestUsageConfigValidate(t *testing.T) {
	base := func(mut func(*Config)) error {
		c := orgConfig()
		c.Usage = &UsageConfig{CloudTrail: &CloudTrailConfig{Bucket: trailBucket, Prefix: "/trail/", OrganizationID: trailOrg, TrailARN: trailARN}, AccessAdvisor: true}
		if mut != nil {
			mut(c)
		}
		return c.Validate()
	}
	if err := base(nil); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	c := orgConfig()
	c.Usage = &UsageConfig{CloudTrail: &CloudTrailConfig{Bucket: trailBucket, Prefix: "/trail/"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	ct := c.Usage.CloudTrail
	if ct.Prefix != "trail" || ct.Region != "us-east-1" || ct.AccountID != "111111111111" || ct.BackfillDays != DefaultBackfillDays ||
		ct.MaxObjectsPerRun != DefaultMaxObjectsPerRun || c.Usage.AdvisorPerRun != DefaultAdvisorPerRun {
		t.Errorf("defaults = %+v", ct)
	}
	if got := ct.logRoot(); got != "trail/AWSLogs/" {
		t.Errorf("logRoot = %q", got)
	}
	for name, mut := range map[string]func(*Config){
		"bucket":         func(c *Config) { c.Usage.CloudTrail.Bucket = "Not_A_Bucket" },
		"prefix chars":   func(c *Config) { c.Usage.CloudTrail.Prefix = "a b" },
		"prefix dotdot":  func(c *Config) { c.Usage.CloudTrail.Prefix = "a/../b" },
		"prefix slashes": func(c *Config) { c.Usage.CloudTrail.Prefix = "a//b" },
		"prefix long":    func(c *Config) { c.Usage.CloudTrail.Prefix = strings.Repeat("a", 201) },
		"region":         func(c *Config) { c.Usage.CloudTrail.Region = "mars" },
		"account":        func(c *Config) { c.Usage.CloudTrail.AccountID = "12" },
		"no account": func(c *Config) {
			c.ManagementAccountID, c.AccountIDs = "", []string{"222222222222"}
		},
		"org id":       func(c *Config) { c.Usage.CloudTrail.OrganizationID = "org-1" },
		"trail arn":    func(c *Config) { c.Usage.CloudTrail.TrailARN = "arn:aws:s3:::x" },
		"kms arn":      func(c *Config) { c.Usage.CloudTrail.KMSKeyARN = "key-1" },
		"backfill":     func(c *Config) { c.Usage.CloudTrail.BackfillDays = MaxBackfillDays + 1 },
		"objects":      func(c *Config) { c.Usage.CloudTrail.MaxObjectsPerRun = MaxMaxObjectsPerRun + 1 },
		"advisor":      func(c *Config) { c.Usage.AdvisorPerRun = MaxAdvisorPerRun + 1 },
		"negative cap": func(c *Config) { c.Usage.CloudTrail.MaxObjectsPerRun = -1 },
	} {
		if err := base(mut); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// no usage settings: a connector as before
	old := orgConfig()
	if err := old.Validate(); err != nil || old.Usage != nil {
		t.Errorf("config without usage = %+v, %v", old.Usage, err)
	}
}

// The policy that lets the reader role read the trail is read-only and scoped
// to the log prefix of the one bucket.
func TestTrailReaderPolicy(t *testing.T) {
	raw := TrailReaderPolicy(*trailConfig())
	if err := CheckReadOnly(raw, readerCatalog(t, nil)); err != nil {
		t.Fatalf("the trail policy is not read-only: %v", err)
	}
	var doc struct {
		Statement []struct {
			Action    []string
			Resource  string
			Condition map[string]map[string][]string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Statement) != 2 {
		t.Fatalf("policy = %s, %v", raw, err)
	}
	if doc.Statement[0].Resource != "arn:aws:s3:::"+trailBucket || doc.Statement[0].Condition["StringLike"]["s3:prefix"][0] != trailRoot+"*" ||
		doc.Statement[1].Resource != "arn:aws:s3:::"+trailBucket+"/"+trailRoot+"*" {
		t.Errorf("not scoped to the log prefix: %s", raw)
	}
	// the usage actions are in ReaderActions, and ReaderActions has no S3 object read
	for _, a := range []string{"iam:GenerateServiceLastAccessedDetails", "iam:GetServiceLastAccessedDetails", "cloudtrail:GetEventSelectors"} {
		if !slices.Contains(ReaderActions, a) {
			t.Errorf("%s is not in ReaderActions", a)
		}
	}
	for _, a := range []string{"s3:GetObject", "s3:ListBucket", "kms:Decrypt"} {
		if slices.Contains(ReaderActions, a) {
			t.Errorf("%s must not be in ReaderActions (on * it reads every bucket)", a)
		}
	}
}

// ---------------------------------------------------------------- log files

func TestParseLogFile(t *testing.T) {
	good := logBody(userCall("2026-10-15T10:00:00Z", "s3.amazonaws.com", "GetObject"), userCall("2026-10-15T10:00:01Z", "s3.amazonaws.com", "GetObject"))
	for _, c := range []struct {
		name    string
		body    []byte
		records int
		code    string // "" for accepted
	}{
		{"records", gz(t, good), 2, ""},
		{"no records", gz(t, `{"Records":[]}`), 0, ""},
		{"extra top level fields", gz(t, `{"Other":{"a":[1,2]},"Records":[{"eventName":"x"}]}`), 1, ""},
		{"not gzip", []byte(good), 0, "malformed"},
		{"empty", nil, 0, "malformed"},
		{"truncated gzip", gz(t, good)[:20], 0, "malformed"},
		{"not json", gz(t, "this is not json"), 0, "malformed"},
		{"json but not a log", gz(t, `[1,2,3]`), 0, "malformed"},
		{"no Records", gz(t, `{"Other":1}`), 0, "malformed"},
		{"Records is not a list", gz(t, `{"Records":{"a":1}}`), 0, "malformed"},
		{"a record is not an object", gz(t, `{"Records":[1]}`), 0, "malformed"},
		{"cut off mid record", gz(t, `{"Records":[{"eventName":"a"},{"eventName":`), 0, "malformed"},
		{"trailing garbage", gz(t, good+"}"), 0, "malformed"},
	} {
		n, err := parseLogFile(c.body, func(*ctEvent) {})
		var rf *refusal
		switch {
		case c.code == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.code == "" && n != c.records:
			t.Errorf("%s: %d records, want %d", c.name, n, c.records)
		case c.code != "" && (err == nil || !asRefusal(err, &rf) || rf.Code != c.code):
			t.Errorf("%s: err = %v, want %s", c.name, err, c.code)
		}
	}
}

func asRefusal(err error, out **refusal) bool {
	r, ok := err.(*refusal)
	*out = r
	return ok
}

func TestParseLogFileBounds(t *testing.T) {
	defer func(a, b, c int) { maxLogObjectBytes, maxLogInflatedBytes, maxLogRecords = a, b, c }(maxLogObjectBytes, maxLogInflatedBytes, maxLogRecords)
	rec := userCall("2026-10-15T10:00:00Z", "s3.amazonaws.com", "GetObject")

	maxLogRecords = 3
	body := gz(t, logBody(rec, rec, rec, rec))
	if _, err := parseLogFile(body, func(*ctEvent) {}); err == nil || !strings.Contains(err.Error(), "too_many_records") {
		t.Errorf("too many records: %v", err)
	}
	if n, err := parseLogFile(gz(t, logBody(rec, rec, rec)), func(*ctEvent) {}); err != nil || n != 3 {
		t.Errorf("at the limit: %d, %v", n, err)
	}

	maxLogRecords = 1000
	maxLogObjectBytes = 10
	if _, err := parseLogFile(gz(t, strings.Repeat("x", 4000)), func(*ctEvent) {}); err == nil || !strings.Contains(err.Error(), "too_large") {
		t.Errorf("a compressed file over the limit: %v", err)
	}

	// a small file that inflates to far more than it is allowed to: a gzip bomb
	maxLogObjectBytes = 1 << 20
	maxLogInflatedBytes = 64 << 10
	bomb := gz(t, `{"Records":[{"eventName":"`+strings.Repeat("a", 4<<20)+`"}]}`)
	if len(bomb) > maxLogObjectBytes {
		t.Fatalf("the bomb is %d bytes compressed", len(bomb))
	}
	if _, err := parseLogFile(bomb, func(*ctEvent) {}); err == nil || !strings.Contains(err.Error(), "inflated_too_large") {
		t.Errorf("gzip bomb: %v", err)
	}
	// and one hidden in a field the ingest skips
	skip := gz(t, `{"Other":"`+strings.Repeat("a", 4<<20)+`","Records":[]}`)
	if _, err := parseLogFile(skip, func(*ctEvent) {}); err == nil || !strings.Contains(err.Error(), "inflated_too_large") {
		t.Errorf("gzip bomb in a skipped field: %v", err)
	}
}

func TestS3DataEvents(t *testing.T) {
	for _, c := range []struct {
		name, body, want string
	}{
		{"none", `{"EventSelectors":[{"ReadWriteType":"All","IncludeManagementEvents":true}]}`, "disabled"},
		{"empty", `{}`, "disabled"},
		{"all buckets, reads and writes", `{"EventSelectors":[{"ReadWriteType":"All","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]}`, "enabled"},
		{"one bucket", `{"EventSelectors":[{"ReadWriteType":"All","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::one/"]}]}]}`, "unknown"},
		{"reads only", `{"EventSelectors":[{"ReadWriteType":"ReadOnly","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]}`, "unknown"},
		{"lambda only", `{"EventSelectors":[{"ReadWriteType":"All","DataResources":[{"Type":"AWS::Lambda::Function","Values":["arn:aws:lambda"]}]}]}`, "disabled"},
		{"advanced, all s3", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.type","Equals":["AWS::S3::Object"]}]}]}`, "enabled"},
		{"advanced, all data events", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]}]}]}`, "enabled"},
		{"advanced, narrowed by bucket", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.type","Equals":["AWS::S3::Object"]},{"Field":"resources.ARN","StartsWith":["arn:aws:s3:::one/"]}]}]}`, "unknown"},
		{"advanced, writes only", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.type","Equals":["AWS::S3::Object"]},{"Field":"readOnly","Equals":["false"]}]}]}`, "unknown"},
		{"advanced, management only", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]}]}`, "disabled"},
	} {
		var sel ctSelectors
		if err := json.Unmarshal([]byte(c.body), &sel); err != nil {
			t.Fatal(err)
		}
		if got, _ := sel.s3DataEvents(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// ---------------------------------------------------------------- the ingest

type usageEnv struct {
	f      *storetest.Fixture
	s      *Service
	k      *store.AWSConnector
	bucket *fakeBucket
	re     *awsreplay.Replay
	sleeps *[]time.Duration
	snap   *store.AWSSnapshot
}

const selectorsAllS3 = `{"TrailARN":"` + trailARN + `","EventSelectors":[{"ReadWriteType":"All","IncludeManagementEvents":true,` +
	`"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]}`

func newUsageEnv(t *testing.T, usage *UsageConfig) *usageEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	re := newReplay(t)
	for i := 0; i < 30; i++ {
		re.Enqueue("cloudtrail/GetEventSelectors", awsreplay.Response{Body: selectorsAllS3})
	}
	bucket := newFakeBucket(re)
	var sleeps []time.Duration
	s := newService(t, re)
	s.Client = testClient(bucket, &sleeps)
	s.Canonical = readerCatalog(t, map[string]catalog.AccessLevel{
		"s3:PutObject": catalog.AccessWrite, "ec2:RunInstances": catalog.AccessWrite, "iam:CreateUser": catalog.AccessWrite,
	}).CanonicalAction
	cfg := *orgConfig()
	cfg.Usage = usage
	var k *store.AWSConnector
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) (err error) {
		k, err = s.CreateConnector(c, CreateInput{Name: "prod", Config: cfg, Credentials: Credentials{AccessKeyID: baseKeyID, SecretAccessKey: baseSecret}}, "admin", testNow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return &usageEnv{f: f, s: s, k: k, bucket: bucket, re: re, sleeps: &sleeps,
		snap: &store.AWSSnapshot{ID: "no-snapshot", AccountIDs: []string{"111111111111", "222222222222"}}}
}

func (e *usageEnv) run(t *testing.T) (*UsageStats, error) {
	t.Helper()
	return e.s.CollectUsage(context.Background(), e.f.DB, e.f.A.ID, e.k.ID, "worker", e.snap)
}

func (e *usageEnv) mustRun(t *testing.T) *UsageStats {
	t.Helper()
	st, err := e.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.bucket.bad) > 0 {
		t.Fatalf("bad requests to the bucket: %v", e.bucket.bad)
	}
	return st
}

// rows is the usage table as "principal action scope day source" -> count.
func (e *usageEnv) rows(t *testing.T) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		rs, err := c.AWSUsage(e.k.ID, "", "2000-01-01", 0)
		for _, r := range rs {
			out[strings.Join([]string{r.PrincipalARN, r.Action, r.ResourceScope, r.Day, r.Source}, " ")] = r.Count
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *usageEnv) state(t *testing.T, source string) *store.AWSUsageState {
	t.Helper()
	var st *store.AWSUsageState
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) (err error) {
		st, err = c.AWSUsageState(e.k.ID, source)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func (e *usageEnv) gaps(t *testing.T) map[string]*store.AWSUsageGap {
	t.Helper()
	out := map[string]*store.AWSUsageGap{}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		gs, err := c.AWSUsageGaps(e.k.ID, 0)
		for _, g := range gs {
			out[g.Source+" "+g.Ref] = g
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func trailOnly() *UsageConfig { return &UsageConfig{CloudTrail: trailConfig()} }

func TestCollectUsage_CloudTrailIsIncremental(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	k1 := trailKey("222222222222", "us-east-1", "2026-10-14", "20261014T0955Z")
	k2 := trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T1005Z")
	k3 := trailKey("111111111111", "eu-west-1", "2026-10-15", "20261015T1010Z")
	obj := "arn:aws:s3:::lake/raw/2026/part-0.csv"
	e.bucket.put(k1, gz(t, logBody(
		roleCall("2026-10-14T09:50:00Z", "s3.amazonaws.com", "GetObject", roleDE, `,"resources":[{"ARN":"`+obj+`","type":"AWS::S3::Object"}]`),
		roleCall("2026-10-14T09:51:00Z", "s3.amazonaws.com", "GetObject", roleDE, `,"resources":[{"ARN":"`+obj+`"}]`),
		roleCall("2026-10-14T09:52:00Z", "s3.amazonaws.com", "HeadObject", roleDE, ""),                           // no resources: scope *
		roleCall("2026-10-14T09:53:00Z", "s3.amazonaws.com", "PutObject", roleDE, `,"errorCode":"AccessDenied"`), // denied: not usage
		`{"eventType":"AwsServiceEvent","eventName":"RotateKey"}`,
		roleCall("2026-10-14T09:54:00Z", "sts.amazonaws.com", "GetNothingAtAll", roleDE, ""), // not in the catalog
	)))
	e.bucket.put(k2, gz(t, logBody(roleCall("2026-10-15T10:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.bucket.put(k3, gz(t, logBody(userCall("2026-10-15T10:05:00Z", "iam.amazonaws.com", "CreateUser"))))
	// a digest-like stray under the prefix and a file of an account that is not read are left alone
	e.bucket.put(trailRoot+"222222222222/CloudTrail/us-east-1/README.txt", []byte("x"))
	e.bucket.put(trailKey("999999999999", "us-east-1", "2026-10-15", "20261015T1010Z"), gz(t, logBody(roleCall("2026-10-15T10:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))

	st := e.mustRun(t)
	ct := st.CloudTrail
	if ct == nil || ct.Objects != 3 || ct.Counted != 5 || ct.Failed != 1 || ct.Skipped != 1 || ct.Unmapped != 1 || ct.Refused != 0 || ct.Backlog {
		t.Fatalf("stats = %+v", ct)
	}
	want := map[string]int64{
		roleDE + " s3:GetObject arn:aws:s3:::lake/* 2026-10-14 cloudtrail": 2,
		roleDE + " s3:GetObject * 2026-10-14 cloudtrail":                   1,
		roleDE + " ec2:RunInstances * 2026-10-15 cloudtrail":               1,
		userAl + " iam:CreateUser * 2026-10-15 cloudtrail":                 1,
	}
	if got := e.rows(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rows = %v\nwant   %v", got, want)
	}
	state := e.state(t, store.AWSUsageCloudTrail)
	var cur trailCursor
	if err := json.Unmarshal(state.Cursor, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Prefixes["222222222222/us-east-1"] != "2026/10/15/222222222222_CloudTrail_us-east-1_20261015T1005Z_abcd1234.json.gz" ||
		cur.Prefixes["111111111111/eu-west-1"] == "" || len(cur.Prefixes) != 2 {
		t.Errorf("cursor = %v", cur.Prefixes)
	}
	if state.S3DataEvents != store.AWSDataEventsEnabled || state.CoveredTo != "2026-10-16" || state.CoveredFrom != "2026-09-16" {
		t.Errorf("state = %+v", state)
	}
	// the unmapped call is a gap that names it, and data events are fully on
	g := e.gaps(t)
	if u := g["cloudtrail unmapped_actions"]; u == nil || !strings.Contains(u.Detail, "sts:GetNothingAtAll") {
		t.Errorf("gaps = %v", g)
	}
	if _, ok := g["cloudtrail data_events"]; ok {
		t.Error("a data-events gap with S3 data events enabled")
	}

	// a second run with nothing new reads no file and changes nothing
	gets, nLists := e.bucket.getCount(), len(e.bucket.lists)
	again := e.mustRun(t)
	if e.bucket.getCount() != gets || again.CloudTrail.Objects != 0 || fmt.Sprint(e.rows(t)) != fmt.Sprint(want) {
		t.Errorf("a run with nothing new read %d files, stats %+v, rows %v", e.bucket.getCount()-gets, again.CloudTrail, e.rows(t))
	}
	// the listing resumed after the cursor, not from the start of the window
	for _, l := range e.bucket.lists[nLists:] {
		if parts := strings.Split(l, "|"); parts[2] == "" && strings.HasSuffix(parts[1], "2026/09/16/") {
			t.Errorf("a listing restarted at the beginning of the window: %q", l)
		}
	}

	// a new file is read once, and added to the day's count
	k4 := trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T1105Z")
	e.bucket.put(k4, gz(t, logBody(roleCall("2026-10-15T11:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	third := e.mustRun(t)
	want[roleDE+" ec2:RunInstances * 2026-10-15 cloudtrail"] = 2
	if third.CloudTrail.Objects != 1 || fmt.Sprint(e.rows(t)) != fmt.Sprint(want) {
		t.Errorf("after a new file: stats %+v rows %v", third.CloudTrail, e.rows(t))
	}
	if n := countOf(e.bucket.gets, k1); n != 1 {
		t.Errorf("file read %d times", n)
	}
	if got := e.bucket.gets[len(e.bucket.gets)-1]; got != k4 {
		t.Errorf("last file read = %s", got)
	}
	if e.gaps(t)["cloudtrail unmapped_actions"] == nil {
		t.Error("the gap for unmapped actions was dropped")
	}
	// audited, with counts only
	if d := auditActions(t, e.f)["aws.usage.ingested"]; d == "" || strings.Contains(d, baseSecret) {
		t.Errorf("audit detail = %q", d)
	}
}

func countOf(list []string, v string) int {
	n := 0
	for _, x := range list {
		if x == v {
			n++
		}
	}
	return n
}

// A run reads at most MaxObjectsPerRun files; the cursor resumes, every file is
// counted once, and no prefix starves another.
func TestCollectUsage_ObjectBudgetAndResume(t *testing.T) {
	ct := trailConfig()
	ct.MaxObjectsPerRun = 4
	e := newUsageEnv(t, &UsageConfig{CloudTrail: ct})
	total := 0
	for i := 0; i < 5; i++ {
		for _, acct := range []string{"111111111111", "222222222222"} {
			e.bucket.put(trailKey(acct, "us-east-1", "2026-10-15", fmt.Sprintf("20261015T%02d00Z", i)),
				gz(t, logBody(userCall(fmt.Sprintf("2026-10-15T%02d:00:00Z", i), "iam.amazonaws.com", "CreateUser"))))
			total++
		}
	}
	first := e.mustRun(t)
	if !first.CloudTrail.Backlog || first.CloudTrail.Objects != 4 {
		t.Fatalf("first = %+v", first.CloudTrail)
	}
	// both prefixes advanced
	var cur trailCursor
	_ = json.Unmarshal(e.state(t, store.AWSUsageCloudTrail).Cursor, &cur)
	if len(cur.Prefixes) != 2 {
		t.Errorf("cursor = %v: a prefix was starved", cur.Prefixes)
	}
	if got := e.state(t, store.AWSUsageCloudTrail).CoveredTo; got >= "2026-10-16" {
		t.Errorf("covered_to = %s with files left", got)
	}
	for i := 0; i < 5 && e.mustRun(t).CloudTrail.Backlog; i++ {
	}
	var sum int64
	for _, c := range e.rows(t) {
		sum += c
	}
	if sum != int64(total) {
		t.Errorf("counted %d events for %d files", sum, total)
	}
	for _, n := range e.bucket.gets {
		if countOf(e.bucket.gets, n) != 1 {
			t.Fatalf("%s was read more than once", n)
		}
	}
	if got := e.state(t, store.AWSUsageCloudTrail).CoveredTo; got != "2026-10-16" {
		t.Errorf("covered_to = %s after the backlog drained", got)
	}
}

func TestCollectUsage_RefusesBadFilesAndKeepsGoing(t *testing.T) {
	defer func(a int) { maxLogObjectBytes = a }(maxLogObjectBytes)
	maxLogObjectBytes = 4096
	e := newUsageEnv(t, trailOnly())
	key := func(stamp string) string { return trailKey("222222222222", "us-east-1", "2026-10-15", stamp) }
	e.bucket.put(key("20261015T0100Z"), gz(t, logBody(roleCall("2026-10-15T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.bucket.put(key("20261015T0200Z"), gz(t, "not json at all"))                                                                 // malformed
	e.bucket.put(key("20261015T0300Z"), []byte("plain text, not gzip"))                                                           // not gzip
	e.bucket.put(key("20261015T0400Z"), gz(t, `{"Records":[{"eventName":"a"},{"eventName":`))                                     // cut off
	e.bucket.put(key("20261015T0500Z"), gz(t, `{"Records":[`+strings.Repeat(`{"a":"`+strings.Repeat("b", 90)+`"},`, 200)+`{}]}`)) // inflates fine, compresses small
	e.bucket.put(key("20261015T0600Z"), []byte("x"))
	e.bucket.sizes[key("20261015T0600Z")] = 10 << 20 // listed as huge: never fetched
	e.bucket.put(key("20261015T0700Z"), gz(t, logBody(roleCall("2026-10-15T07:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))

	st := e.mustRun(t)
	ct := st.CloudTrail
	if ct.Refused != 4 || ct.Objects != 3 {
		t.Fatalf("stats = %+v", ct)
	}
	if got := e.rows(t)[roleDE+" ec2:RunInstances * 2026-10-15 cloudtrail"]; got != 2 {
		t.Errorf("count = %d: the good files around the bad ones were not both counted", got)
	}
	if countOf(e.bucket.gets, key("20261015T0600Z")) != 0 {
		t.Error("an object listed over the size limit was fetched")
	}
	g := e.gaps(t)
	for stamp, code := range map[string]string{"20261015T0200Z": "malformed", "20261015T0300Z": "malformed", "20261015T0400Z": "malformed", "20261015T0600Z": "too_large"} {
		x := g["cloudtrail "+key(stamp)]
		if x == nil || x.Code != code || x.Day != "2026-10-15" {
			t.Errorf("gap for %s = %+v, want %s", stamp, x, code)
		}
	}
	// the refused files are behind the cursor: they are not read again, and the gaps stay
	gets := e.bucket.getCount()
	e.mustRun(t)
	if e.bucket.getCount() != gets || len(e.gaps(t)) != len(g) {
		t.Errorf("refused files were read again (%d gets), or their gaps changed", e.bucket.getCount()-gets)
	}
}

func TestCollectUsage_AccessDeniedIsAGapAndHoldsTheCursor(t *testing.T) {
	ct := trailConfig()
	ct.KMSKeyARN = "arn:aws:kms:us-east-1:111111111111:key/11111111-2222-3333-4444-555555555555"
	e := newUsageEnv(t, &UsageConfig{CloudTrail: ct})
	k1 := trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0100Z")
	k2 := trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0200Z")
	k3 := trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0300Z")
	for _, k := range []string{k1, k2, k3} {
		e.bucket.put(k, gz(t, logBody(roleCall("2026-10-15T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	}
	e.bucket.status[k2] = 403
	st := e.mustRun(t)
	if st.CloudTrail.Objects != 1 {
		t.Fatalf("stats = %+v", st.CloudTrail)
	}
	g := e.gaps(t)["cloudtrail s3:222222222222/us-east-1"]
	if g == nil || g.Code != "AccessDenied" || !strings.Contains(g.Detail, "kms:Decrypt on "+ct.KMSKeyARN) || !strings.Contains(g.Detail, "TrailReaderPolicy") {
		t.Errorf("gap = %+v", g)
	}
	if len(e.rows(t)) != 1 {
		t.Errorf("rows = %v", e.rows(t))
	}
	// it is fixed: the file that failed is read next, nothing is skipped, and the gap is cleared
	delete(e.bucket.status, k2)
	e.mustRun(t)
	if got := e.rows(t)[roleDE+" ec2:RunInstances * 2026-10-15 cloudtrail"]; got != 3 {
		t.Errorf("count = %d, want all 3 files", got)
	}
	if e.gaps(t)["cloudtrail s3:222222222222/us-east-1"] != nil {
		t.Error("the gap was not cleared")
	}
}

func TestCollectUsage_UnlistableBucketIsAnErrorWithAGap(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	e.bucket.listErr = 403
	st, err := e.run(t)
	if err == nil || st == nil || st.CloudTrail == nil {
		t.Fatalf("run = %+v, %v", st, err)
	}
	g := e.gaps(t)
	if x := g["cloudtrail list:111111111111"]; x == nil || x.Code != "AccessDenied" || !strings.Contains(x.Detail, "TrailReaderPolicy") {
		t.Errorf("gaps = %v", g)
	}
	if len(e.rows(t)) != 0 {
		t.Error("rows were written")
	}
	// it stops after three accounts in a row fail rather than asking for every account
	if n := len(e.bucket.lists); n > 3 {
		t.Errorf("%d listings for a bucket that denies them all", n)
	}
}

func TestCollectUsage_DataEventsState(t *testing.T) {
	for _, c := range []struct {
		name, body, trail, want, gap string
	}{
		{"off", `{"EventSelectors":[{"ReadWriteType":"All","IncludeManagementEvents":true}]}`, trailARN, "disabled", "data_events_disabled"},
		{"partial", `{"EventSelectors":[{"ReadWriteType":"WriteOnly","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]}`, trailARN, "unknown", "data_events_unknown"},
		{"on", selectorsAllS3, trailARN, "enabled", ""},
		{"no trail configured", "", "", "unknown", "data_events_unknown"},
	} {
		ct := trailConfig()
		ct.TrailARN = c.trail
		e := newUsageEnv(t, &UsageConfig{CloudTrail: ct})
		if c.body != "" {
			e.re = newReplay(t).Enqueue("cloudtrail/GetEventSelectors", awsreplay.Response{Body: c.body})
			e.bucket.re = e.re
		}
		e.mustRun(t)
		st := e.state(t, store.AWSUsageCloudTrail)
		if st.S3DataEvents != c.want {
			t.Errorf("%s: s3_data_events = %s, want %s", c.name, st.S3DataEvents, c.want)
		}
		g := e.gaps(t)["cloudtrail data_events"]
		if (c.gap == "") != (g == nil) || g != nil && g.Code != c.gap {
			t.Errorf("%s: gap = %+v, want %q", c.name, g, c.gap)
		}
	}
	// turning data events on later clears the gap
	e := newUsageEnv(t, trailOnly())
	e.re = newReplay(t).Enqueue("cloudtrail/GetEventSelectors",
		awsreplay.Response{Body: `{"EventSelectors":[{"ReadWriteType":"All"}]}`}, awsreplay.Response{Body: selectorsAllS3})
	e.bucket.re = e.re
	e.mustRun(t)
	if e.gaps(t)["cloudtrail data_events"] == nil {
		t.Fatal("no gap with data events off")
	}
	e.mustRun(t)
	if e.gaps(t)["cloudtrail data_events"] != nil || e.state(t, store.AWSUsageCloudTrail).S3DataEvents != "enabled" {
		t.Errorf("after enabling: gaps = %v, state = %+v", e.gaps(t), e.state(t, store.AWSUsageCloudTrail))
	}
}

func TestCollectUsage_NoUsageConfigDoesNothing(t *testing.T) {
	e := newUsageEnv(t, nil)
	st, err := e.run(t)
	if st != nil || err != nil || len(e.re.Requests()) != 0 {
		t.Errorf("run = %+v, %v with %d requests", st, err, len(e.re.Requests()))
	}
}

// ---------------------------------------------------------------- Access Advisor

// collected runs the estate collection of the fixtures and returns its snapshot.
func (e *usageEnv) collected(t *testing.T) {
	t.Helper()
	hdr, err := e.s.Collect(context.Background(), e.f.DB, e.f.A.ID, e.k.ID, "worker")
	if err != nil {
		t.Fatal(err)
	}
	e.snap = hdr
}

func TestCollectUsage_AccessAdvisor(t *testing.T) {
	e := newUsageEnv(t, &UsageConfig{AccessAdvisor: true, AdvisorPerRun: 2})
	e.collected(t)
	*e.sleeps = nil

	first := e.mustRun(t)
	a := first.Advisor
	if a == nil || a.Principals != 2 || a.Remaining < 1 || a.Resting {
		t.Fatalf("first run = %+v", a)
	}
	// rows: action level, service level, and nothing for a service never used; no row has a count but 1
	rows := e.rows(t)
	for k, c := range rows {
		if !strings.HasSuffix(k, " access_advisor") || c != 1 || !strings.Contains(k, " * 2026-") {
			t.Errorf("row %q = %d", k, c)
		}
	}
	var someone string
	for k := range rows {
		someone = strings.Fields(k)[0]
	}
	for _, want := range []string{"s3:GetObject * 2026-10-14", "s3:PutObject * 2026-09-02", "s3:* * 2026-10-14", "lambda:* * 2026-10-01"} {
		if !hasRow(rows, someone+" "+want) {
			t.Errorf("no row %q for %s in %v", want, someone, rows)
		}
	}
	for k := range rows {
		if strings.Contains(k, " sqs:") {
			t.Errorf("a row for a service never used: %s", k)
		}
	}
	// the Generate and Get calls are IAM read actions of the reader policy, and are paced between principals
	for _, q := range e.re.Requests() {
		if q.Service == "iam" && strings.Contains(q.Operation, "LastAccessed") && !slices.Contains(ReaderActions, "iam:"+q.Operation) {
			t.Errorf("%s is not in ReaderActions", q.Operation)
		}
		if q.Operation == "GenerateServiceLastAccessedDetails" && q.Form.Get("Granularity") != "ACTION_LEVEL" {
			t.Errorf("Granularity = %q", q.Form.Get("Granularity"))
		}
	}
	if !slices.Contains(*e.sleeps, advisorPace) {
		t.Errorf("sleeps = %v: calls to IAM are not paced", *e.sleeps)
	}
	// the round continues where it stopped, then rests for a day
	calls := e.re.Calls("iam/GenerateServiceLastAccessedDetails")
	for i := 0; i < 20; i++ {
		if st := e.mustRun(t); st.Advisor.Resting || st.Advisor.Remaining == 0 {
			break
		}
	}
	done := e.re.Calls("iam/GenerateServiceLastAccessedDetails")
	if done <= calls {
		t.Fatal("the round did not continue")
	}
	rest := e.mustRun(t)
	if !rest.Advisor.Resting || e.re.Calls("iam/GenerateServiceLastAccessedDetails") != done {
		t.Errorf("a finished round called IAM again: %+v", rest.Advisor)
	}
	// every user and role of the snapshot was asked about exactly once
	asked := map[string]int{}
	for _, q := range e.re.Requests() {
		if q.Operation == "GenerateServiceLastAccessedDetails" {
			asked[q.Form.Get("Arn")]++
		}
	}
	for arn, n := range asked {
		if n != 1 || !strings.Contains(arn, ":iam::") {
			t.Errorf("%s asked %d times", arn, n)
		}
	}
	if len(asked) < 3 {
		t.Errorf("asked about %v", asked)
	}
	for arn := range asked {
		if strings.Contains(arn, "aws-service-role") {
			t.Errorf("asked about a service-linked role: %s", arn)
		}
	}
}

func hasRow(rows map[string]int64, prefix string) bool {
	for k := range rows {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func TestCollectUsage_AccessAdvisorThrottled(t *testing.T) {
	e := newUsageEnv(t, &UsageConfig{AccessAdvisor: true, AdvisorPerRun: 10})
	e.collected(t)
	// IAM throttles every Generate beyond the client's retries: the run stops, records the gap, and keeps its place
	throttle := awsreplay.Response{Status: 400, Body: `<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`}
	re := newReplay(t)
	var resp []awsreplay.Response
	for i := 0; i < 6; i++ {
		resp = append(resp, throttle)
	}
	re.Enqueue("iam/GenerateServiceLastAccessedDetails", resp...)
	e.bucket.re = re
	*e.sleeps = nil
	st := e.mustRun(t)
	if st.Advisor.Principals != 1 || st.Advisor.Remaining < 1 || st.Advisor.Rows != 0 {
		t.Fatalf("advisor = %+v", st.Advisor)
	}
	if len(*e.sleeps) < 5 {
		t.Errorf("backoff sleeps = %v", *e.sleeps)
	}
	var rl *store.AWSUsageGap
	for k, g := range e.gaps(t) {
		if strings.HasPrefix(k, "access_advisor ") && g.Code == "rate_limited" {
			rl = g
		}
	}
	if rl == nil {
		t.Fatalf("gaps = %v", e.gaps(t))
	}
	// the next run starts at the principal that was throttled, and clears its gap
	e.bucket.re = newReplay(t)
	next := e.mustRun(t)
	if next.Advisor.Principals < 2 {
		t.Fatalf("next = %+v", next.Advisor)
	}
	for k, g := range e.gaps(t) {
		if g.Code == "rate_limited" {
			t.Errorf("gap %s was not cleared", k)
		}
	}
}

func TestCollectUsage_AccessAdvisorJobStates(t *testing.T) {
	e := newUsageEnv(t, &UsageConfig{AccessAdvisor: true, AdvisorPerRun: 1})
	e.collected(t)
	inProgress := awsreplay.Response{Body: `<GetServiceLastAccessedDetailsResponse><GetServiceLastAccessedDetailsResult><JobStatus>IN_PROGRESS</JobStatus></GetServiceLastAccessedDetailsResult></GetServiceLastAccessedDetailsResponse>`}
	re := newReplay(t)
	re.Enqueue("iam/GetServiceLastAccessedDetails", inProgress, inProgress, awsreplay.Response{Body: fixture(t, "iam/GetServiceLastAccessedDetails/1.xml")})
	e.bucket.re = re
	*e.sleeps = nil
	st := e.mustRun(t)
	if st.Advisor.Rows == 0 || re.Calls("iam/GetServiceLastAccessedDetails") != 3 {
		t.Errorf("a report that took three polls: %+v, %d polls", st.Advisor, re.Calls("iam/GetServiceLastAccessedDetails"))
	}
	if n := countDur(*e.sleeps, advisorPollEvery); n != 2 {
		t.Errorf("poll waits = %d", n)
	}

	// a failed job is a gap for that principal, and the run goes on
	re = newReplay(t)
	re.Enqueue("iam/GetServiceLastAccessedDetails", awsreplay.Response{Body: `<GetServiceLastAccessedDetailsResponse><GetServiceLastAccessedDetailsResult><JobStatus>FAILED</JobStatus>` +
		`<Error><Code>InvalidInput</Code><Message>bad</Message></Error></GetServiceLastAccessedDetailsResult></GetServiceLastAccessedDetailsResponse>`})
	e.bucket.re = re
	e.mustRun(t)
	found := false
	for k, g := range e.gaps(t) {
		if strings.HasPrefix(k, "access_advisor ") && g.Code == "InvalidInput" {
			found = true
		}
	}
	if !found {
		t.Errorf("gaps = %v", e.gaps(t))
	}
}

func countDur(l []time.Duration, d time.Duration) int {
	n := 0
	for _, x := range l {
		if x == d {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------- with the collection job

// The job runs the usage ingest next to the estate collection, an unchanged
// estate still reads new log files, and a failing ingest never fails the
// collection.
func TestCollectAndMaterialize_RunsUsageIngest(t *testing.T) {
	e := newUsageEnv(t, &UsageConfig{CloudTrail: trailConfig(), AccessAdvisor: true, AdvisorPerRun: 1000})
	e.s.Eval = evalConfig()
	e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0100Z"),
		gz(t, logBody(roleCall("2026-10-15T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	ctx := context.Background()
	res, err := e.s.CollectAndMaterialize(ctx, e.f.DB, e.f.A.ID, e.k.ID, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Usage == nil || res.UsageError != "" || res.Usage.CloudTrail.Counted != 1 || res.Usage.Advisor.Principals == 0 {
		t.Fatalf("result = %+v usage %+v err %q", res, res.Usage, res.UsageError)
	}
	if got := e.rows(t)[roleDE+" ec2:RunInstances * 2026-10-15 cloudtrail"]; got != 1 {
		t.Errorf("rows = %v", e.rows(t))
	}
	if b, err := json.Marshal(res); err != nil || strings.Contains(string(b), baseSecret) {
		t.Errorf("result JSON = %s, %v", b, err)
	}

	// the estate is the same, and a new log file arrives
	e.bucket.re = newReplay(t)
	e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0200Z"),
		gz(t, logBody(roleCall("2026-10-15T02:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.bucket.re.Enqueue("cloudtrail/GetEventSelectors", awsreplay.Response{Body: selectorsAllS3})
	res, err = e.s.CollectAndMaterialize(ctx, e.f.DB, e.f.A.ID, e.k.ID, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Usage == nil || res.Usage.CloudTrail.Counted != 1 || res.Usage.Advisor == nil || !res.Usage.Advisor.Resting {
		t.Fatalf("second result = %+v usage %+v", res, res.Usage)
	}
	if got := e.rows(t)[roleDE+" ec2:RunInstances * 2026-10-15 cloudtrail"]; got != 2 {
		t.Errorf("rows = %v", e.rows(t))
	}

	// the bucket stops answering: the collection still succeeds, and says why the usage did not
	e.bucket.re = newReplay(t)
	e.bucket.listErr = 403
	res, err = e.s.CollectAndMaterialize(ctx, e.f.DB, e.f.A.ID, e.k.ID, "worker")
	if err != nil || res.UsageError == "" {
		t.Fatalf("result = %+v, %v; want success with a usage error", res, err)
	}
	var got *store.AWSConnector
	_ = e.f.DB.ReadTenant(ctx, e.f.A.ID, func(c *store.TenantTx) (err error) { got, err = c.AWSConnector(e.k.ID); return err })
	if got.Status != store.AWSConnectorOK {
		t.Errorf("connector status = %s", got.Status)
	}
}

// usageActions are the ReaderActions that only the usage ingest calls.
var usageActions = map[string]bool{"iam:GenerateServiceLastAccessedDetails": true, "iam:GetServiceLastAccessedDetails": true, "cloudtrail:GetEventSelectors": true}

// Every call of the usage ingest is a read the customer allowed: the IAM and
// CloudTrail ones are ReaderActions, and the S3 ones are what TrailReaderPolicy
// grants on the log prefix.
func TestCollectUsage_UsesOnlyReaderActions(t *testing.T) {
	e := newUsageEnv(t, &UsageConfig{CloudTrail: trailConfig(), AccessAdvisor: true, AdvisorPerRun: 1000})
	e.collected(t)
	e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0100Z"), gz(t, logBody(userCall("2026-10-15T01:00:00Z", "iam.amazonaws.com", "CreateUser"))))
	e.mustRun(t)
	used := map[string]bool{}
	for _, q := range e.re.Requests() {
		if q.Service == "sts" || q.Operation == "GetAccountAuthorizationDetails" {
			continue
		}
		if a := q.Service + ":" + q.Operation; !slices.Contains(ReaderActions, a) || !usageActions[a] && q.Service != "iam" {
			if !usageActions[a] {
				continue // the estate collection's own reads
			}
			t.Errorf("the usage ingest called %s, which ReaderActions does not allow", a)
		}
		used[q.Service+":"+q.Operation] = true
	}
	for a := range usageActions {
		if !used[a] {
			t.Errorf("%s is in ReaderActions for the usage ingest but was not called", a)
		}
	}
	e.bucket.mu.Lock()
	defer e.bucket.mu.Unlock()
	if len(e.bucket.gets) == 0 || len(e.bucket.lists) == 0 {
		t.Error("the bucket was not read")
	}
}

// ---------------------------------------------------------------- security review (PR #673)

// A file that inflates to exactly the limit is read; one byte more is refused.
func TestParseLogFileInflateBoundary(t *testing.T) {
	defer func(a int) { maxLogInflatedBytes = a }(maxLogInflatedBytes)
	body := logBody(userCall("2026-10-15T10:00:00Z", "s3.amazonaws.com", "GetObject"))
	maxLogInflatedBytes = len(body)
	if n, err := parseLogFile(gz(t, body), func(*ctEvent) {}); err != nil || n != 1 {
		t.Errorf("a file of exactly the limit: %d, %v", n, err)
	}
	maxLogInflatedBytes = len(body) - 1
	if _, err := parseLogFile(gz(t, body), func(*ctEvent) {}); err == nil || !strings.Contains(err.Error(), "inflated_too_large") {
		t.Errorf("a file one byte over the limit: %v", err)
	}
}

// An account whose log prefix cannot be listed keeps its gap on every run: it
// was cleared on the run after it was recorded, so the account looked covered.
func TestCollectUsage_ListingGapDoesNotFlap(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0100Z"),
		gz(t, logBody(roleCall("2026-10-15T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.bucket.listDeny = map[string]int{"/111111111111/": 403}
	for run := 1; run <= 3; run++ {
		if _, err := e.run(t); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if g := e.gaps(t)["cloudtrail list:111111111111"]; g == nil || g.Code != "AccessDenied" {
			t.Fatalf("run %d: the listing gap is gone: %v", run, e.gaps(t))
		}
	}
	e.bucket.listDeny = nil
	e.mustRun(t)
	if e.gaps(t)["cloudtrail list:111111111111"] != nil {
		t.Error("the listing gap was not cleared once the listing worked")
	}
}

// A key dated in the future does not move the cursor past the files delivered
// after it, and a record dated in the future is not filed.
func TestCollectUsage_FutureKeyAndEventTime(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	k1 := trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0100Z")
	e.bucket.put(k1, gz(t, logBody(
		roleCall("2026-10-15T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""),
		roleCall("2999-01-01T00:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""),
		roleCall("2001-01-01T00:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	future := trailKey("222222222222", "us-east-1", "2099-12-31", "20991231T0000Z")
	e.bucket.put(future, gz(t, logBody(roleCall("2099-12-31T00:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	st := e.mustRun(t)
	if st.CloudTrail.Objects != 1 || st.CloudTrail.Counted != 1 || st.CloudTrail.Skipped != 2 {
		t.Fatalf("stats = %+v", st.CloudTrail)
	}
	if countOf(e.bucket.gets, future) != 0 {
		t.Error("the future-dated file was read")
	}
	if g := e.gaps(t)["cloudtrail s3:222222222222/us-east-1"]; g == nil || g.Code != "implausible_key" {
		t.Errorf("gaps = %v", e.gaps(t))
	}
	for k := range e.rows(t) {
		if !strings.Contains(k, " 2026-10-15 ") {
			t.Errorf("row %q", k)
		}
	}
	// a file delivered later, with a key before the future one, is still read
	k2 := trailKey("222222222222", "us-east-1", "2026-10-16", "20261016T0100Z")
	e.bucket.put(k2, gz(t, logBody(roleCall("2026-10-16T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.mustRun(t)
	if countOf(e.bucket.gets, k2) != 1 {
		t.Errorf("a file after a future-dated key was skipped: gets %v", e.bucket.gets)
	}
}

// A run holds at most maxUsageRows rows: it stops after the file that reached
// them, and later runs count the rest exactly once.
func TestCollectUsage_RowCapStopsTheRun(t *testing.T) {
	defer func(n int) { maxUsageRows = n }(maxUsageRows)
	maxUsageRows = 2
	e := newUsageEnv(t, trailOnly())
	for i := 0; i < 3; i++ {
		e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", fmt.Sprintf("20261015T%02d00Z", i)), gz(t, logBody(
			roleCall(fmt.Sprintf("2026-10-1%dT01:00:00Z", 2*i), "ec2.amazonaws.com", "RunInstances", roleDE, ""),
			roleCall(fmt.Sprintf("2026-10-1%dT01:00:00Z", 2*i+1), "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	}
	first := e.mustRun(t)
	if first.CloudTrail.Objects != 1 || !first.CloudTrail.Backlog || first.CloudTrail.Rows != 2 {
		t.Fatalf("first = %+v", first.CloudTrail)
	}
	for i := 0; i < 5 && e.mustRun(t).CloudTrail.Backlog; i++ {
	}
	var sum int64
	for _, c := range e.rows(t) {
		sum += c
	}
	if sum != 6 {
		t.Errorf("counted %d events, want 6: %v", sum, e.rows(t))
	}
}

// Two runs that start from the same state cannot both write: the second would
// count the same files again.
func TestCollectUsage_StaleStateIsRefused(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0100Z"),
		gz(t, logBody(roleCall("2026-10-15T01:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.mustRun(t)
	stale := e.state(t, store.AWSUsageCloudTrail)
	e.bucket.put(trailKey("222222222222", "us-east-1", "2026-10-15", "20261015T0200Z"),
		gz(t, logBody(roleCall("2026-10-15T02:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))))
	e.mustRun(t)
	before := fmt.Sprint(e.rows(t))
	row := &store.AWSUsageDay{ConnectorID: e.k.ID, PrincipalARN: roleDE, Action: "ec2:RunInstances", ResourceScope: "*", Day: "2026-10-15",
		Source: store.AWSUsageCloudTrail, Count: 1, LastSeen: testNow}
	for name, prior := range map[string]*store.AWSUsageState{"stale": stale, "none": nil} {
		b := &usageBatch{rows: []*store.AWSUsageDay{row}, state: store.AWSUsageState{ConnectorID: e.k.ID, Source: store.AWSUsageCloudTrail,
			Cursor: json.RawMessage(`{"prefixes":{}}`), UpdatedAt: testNow}}
		err := e.s.persistUsage(context.Background(), e.f.DB, e.f.A.ID, "worker", b, prior, map[string]*store.AWSUsageGap{}, 1, 0)
		if !errors.Is(err, store.ErrAWSUsageStateMoved) {
			t.Errorf("%s prior: err = %v", name, err)
		}
	}
	if got := fmt.Sprint(e.rows(t)); got != before {
		t.Errorf("rows changed by a refused write: %s, was %s", got, before)
	}
}

// One run's Access Advisor time is bounded: the rest of the round waits.
func TestCollectUsage_AccessAdvisorRunBudget(t *testing.T) {
	defer func(d time.Duration) { advisorRunBudget = d }(advisorRunBudget)
	advisorRunBudget = 0
	e := newUsageEnv(t, &UsageConfig{AccessAdvisor: true, AdvisorPerRun: 1000})
	e.collected(t)
	st := e.mustRun(t)
	if st.Advisor.Principals != 1 || st.Advisor.Remaining < 1 {
		t.Errorf("advisor = %+v: the time budget did not stop the run", st.Advisor)
	}
}
