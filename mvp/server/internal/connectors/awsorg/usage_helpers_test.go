package awsorg

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
)

const (
	trailBucket  = "acme-trail-logs"
	trailAccount = "111111111111"
	trailOrg     = "o-abcde12345"
	trailRoot    = "trail/AWSLogs/" + trailOrg + "/"
	trailARN     = "arn:aws:cloudtrail:us-east-1:111111111111:trail/org-trail"
)

func trailConfig() *CloudTrailConfig {
	return &CloudTrailConfig{Bucket: trailBucket, Prefix: "trail", Region: "us-east-1", AccountID: trailAccount,
		OrganizationID: trailOrg, TrailARN: trailARN}
}

// fakeBucket is an S3 bucket that answers ListObjectsV2 and GetObject for the
// trail's host, and sends every other request to the replay (STS, IAM,
// CloudTrail). It checks what the connector must send: the assumed role's keys
// and the expected bucket owner.
type fakeBucket struct {
	re *awsreplay.Replay

	mu       sync.Mutex
	objects  map[string][]byte
	sizes    map[string]int64 // a listed size different from the object's
	status   map[string]int   // key -> status of its GET (403 ...)
	listErr  int              // status of every list when set
	listDeny map[string]int   // prefix substring -> status of the lists under it
	gets     []string
	lists    []string
	bad      []string
}

func newFakeBucket(re *awsreplay.Replay) *fakeBucket {
	return &fakeBucket{re: re, objects: map[string][]byte{}, sizes: map[string]int64{}, status: map[string]int{}}
}

func (f *fakeBucket) put(key string, b []byte) { f.objects[key] = b }

func (f *fakeBucket) getCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.gets)
}

func (f *fakeBucket) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Host != trailBucket+".s3.us-east-1.amazonaws.com" {
		return f.re.Do(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(req.Header.Get("Authorization"), "Credential="+sessionKeyID+"/") {
		f.bad = append(f.bad, "not signed with the assumed role's keys")
	}
	if got := req.Header.Get("X-Amz-Expected-Bucket-Owner"); got != trailAccount {
		f.bad = append(f.bad, "expected bucket owner is "+got)
	}
	if req.Method != http.MethodGet {
		f.bad = append(f.bad, "method "+req.Method)
	}
	respond := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
	}
	q := req.URL.Query()
	if q.Get("list-type") == "2" {
		f.lists = append(f.lists, q.Get("prefix")+"|"+q.Get("start-after")+"|"+q.Get("delimiter"))
		for sub, st := range f.listDeny {
			if strings.Contains(q.Get("prefix"), sub) {
				return respond(st, []byte("<Error><Code>AccessDenied</Code><Message>denied</Message></Error>"))
			}
		}
		if f.listErr != 0 {
			return respond(f.listErr, []byte("<Error><Code>AccessDenied</Code><Message>denied</Message></Error>"))
		}
		return respond(200, f.list(q.Get("prefix"), q.Get("start-after"), q.Get("delimiter"), q.Get("continuation-token"), q.Get("max-keys")))
	}
	key := strings.TrimPrefix(req.URL.Path, "/")
	f.gets = append(f.gets, key)
	if st := f.status[key]; st != 0 {
		return respond(st, []byte("<Error><Code>AccessDenied</Code><Message>kms:Decrypt denied</Message></Error>"))
	}
	b, ok := f.objects[key]
	if !ok {
		return respond(404, []byte("<Error><Code>NoSuchKey</Code><Message>no</Message></Error>"))
	}
	return respond(200, b)
}

type listXML struct {
	XMLName   xml.Name `xml:"ListBucketResult"`
	Truncated bool     `xml:"IsTruncated"`
	Contents  []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
	Prefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
	Next string `xml:"NextContinuationToken,omitempty"`
}

func (f *fakeBucket) list(prefix, after, delim, token, maxKeys string) []byte {
	max, _ := strconv.Atoi(maxKeys)
	if max <= 0 {
		max = 1000
	}
	if token != "" {
		after = token
	}
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var r listXML
	if delim != "" {
		seen := map[string]bool{}
		for _, k := range keys {
			rest := strings.TrimPrefix(k, prefix)
			if i := strings.Index(rest, delim); i >= 0 {
				p := prefix + rest[:i+1]
				if !seen[p] {
					seen[p] = true
					r.Prefixes = append(r.Prefixes, struct {
						Prefix string `xml:"Prefix"`
					}{p})
				}
			}
		}
	} else {
		if len(keys) > max {
			r.Truncated, r.Next = true, keys[max-1]
			keys = keys[:max]
		}
		for _, k := range keys {
			size := int64(len(f.objects[k]))
			if s, ok := f.sizes[k]; ok {
				size = s
			}
			r.Contents = append(r.Contents, struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			}{k, size})
		}
	}
	b, err := xml.Marshal(r)
	if err != nil {
		panic(err)
	}
	return b
}

// gz compresses a log file body.
func gz(t testing.TB, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// logBody is the JSON of a log file with the records.
func logBody(records ...string) string { return `{"Records":[` + strings.Join(records, ",") + `]}` }

// roleCall is a record of a role session calling an API.
func roleCall(at, source, name, roleARN string, extra string) string {
	return fmt.Sprintf(`{"eventVersion":"1.08","eventTime":%q,"eventSource":%q,"eventName":%q,"eventType":"AwsApiCall","eventCategory":"Management",`+
		`"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::222222222222:assumed-role/x/session","sessionContext":{"sessionIssuer":{"type":"Role","arn":%q}}}%s}`,
		at, source, name, roleARN, extra)
}

const (
	roleDE = "arn:aws:iam::222222222222:role/DataEngineer"
	userAl = "arn:aws:iam::111111111111:user/alice"
)

func userCall(at, source, name string) string {
	return fmt.Sprintf(`{"eventTime":%q,"eventSource":%q,"eventName":%q,"eventType":"AwsApiCall","eventCategory":"Management","userIdentity":{"type":"IAMUser","arn":%q}}`,
		at, source, name, userAl)
}

// trailKey is the key of a log file of an account, region and time.
func trailKey(account, region, day, stamp string) string {
	d := strings.ReplaceAll(day, "-", "/")
	return trailRoot + account + "/CloudTrail/" + region + "/" + d + "/" + account + "_CloudTrail_" + region + "_" + stamp + "_abcd1234.json.gz"
}
