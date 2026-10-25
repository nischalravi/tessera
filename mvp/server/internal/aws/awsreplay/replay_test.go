package awsreplay

import (
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

var keys = sigv4.Credentials{AccessKeyID: "AKIAEXAMPLEEXAMPLE1", SecretAccessKey: "secret0123456789secret0123456789"}

func signed(t *testing.T, method, url, body string, hdr map[string]string, service string, c sigv4.Credentials) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if err := sigv4.Sign(req, []byte(body), c, "us-east-1", service, time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestOperation(t *testing.T) {
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
	for _, c := range []struct {
		name, method, url, body string
		hdr                     map[string]string
		want                    string
	}{
		{"query", "POST", "https://iam.amazonaws.com/", "Action=GetAccountAuthorizationDetails&Version=x", form, "GetAccountAuthorizationDetails"},
		{"json", "POST", "https://kms.us-east-1.amazonaws.com/", "{}", map[string]string{"X-Amz-Target": "TrentService.ListKeys"}, "ListKeys"},
		{"s3 list", "GET", "https://s3.us-east-1.amazonaws.com/?max-buckets=1", "", nil, "ListAllMyBuckets"},
		{"s3 policy", "GET", "https://b.s3.us-east-1.amazonaws.com/?policy", "", nil, "GetBucketPolicy"},
		{"s3 acl path-style", "GET", "https://s3.us-east-1.amazonaws.com/a.b?acl", "", nil, "GetBucketAcl"},
		{"s3 ownership", "GET", "https://b.s3.us-east-1.amazonaws.com/?ownershipControls", "", nil, "GetBucketOwnershipControls"},
		{"s3 bpa", "GET", "https://b.s3.us-east-1.amazonaws.com/?publicAccessBlock", "", nil, "GetBucketPublicAccessBlock"},
		{"s3control bpa", "GET", "https://1.s3-control.us-east-1.amazonaws.com/v20180820/configuration/publicAccessBlock", "", nil, "GetPublicAccessBlock"},
		{"s3control list", "GET", "https://1.s3-control.us-east-1.amazonaws.com/v20180820/accesspoint", "", nil, "ListAccessPoints"},
		{"s3control policy", "GET", "https://1.s3-control.us-east-1.amazonaws.com/v20180820/accesspoint/ap/policy", "", nil, "GetAccessPointPolicy"},
		{"lambda list", "GET", "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions", "", nil, "ListFunctions"},
		{"lambda policy", "GET", "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/f/policy", "", nil, "GetPolicy"},
		{"unknown", "GET", "https://iam.amazonaws.com/x", "", nil, "Unknown"},
	} {
		req := signed(t, c.method, c.url, c.body, c.hdr, "x", keys)
		if got := Operation(req, []byte(c.body)); got != c.want {
			t.Errorf("%s: Operation = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestReplay(t *testing.T) {
	fsys := fstest.MapFS{
		"iam/GetUser/1.xml":     {Data: []byte("<one/>")},
		"iam/GetUser/2.404.xml": {Data: []byte("<Error><Code>NoSuchEntity</Code></Error>")},
	}
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	do := func(r *Replay, c sigv4.Credentials) *http.Response {
		resp, err := r.Do(signed(t, "POST", "https://iam.amazonaws.com/", "Action=GetUser", form, "iam", c))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	r := NewReplay(fsys).Verify(keys.AccessKeyID, keys.SecretAccessKey)
	if resp := do(r, keys); resp.StatusCode != 200 {
		t.Errorf("first status %d", resp.StatusCode)
	}
	if resp := do(r, keys); resp.StatusCode != 404 {
		t.Errorf("second status %d", resp.StatusCode)
	}
	if resp := do(r, keys); resp.StatusCode != 400 || len(r.Unrecorded()) != 1 {
		t.Errorf("a third call with no recording: status %d, unrecorded %v", resp.StatusCode, r.Unrecorded())
	}
	if r.Calls("iam/GetUser") != 3 || len(r.BadSignatures()) != 0 {
		t.Errorf("calls %d, bad %v", r.Calls("iam/GetUser"), r.BadSignatures())
	}

	// RepeatLast serves the last recording again
	r = NewReplay(fsys)
	r.RepeatLast = true
	do(r, keys)
	do(r, keys)
	if resp := do(r, keys); resp.StatusCode != 404 || len(r.Unrecorded()) != 0 {
		t.Errorf("RepeatLast: status %d, unrecorded %v", resp.StatusCode, r.Unrecorded())
	}

	// a wrong secret is a 403 and is listed
	r = NewReplay(fsys).Verify(keys.AccessKeyID, "another-secret-another-secret-0000")
	if resp := do(r, keys); resp.StatusCode != 403 || len(r.BadSignatures()) != 1 {
		t.Errorf("wrong secret: status %d, bad %v", resp.StatusCode, r.BadSignatures())
	}

	// a queue replaces the files of its operation
	r = NewReplay(fsys).Enqueue("iam/GetUser", Response{Status: 429, Body: "q"})
	if resp := do(r, keys); resp.StatusCode != 429 {
		t.Errorf("queued status %d", resp.StatusCode)
	}

	// unsigned, plain-http and non-AWS requests are refused
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/", nil)
	if _, err := r.Do(req); err == nil {
		t.Error("an unsigned request was served")
	}
	for _, u := range []string{"http://iam.amazonaws.com/", "https://evil.example/"} {
		req := signed(t, "GET", u, "", nil, "iam", keys)
		if _, err := r.Do(req); err == nil {
			t.Errorf("%s was served", u)
		}
	}
}

// TestUnsignedOnlyWebIdentity: sts:AssumeRoleWithWebIdentity is the one call
// the replayer accepts without a signature (it is recorded with no access key);
// any other unsigned call is refused.
func TestUnsignedOnlyWebIdentity(t *testing.T) {
	r := NewReplay(nil).Enqueue("sts/AssumeRoleWithWebIdentity", Response{Body: "<ok/>"})
	post := func(host, form string) (*http.Response, error) {
		req, _ := http.NewRequest("POST", "https://"+host+"/", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		return r.Do(req)
	}
	resp, err := post("sts.us-east-1.amazonaws.com", "Action=AssumeRoleWithWebIdentity&WebIdentityToken=t")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("web identity: %v %v", resp, err)
	}
	q := r.Requests()[0]
	if q.Service != "sts" || q.Operation != "AssumeRoleWithWebIdentity" || q.Region != "us-east-1" || q.AccessKeyID != "" || q.Form.Get("WebIdentityToken") != "t" {
		t.Errorf("request = %+v", q)
	}
	for name, c := range map[string][2]string{
		"another STS action": {"sts.us-east-1.amazonaws.com", "Action=AssumeRole"},
		"another service":    {"iam.amazonaws.com", "Action=AssumeRoleWithWebIdentity"},
		"odd STS host":       {"sts.evil.us-east-1.amazonaws.com", "Action=AssumeRoleWithWebIdentity"},
	} {
		if _, err := post(c[0], c[1]); err == nil {
			t.Errorf("%s: served unsigned", name)
		}
	}
}
