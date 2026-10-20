package sigv4

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

var vanillaKeys = Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

var vanillaTime = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

// TestGetVanilla is the published AWS Signature Version 4 test-suite case
// "get-vanilla" (aws-sig-v4-test-suite): GET / on example.amazonaws.com,
// us-east-1, service "service", signed headers host and x-amz-date.
func TestGetVanilla(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(req, nil, vanillaKeys, "us-east-1", "service", vanillaTime); err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization =\n %s\nwant\n %s", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

func TestSignDetails(t *testing.T) {
	sign := func(method, url, body string, hdr map[string]string, c Credentials, service string) *http.Request {
		t.Helper()
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if err := Sign(req, []byte(body), c, "us-east-1", service, vanillaTime); err != nil {
			t.Fatal(err)
		}
		return req
	}
	signedHeaders := func(r *http.Request) string {
		a := r.Header.Get("Authorization")
		i := strings.Index(a, "SignedHeaders=")
		return strings.Split(a[i+len("SignedHeaders="):], ",")[0]
	}
	sig := func(r *http.Request) string {
		a := r.Header.Get("Authorization")
		return a[strings.LastIndex(a, "Signature=")+len("Signature="):]
	}

	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
	a := sign("POST", "https://iam.amazonaws.com/", "Action=GetUser&Version=2010-05-08", form, vanillaKeys, "iam")
	if got := signedHeaders(a); got != "content-type;host;x-amz-date" {
		t.Errorf("signed headers = %q", got)
	}
	// deterministic, and sensitive to the body, the key, the service and the headers
	again := sign("POST", "https://iam.amazonaws.com/", "Action=GetUser&Version=2010-05-08", form, vanillaKeys, "iam")
	if sig(a) != sig(again) {
		t.Error("the signature is not deterministic")
	}
	for name, other := range map[string]*http.Request{
		"body":    sign("POST", "https://iam.amazonaws.com/", "Action=GetUser&Version=2010-05-09", form, vanillaKeys, "iam"),
		"service": sign("POST", "https://iam.amazonaws.com/", "Action=GetUser&Version=2010-05-08", form, vanillaKeys, "sts"),
		"secret": sign("POST", "https://iam.amazonaws.com/", "Action=GetUser&Version=2010-05-08", form,
			Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "other"}, "iam"),
		"target": sign("POST", "https://iam.amazonaws.com/", "Action=GetUser&Version=2010-05-08",
			map[string]string{"Content-Type": form["Content-Type"], "X-Amz-Target": "x"}, vanillaKeys, "iam"),
	} {
		if sig(other) == sig(a) {
			t.Errorf("the signature does not depend on the %s", name)
		}
	}

	// temporary credentials: the token is sent and signed
	tmp := vanillaKeys
	tmp.SessionToken = "tok/en"
	b := sign("GET", "https://iam.amazonaws.com/?Action=ListUsers", "", nil, tmp, "iam")
	if b.Header.Get("X-Amz-Security-Token") != "tok/en" || signedHeaders(b) != "host;x-amz-date;x-amz-security-token" {
		t.Errorf("session token not signed: %q %q", b.Header.Get("X-Amz-Security-Token"), signedHeaders(b))
	}

	// S3 adds and signs the payload hash header; no other service does
	s := sign("GET", "https://b.s3.us-east-1.amazonaws.com/?policy", "", nil, vanillaKeys, "s3")
	const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if s.Header.Get("X-Amz-Content-Sha256") != empty || signedHeaders(s) != "host;x-amz-content-sha256;x-amz-date" {
		t.Errorf("s3 headers: %q %q", s.Header.Get("X-Amz-Content-Sha256"), signedHeaders(s))
	}
	if a.Header.Get("X-Amz-Content-Sha256") != "" {
		t.Error("a non-S3 request carries X-Amz-Content-Sha256")
	}
}

func TestCanonicalForms(t *testing.T) {
	// non-S3 encodes the path twice, S3 once
	if got := canonicalPath("/a b/c:d", false); got != "/a%2520b/c%253Ad" {
		t.Errorf("double-encoded path = %q", got)
	}
	if got := canonicalPath("/a b/c:d", true); got != "/a%20b/c%3Ad" {
		t.Errorf("single-encoded path = %q", got)
	}
	if got := canonicalPath("", false); got != "/" {
		t.Errorf("empty path = %q", got)
	}
	req, _ := http.NewRequest("GET", "https://h/?b=2&a=1&a=0&policy&q=x%20y", nil)
	if got := canonicalQuery(req); got != "a=0&a=1&b=2&policy=&q=x%20y" {
		t.Errorf("canonical query = %q", got)
	}
	if got := Encode("a/b c~d_e-f.g*"); got != "a%2Fb%20c~d_e-f.g%2A" {
		t.Errorf("Encode = %q", got)
	}
}

func TestSignRefusesBadInput(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	if err := Sign(req, nil, Credentials{AccessKeyID: "A"}, "us-east-1", "iam", vanillaTime); err == nil {
		t.Error("signed with no secret")
	}
	if err := Sign(req, nil, vanillaKeys, "", "iam", vanillaTime); err == nil {
		t.Error("signed with no region")
	}
}

func TestCredentialsNeverPrint(t *testing.T) {
	c := Credentials{AccessKeyID: "AKIA", SecretAccessKey: "supersecret", SessionToken: "tok"}
	for _, s := range []string{c.String(), c.GoString(), fmt.Sprintf("%v %+v %#v", c, c, c)} {
		if strings.Contains(s, "supersecret") || strings.Contains(s, "AKIA") || !strings.Contains(s, "REDACTED") {
			t.Errorf("credentials leaked: %q", s)
		}
	}
}
