package rotation

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The worked example of "Create a signed AWS API request" in the AWS
// documentation (a GET of IAM ListUsers), which fixes the signature.
func TestSignV4_AWSDocumentationExample(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	signV4(req, nil, awsCreds{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		"us-east-1", "iam", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization:\n got %s\nwant %s", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

func TestSignV4_SessionTokenAndTargetAreSigned(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://secretsmanager.eu-west-1.amazonaws.com/", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.DescribeSecret")
	signV4(req, []byte("{}"), awsCreds{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s", SessionToken: "tok"},
		"eu-west-1", "secretsmanager", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,") ||
		!strings.Contains(auth, "Credential=AKIAEXAMPLE/20260102/eu-west-1/secretsmanager/aws4_request") {
		t.Errorf("Authorization = %s", auth)
	}
	if req.Header.Get("X-Amz-Security-Token") != "tok" {
		t.Error("the session token header is missing")
	}
	if strings.Contains(auth, "tok") && !strings.Contains(auth, "x-amz-security-token") {
		t.Error("the session token leaked into Authorization")
	}
}

func TestAWSEscape(t *testing.T) {
	for in, want := range map[string]string{"a b": "a%20b", "A-z_0.9~": "A-z_0.9~", "x/y+z=": "x%2Fy%2Bz%3D", "é": "%C3%A9"} {
		if got := awsEscape(in); got != want {
			t.Errorf("awsEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
