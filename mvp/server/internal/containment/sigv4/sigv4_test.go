package sigv4

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type suite struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
	Service         string `json:"service"`
	Time            string `json:"time"`
	Cases           []struct {
		Name             string            `json:"name"`
		Method           string            `json:"method"`
		Path             string            `json:"path"`
		Query            string            `json:"query"`
		Headers          map[string]string `json:"headers"`
		Body             string            `json:"body"`
		CanonicalRequest string            `json:"canonical_request"`
		StringToSign     string            `json:"string_to_sign"`
		Authorization    string            `json:"authorization"`
	} `json:"cases"`
}

// TestAWSSuite signs the requests of AWS's published SigV4 test suite and
// compares the canonical request, the string to sign and the signature.
func TestAWSSuite(t *testing.T) {
	raw, err := os.ReadFile("testdata/suite.json")
	if err != nil {
		t.Fatal(err)
	}
	var s suite
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, s.Time)
	if err != nil {
		t.Fatal(err)
	}
	creds := Credentials{AccessKeyID: s.AccessKeyID, SecretAccessKey: s.SecretAccessKey}
	for _, c := range s.Cases {
		t.Run(c.Name, func(t *testing.T) {
			u := "https://example.amazonaws.com" + c.Path
			if c.Query != "" {
				u += "?" + c.Query
			}
			req, err := http.NewRequest(c.Method, u, strings.NewReader(c.Body))
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range c.Headers {
				req.Header.Set(k, v)
			}
			if err := Sign(req, []byte(c.Body), creds, s.Region, s.Service, at); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Authorization"); got != c.Authorization {
				t.Errorf("authorization\n got %s\nwant %s", got, c.Authorization)
			}
			// the canonical request is computed from the request as signed
			if c.CanonicalRequest != "" {
				got, _ := CanonicalRequest(req, []byte(c.Body))
				if got != c.CanonicalRequest {
					t.Errorf("canonical request\n got %q\nwant %q", got, c.CanonicalRequest)
				}
			}
			if c.StringToSign != "" {
				creq, _ := CanonicalRequest(req, []byte(c.Body))
				if got := StringToSign("20150830T123600Z", "20150830/us-east-1/service/aws4_request", creq); got != c.StringToSign {
					t.Errorf("string to sign\n got %q\nwant %q", got, c.StringToSign)
				}
			}
		})
	}
}

func TestSessionTokenIsSignedAndSent(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://organizations.us-east-1.amazonaws.com/", strings.NewReader("{}"))
	req.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.DescribePolicy")
	err := Sign(req, []byte("{}"), Credentials{AccessKeyID: "AKID", SecretAccessKey: "s", SessionToken: "tok"},
		"us-east-1", "organizations", time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	a := req.Header.Get("Authorization")
	if req.Header.Get("X-Amz-Security-Token") != "tok" || !strings.Contains(a, "SignedHeaders=host;x-amz-date;x-amz-security-token;x-amz-target,") ||
		!strings.Contains(a, "Credential=AKID/20261008/us-east-1/organizations/aws4_request") {
		t.Errorf("authorization %s", a)
	}
	if strings.Contains(a, "tok") && strings.Contains(a, "Signature=tok") {
		t.Error("token leaked into the signature header")
	}
}

func TestCanonicalForm(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com:443/a%20b/?q=a+b&z=&a=%7E", nil)
	req.Header.Set("My-Header", "  a   b  c ")
	req.Header.Add("My-Header", "d")
	req.Header.Set("User-Agent", "unsigned")
	creq, signed := CanonicalRequest(req, nil)
	want := "GET\n/a%2520b/\na=~&q=a%20b&z=\nhost:example.amazonaws.com\nmy-header:a b c,d\n\nhost;my-header\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if creq != want || signed != "host;my-header" {
		t.Errorf("canonical request %q (signed %s)", creq, signed)
	}
}

func TestSignRefusesMissingInput(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	now := time.Now()
	if Sign(req, nil, Credentials{}, "us-east-1", "svc", now) == nil {
		t.Error("no credentials accepted")
	}
	if Sign(req, nil, Credentials{AccessKeyID: "a", SecretAccessKey: "b"}, "", "svc", now) == nil {
		t.Error("no region accepted")
	}
}
