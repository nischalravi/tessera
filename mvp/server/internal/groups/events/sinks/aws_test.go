package sinks

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// TestSigV4_AWSVector checks the signer against the AWS Signature Version 4
// test suite's "get-vanilla" case.
func TestSigV4_AWSVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	signV4(req, nil, awsKeys{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		"us-east-1", "service", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization = %q\nwant            %q", got, want)
	}
}

func TestSigV4_SessionTokenAndBodyAreSigned(t *testing.T) {
	sign := func(token string, body string) string {
		req, _ := http.NewRequest(http.MethodPost, "https://sqs.eu-west-1.amazonaws.com/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		signV4(req, []byte(body), awsKeys{AccessKeyID: "AK", SecretAccessKey: "sk", SessionToken: token}, "eu-west-1", "sqs",
			time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
		if token != "" && req.Header.Get("X-Amz-Security-Token") != token {
			t.Error("the session token is not sent")
		}
		return req.Header.Get("Authorization")
	}
	base := sign("", "{}")
	if sign("", "{ }") == base {
		t.Error("the signature does not cover the body")
	}
	with := sign("tok", "{}")
	if with == base || !strings.Contains(with, "x-amz-security-token") {
		t.Errorf("the session token is not signed: %s", with)
	}
}

// awsFake is an in-process SQS and SNS endpoint on a TLS test server.
type awsFake struct {
	srv  *httptest.Server
	reqs []*http.Request
	body [][]byte
	code int
}

func newAWSFake(t *testing.T) *awsFake {
	t.Helper()
	f := &awsFake{code: 200}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.reqs, f.body = append(f.reqs, r), append(f.body, b)
		w.WriteHeader(f.code)
		_, _ = w.Write([]byte(`{"__type":"AWS.SimpleQueueService.NonExistentQueue"}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// client is a safehttp client that trusts the fake's certificate and, as in dev, may reach loopback.
func (f *awsFake) client(t *testing.T) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	c, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var fixedNow = func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }

func TestAWS_SQSPublish(t *testing.T) {
	f := newAWSFake(t)
	spec := Spec{Kind: KindSQS, Config: Config{Region: "eu-west-1", QueueURL: "https://sqs.eu-west-1.amazonaws.com/123456789012/groups.fifo",
		Endpoint: f.srv.URL + "/"}, Creds: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret", SessionToken: "tok"}}
	p, err := newAWS(f.client(t), spec, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), Message{ID: "t/5", Seq: 5, Type: "group.created", Key: "grp-1", Body: []byte(`{"id":"t/5"}`)}); err != nil {
		t.Fatal(err)
	}
	r := f.reqs[0]
	if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "AmazonSQS.SendMessage" ||
		r.Header.Get("Content-Type") != "application/x-amz-json-1.0" || r.Header.Get("X-Amz-Security-Token") != "tok" {
		t.Errorf("request = %s %v", r.Method, r.Header)
	}
	if a := r.Header.Get("Authorization"); !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261001/eu-west-1/sqs/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=") {
		t.Errorf("Authorization = %q", a)
	}
	var in map[string]any
	if err := json.Unmarshal(f.body[0], &in); err != nil {
		t.Fatal(err)
	}
	if in["MessageBody"] != `{"id":"t/5"}` || in["QueueUrl"] == "" || in["MessageGroupId"] != "grp-1" || in["MessageDeduplicationId"] != "t/5" {
		t.Errorf("body = %v", in)
	}
	if at := in["MessageAttributes"].(map[string]any)["type"].(map[string]any); at["StringValue"] != "group.created" {
		t.Errorf("attributes = %v", in["MessageAttributes"])
	}
	// the secret is never sent
	if strings.Contains(string(f.body[0]), "secret") || strings.Contains(r.Header.Get("Authorization"), "secret") {
		t.Error("the secret access key appears in the request")
	}

	// a standard queue has no message group, and a refusal is an error that names the status
	spec.Config.QueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/groups"
	p, _ = newAWS(f.client(t), spec, fixedNow)
	f.code = 400
	err = p.Publish(context.Background(), Message{ID: "t/6", Type: "group.created", Key: "g", Body: []byte(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "NonExistentQueue") {
		t.Errorf("a 400 = %v", err)
	}
	var in2 map[string]any
	_ = json.Unmarshal(f.body[1], &in2)
	if _, ok := in2["MessageGroupId"]; ok {
		t.Errorf("a standard queue got a message group: %v", in2)
	}
}

func TestAWS_SNSPublish(t *testing.T) {
	f := newAWSFake(t)
	arn := "arn:aws:sns:eu-west-1:123456789012:groups.fifo"
	spec := Spec{Kind: KindSNS, Config: Config{Region: "eu-west-1", TopicARN: arn, Endpoint: f.srv.URL + "/"},
		Creds: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret"}}
	p, err := newAWS(f.client(t), spec, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), Message{ID: "t/9", Type: "membership.direct.added", Key: "grp-2", Body: []byte(`{"a":"b"}`)}); err != nil {
		t.Fatal(err)
	}
	r := f.reqs[0]
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261001/eu-west-1/sns/aws4_request") ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		t.Errorf("request headers = %v", r.Header)
	}
	form, err := url.ParseQuery(string(f.body[0]))
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"Action": "Publish", "Version": "2010-03-31", "TopicArn": arn, "Message": `{"a":"b"}`,
		"MessageGroupId": "grp-2", "MessageDeduplicationId": "t/9", "MessageAttributes.entry.1.Name": "type",
		"MessageAttributes.entry.1.Value.StringValue": "membership.direct.added"} {
		if form.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, form.Get(k), want)
		}
	}
}

func TestAWS_DefaultEndpoints(t *testing.T) {
	c, err := safehttp.New(safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, region, want string
	}{
		{KindSQS, "eu-west-1", "https://sqs.eu-west-1.amazonaws.com/"},
		{KindSNS, "us-east-2", "https://sns.us-east-2.amazonaws.com/"},
		{KindSQS, "cn-north-1", "https://sqs.cn-north-1.amazonaws.com.cn/"},
	} {
		p, err := newAWS(c, Spec{Kind: tc.kind, Config: Config{Region: tc.region}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.(*awsPublisher).endpoint; got != tc.want {
			t.Errorf("%s %s endpoint = %q, want %q", tc.kind, tc.region, got, tc.want)
		}
	}
}
