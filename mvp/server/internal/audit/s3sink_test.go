package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// stubS3 is an AWS SDK for Go v2 S3 client stub: it records the puts and
// answers from fields.
type stubS3 struct {
	puts       []*s3.PutObjectInput
	bodies     []string
	putErr     error
	versionID  string
	head       *s3.HeadObjectOutput
	headErr    error
	headInputs []*s3.HeadObjectInput
}

func (s *stubS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b, _ := io.ReadAll(in.Body)
	s.puts, s.bodies = append(s.puts, in), append(s.bodies, string(b))
	if s.putErr != nil {
		return nil, s.putErr
	}
	return &s3.PutObjectOutput{VersionId: aws.String(s.versionID)}, nil
}

func (s *stubS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	s.headInputs = append(s.headInputs, in)
	return s.head, s.headErr
}

const testTID = "00000000-0000-4000-8000-00000000a0d1"

func testAnchor() audit.Anchor {
	return audit.Anchor{TID: testTID, Slug: "tenant-a", Seq: 42, HeadHash: "abc123", JWS: "eyJhbGciOiJFZERTQSJ9.e30.c2ln"}
}

func sum64(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(h[:])
}

// TestS3Sink_PutsLockedObject: one object per checkpoint at prefix/tid/seq.jws,
// COMPLIANCE mode, seven years from now, never replacing an existing object,
// checksummed, and the reference carries the version id.
func TestS3Sink_PutsLockedObject(t *testing.T) {
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	stub := &stubS3{versionID: "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY"}
	sink, err := audit.NewS3Sink("s3://tessera-audit/prod/anchors/", stub)
	if err != nil {
		t.Fatal(err)
	}
	sink.Now = func() time.Time { return now }
	a := testAnchor()
	ref, err := sink.Anchor(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if want := "s3://tessera-audit/prod/anchors/" + testTID + "/42.jws?versionId=3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY"; ref != want {
		t.Errorf("ref %q, want %q", ref, want)
	}
	if len(stub.puts) != 1 {
		t.Fatalf("%d puts", len(stub.puts))
	}
	in := stub.puts[0]
	checks := map[string]bool{
		"bucket":       aws.ToString(in.Bucket) == "tessera-audit",
		"key":          aws.ToString(in.Key) == "prod/anchors/"+testTID+"/42.jws",
		"body":         stub.bodies[0] == a.JWS,
		"compliance":   in.ObjectLockMode == s3types.ObjectLockModeCompliance,
		"retain 7y":    in.ObjectLockRetainUntilDate != nil && in.ObjectLockRetainUntilDate.Equal(time.Date(2033, 10, 8, 9, 30, 0, 0, time.UTC)),
		"no overwrite": aws.ToString(in.IfNoneMatch) == "*",
		"checksum":     aws.ToString(in.ChecksumSHA256) == sum64(a.JWS),
		"metadata":     in.Metadata["tid"] == testTID && in.Metadata["seq"] == "42" && in.Metadata["head-hash"] == "abc123",
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("put %s wrong: %+v", name, in)
		}
	}
}

// TestS3Sink_Errors: failures are errors (the checkpoint stays failed and is
// retried), a response without a version id is refused, and a repeated put of
// the same checkpoint is recognised by its checksum.
func TestS3Sink_Errors(t *testing.T) {
	precondition := &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold"}
	a := testAnchor()
	for _, tc := range []struct {
		name    string
		stub    *stubS3
		anchor  audit.Anchor
		wantRef string // suffix
		wantErr string
	}{
		{name: "put fails", stub: &stubS3{putErr: errors.New("connection reset")}, anchor: a, wantErr: "connection reset"},
		{name: "no version id (bucket not versioned)", stub: &stubS3{versionID: ""}, anchor: a, wantErr: "no version id"},
		{name: "already anchored, same content", anchor: a,
			stub:    &stubS3{putErr: precondition, head: &s3.HeadObjectOutput{ChecksumSHA256: aws.String(sum64(a.JWS)), VersionId: aws.String("v1")}},
			wantRef: "/42.jws?versionId=v1"},
		{name: "already anchored, different content", anchor: a,
			stub:    &stubS3{putErr: precondition, head: &s3.HeadObjectOutput{ChecksumSHA256: aws.String(sum64("other")), VersionId: aws.String("v1")}},
			wantErr: "different content"},
		{name: "already anchored, head fails", anchor: a,
			stub: &stubS3{putErr: precondition, headErr: errors.New("access denied")}, wantErr: "cannot be read"},
		{name: "bad tenant id", anchor: audit.Anchor{TID: "../../etc", Seq: 1, JWS: "x"}, stub: &stubS3{versionID: "v"}, wantErr: "cannot anchor"},
		{name: "bad seq", anchor: audit.Anchor{TID: testTID, Seq: 0, JWS: "x"}, stub: &stubS3{versionID: "v"}, wantErr: "cannot anchor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := audit.NewS3Sink("s3://bucket-name/p", tc.stub)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := sink.Anchor(context.Background(), tc.anchor)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err %v, want %q", err, tc.wantErr)
				}
			case err != nil:
				t.Errorf("err %v", err)
			case !strings.HasSuffix(ref, tc.wantRef):
				t.Errorf("ref %q, want suffix %q", ref, tc.wantRef)
			}
		})
	}
}

func TestParseS3URL(t *testing.T) {
	for _, tc := range []struct {
		in, bucket, prefix string
		bad                bool
	}{
		{in: "s3://bucket-name", bucket: "bucket-name"},
		{in: "s3://bucket-name/", bucket: "bucket-name"},
		{in: "s3://bucket-name/a/b/", bucket: "bucket-name", prefix: "a/b"},
		{in: "s3://my.bucket.name/x", bucket: "my.bucket.name", prefix: "x"},
		{in: "file:///x", bad: true},
		{in: "s3://", bad: true},
		{in: "s3://UPPER/x", bad: true},
		{in: "s3://ab/x", bad: true},
		{in: "s3://bucket-name/a/../b", bad: true},
		{in: "s3://bucket-name/a//b", bad: true},
		{in: "s3://bucket-name/a?versionId=1", bad: true},
		{in: "s3://user:pw@bucket-name/a", bad: true},
		{in: "s3://bucket-name/a%00b", bad: true},
	} {
		b, p, err := audit.ParseS3URL(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("%q accepted as %q %q", tc.in, b, p)
			}
			continue
		}
		if err != nil || b != tc.bucket || p != tc.prefix {
			t.Errorf("%q: %q %q %v", tc.in, b, p, err)
		}
	}
}

func TestNewSink_S3NeedsSafeHTTP(t *testing.T) {
	if _, err := audit.NewSink("s3://bucket-name/p"); err == nil || !strings.Contains(err.Error(), "safehttp") {
		t.Errorf("s3 without a client: %v", err)
	}
	s, err := audit.NewSink("s3://bucket-name/p", audit.WithS3Client(&stubS3{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*audit.S3Sink); !ok {
		t.Errorf("sink %T", s)
	}
	if _, err := audit.NewSink("s3://Bad_Bucket/p", audit.WithS3Client(&stubS3{})); err == nil {
		t.Error("invalid bucket accepted")
	}
}

// roundTripper answers every request with 200 and a version id, and records it.
type roundTripper struct {
	reqs []*http.Request
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.reqs = append(r.reqs, req)
	_, _ = io.Copy(io.Discard, req.Body)
	return &http.Response{StatusCode: 200, Header: http.Header{"X-Amz-Version-Id": {"ver-1"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// awsEnv gives the SDK static credentials and a region, and keeps it away from
// the developer's real AWS configuration and the metadata service.
func awsEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_REGION": "us-east-1",
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": "/nonexistent", "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent",
		"AWS_MAX_ATTEMPTS": "1", "AWS_ENDPOINT_URL": "", "AWS_ENDPOINT_URL_S3": "", "AWS_PROFILE": "", "AWS_CA_BUNDLE": "",
	} {
		t.Setenv(k, v)
	}
}

// TestS3Sink_RealSDKClientUsesGivenHTTPClient: the AWS SDK client built by
// NewS3Client sends a signed, Object-Lock PutObject through the http.Client it
// is given (the safehttp client in production), and reads the version id from
// the response.
func TestS3Sink_RealSDKClientUsesGivenHTTPClient(t *testing.T) {
	awsEnv(t)
	rt := &roundTripper{}
	sink, err := audit.NewSink("s3://bucket-name/p", audit.WithHTTPClient(&http.Client{Transport: rt}))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := sink.Anchor(context.Background(), testAnchor())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ref, "?versionId=ver-1") {
		t.Errorf("ref %q", ref)
	}
	if len(rt.reqs) != 1 {
		t.Fatalf("%d requests through the given client", len(rt.reqs))
	}
	r := rt.reqs[0]
	if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/"+testTID+"/42.jws") ||
		r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" || r.Header.Get("If-None-Match") != "*" ||
		r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		t.Errorf("request %s %s %v", r.Method, r.URL, r.Header)
	}
}

type fixedDNS map[string]string

func (f fixedDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ip, ok := f[host]
	if !ok {
		return nil, errors.New("no such host " + host)
	}
	return []netip.Addr{netip.MustParseAddr(ip)}, nil
}

// TestS3Sink_SafeHTTPBlocksInternalEndpoints: with the safehttp client behind
// the SDK, an S3 endpoint that resolves to an internal address (SSRF through a
// poisoned endpoint setting or DNS) is refused before any connection.
func TestS3Sink_SafeHTTPBlocksInternalEndpoints(t *testing.T) {
	awsEnv(t)
	t.Setenv("AWS_ENDPOINT_URL_S3", "https://s3.internal.example")
	hc, err := safehttp.New(safehttp.Options{Env: config.Prod, Resolver: fixedDNS{"s3.internal.example": "169.254.169.254", "bucket-name.s3.internal.example": "169.254.169.254"}})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := audit.NewSink("s3://bucket-name/p", audit.WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = sink.Anchor(ctx, testAnchor())
	if err == nil || !strings.Contains(err.Error(), "safehttp") {
		t.Errorf("internal endpoint reached or wrong error: %v", err)
	}
}
