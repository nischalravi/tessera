package awsorg

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func sessionOver(t *testing.T, r *awstest.Replay, sleeps *[]time.Duration) session {
	t.Helper()
	r.Verify(baseKeyID, baseSecret)
	return session{cl: testClient(r, sleeps), creds: baseCreds()}
}

const (
	throttleXML = `<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>r</RequestId></ErrorResponse>`
	okRoots     = `{"Roots":[{"Id":"r-ab12","Name":"Root"}]}`
)

func TestClient_ThrottlingBacksOff(t *testing.T) {
	r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots",
		awstest.Response{Status: 400, Body: `{"__type":"com.amazonaws.organizations#TooManyRequestsException","message":"slow down"}`},
		awstest.Response{Status: 429, Body: `{"message":"Too Many Requests"}`},
		awstest.Response{Status: 503, Body: ``},
		awstest.Response{Body: okRoots})
	var sleeps []time.Duration
	s := sessionOver(t, r, &sleeps)
	roots, err := s.listRoots(context.Background())
	if err != nil || len(roots) != 1 || roots[0].ID != "r-ab12" {
		t.Fatalf("listRoots = %v, %v", roots, err)
	}
	if n := r.Calls("organizations/ListRoots"); n != 4 {
		t.Errorf("%d attempts, want 4", n)
	}
	// full jitter at its maximum (the test's Jitter): 200 ms, 400 ms, 800 ms
	if want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond}; !slices.Equal(sleeps, want) {
		t.Errorf("waits = %v, want %v", sleeps, want)
	}
	if b := r.BadSignatures(); len(b) != 0 {
		t.Errorf("a retry was signed wrongly: %v", b)
	}
}

func TestClient_QueryProtocolThrottling(t *testing.T) {
	r := awstest.NewReplay(nil).Enqueue("iam/GetAccountAuthorizationDetails",
		awstest.Response{Status: 400, Body: throttleXML},
		awstest.Response{Body: `<GetAccountAuthorizationDetailsResponse><GetAccountAuthorizationDetailsResult><IsTruncated>false</IsTruncated></GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>`})
	var sleeps []time.Duration
	d, err := sessionOver(t, r, &sleeps).getAccountAuthorizationDetails(context.Background())
	if err != nil || len(d.Users) != 0 || len(sleeps) != 1 {
		t.Fatalf("details = %+v, %v, waits %v", d, err, sleeps)
	}
}

func TestClient_RetryAfterIsHonoured(t *testing.T) {
	r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots",
		awstest.Response{Status: 429, Body: `{}`, Header: http.Header{"Retry-After": {"7"}}},
		awstest.Response{Status: 429, Body: `{}`, Header: http.Header{"Retry-After": {"3600"}}},
		awstest.Response{Body: okRoots})
	var sleeps []time.Duration
	if _, err := sessionOver(t, r, &sleeps).listRoots(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 7 s beats the 200 ms backoff; an hour is capped at 30 s
	if want := []time.Duration{7 * time.Second, 30 * time.Second}; !slices.Equal(sleeps, want) {
		t.Errorf("waits = %v, want %v", sleeps, want)
	}
}

func TestClient_BackoffIsCapped(t *testing.T) {
	c := &Client{BaseDelay: time.Second, MaxDelay: 5 * time.Second, Jitter: func(max time.Duration) time.Duration { return max }}
	var got []time.Duration
	for n := 1; n <= 6; n++ {
		got = append(got, c.backoff(n, nil))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second}
	if !slices.Equal(got, want) {
		t.Errorf("backoff = %v, want %v", got, want)
	}
	// the default jitter stays within [0, max]
	d := &Client{}
	for range 50 {
		if j := d.backoff(3, nil); j < 0 || j > 800*time.Millisecond {
			t.Fatalf("jitter %v outside [0, 800ms]", j)
		}
	}
}

func TestClient_GivesUp(t *testing.T) {
	var q []awstest.Response
	for range 10 {
		q = append(q, awstest.Response{Status: 400, Body: throttleXML})
	}
	r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots", q...)
	s := sessionOver(t, r, nil)
	s.cl.MaxAttempts = 3
	_, err := s.listRoots(context.Background())
	if err == nil || !strings.Contains(err.Error(), "gave up after 3 attempts") || !IsCode(err, "Throttling") {
		t.Errorf("err = %v", err)
	}
	if n := r.Calls("organizations/ListRoots"); n != 3 {
		t.Errorf("%d attempts, want 3", n)
	}
}

func TestClient_DoesNotRetryDefinitiveErrors(t *testing.T) {
	for name, resp := range map[string]awstest.Response{
		"access denied": {Status: 400, Body: `{"__type":"AccessDeniedException","message":"no"}`},
		"not found":     {Status: 404, Body: `<Error><Code>NoSuchBucket</Code><Message>x</Message></Error>`},
		"bad request":   {Status: 400, Body: `{"__type":"ValidationException","message":"x"}`},
		"forbidden":     {Status: 403, Body: ``},
		"signature":     {Status: 403, Body: `<Error><Code>SignatureDoesNotMatch</Code><Message>x</Message></Error>`},
	} {
		t.Run(name, func(t *testing.T) {
			r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots", resp, awstest.Response{Body: okRoots})
			_, err := sessionOver(t, r, nil).listRoots(context.Background())
			if err == nil || r.Calls("organizations/ListRoots") != 1 {
				t.Errorf("err = %v after %d calls, want one call and an error", err, r.Calls("organizations/ListRoots"))
			}
			var ae *Error
			if !errors.As(err, &ae) || ae.Status != resp.Status || ae.Op != "ListRoots" || ae.Service != "organizations" {
				t.Errorf("err = %#v", err)
			}
		})
	}
}

func TestClient_ErrorParsing(t *testing.T) {
	for _, c := range []struct {
		name, body string
		hdr        http.Header
		code, msg  string
	}{
		{"json type with namespace", `{"__type":"com.amazonaws.kms#NotFoundException","message":"key gone"}`, nil, "NotFoundException", "key gone"},
		{"json type with url", `{"__type":"AccessDeniedException:http://internal.amazon.com/coral/","Message":"denied"}`, nil, "AccessDeniedException", "denied"},
		{"json header", `{"message":"nope"}`, http.Header{"X-Amzn-Errortype": {"ResourceNotFoundException:"}}, "ResourceNotFoundException", "nope"},
		{"query xml", `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>no such user</Message></Error></ErrorResponse>`, nil, "NoSuchEntity", "no such user"},
		{"rest xml", `<Error><Code>NoSuchBucketPolicy</Code><Message>none</Message></Error>`, nil, "NoSuchBucketPolicy", "none"},
		{"empty", ``, nil, "HTTP418", ""},
		{"html", `<html>proxy error</html>`, nil, "HTTP418", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := parseError(call{Service: "x", Op: "Y"}, &http.Response{StatusCode: 418, Header: c.hdr}, []byte(c.body))
			if c.hdr == nil {
				e = parseError(call{Service: "x", Op: "Y"}, &http.Response{StatusCode: 418, Header: http.Header{}}, []byte(c.body))
			}
			if e.Code != c.code || e.Message != c.msg {
				t.Errorf("code %q message %q, want %q %q", e.Code, e.Message, c.code, c.msg)
			}
		})
	}
	long := parseError(call{}, &http.Response{StatusCode: 400, Header: http.Header{}}, []byte(`{"__type":"E","message":"`+strings.Repeat("x", 5000)+`"}`))
	if len(long.Message) > 400 {
		t.Errorf("an error message of %d bytes is kept whole", len(long.Message))
	}
}

// flaky is a Doer that fails the first n requests at the transport level.
type flaky struct {
	next  Doer
	fails int
	err   error
	calls int
}

func (f *flaky) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if f.calls <= f.fails {
		return nil, f.err
	}
	return f.next.Do(req)
}

func TestClient_TransportErrors(t *testing.T) {
	t.Run("retried", func(t *testing.T) {
		r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots", awstest.Response{Body: okRoots})
		f := &flaky{next: r, fails: 2, err: errors.New("connection reset by peer")}
		s := session{cl: testClient(f, nil), creds: baseCreds()}
		if roots, err := s.listRoots(context.Background()); err != nil || len(roots) != 1 || f.calls != 3 {
			t.Errorf("roots %v, err %v, %d calls", roots, err, f.calls)
		}
	})
	t.Run("a refusal of the SSRF guard is final", func(t *testing.T) {
		for _, refusal := range []error{safehttp.ErrBlockedAddress, safehttp.ErrURL, safehttp.ErrRedirect, safehttp.ErrTooLarge} {
			f := &flaky{fails: 100, err: fmt.Errorf("Post: %w", refusal)}
			s := session{cl: testClient(f, nil), creds: baseCreds()}
			if _, err := s.listRoots(context.Background()); !errors.Is(err, refusal) || f.calls != 1 {
				t.Errorf("%v: err %v after %d calls", refusal, err, f.calls)
			}
		}
	})
	t.Run("a cancelled context stops the retries", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		f := &flaky{fails: 100, err: errors.New("timeout")}
		s := session{cl: testClient(f, nil), creds: baseCreds()}
		s.cl.Sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
		if _, err := s.listRoots(ctx); !errors.Is(err, context.Canceled) || f.calls != 1 {
			t.Errorf("err %v after %d calls", err, f.calls)
		}
	})
	t.Run("unsigned requests are never sent", func(t *testing.T) {
		f := &flaky{fails: 0}
		s := session{cl: testClient(f, nil), creds: sigv4.Credentials{AccessKeyID: "AKIA"}}
		if _, err := s.listRoots(context.Background()); !errors.Is(err, errSigning) || f.calls != 0 {
			t.Errorf("err %v after %d calls", err, f.calls)
		}
	})
}

func TestClient_RefusesBadRegionAndHost(t *testing.T) {
	r := awstest.NewReplay(nil)
	s := sessionOver(t, r, nil)
	for _, region := range []string{"", "us-east-1.evil.example", "US-EAST-1", "us-east-1/../x", "x", "us-east-1@evil.example"} {
		if _, err := s.listKeys(context.Background(), region); err == nil {
			t.Errorf("region %q accepted", region)
		}
	}
	for _, bucket := range []string{"", "a", "UPPER", "evil.com/x", "a b", "-lead", "trail-", "x@y", strings.Repeat("a", 64)} {
		if _, _, err := bucketRequest(bucket, "us-east-1"); err == nil {
			t.Errorf("bucket %q accepted", bucket)
		}
	}
	for _, name := range []string{"", "a/b", "..", "x y", "a%2Fb", strings.Repeat("a", 65)} {
		if _, err := s.functionPolicy(context.Background(), "us-east-1", name); err == nil {
			t.Errorf("function %q accepted", name)
		}
	}
	for _, name := range []string{"", "Upper", "a/b", "ab", "x y", strings.Repeat("a", 51)} {
		if validAccessPointName(name) {
			t.Errorf("access point %q accepted", name)
		}
	}
	if _, err := s.getAccountPublicAccessBlock(context.Background(), "12345", "us-east-1"); err == nil {
		t.Error("a short account id accepted")
	}
	if len(r.Requests()) != 0 {
		t.Errorf("%d requests were sent for refused input", len(r.Requests()))
	}
}

// TestPagination: every List*/Describe* call follows its token to the last page.
func TestPagination(t *testing.T) {
	type tc struct {
		name, op     string
		page1, page2 string
		token        func(awstest.Request) string // the token the second request carries
		want         string
		run          func(context.Context, session) (string, error)
	}
	form := func(k string) func(awstest.Request) string {
		return func(q awstest.Request) string { return q.Form.Get(k) }
	}
	query := func(k string) func(awstest.Request) string {
		return func(q awstest.Request) string { return q.Query.Get(k) }
	}
	jsonHas := func(k string) func(awstest.Request) string {
		return func(q awstest.Request) string {
			i := strings.Index(q.JSON, `"`+k+`":"`)
			if i < 0 {
				return ""
			}
			rest := q.JSON[i+len(k)+4:]
			return rest[:strings.Index(rest, `"`)]
		}
	}
	join := func(v []string) string { return strings.Join(v, ",") }
	ids := func(refs []orgNodeRef) string {
		var s []string
		for _, r := range refs {
			s = append(s, r.ID)
		}
		return join(s)
	}
	cases := []tc{
		{"organizations ListRoots", "organizations/ListRoots", `{"Roots":[{"Id":"a"}],"NextToken":"t1"}`, `{"Roots":[{"Id":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) { r, err := s.listRoots(ctx); return ids(r), err }},
		{"organizations ListOrganizationalUnitsForParent", "organizations/ListOrganizationalUnitsForParent", `{"OrganizationalUnits":[{"Id":"a"}],"NextToken":"t1"}`, `{"OrganizationalUnits":[{"Id":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listOUs(ctx, "r-1")
				return ids(r), err
			}},
		{"organizations ListAccountsForParent", "organizations/ListAccountsForParent", `{"Accounts":[{"Id":"a"}],"NextToken":"t1"}`, `{"Accounts":[{"Id":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listAccounts(ctx, "r-1")
				return ids(r), err
			}},
		{"organizations ListPolicies", "organizations/ListPolicies", `{"Policies":[{"Id":"a"}],"NextToken":"t1"}`, `{"Policies":[{"Id":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listPolicies(ctx, policyTypeSCP)
				var o []string
				for _, p := range r {
					o = append(o, p.ID)
				}
				return join(o), err
			}},
		{"organizations ListTargetsForPolicy", "organizations/ListTargetsForPolicy", `{"Targets":[{"TargetId":"a"}],"NextToken":"t1"}`, `{"Targets":[{"TargetId":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listTargetsForPolicy(ctx, "p-1")
				return join(r), err
			}},
		{"s3 ListAllMyBuckets", "s3/ListAllMyBuckets", `<ListAllMyBucketsResult><Buckets><Bucket><Name>a</Name></Bucket></Buckets><ContinuationToken>t1</ContinuationToken></ListAllMyBucketsResult>`,
			`<ListAllMyBucketsResult><Buckets><Bucket><Name>b</Name></Bucket></Buckets></ListAllMyBucketsResult>`, query("continuation-token"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, _, err := s.listBuckets(ctx, "us-east-1")
				var o []string
				for _, b := range r {
					o = append(o, b.Name)
				}
				return join(o), err
			}},
		{"s3control ListAccessPoints", "s3/ListAccessPoints", `<ListAccessPointsResult><AccessPointList><AccessPoint><Name>a</Name></AccessPoint></AccessPointList><NextToken>t1</NextToken></ListAccessPointsResult>`,
			`<ListAccessPointsResult><AccessPointList><AccessPoint><Name>b</Name></AccessPoint></AccessPointList></ListAccessPointsResult>`, query("nextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listAccessPoints(ctx, "111111111111", "us-east-1")
				var o []string
				for _, a := range r {
					o = append(o, a.Name)
				}
				return join(o), err
			}},
		{"kms ListKeys", "kms/ListKeys", `{"Keys":[{"KeyId":"a"}],"NextMarker":"t1","Truncated":true}`, `{"Keys":[{"KeyId":"b"}],"Truncated":false}`, jsonHas("Marker"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listKeys(ctx, "us-east-1")
				var o []string
				for _, k := range r {
					o = append(o, k.ID)
				}
				return join(o), err
			}},
		{"kms ListGrants", "kms/ListGrants", `{"Grants":[{"GrantId":"a"}],"NextMarker":"t1","Truncated":true}`, `{"Grants":[{"GrantId":"b"}],"Truncated":false}`, jsonHas("Marker"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listGrants(ctx, "us-east-1", "k")
				var o []string
				for _, g := range r {
					o = append(o, g.GrantID)
				}
				return join(o), err
			}},
		{"sqs ListQueues", "sqs/ListQueues", `{"QueueUrls":["a"],"NextToken":"t1"}`, `{"QueueUrls":["b"]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listQueueURLs(ctx, "us-east-1")
				return join(r), err
			}},
		{"sns ListTopics", "sns/ListTopics", `<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>a</TopicArn></member></Topics><NextToken>t1</NextToken></ListTopicsResult></ListTopicsResponse>`,
			`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>b</TopicArn></member></Topics></ListTopicsResult></ListTopicsResponse>`, form("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listTopics(ctx, "us-east-1")
				return join(r), err
			}},
		{"secretsmanager ListSecrets", "secretsmanager/ListSecrets", `{"SecretList":[{"ARN":"a"}],"NextToken":"t1"}`, `{"SecretList":[{"ARN":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listSecretARNs(ctx, "us-east-1")
				return join(r), err
			}},
		{"lambda ListFunctions", "lambda/ListFunctions", `{"Functions":[{"FunctionName":"a"}],"NextMarker":"t1"}`, `{"Functions":[{"FunctionName":"b"}]}`, query("Marker"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listFunctions(ctx, "us-east-1")
				var o []string
				for _, f := range r {
					o = append(o, f.Name)
				}
				return join(o), err
			}},
		{"ecr DescribeRepositories", "ecr/DescribeRepositories", `{"repositories":[{"repositoryName":"a"}],"nextToken":"t1"}`, `{"repositories":[{"repositoryName":"b"}]}`, jsonHas("nextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listRepositories(ctx, "us-east-1")
				var o []string
				for _, x := range r {
					o = append(o, x.Name)
				}
				return join(o), err
			}},
		{"ec2 DescribeVpcEndpoints", "ec2/DescribeVpcEndpoints", `<R><vpcEndpointSet><item><vpcEndpointId>a</vpcEndpointId></item></vpcEndpointSet><nextToken>t1</nextToken></R>`,
			`<R><vpcEndpointSet><item><vpcEndpointId>b</vpcEndpointId></item></vpcEndpointSet></R>`, form("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.describeVPCEndpoints(ctx, "us-east-1")
				var o []string
				for _, e := range r {
					o = append(o, e.ID)
				}
				return join(o), err
			}},
		{"sso ListInstances", "sso/ListInstances", `{"Instances":[{"InstanceArn":"a"}],"NextToken":"t1"}`, `{"Instances":[{"InstanceArn":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listSSOInstances(ctx, "us-east-1")
				var o []string
				for _, i := range r {
					o = append(o, i.ARN)
				}
				return join(o), err
			}},
		{"sso ListPermissionSets", "sso/ListPermissionSets", `{"PermissionSets":["a"],"NextToken":"t1"}`, `{"PermissionSets":["b"]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listPermissionSets(ctx, "us-east-1", "i")
				return join(r), err
			}},
		{"sso ListAccountAssignments", "sso/ListAccountAssignments", `{"AccountAssignments":[{"PrincipalId":"a"}],"NextToken":"t1"}`, `{"AccountAssignments":[{"PrincipalId":"b"}]}`, jsonHas("NextToken"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				r, err := s.listAccountAssignments(ctx, "us-east-1", "i", "ps", "111111111111")
				var o []string
				for _, a := range r {
					o = append(o, a.PrincipalID)
				}
				return join(o), err
			}},
		{"iam GetAccountAuthorizationDetails", "iam/GetAccountAuthorizationDetails",
			`<R><GetAccountAuthorizationDetailsResult><IsTruncated>true</IsTruncated><Marker>t1</Marker><UserDetailList><member><UserName>a</UserName></member></UserDetailList></GetAccountAuthorizationDetailsResult></R>`,
			`<R><GetAccountAuthorizationDetailsResult><IsTruncated>false</IsTruncated><UserDetailList><member><UserName>b</UserName></member></UserDetailList></GetAccountAuthorizationDetailsResult></R>`, form("Marker"), "a,b",
			func(ctx context.Context, s session) (string, error) {
				d, err := s.getAccountAuthorizationDetails(ctx)
				var o []string
				for _, u := range d.Users {
					o = append(o, u.UserName)
				}
				return join(o), err
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := awstest.NewReplay(nil).Enqueue(c.op, awstest.Response{Body: c.page1}, awstest.Response{Body: c.page2})
			got, err := c.run(context.Background(), sessionOver(t, r, nil))
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q (both pages)", got, err, c.want)
			}
			reqs := r.Requests()
			if len(reqs) != 2 {
				t.Fatalf("%d requests, want 2", len(reqs))
			}
			if tok := c.token(reqs[0]); tok != "" {
				t.Errorf("the first request carries the token %q", tok)
			}
			if tok := c.token(reqs[1]); tok != "t1" {
				t.Errorf("the second request carries the token %q, want t1", tok)
			}
		})
	}

	t.Run("a repeated token is an error, not a loop", func(t *testing.T) {
		page := awstest.Response{Body: `{"Roots":[{"Id":"a"}],"NextToken":"same"}`}
		r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots", page, page, page, page)
		if _, err := sessionOver(t, r, nil).listRoots(context.Background()); err == nil || !strings.Contains(err.Error(), "token repeated") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a truncated IAM page with no marker is an error", func(t *testing.T) {
		r := awstest.NewReplay(nil).Enqueue("iam/GetAccountAuthorizationDetails",
			awstest.Response{Body: `<R><GetAccountAuthorizationDetailsResult><IsTruncated>true</IsTruncated></GetAccountAuthorizationDetailsResult></R>`})
		if _, err := sessionOver(t, r, nil).getAccountAuthorizationDetails(context.Background()); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("a page failure after the first page fails the call", func(t *testing.T) {
		r := awstest.NewReplay(nil).Enqueue("organizations/ListRoots", awstest.Response{Body: `{"Roots":[{"Id":"a"}],"NextToken":"t1"}`},
			awstest.Response{Status: 400, Body: `{"__type":"AccessDeniedException","message":"no"}`})
		if _, err := sessionOver(t, r, nil).listRoots(context.Background()); !IsAccessDenied(err) {
			t.Errorf("err = %v; a half-read list must not look complete", err)
		}
	})
}
