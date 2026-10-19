package harness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
)

const (
	testAcct   = "111111111111"
	testUser   = "arn:aws:iam::111111111111:user/alice"
	testBucket = "arn:aws:s3:::tsr-bkt"
	testObject = "arn:aws:s3:::tsr-bkt/k"
	fixtureV   = "synthetic-1"
)

const allowGetObject = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`

func baseSpec(id string) *RequestSpec {
	return &RequestSpec{
		ID: id, Stratum: S2GrammarFuzz, FixtureVersion: fixtureV,
		PrincipalARN: testUser, Action: "s3:GetObject", Resource: testObject,
		Identity: []string{allowGetObject},
	}
}

// xmlMatch, xmlRes and xmlResult build the IAM query-protocol XML of a
// simulator response. They are test scaffolding for synthetic cassettes.
type xmlMatch struct {
	ID, Type string
	Line     int
}

type xmlRes struct {
	Name, Decision string
	Matched        []xmlMatch
	Missing        []string
}

type xmlResult struct {
	Action, Resource, Decision string
	Matched                    []xmlMatch
	Missing                    []string
	PerResource                []xmlRes
	OrgDenied, BoundaryDenied  bool
}

func matchedXML(ms []xmlMatch) string {
	var b strings.Builder
	b.WriteString("<MatchedStatements>")
	for _, m := range ms {
		fmt.Fprintf(&b, "<member><SourcePolicyId>%s</SourcePolicyId><SourcePolicyType>%s</SourcePolicyType><StartPosition><Line>%d</Line><Column>1</Column></StartPosition><EndPosition><Line>%d</Line><Column>2</Column></EndPosition></member>", m.ID, m.Type, m.Line, m.Line)
	}
	b.WriteString("</MatchedStatements>")
	return b.String()
}

func missingXML(vs []string) string {
	var b strings.Builder
	b.WriteString("<MissingContextValues>")
	for _, v := range vs {
		fmt.Fprintf(&b, "<member>%s</member>", v)
	}
	b.WriteString("</MissingContextValues>")
	return b.String()
}

// evalXML renders a SimulateCustomPolicy (or SimulatePrincipalPolicy) response.
func evalXML(op string, results []xmlResult, truncated bool, marker string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<%sResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><%sResult><EvaluationResults>`, op, op)
	for _, r := range results {
		fmt.Fprintf(&b, "<member><EvalActionName>%s</EvalActionName><EvalResourceName>%s</EvalResourceName><EvalDecision>%s</EvalDecision>", r.Action, r.Resource, r.Decision)
		b.WriteString(matchedXML(r.Matched))
		b.WriteString(missingXML(r.Missing))
		if r.OrgDenied {
			b.WriteString("<OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>")
		}
		if r.BoundaryDenied {
			b.WriteString("<PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>false</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail>")
		}
		if len(r.PerResource) > 0 {
			b.WriteString("<ResourceSpecificResults>")
			for _, p := range r.PerResource {
				fmt.Fprintf(&b, "<member><EvalResourceName>%s</EvalResourceName><EvalResourceDecision>%s</EvalResourceDecision>", p.Name, p.Decision)
				b.WriteString(matchedXML(p.Matched))
				b.WriteString(missingXML(p.Missing))
				b.WriteString("</member>")
			}
			b.WriteString("</ResourceSpecificResults>")
		}
		b.WriteString("</member>")
	}
	fmt.Fprintf(&b, "</EvaluationResults><IsTruncated>%t</IsTruncated>", truncated)
	if marker != "" {
		fmt.Fprintf(&b, "<Marker>%s</Marker>", marker)
	}
	fmt.Fprintf(&b, `</%sResult><ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></%sResponse>`, op, op)
	return b.String()
}

func okResp(body string) awstest.Response {
	return awstest.Response{Status: 200, Headers: map[string]string{"Content-Type": "text/xml"}, Body: body}
}

func throttleResp(retryAfter string) awstest.Response {
	h := map[string]string{"Content-Type": "text/xml"}
	if retryAfter != "" {
		h["Retry-After"] = retryAfter
	}
	return awstest.Response{Status: 400, Headers: h, Body: `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ErrorResponse>`}
}

// scripted is an inner HTTP client that answers requests from a queue, whatever
// they are: the stand-in for AWS when authoring a synthetic cassette.
type scripted struct{ queue []awstest.Response }

func (s *scripted) Do(req *http.Request) (*http.Response, error) {
	if len(s.queue) == 0 {
		return nil, fmt.Errorf("scripted: no response queued for %s", req.URL)
	}
	r := s.queue[0]
	s.queue = s.queue[1:]
	h := http.Header{}
	for k, v := range r.Headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: r.Status, Header: h, Body: io.NopCloser(bytes.NewReader([]byte(r.Body))), Request: req}, nil
}

// nopRetry keeps the SDK from retrying, so the harness's own Backoff is what
// the tests observe.
func nopRetry() aws.Retryer { return aws.NopRetryer{} }

// recordCassette runs the oracle once against a scripted AWS in record mode and
// returns the cassette it wrote, so the keys are exactly the SDK's requests.
func recordCassette(t testing.TB, s *RequestSpec, kind OracleKind, responses ...awstest.Response) *awstest.Cassette {
	t.Helper()
	rec, err := awstest.NewRecorder(&scripted{queue: responses}, s.FixtureVersion)
	if err != nil {
		t.Fatal(err)
	}
	client := NewIAMClient(rec, "us-east-1", nopRetry)
	bo := Backoff{Base: 1, MaxAttempts: 5}
	var o Oracle = &SimCustom{Client: client, Backoff: bo}
	if kind == OracleSimPrincipal {
		o = &SimPrincipal{Client: client, Backoff: bo}
	}
	if _, err := o.Ask(context.Background(), s); err != nil {
		t.Fatalf("recording %s: %v", s.ID, err)
	}
	return rec.Cassette()
}

// replayOracle returns the oracle of kind reading the cassette.
func replayOracle(c *awstest.Cassette, kind OracleKind, bo Backoff) Oracle {
	client := NewIAMClient(awstest.NewReplay(c), "us-east-1", nopRetry)
	if kind == OracleSimPrincipal {
		return &SimPrincipal{Client: client, Backoff: bo}
	}
	return &SimCustom{Client: client, Backoff: bo}
}

// sleepLog records the delays a Backoff asked for, without waiting.
type sleepLog struct{ d []time.Duration }

func (s *sleepLog) sleep(_ context.Context, d time.Duration) error {
	s.d = append(s.d, d)
	return nil
}
