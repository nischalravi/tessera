package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SQS and SNS over HTTPS with SigV4. SQS uses its JSON protocol
// (X-Amz-Target: AmazonSQS.SendMessage) and SNS its query protocol
// (Action=Publish). The client is the safehttp one, so the endpoint is checked
// like any other outbound URL. A FIFO queue or topic (name ending in .fifo)
// gets the group id as MessageGroupId, which orders messages per group, and the
// CloudEvents id as the deduplication id, which makes a redelivery harmless.

type awsPublisher struct {
	http     *http.Client
	keys     awsKeys
	kind     string
	region   string
	endpoint string // full URL requests are posted to
	target   string // queue URL or topic ARN
	fifo     bool
	now      func() time.Time
}

func newAWS(c *http.Client, s Spec, now func() time.Time) (Publisher, error) {
	if c == nil {
		return nil, errors.New("sinks: no HTTP client for AWS")
	}
	if now == nil {
		now = time.Now
	}
	p := &awsPublisher{http: c, kind: s.Kind, region: s.Config.Region, now: now,
		keys: awsKeys{AccessKeyID: s.Creds.AccessKeyID, SecretAccessKey: s.Creds.SecretAccessKey, SessionToken: s.Creds.SessionToken}}
	service := s.Kind // "sqs" and "sns" are also the signing service names
	p.endpoint = s.Config.Endpoint
	if p.endpoint == "" {
		suffix := ".amazonaws.com"
		if strings.HasPrefix(p.region, "cn-") {
			suffix += ".cn"
		}
		p.endpoint = "https://" + service + "." + p.region + suffix + "/"
	}
	if s.Kind == KindSQS {
		p.target = s.Config.QueueURL
	} else {
		p.target = s.Config.TopicARN
	}
	p.fifo = strings.HasSuffix(p.target, ".fifo")
	return p, nil
}

func (p *awsPublisher) Close() error { return nil }

type sqsAttr struct {
	DataType    string
	StringValue string
}

func (p *awsPublisher) Publish(ctx context.Context, m Message) error {
	var body []byte
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, nil)
	if err != nil {
		return err
	}
	switch p.kind {
	case KindSQS:
		in := map[string]any{"QueueUrl": p.target, "MessageBody": string(m.Body),
			"MessageAttributes": map[string]sqsAttr{"type": {DataType: "String", StringValue: m.Type}}}
		if p.fifo {
			in["MessageGroupId"], in["MessageDeduplicationId"] = m.Key, m.ID
		}
		if body, err = json.Marshal(in); err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", "AmazonSQS.SendMessage")
	default:
		f := url.Values{"Action": {"Publish"}, "Version": {"2010-03-31"}, "TopicArn": {p.target}, "Message": {string(m.Body)},
			"MessageAttributes.entry.1.Name": {"type"}, "MessageAttributes.entry.1.Value.DataType": {"String"},
			"MessageAttributes.entry.1.Value.StringValue": {m.Type}}
		if p.fifo {
			f.Set("MessageGroupId", m.Key)
			f.Set("MessageDeduplicationId", m.ID)
		}
		body = []byte(f.Encode())
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	signV4(req, body, p.keys, p.region, p.kind, p.now())

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("aws %s: %w", p.kind, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("aws %s: HTTP %d: %s", p.kind, resp.StatusCode, oneLine(out, 200))
	}
	return nil
}

// oneLine shortens a broker's error body for a log line or a health field.
func oneLine(b []byte, n int) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
