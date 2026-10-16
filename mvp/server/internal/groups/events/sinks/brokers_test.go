package sinks

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// fakeAMQP is an in-process RabbitMQ session.
type fakeAMQP struct {
	sent   *[]amqpMessage
	to     *[]string
	fail   *error
	closed bool
}

func (f *fakeAMQP) Publish(_ context.Context, exchange string, m amqpMessage) error {
	if *f.fail != nil {
		return *f.fail
	}
	*f.sent, *f.to = append(*f.sent, m), append(*f.to, exchange)
	return nil
}
func (f *fakeAMQP) Close() error { f.closed = true; return nil }

func TestRabbitMQ_PublishRoutesAndReconnects(t *testing.T) {
	var (
		sent    []amqpMessage
		to      []string
		fail    error
		dials   int
		last    *fakeAMQP
		dialErr error
	)
	p := &rabbitPublisher{cfg: Config{Exchange: "tessera.groups"}, dial: func(context.Context) (amqpSession, error) {
		dials++
		if dialErr != nil {
			return nil, dialErr
		}
		last = &fakeAMQP{sent: &sent, to: &to, fail: &fail}
		return last, nil
	}}
	m := Message{ID: "t/1", Type: "group.created", Key: "g1", Body: []byte("{}")}
	if err := p.Publish(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	// the routing key defaults to the event type; the CloudEvents id travels as the message id
	if len(sent) != 1 || sent[0].Key != "group.created" || sent[0].MessageID != "t/1" || sent[0].ContentType != ContentType || to[0] != "tessera.groups" {
		t.Errorf("sent = %+v to %v", sent, to)
	}
	p.cfg.RoutingKey = "groups"
	_ = p.Publish(context.Background(), m)
	if sent[1].Key != "groups" || dials != 1 {
		t.Errorf("key = %q after %d dials", sent[1].Key, dials)
	}
	// a failed publish drops the connection; the next publish dials again
	fail = errors.New("channel closed")
	first := last
	if err := p.Publish(context.Background(), m); err == nil || !strings.Contains(err.Error(), "channel closed") {
		t.Errorf("failed publish = %v", err)
	}
	if !first.closed {
		t.Error("the broken session was not closed")
	}
	fail = nil
	if err := p.Publish(context.Background(), m); err != nil || dials != 2 {
		t.Errorf("after the failure: %v, %d dials", err, dials)
	}
	dialErr = errors.New("refused")
	_ = p.Close()
	if err := p.Publish(context.Background(), m); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("dial failure = %v", err)
	}
}

type fakeKafka struct {
	recs []struct {
		topic, key string
		headers    map[string]string
		value      []byte
	}
	err    error
	closed bool
}

func (f *fakeKafka) Produce(_ context.Context, topic, key string, headers map[string]string, value []byte) error {
	if f.err != nil {
		return f.err
	}
	f.recs = append(f.recs, struct {
		topic, key string
		headers    map[string]string
		value      []byte
	}{topic, key, headers, value})
	return nil
}
func (f *fakeKafka) Close() { f.closed = true }

func TestKafka_PublishKeysByGroup(t *testing.T) {
	fk := &fakeKafka{}
	p := &kafkaPublisher{topic: "tessera.groups", prod: fk}
	if err := p.Publish(context.Background(), Message{ID: "t/3", Type: "membership.direct.added", Key: "grp-9", Body: []byte(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	r := fk.recs[0]
	if r.topic != "tessera.groups" || r.key != "grp-9" || string(r.value) != `{"a":1}` || r.headers["ce_id"] != "t/3" ||
		r.headers["ce_type"] != "io.tessera.groups.membership.direct.added" || r.headers["content-type"] != ContentType {
		t.Errorf("record = %+v", r)
	}
	fk.err = errors.New("not enough replicas")
	if err := p.Publish(context.Background(), Message{Key: "g"}); err == nil || !strings.Contains(err.Error(), "not enough replicas") {
		t.Errorf("failure = %v", err)
	}
	_ = p.Close()
	if !fk.closed {
		t.Error("Close did not close the producer")
	}
}

// listener counts the connections a test address receives.
func listener(t *testing.T) (addr string, accepted *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted = new(atomic.Int64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done })
	return l.Addr().String(), accepted
}

// TestNetwork_DialIsGuarded: RabbitMQ and Kafka connect through the safehttp
// dialer. Against a loopback broker, a production network refuses before any
// connection is made; the dev network with the loopback exception connects (the
// control that shows the listener works).
func TestNetwork_DialIsGuarded(t *testing.T) {
	addr, accepted := listener(t)
	_, port, _ := net.SplitHostPort(addr)
	prod, err := NewNetworkWith(safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := NewNetworkWith(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if prod.AllowInsecure || !dev.AllowInsecure {
		t.Fatalf("AllowInsecure: prod %v, dev %v", prod.AllowInsecure, dev.AllowInsecure)
	}
	rabbit := Spec{Kind: KindRabbitMQ, Config: Config{URL: "amqps://127.0.0.1:" + port + "/", Exchange: "x"},
		Creds: Credentials{Username: "u", Password: "p"}}
	kafka := Spec{Kind: KindKafka, Config: Config{Brokers: []string{"127.0.0.1:" + port}, Topic: "t", Plaintext: true}}

	// production: refused, nothing connects
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := prod.Open(ctx, rabbit)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(ctx, Message{Type: "group.created", Key: "g"}); !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Errorf("rabbitmq to loopback in prod = %v, want ErrBlockedAddress", err)
	}
	if _, err := prod.Open(ctx, kafka); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("plaintext kafka in prod = %v, want a refusal", err)
	}
	kafka.Config.Plaintext = false
	kp, err := prod.Open(ctx, kafka)
	if err != nil {
		t.Fatal(err)
	}
	kctx, kcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer kcancel()
	if err := kp.Publish(kctx, Message{Type: "group.created", Key: "g", Body: []byte("{}")}); err == nil {
		t.Error("kafka to loopback in prod succeeded")
	}
	_ = kp.Close()
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the guarded dialer let %d connections through to loopback", n)
	}

	// dev with the loopback exception: the dialer connects (control)
	kafka.Config.Plaintext = true
	dp, err := dev.Open(ctx, kafka)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer dcancel()
	_ = dp.Publish(dctx, Message{Type: "group.created", Key: "g", Body: []byte("{}")})
	_ = dp.Close()
	if accepted.Load() == 0 {
		t.Error("control: the dev network never connected to the listener")
	}
}

func TestValidate(t *testing.T) {
	sqsOK := Config{Region: "eu-west-1", QueueURL: "https://sqs.eu-west-1.amazonaws.com/123456789012/q"}
	awsCreds := Credentials{AccessKeyID: "AK", SecretAccessKey: "sk"}
	mqOK := Config{URL: "amqps://mq.example.com/vh", Exchange: "ex"}
	mqCreds := Credentials{Username: "u", Password: "p"}
	kOK := Config{Brokers: []string{"k1.example.com:9093", "10.0.0.1:9093"}, Topic: "tessera.groups"}
	with := func(c Config, f func(*Config)) Config { f(&c); return c }
	for _, tc := range []struct {
		name  string
		kind  string
		cfg   Config
		creds Credentials
		dev   bool
		field string // "" = valid
	}{
		{"sqs ok", KindSQS, sqsOK, awsCreds, false, ""},
		{"sqs http queue", KindSQS, with(sqsOK, func(c *Config) { c.QueueURL = "http://sqs.eu-west-1.amazonaws.com/1/q" }), awsCreds, false, "queue_url"},
		{"sqs http queue in dev", KindSQS, with(sqsOK, func(c *Config) { c.QueueURL = "http://127.0.0.1:4566/1/q" }), awsCreds, true, ""},
		{"sqs bad region", KindSQS, with(sqsOK, func(c *Config) { c.Region = "mars" }), awsCreds, false, "region"},
		{"sqs no creds", KindSQS, sqsOK, Credentials{}, false, "access_key_id"},
		{"sqs with a topic", KindSQS, with(sqsOK, func(c *Config) { c.TopicARN = "x" }), awsCreds, false, "topic_arn"},
		{"sqs with a password", KindSQS, sqsOK, Credentials{AccessKeyID: "a", SecretAccessKey: "b", Password: "c"}, false, "password"},
		{"sqs endpoint with userinfo", KindSQS, with(sqsOK, func(c *Config) { c.Endpoint = "https://u:p@vpce.example.com/" }), awsCreds, false, "endpoint"},
		{"sns ok", KindSNS, Config{Region: "eu-west-1", TopicARN: "arn:aws:sns:eu-west-1:123456789012:groups.fifo"}, awsCreds, false, ""},
		{"sns region mismatch", KindSNS, Config{Region: "eu-west-2", TopicARN: "arn:aws:sns:eu-west-1:123456789012:groups"}, awsCreds, false, "topic_arn"},
		{"sns not an arn", KindSNS, Config{Region: "eu-west-1", TopicARN: "groups"}, awsCreds, false, "topic_arn"},
		{"rabbitmq ok", KindRabbitMQ, mqOK, mqCreds, false, ""},
		{"rabbitmq plain amqp", KindRabbitMQ, with(mqOK, func(c *Config) { c.URL = "amqp://mq.example.com/" }), mqCreds, false, "url"},
		{"rabbitmq plain amqp in dev", KindRabbitMQ, with(mqOK, func(c *Config) { c.URL = "amqp://localhost/" }), mqCreds, true, ""},
		{"rabbitmq userinfo", KindRabbitMQ, with(mqOK, func(c *Config) { c.URL = "amqps://guest:guest@mq.example.com/" }), mqCreds, false, "url"},
		{"rabbitmq query", KindRabbitMQ, with(mqOK, func(c *Config) { c.URL = "amqps://mq.example.com/?cacertfile=/etc/passwd" }), mqCreds, false, "url"},
		{"rabbitmq http", KindRabbitMQ, with(mqOK, func(c *Config) { c.URL = "https://mq.example.com/" }), mqCreds, false, "url"},
		{"rabbitmq no exchange", KindRabbitMQ, Config{URL: "amqps://mq.example.com/"}, mqCreds, false, "exchange"},
		{"rabbitmq no creds", KindRabbitMQ, mqOK, Credentials{}, false, "username"},
		{"kafka ok", KindKafka, kOK, Credentials{}, false, ""},
		{"kafka scram", KindKafka, with(kOK, func(c *Config) { c.SASL = "scram-sha-512" }), mqCreds, false, ""},
		{"kafka sasl without creds", KindKafka, with(kOK, func(c *Config) { c.SASL = "plain" }), Credentials{}, false, "username"},
		{"kafka creds without sasl", KindKafka, kOK, mqCreds, false, "sasl"},
		{"kafka bad mechanism", KindKafka, with(kOK, func(c *Config) { c.SASL = "gssapi" }), mqCreds, false, "sasl"},
		{"kafka plaintext", KindKafka, with(kOK, func(c *Config) { c.Plaintext = true }), Credentials{}, false, "plaintext"},
		{"kafka plaintext in dev", KindKafka, with(kOK, func(c *Config) { c.Plaintext = true }), Credentials{}, true, ""},
		{"kafka no port", KindKafka, with(kOK, func(c *Config) { c.Brokers = []string{"k1.example.com"} }), Credentials{}, false, "brokers"},
		{"kafka no brokers", KindKafka, Config{Topic: "t"}, Credentials{}, false, "brokers"},
		{"kafka bad topic", KindKafka, with(kOK, func(c *Config) { c.Topic = "a b" }), Credentials{}, false, "topic"},
		{"kafka dot topic", KindKafka, with(kOK, func(c *Config) { c.Topic = ".." }), Credentials{}, false, "topic"},
		{"unknown kind", "activemq", kOK, Credentials{}, false, "kind"},
		{"control character", KindKafka, with(kOK, func(c *Config) { c.Topic = "a\nb" }), Credentials{}, false, "topic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.kind, tc.cfg, tc.creds, tc.dev)
			var ve *ValidationError
			switch {
			case tc.field == "" && err != nil:
				t.Errorf("Validate = %v, want valid", err)
			case tc.field != "" && !errors.As(err, &ve):
				t.Errorf("Validate = %v, want a refusal of %s", err, tc.field)
			case tc.field != "" && ve.Field != tc.field:
				t.Errorf("Validate refused %s (%s), want %s", ve.Field, ve.Msg, tc.field)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	for _, tc := range []struct {
		filter []string
		typ    string
		want   bool
	}{
		{nil, "group.created", true},
		{[]string{"group.created"}, "group.created", true},
		{[]string{"group.created"}, "group.updated", false},
		{[]string{"membership."}, "membership.direct.added", true},
		{[]string{"membership."}, "group.created", false},
		{[]string{"group.created", "membership."}, "membership.effective.removed", true},
	} {
		if got := Matches(tc.filter, tc.typ); got != tc.want {
			t.Errorf("Matches(%v, %q) = %v", tc.filter, tc.typ, got)
		}
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := Backoff(i); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i, got, w)
		}
	}
	if Backoff(9) != 256*time.Second || Backoff(10) != 5*time.Minute || Backoff(1000) != 5*time.Minute {
		t.Errorf("Backoff caps: %v %v %v", Backoff(9), Backoff(10), Backoff(1000))
	}
}
