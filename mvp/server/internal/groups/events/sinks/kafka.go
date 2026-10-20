package sinks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// Kafka through franz-go (pure Go). Records are keyed by the group id, so the
// default hash partitioner keeps one group's events in one partition, in
// order; the producer is idempotent and waits for every in-sync replica
// (acks=all), and Publish returns once the broker has acknowledged the record.
// Every broker connection, including the ones the cluster's metadata names,
// is dialed with the safehttp dialer, and TLS is on unless dev turns it off.

// kafkaProducer sends one record and waits for its acknowledgement. The real
// one wraps a franz-go client; tests use an in-process fake.
type kafkaProducer interface {
	Produce(ctx context.Context, topic, key string, headers map[string]string, value []byte) error
	Close()
}

type kafkaPublisher struct {
	topic string
	prod  kafkaProducer
}

func newKafka(_ context.Context, n *Network, s Spec) (Publisher, error) {
	// the dialer connects only to the ports of the brokers this sink names
	var ports []int
	for _, b := range s.Config.Brokers {
		if _, ps, err := net.SplitHostPort(b); err == nil {
			if pn, err := strconv.Atoi(ps); err == nil {
				ports = append(ports, pn)
			}
		}
	}
	guarded, err := n.dialer(ports...)
	if err != nil {
		return nil, err
	}
	var mech sasl.Mechanism
	switch s.Config.SASL {
	case "plain":
		mech = plain.Auth{User: s.Creds.Username, Pass: s.Creds.Password}.AsMechanism()
	case "scram-sha-256":
		mech = scram.Auth{User: s.Creds.Username, Pass: s.Creds.Password}.AsSha256Mechanism()
	case "scram-sha-512":
		mech = scram.Auth{User: s.Creds.Username, Pass: s.Creds.Password}.AsSha512Mechanism()
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := guarded(ctx, network, addr)
		if err != nil || s.Config.Plaintext {
			return c, err
		}
		host, _, _ := net.SplitHostPort(addr)
		tc := tls.Client(c, n.tlsConfig(host))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, err
		}
		return tc, nil
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(s.Config.Brokers...),
		kgo.Dialer(dial),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordDeliveryTimeout(20 * time.Second),
		kgo.ProduceRequestTimeout(10 * time.Second),
		kgo.ClientID("tessera-groups-sink"),
	}
	if mech != nil {
		opts = append(opts, kgo.SASL(mech))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("kafka: %w", err)
	}
	return &kafkaPublisher{topic: s.Config.Topic, prod: &franzProducer{cl: cl}}, nil
}

func (p *kafkaPublisher) Publish(ctx context.Context, m Message) error {
	err := p.prod.Produce(ctx, p.topic, m.Key, map[string]string{"ce_id": m.ID, "ce_type": "io.tessera.groups." + m.Type,
		"content-type": ContentType}, m.Body)
	if err != nil {
		return fmt.Errorf("kafka: %w", err)
	}
	return nil
}

func (p *kafkaPublisher) Close() error {
	p.prod.Close()
	return nil
}

type franzProducer struct{ cl *kgo.Client }

func (f *franzProducer) Produce(ctx context.Context, topic, key string, headers map[string]string, value []byte) error {
	rec := &kgo.Record{Topic: topic, Key: []byte(key), Value: value}
	for k, v := range headers {
		rec.Headers = append(rec.Headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
	}
	return f.cl.ProduceSync(ctx, rec).FirstErr()
}

func (f *franzProducer) Close() { f.cl.Close() }
