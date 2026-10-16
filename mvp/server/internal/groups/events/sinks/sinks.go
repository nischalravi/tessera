// Package sinks streams the group change events of the outbox
// (internal/groups/events) to external brokers: AWS SQS, AWS SNS, RabbitMQ and
// Kafka (issue #61, GR-18; design docs/design/groups-grouper-parity.md §10.1).
//
// Messages are CloudEvents 1.0 JSON (events.ToCloudEvent). Delivery is at
// least once and ordered per group: a sink's runner takes events in seq order,
// publishes them one at a time and moves the sink's cursor only after the
// broker has accepted them, so a crash replays a batch (receivers deduplicate
// on the CloudEvents id "<tenant>/<seq>"). An event that fails is retried with
// backoff before anything after it is sent; after MaxAttempts it becomes a
// dead letter and the stream moves on.
//
// Every connection goes through internal/safehttp's address checks: AWS over
// its guarded HTTP client, RabbitMQ and Kafka through safehttp.NewDialer.
// Credentials are sealed at rest (service.go) and never leave the server.
package sinks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Kinds of sink.
const (
	KindSQS      = store.SinkSQS
	KindSNS      = store.SinkSNS
	KindRabbitMQ = store.SinkRabbitMQ
	KindKafka    = store.SinkKafka
)

// Kinds lists the supported kinds.
func Kinds() []string { return []string{KindSQS, KindSNS, KindRabbitMQ, KindKafka} }

// ErrNotAvailable is returned by a publisher that cannot be built.
var ErrNotAvailable = errors.New("sinks: this kind of sink is not available")

// Config is a sink's non-secret settings. Which fields apply depends on the
// kind; Validate refuses the rest.
type Config struct {
	// sqs and sns
	Region string `json:"region,omitempty"`
	// Endpoint replaces https://sqs.<region>.amazonaws.com/ or the SNS one (a
	// VPC endpoint, LocalStack); https only.
	Endpoint string `json:"endpoint,omitempty"`
	QueueURL string `json:"queue_url,omitempty"` // sqs
	TopicARN string `json:"topic_arn,omitempty"` // sns

	// rabbitmq: amqps://host[:port]/vhost, without credentials
	URL        string `json:"url,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	RoutingKey string `json:"routing_key,omitempty"` // default: the event type

	// kafka
	Brokers []string `json:"brokers,omitempty"` // host:port
	Topic   string   `json:"topic,omitempty"`
	// SASL is "", "plain", "scram-sha-256" or "scram-sha-512"
	SASL string `json:"sasl,omitempty"`
	// Plaintext turns TLS off; dev only.
	Plaintext bool `json:"plaintext,omitempty"`
}

// Credentials are a sink's secrets. They are stored sealed and never returned.
type Credentials struct {
	// sqs and sns: an access key (and a session token for temporary keys)
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	// rabbitmq and kafka SASL
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// IsZero reports whether no credential is set.
func (c Credentials) IsZero() bool { return c == Credentials{} }

// Message is one event as a broker receives it.
type Message struct {
	// ID is the CloudEvents id "<tenant>/<seq>": a redelivery has the same one.
	ID  string
	Seq int64
	// Type is the event type ("membership.direct.added").
	Type string
	// Key orders messages: the group (object) id. Kafka partitions by it; a
	// FIFO queue or topic uses it as the message group.
	Key  string
	Body []byte
}

// ContentType of Message.Body.
const ContentType = "application/cloudevents+json"

// Publisher delivers messages to one broker. Publish returns only once the
// broker has accepted the message (a send confirm, an HTTP 200, all in-sync
// replicas), or an error. A Publisher is used by one goroutine at a time.
type Publisher interface {
	Publish(ctx context.Context, m Message) error
	Close() error
}

// Spec is everything needed to open a Publisher.
type Spec struct {
	Kind   string
	Config Config
	Creds  Credentials
}

// OpenFunc opens a Publisher. The runner's default is Network.Open; tests pass
// a fake.
type OpenFunc func(ctx context.Context, s Spec) (Publisher, error)

// Network is the guarded network access of the sinks.
type Network struct {
	// HTTP is a safehttp client (AWS).
	HTTP *http.Client
	// Dial is a safehttp dialer (RabbitMQ, Kafka).
	Dial safehttp.DialFunc
	// AllowInsecure permits plain amqp:// and non-TLS Kafka. Dev only.
	AllowInsecure bool
	// RootCAs replaces the system roots for TLS to a broker (a private CA, a test).
	RootCAs *x509.CertPool
}

// NewNetwork builds the network access for the running configuration.
func NewNetwork(c *config.Config) (*Network, error) {
	return NewNetworkWith(safehttp.Options{Env: c.Env, AllowLoopback: c.OutboundAllowLoopback})
}

// NewNetworkWith builds the network access from safehttp options. AllowInsecure
// follows Env: plain connections are allowed in dev only.
func NewNetworkWith(o safehttp.Options) (*Network, error) {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second // a publish waits for the broker
	}
	h, err := safehttp.New(o)
	if err != nil {
		return nil, err
	}
	d, err := safehttp.NewDialer(o)
	if err != nil {
		return nil, err
	}
	return &Network{HTTP: h, Dial: d, AllowInsecure: o.Env == config.Dev, RootCAs: o.RootCAs}, nil
}

func (n *Network) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: n.RootCAs, ServerName: serverName}
}

// Open builds the publisher of a sink.
func (n *Network) Open(ctx context.Context, s Spec) (Publisher, error) {
	if err := Validate(s.Kind, s.Config, s.Creds, n.AllowInsecure); err != nil {
		return nil, err
	}
	switch s.Kind {
	case KindSQS, KindSNS:
		return newAWS(n.HTTP, s, nil)
	case KindRabbitMQ:
		return newRabbitMQ(ctx, n, s)
	case KindKafka:
		return newKafka(ctx, n, s)
	}
	return nil, fmt.Errorf("sinks: unknown kind %q", s.Kind)
}

// ---------------------------------------------------------------- validation

// ValidationError is a refused configuration: Field names the setting.
type ValidationError struct {
	Field, Msg string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, format string, a ...any) error {
	return &ValidationError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

var (
	regionRE   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	topicARNRE = regexp.MustCompile(`^arn:aws(-[a-z]+)*:sns:([a-z]{2}(-[a-z]+)+-[0-9]{1,2}):[0-9]{12}:[A-Za-z0-9_-]{1,256}(\.fifo)?$`)
	kafkaTopic = regexp.MustCompile(`^[A-Za-z0-9._-]{1,249}$`)
	hostRE     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
	typeRE     = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)*\.?$`)
)

const maxField = 2048

// Validate checks a sink's configuration and credentials. allowInsecure (dev)
// permits plain amqp:// and non-TLS Kafka; everywhere else TLS is required.
func Validate(kind string, c Config, cr Credentials, allowInsecure bool) error {
	for name, v := range map[string]string{"region": c.Region, "endpoint": c.Endpoint, "queue_url": c.QueueURL, "topic_arn": c.TopicARN,
		"url": c.URL, "exchange": c.Exchange, "routing_key": c.RoutingKey, "topic": c.Topic, "sasl": c.SASL, "access_key_id": cr.AccessKeyID,
		"secret_access_key": cr.SecretAccessKey, "session_token": cr.SessionToken, "username": cr.Username, "password": cr.Password} {
		if len(v) > maxField || strings.ContainsAny(v, "\x00\r\n") {
			return bad(name, "is too long or has control characters")
		}
	}
	only := func(allowed map[string]bool) error {
		for name, set := range map[string]bool{"region": c.Region != "", "endpoint": c.Endpoint != "", "queue_url": c.QueueURL != "",
			"topic_arn": c.TopicARN != "", "url": c.URL != "", "exchange": c.Exchange != "", "routing_key": c.RoutingKey != "",
			"brokers": len(c.Brokers) > 0, "topic": c.Topic != "", "sasl": c.SASL != "", "plaintext": c.Plaintext} {
			if set && !allowed[name] {
				return bad(name, "does not apply to a %s sink", kind)
			}
		}
		for name, set := range map[string]bool{"access_key_id": cr.AccessKeyID != "", "secret_access_key": cr.SecretAccessKey != "",
			"session_token": cr.SessionToken != "", "username": cr.Username != "", "password": cr.Password != ""} {
			if set && !allowed[name] {
				return bad(name, "does not apply to a %s sink", kind)
			}
		}
		return nil
	}
	switch kind {
	case KindSQS, KindSNS:
		allowed := map[string]bool{"region": true, "endpoint": true, "access_key_id": true, "secret_access_key": true, "session_token": true}
		allowed["queue_url"], allowed["topic_arn"] = kind == KindSQS, kind == KindSNS
		if err := only(allowed); err != nil {
			return err
		}
		if !regionRE.MatchString(c.Region) {
			return bad("region", "must be an AWS region such as eu-west-1")
		}
		if c.Endpoint != "" {
			if err := httpsURL("endpoint", c.Endpoint, allowInsecure); err != nil {
				return err
			}
		}
		if kind == KindSQS {
			if err := httpsURL("queue_url", c.QueueURL, allowInsecure); err != nil {
				return err
			}
		} else if m := topicARNRE.FindStringSubmatch(c.TopicARN); m == nil {
			return bad("topic_arn", "must be an SNS topic ARN")
		} else if m[2] != c.Region {
			return bad("topic_arn", "is in region %s, not %s", m[2], c.Region)
		}
		if cr.AccessKeyID == "" || cr.SecretAccessKey == "" {
			return bad("access_key_id", "an access key id and secret access key are required")
		}
	case KindRabbitMQ:
		if err := only(map[string]bool{"url": true, "exchange": true, "routing_key": true, "username": true, "password": true}); err != nil {
			return err
		}
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || u.Hostname() == "" {
			return bad("url", "must be an amqps://host[:port]/vhost URL")
		}
		switch {
		case u.Scheme == "amqps":
		case u.Scheme == "amqp" && allowInsecure:
		case u.Scheme == "amqp":
			return bad("url", "must use amqps: TLS is required outside dev")
		default:
			return bad("url", "must be an amqps://host[:port]/vhost URL")
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return bad("url", "must not carry credentials, a query or a fragment (credentials are set apart)")
		}
		if p := u.Port(); p != "" {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return bad("url", "has an invalid port")
			}
		}
		if c.Exchange == "" && c.RoutingKey == "" {
			return bad("exchange", "an exchange (or, for the default exchange, a routing_key naming the queue) is required")
		}
		if cr.Username == "" || cr.Password == "" {
			return bad("username", "a username and password are required")
		}
	case KindKafka:
		if err := only(map[string]bool{"brokers": true, "topic": true, "sasl": true, "plaintext": true, "username": true, "password": true}); err != nil {
			return err
		}
		if len(c.Brokers) == 0 || len(c.Brokers) > 20 {
			return bad("brokers", "needs 1 to 20 host:port entries")
		}
		for _, b := range c.Brokers {
			h, p, err := net.SplitHostPort(b)
			if n, perr := strconv.Atoi(p); err != nil || perr != nil || n < 1 || n > 65535 || (!hostRE.MatchString(h) && net.ParseIP(h) == nil) {
				return bad("brokers", "%q is not host:port", b)
			}
		}
		if !kafkaTopic.MatchString(c.Topic) || c.Topic == "." || c.Topic == ".." {
			return bad("topic", "is not a valid Kafka topic name")
		}
		switch c.SASL {
		case "":
			if cr.Username != "" || cr.Password != "" {
				return bad("sasl", "is required when credentials are given (plain, scram-sha-256 or scram-sha-512)")
			}
		case "plain", "scram-sha-256", "scram-sha-512":
			if cr.Username == "" || cr.Password == "" {
				return bad("username", "a username and password are required for SASL")
			}
		default:
			return bad("sasl", "must be plain, scram-sha-256 or scram-sha-512")
		}
		if c.Plaintext && !allowInsecure {
			return bad("plaintext", "TLS is required outside dev")
		}
	default:
		return bad("kind", "must be one of %s", strings.Join(Kinds(), ", "))
	}
	return nil
}

func httpsURL(field, raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return bad(field, "must be an https URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && allowInsecure) {
		return bad(field, "must be an https URL")
	}
	return nil
}

// ValidateTypes checks an event-type filter: each entry is a type of the
// catalogue ("group.created") or a prefix ending in a dot ("membership.").
func ValidateTypes(types []string, known func(string) bool) error {
	if len(types) > 50 {
		return bad("event_types", "has at most 50 entries")
	}
	for _, t := range types {
		if len(t) > 80 || !typeRE.MatchString(t) {
			return bad("event_types", "%q is not an event type or a prefix like \"membership.\"", t)
		}
		if strings.HasSuffix(t, ".") {
			continue
		}
		if !known(t) {
			return bad("event_types", "%q is not an event type", t)
		}
	}
	return nil
}

// Matches reports whether an event type passes a filter (an empty filter
// passes everything).
func Matches(types []string, eventType string) bool {
	if len(types) == 0 {
		return true
	}
	for _, t := range types {
		if t == eventType || (strings.HasSuffix(t, ".") && strings.HasPrefix(eventType, t)) {
			return true
		}
	}
	return false
}
