package sinks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitMQ over AMQP 0-9-1 with publisher confirms: Publish returns once the
// broker has confirmed the message. The connection is made with the safehttp
// dialer (so a broker URL cannot point at a private or metadata address) and
// amqps verifies the broker's certificate. A failed publish drops the
// connection and the next one reconnects.

// amqpMessage is what the session publishes.
type amqpMessage struct {
	MessageID, Type, ContentType string
	Key                          string // routing key
	Body                         []byte
}

// amqpSession is one channel in confirm mode. The real one wraps amqp091-go;
// tests use an in-process fake.
type amqpSession interface {
	// Publish sends m to the exchange and waits for the broker's confirm.
	Publish(ctx context.Context, exchange string, m amqpMessage) error
	Close() error
}

type rabbitPublisher struct {
	cfg  Config
	dial func(ctx context.Context) (amqpSession, error)
	sess amqpSession
}

func newRabbitMQ(_ context.Context, n *Network, s Spec) (Publisher, error) {
	u, err := url.Parse(s.Config.URL)
	if err != nil {
		return nil, err
	}
	return &rabbitPublisher{cfg: s.Config, dial: func(ctx context.Context) (amqpSession, error) {
		return dialAMQP(ctx, n, u, s.Creds)
	}}, nil
}

func (p *rabbitPublisher) Publish(ctx context.Context, m Message) error {
	if p.sess == nil {
		sess, err := p.dial(ctx)
		if err != nil {
			return fmt.Errorf("rabbitmq: %w", err)
		}
		p.sess = sess
	}
	key := p.cfg.RoutingKey
	if key == "" {
		key = m.Type
	}
	err := p.sess.Publish(ctx, p.cfg.Exchange, amqpMessage{MessageID: m.ID, Type: m.Type, ContentType: ContentType, Key: key, Body: m.Body})
	if err != nil {
		_ = p.sess.Close()
		p.sess = nil
		return fmt.Errorf("rabbitmq: %w", err)
	}
	return nil
}

func (p *rabbitPublisher) Close() error {
	if p.sess == nil {
		return nil
	}
	err := p.sess.Close()
	p.sess = nil
	return err
}

type amqpConn struct {
	conn *amqp.Connection
	ch   *amqp.Channel
}

func dialAMQP(ctx context.Context, n *Network, u *url.URL, cr Credentials) (amqpSession, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5671"
		if u.Scheme == "amqp" {
			port = "5672"
		}
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: port %q", port)
	}
	// the dialer connects only to the port this sink's URL names
	guarded, err := n.dialer(pn)
	if err != nil {
		return nil, err
	}
	// the URL handed to the library has no credentials: they are passed as SASL
	uri := url.URL{Scheme: u.Scheme, Host: net.JoinHostPort(host, port), Path: u.EscapedPath()}
	cfg := amqp.Config{
		SASL:      []amqp.Authentication{&amqp.PlainAuth{Username: cr.Username, Password: cr.Password}},
		Heartbeat: 10 * time.Second,
		Locale:    "en_US",
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := guarded(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// the library's own handshake deadline: 10 s to open the connection
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			return c, nil
		},
	}
	if u.Scheme == "amqps" {
		cfg.TLSClientConfig = n.tlsConfig(host)
	}
	conn, err := amqp.DialConfig(uri.String(), cfg)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := ch.Confirm(false); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &amqpConn{conn: conn, ch: ch}, nil
}

func (c *amqpConn) Publish(ctx context.Context, exchange string, m amqpMessage) error {
	dc, err := c.ch.PublishWithDeferredConfirmWithContext(ctx, exchange, m.Key, false, false, amqp.Publishing{
		ContentType: m.ContentType, DeliveryMode: amqp.Persistent, MessageId: m.MessageID, Type: m.Type, Body: m.Body,
		Timestamp: time.Now().UTC()})
	if err != nil {
		return err
	}
	ok, err := dc.WaitContext(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the broker nacked the message")
	}
	return nil
}

func (c *amqpConn) Close() error { return c.conn.Close() }
