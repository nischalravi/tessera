package sinks

import (
	"errors"
	"strings"
	"testing"
)

// A sink whose URL has a non-ASCII host, written or percent-encoded, is refused when it is saved, naming the field and
// not echoing the value; ASCII, punycode and IPv6 hosts still pass (#942).
func TestValidate_RefusesNonASCIIHosts(t *testing.T) {
	awsCreds := Credentials{AccessKeyID: "AK", SecretAccessKey: "sk"}
	mqCreds := Credentials{Username: "u", Password: "p"}
	sqs := func(h string) Config {
		return Config{Region: "eu-west-1", QueueURL: "https://" + h + "/123456789012/q"}
	}
	sqsEndpoint := func(h string) Config {
		c := sqs("sqs.eu-west-1.amazonaws.com")
		c.Endpoint = "https://" + h + "/"
		return c
	}
	mq := func(h string) Config { return Config{URL: "amqps://" + h + "/v", Exchange: "x"} }
	type tc struct {
		name, field string
		kind        string
		cfg         func(h string) Config
		cr          Credentials
	}
	for _, c := range []tc{
		{"sqs queue_url", "queue_url", KindSQS, sqs, awsCreds},
		{"sqs endpoint", "endpoint", KindSQS, sqsEndpoint, awsCreds},
		{"rabbitmq url", "url", KindRabbitMQ, mq, mqCreds},
	} {
		for _, h := range []string{"exämple.com", "h%E2%88%B6x.example", "h%e2%88%b6x.example"} {
			err := Validate(c.kind, c.cfg(h), c.cr, false)
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Field != c.field || !strings.Contains(ve.Msg, "must be ASCII") || strings.Contains(ve.Msg, h) {
				t.Errorf("%s %s: %v", c.name, h, err)
			}
		}
		for _, h := range []string{"mq.example.com", "xn--exmple-cua.com", "mq.example.com:5671", "[2001:db8::1]:5671"} {
			if err := Validate(c.kind, c.cfg(h), c.cr, false); err != nil && strings.Contains(err.Error(), "must be ASCII") {
				t.Errorf("%s %s was refused as non-ASCII: %v", c.name, h, err)
			}
		}
	}
}
