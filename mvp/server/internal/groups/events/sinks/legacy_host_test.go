package sinks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A sink stored before the ASCII-host rule (#944) can still be disabled or renamed while its URLs are unchanged; a changed
// URL, or enabling it, gets the full check (#953).
func TestUpdate_LegacyNonASCIIHost(t *testing.T) {
	sqs := func(queue, endpoint string) Config {
		return Config{Region: "eu-west-1", QueueURL: queue, Endpoint: endpoint}
	}
	amqp := func(u string) Config { return Config{URL: u, Exchange: "x"} }
	const legacyQueue = "https://sqs.eu-west-1.exämple.com/123/q"
	const legacyEndpoint = "https://enpöint.example.com"
	const legacyAMQP = "amqps://brökér.example.com:5671/v"
	kinds := []struct {
		name   string
		in     CreateInput
		legacy Config
		other  Config
	}{
		{"sqs queue_url", CreateInput{Kind: KindSQS, Config: sqs("https://sqs.eu-west-1.amazonaws.com/123/q", ""),
			Creds: Credentials{AccessKeyID: "a", SecretAccessKey: "b"}}, sqs(legacyQueue, ""), sqs("https://sqs.eu-west-1.göod.com/123/q", "")},
		{"sqs endpoint", CreateInput{Kind: KindSQS, Config: sqs("https://sqs.eu-west-1.amazonaws.com/123/q", ""),
			Creds: Credentials{AccessKeyID: "a", SecretAccessKey: "b"}}, sqs("https://sqs.eu-west-1.amazonaws.com/123/q", legacyEndpoint),
			sqs("https://sqs.eu-west-1.amazonaws.com/123/q", "https://göod.example.com")},
		{"rabbitmq url", CreateInput{Kind: KindRabbitMQ, Config: amqp("amqps://b.example.com:5671/v"),
			Creds: Credentials{Username: "u", Password: "p"}}, amqp(legacyAMQP), amqp("amqps://göod.example.com:5671/v")},
	}
	b := func(v bool) *bool { return &v }
	for _, k := range kinds {
		cases := []struct {
			name     string
			disabled bool
			in       func(legacy, other Config) UpdateInput
			refused  bool
		}{
			{"disable", false, func(_, _ Config) UpdateInput { return UpdateInput{Enabled: b(false)} }, false},
			{"rename", false, func(_, _ Config) UpdateInput { n := "renamed"; return UpdateInput{Name: &n} }, false},
			{"rename disabled", true, func(_, _ Config) UpdateInput { n := "renamed"; return UpdateInput{Name: &n} }, false},
			{"same config resent while disabling", false, func(l, _ Config) UpdateInput { return UpdateInput{Enabled: b(false), Config: &l} }, false},
			{"enable", true, func(_, _ Config) UpdateInput { return UpdateInput{Enabled: b(true)} }, true},
			{"other host", false, func(_, o Config) UpdateInput { return UpdateInput{Config: &o} }, true},
			{"other host while disabling", false, func(_, o Config) UpdateInput { return UpdateInput{Enabled: b(false), Config: &o} }, true},
		}
		for _, tc := range cases {
			t.Run(k.name+" "+tc.name, func(t *testing.T) {
				h := newHarness(t)
				sink := h.sink(k.in)
				// the row as an earlier version stored it
				h.tx(func(c *store.TenantTx) error {
					var err error
					if sink.Config, err = json.Marshal(k.legacy); err != nil {
						return err
					}
					sink.Enabled = !tc.disabled
					return c.UpdateGrpSink(sink, h.now)
				})
				err := func() error {
					var err error
					h.tx(func(c *store.TenantTx) error {
						_, err = h.svc.Update(c, sink.ID, tc.in(k.legacy, k.other), "alice", h.now)
						return nil
					})
					return err
				}()
				if tc.refused != (err != nil) || (err != nil && !strings.Contains(err.Error(), "must be ASCII")) {
					t.Fatalf("refused=%v, got %v", tc.refused, err)
				}
			})
		}
	}
}
