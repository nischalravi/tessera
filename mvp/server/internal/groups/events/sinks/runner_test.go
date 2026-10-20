package sinks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000e5")
)

// fakePub is an in-process broker: it records every accepted message in order.
type fakePub struct {
	mu    sync.Mutex
	got   []Message
	calls int
	// fail decides, per call, whether the broker refuses the message
	fail func(m Message, call int) error
	// after runs once a message has been accepted
	after func(n int)
}

func (f *fakePub) Publish(_ context.Context, m Message) error {
	f.mu.Lock()
	f.calls++
	if f.fail != nil {
		if err := f.fail(m, f.calls); err != nil {
			f.mu.Unlock()
			return err
		}
	}
	f.got = append(f.got, m)
	n := len(f.got)
	f.mu.Unlock()
	if f.after != nil {
		f.after(n)
	}
	return nil
}
func (f *fakePub) Close() error { return nil }

func (f *fakePub) seqs() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int64
	for _, m := range f.got {
		out = append(out, m.Seq)
	}
	return out
}

type harness struct {
	t       *testing.T
	db      *store.DB
	svc     *Service
	run     *Runner
	pub     *fakePub
	now     time.Time
	openErr error
	opens   int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "sinks.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "sinks", Name: "sinks", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: db, svc: &Service{Sealer: sealer}, pub: &fakePub{}, now: t0}
	h.run = &Runner{DB: db, Svc: h.svc, Clock: func() time.Time { return h.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Wait: func(int) time.Duration { return 0 }, Max: 3,
		Open: func(context.Context, Spec) (Publisher, error) {
			h.opens++
			if h.openErr != nil {
				return nil, h.openErr
			}
			return h.pub, nil
		}}
	return h
}

func (h *harness) tx(fn func(*store.TenantTx) error) {
	h.t.Helper()
	if err := h.db.InTenant(context.Background(), tid, fn); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) sink(in CreateInput) *store.GrpSink {
	h.t.Helper()
	if in.Name == "" {
		in.Name = "main"
	}
	if in.Kind == "" {
		in.Kind = KindKafka
		in.Config = Config{Brokers: []string{"k.example.com:9093"}, Topic: "groups"}
	}
	in.Enabled = true
	var k *store.GrpSink
	h.tx(func(c *store.TenantTx) (err error) {
		k, err = h.svc.Create(c, in, "alice", h.now)
		return err
	})
	return k
}

// emit appends events, one per entry of groups (the group each belongs to).
func (h *harness) emit(typ string, groups ...string) {
	h.t.Helper()
	h.tx(func(c *store.TenantTx) error {
		for _, g := range groups {
			if err := events.Append(c, events.New(typ, g, h.now, store.CauseAPI)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (h *harness) pass(id string) {
	h.t.Helper()
	if err := h.run.Sink(context.Background(), tid, id); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) reload(id string) (k *store.GrpSink, cursor int64, dead []*store.GrpDeadLetter) {
	h.t.Helper()
	err := h.db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) (err error) {
		if k, err = c.GrpSink(id); err != nil {
			return err
		}
		if cursor, err = c.GrpCursor(Consumer(id)); err != nil {
			return err
		}
		dead, err = c.GrpDeadLetters(id, "", 100)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return k, cursor, dead
}

func (h *harness) audited(action string) []*store.AuditEvent {
	h.t.Helper()
	var out []*store.AuditEvent
	err := h.db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		all, err := c.AuditEvents(store.AuditFilter{Limit: 500})
		for _, e := range all {
			if e.Action == action {
				out = append(out, e)
			}
		}
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// TestSink_OrderedPerGroup: with many groups interleaved and a broker that
// refuses every few messages, each group's events arrive in seq order, none is
// lost or repeated, and the sink ends caught up.
func TestSink_OrderedPerGroup(t *testing.T) {
	h := newHarness(t)
	h.run.Max = 50
	h.run.Batch = 17
	k := h.sink(CreateInput{})

	groups := []string{"g-alpha", "g-beta", "g-gamma", "g-delta", "g-epsilon"}
	rng := rand.New(rand.NewSource(61))
	var order []string
	for _, g := range groups {
		for i := 0; i < 20; i++ {
			order = append(order, g)
		}
	}
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	h.emit(events.MembershipEffectiveAdded, order...)

	// the broker refuses the first attempt at every 7th event
	refused := map[int64]bool{}
	h.pub.fail = func(m Message, _ int) error {
		if m.Seq%7 == 0 && !refused[m.Seq] {
			refused[m.Seq] = true
			return errors.New("broker busy")
		}
		return nil
	}
	for i := 0; i < 200 && len(h.pub.seqs()) < len(order); i++ {
		h.pass(k.ID)
	}

	got := h.pub.seqs()
	if len(got) != len(order) {
		t.Fatalf("delivered %d of %d events", len(got), len(order))
	}
	lastOf := map[string]int64{}
	seen := map[int64]bool{}
	for _, m := range h.pub.got {
		if seen[m.Seq] {
			t.Errorf("seq %d delivered twice", m.Seq)
		}
		seen[m.Seq] = true
		if m.Seq <= lastOf[m.Key] {
			t.Errorf("group %s: seq %d arrived after %d", m.Key, m.Seq, lastOf[m.Key])
		}
		lastOf[m.Key] = m.Seq
		if want := order[m.Seq-1]; m.Key != want {
			t.Errorf("seq %d is for group %s, the message says %s", m.Seq, want, m.Key)
		}
	}
	// the stream is in global seq order too, which is what makes it ordered per group
	if !slices.IsSorted(got) {
		t.Errorf("not in seq order: %v", got)
	}
	k, cursor, dead := h.reload(k.ID)
	if cursor != int64(len(order)) || k.State != store.SinkOK || k.Attempts != 0 || len(dead) != 0 || k.DeliveredCount != int64(len(order)) ||
		k.LastDeliveredSeq != int64(len(order)) || k.LastDeliveredAt == nil {
		t.Errorf("sink = %+v, cursor %d, %d dead", k, cursor, len(dead))
	}
	// a message is a CloudEvent with the id receivers deduplicate on
	var ce map[string]any
	if err := json.Unmarshal(h.pub.got[3].Body, &ce); err != nil || ce["specversion"] != "1.0" ||
		ce["id"] != fmt.Sprintf("%s/%d", tid, h.pub.got[3].Seq) || ce["type"] != "io.tessera.groups."+events.MembershipEffectiveAdded {
		t.Errorf("message = %s (%v)", h.pub.got[3].Body, err)
	}
}

// TestSink_DeadLetterAfterRetries: an event the broker keeps refusing blocks
// the events behind it until it has had Max attempts, then it is a dead letter
// (audited), the stream moves on, and the dead letter can be redelivered.
func TestSink_DeadLetterAfterRetries(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{})
	h.emit(events.GroupCreated, "g1", "g2", "g3", "g4")
	poison := func(m Message, _ int) error {
		if m.Seq == 2 {
			return errors.New("message rejected: invalid payload")
		}
		return nil
	}
	h.pub.fail = poison

	h.pass(k.ID) // seq 1 is delivered, seq 2 is refused (attempt 1)
	got, cursor, dead := h.reload(k.ID)
	if !slices.Equal(h.pub.seqs(), []int64{1}) || cursor != 1 || got.State != store.SinkRetrying || got.Attempts != 1 ||
		!strings.Contains(got.LastError, "invalid payload") || len(dead) != 0 {
		t.Fatalf("after attempt 1: delivered %v, cursor %d, %+v", h.pub.seqs(), cursor, got)
	}
	h.pass(k.ID) // attempt 2: nothing behind seq 2 is sent
	got, cursor, dead = h.reload(k.ID)
	if !slices.Equal(h.pub.seqs(), []int64{1}) || cursor != 1 || got.Attempts != 2 || len(dead) != 0 {
		t.Fatalf("after attempt 2: delivered %v, cursor %d, attempts %d", h.pub.seqs(), cursor, got.Attempts)
	}
	h.pass(k.ID) // attempt 3 = Max: dead letter, and the pass ends
	got, cursor, dead = h.reload(k.ID)
	if cursor != 2 || got.Attempts != 0 || got.State != store.SinkOK || len(dead) != 1 {
		t.Fatalf("after attempt 3: cursor %d, %+v, %d dead", cursor, got, len(dead))
	}
	d := dead[0]
	if d.Seq != 2 || d.Status != store.DeadLetterDead || d.Attempts != 3 || d.EventType != events.GroupCreated || d.ObjectID != "g2" ||
		!strings.Contains(d.LastError, "invalid payload") || !strings.Contains(d.Payload, fmt.Sprintf(`"id":"%s/2"`, tid)) {
		t.Errorf("dead letter = %+v", d)
	}
	if ev := h.audited(ActionDeadLetter); len(ev) != 1 {
		t.Errorf("%d dead-letter audit events, want 1", len(ev))
	}

	h.pass(k.ID) // the rest flows
	if !slices.Equal(h.pub.seqs(), []int64{1, 3, 4}) {
		t.Errorf("delivered %v, want [1 3 4]", h.pub.seqs())
	}
	got, cursor, _ = h.reload(k.ID)
	if cursor != 4 || got.DeliveredCount != 3 {
		t.Errorf("cursor %d, delivered %d", cursor, got.DeliveredCount)
	}

	// requeue it, and the broker now accepts it: it is sent, out of order, with its original id
	h.pub.fail = nil
	h.tx(func(c *store.TenantTx) error { return h.svc.Requeue(c, k.ID, 2, "alice", h.now) })
	h.emit(events.GroupCreated, "g5")
	h.pass(k.ID)
	if !slices.Equal(h.pub.seqs(), []int64{1, 3, 4, 2, 5}) {
		t.Errorf("after the requeue delivered %v, want [1 3 4 2 5]", h.pub.seqs())
	}
	_, _, dead = h.reload(k.ID)
	if dead[0].Status != store.DeadLetterDelivered || h.pub.got[3].ID != fmt.Sprintf("%s/2", tid) {
		t.Errorf("dead letter after redelivery = %+v, message %+v", dead[0], h.pub.got[3])
	}
	if len(h.audited(ActionRedeliver)) != 1 || len(h.audited(ActionRedelivered)) != 1 {
		t.Error("the redelivery is not audited")
	}
}

func TestSink_RequeuedDeadLetterThatFailsAgainStaysDead(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{})
	h.emit(events.GroupCreated, "g1")
	h.pub.fail = func(Message, int) error { return errors.New("down") }
	for i := 0; i < 3; i++ {
		h.pass(k.ID)
	}
	_, _, dead := h.reload(k.ID)
	if len(dead) != 1 {
		t.Fatalf("%d dead letters", len(dead))
	}
	h.tx(func(c *store.TenantTx) error { return h.svc.Requeue(c, k.ID, 1, "alice", h.now) })
	h.pass(k.ID)
	_, _, dead = h.reload(k.ID)
	if dead[0].Status != store.DeadLetterDead || dead[0].Attempts != 4 {
		t.Errorf("after a failed redelivery: %+v", dead[0])
	}
	// discard gives up on it; a discarded letter cannot be requeued
	h.tx(func(c *store.TenantTx) error { return h.svc.Discard(c, k.ID, 1, "alice", h.now) })
	err := h.db.InTenant(context.Background(), tid, func(c *store.TenantTx) error { return h.svc.Requeue(c, k.ID, 1, "alice", h.now) })
	var se *Error
	if !errors.As(err, &se) || se.Kind != "conflict" {
		t.Errorf("requeue of a discarded letter = %v", err)
	}
}

// TestSink_BackoffHoldsTheStream: after a refusal nothing is sent until the
// backoff has passed.
func TestSink_BackoffHoldsTheStream(t *testing.T) {
	h := newHarness(t)
	h.run.Wait = func(int) time.Duration { return 10 * time.Second }
	k := h.sink(CreateInput{})
	h.emit(events.GroupCreated, "g1", "g2")
	h.pub.fail = func(Message, int) error { return errors.New("down") }
	h.pass(k.ID)
	calls := h.pub.calls
	got, _, _ := h.reload(k.ID)
	if calls != 1 || got.NextAttemptAt == nil || !got.NextAttemptAt.Equal(t0.Add(10*time.Second)) {
		t.Fatalf("after the refusal: %d calls, next %v", calls, got.NextAttemptAt)
	}
	h.now = t0.Add(5 * time.Second)
	h.pass(k.ID)
	if h.pub.calls != calls {
		t.Errorf("published during the backoff (%d calls)", h.pub.calls)
	}
	h.pub.fail = nil
	h.now = t0.Add(11 * time.Second)
	h.pass(k.ID)
	got, cursor, _ := h.reload(k.ID)
	if !slices.Equal(h.pub.seqs(), []int64{1, 2}) || cursor != 2 || got.State != store.SinkOK || got.NextAttemptAt != nil || got.LastError != "" {
		t.Errorf("after the backoff: delivered %v, cursor %d, %+v", h.pub.seqs(), cursor, got)
	}
}

// TestSink_AtLeastOnce: a crash after the broker accepted events but before the
// cursor moved replays them, never skips one, and keeps each group in order.
func TestSink_AtLeastOnce(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{})
	h.emit(events.GroupUpdated, "g1", "g2", "g1", "g2", "g1", "g2")
	ctx, crash := context.WithCancel(context.Background())
	h.pub.after = func(n int) {
		if n == 3 {
			crash() // the process dies after the third message was accepted
		}
	}
	if err := h.run.Sink(ctx, tid, k.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("crashed pass = %v", err)
	}
	if _, cursor, _ := h.reload(k.ID); cursor != 0 {
		t.Fatalf("the cursor moved to %d without an ack", cursor)
	}
	h.pub.after = nil
	h.pass(k.ID)
	got := h.pub.seqs()
	if !slices.Equal(got, []int64{1, 2, 3, 1, 2, 3, 4, 5, 6}) {
		t.Errorf("delivered %v: the first three are replayed, then the rest", got)
	}
	for seq := int64(1); seq <= 6; seq++ {
		if !slices.Contains(got, seq) {
			t.Errorf("seq %d was lost", seq)
		}
	}
	if _, cursor, _ := h.reload(k.ID); cursor != 6 {
		t.Errorf("cursor = %d", cursor)
	}
}

func TestSink_FilterSkipsButAdvances(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{EventTypes: []string{"group."}})
	h.emit(events.MembershipDirectAdded, "g1", "g1")
	h.emit(events.GroupCreated, "g2")
	h.emit(events.MembershipDirectRemoved, "g1")
	h.pass(k.ID)
	if !slices.Equal(h.pub.seqs(), []int64{3}) {
		t.Errorf("delivered %v, want only the group event", h.pub.seqs())
	}
	got, cursor, _ := h.reload(k.ID)
	if cursor != 4 || got.DeliveredCount != 1 {
		t.Errorf("cursor %d, delivered %d", cursor, got.DeliveredCount)
	}
}

func TestSink_StartsAtNowUnlessAskedForTheBeginning(t *testing.T) {
	h := newHarness(t)
	h.emit(events.GroupCreated, "old1", "old2")
	fromNow := h.sink(CreateInput{Name: "now"})
	fromStart := h.sink(CreateInput{Name: "start", From: "start"})
	h.emit(events.GroupCreated, "new")
	h.pass(fromNow.ID)
	if !slices.Equal(h.pub.seqs(), []int64{3}) {
		t.Errorf("a new sink delivered %v, want only [3]", h.pub.seqs())
	}
	h.pub.got = nil
	h.pass(fromStart.ID)
	if !slices.Equal(h.pub.seqs(), []int64{1, 2, 3}) {
		t.Errorf("a sink from the start delivered %v", h.pub.seqs())
	}
}

// TestSink_CannotOpenIsRetriedWithoutDeadLetters: a sink whose broker cannot be
// reached records the failure but dead-letters nothing and loses nothing.
func TestSink_CannotOpenIsRetriedWithoutDeadLetters(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{})
	h.emit(events.GroupCreated, "g1")
	h.openErr = errors.New("safehttp: destination address not allowed")
	for i := 0; i < 6; i++ {
		h.pass(k.ID)
	}
	got, cursor, dead := h.reload(k.ID)
	if cursor != 0 || len(dead) != 0 || got.State != store.SinkRetrying || got.Attempts != 6 || !strings.Contains(got.LastError, "not allowed") {
		t.Fatalf("cursor %d, %d dead, %+v", cursor, len(dead), got)
	}
	h.openErr = nil
	h.pass(k.ID)
	got, cursor, _ = h.reload(k.ID)
	if cursor != 1 || got.State != store.SinkOK || got.Attempts != 0 {
		t.Errorf("after the broker came back: cursor %d, %+v", cursor, got)
	}
}

// TestSink_DisabledAndChangedSinks: a disabled sink sends nothing; changing a
// sink makes the runner build a new publisher.
func TestSink_DisabledAndChangedSinks(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{})
	h.emit(events.GroupCreated, "g1")
	off := false
	h.tx(func(c *store.TenantTx) error {
		_, err := h.svc.Update(c, k.ID, UpdateInput{Enabled: &off}, "alice", h.now)
		return err
	})
	if err := h.run.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.pub.seqs()) != 0 {
		t.Fatal("a disabled sink delivered")
	}
	on := true
	h.now = h.now.Add(time.Second)
	h.tx(func(c *store.TenantTx) error {
		_, err := h.svc.Update(c, k.ID, UpdateInput{Enabled: &on}, "alice", h.now)
		return err
	})
	if err := h.run.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.pub.seqs(), []int64{1}) || h.opens != 1 {
		t.Fatalf("delivered %v with %d opens", h.pub.seqs(), h.opens)
	}
	h.now = h.now.Add(time.Second)
	topic := Config{Brokers: []string{"k.example.com:9093"}, Topic: "other"}
	h.tx(func(c *store.TenantTx) error {
		_, err := h.svc.Update(c, k.ID, UpdateInput{Config: &topic}, "alice", h.now)
		return err
	})
	h.emit(events.GroupCreated, "g2")
	if err := h.run.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.opens != 2 || !slices.Equal(h.pub.seqs(), []int64{1, 2}) {
		t.Errorf("after a config change: %d opens, delivered %v", h.opens, h.pub.seqs())
	}
}

// TestSink_CredentialsAreSealed: credentials are stored sealed, bound to their
// sink, and never appear in the audit trail.
func TestSink_CredentialsAreSealed(t *testing.T) {
	h := newHarness(t)
	secret := "s3cr3t-Passw0rd-Value"
	k := h.sink(CreateInput{Kind: KindRabbitMQ, Config: Config{URL: "amqps://mq.example.com/", Exchange: "ex"},
		Creds: Credentials{Username: "svc", Password: secret}})
	if len(k.SecretEnc) == 0 || strings.Contains(string(k.SecretEnc), secret) || strings.Contains(string(k.Config), secret) {
		t.Fatal("the credentials are not sealed")
	}
	h.tx(func(c *store.TenantTx) error {
		cr, err := h.svc.Credentials(c, k)
		if err != nil || cr.Password != secret || cr.Username != "svc" {
			t.Errorf("Credentials = %+v, %v", cr, err)
		}
		// moved to another sink, the blob does not open
		other := *k
		other.ID = "00000000-0000-4000-8000-000000000001"
		if _, err := h.svc.Credentials(c, &other); err == nil {
			t.Error("a sealed credential opened under another sink's id")
		}
		return nil
	})
	var trail strings.Builder
	h.tx(func(c *store.TenantTx) error {
		all, err := c.AuditEvents(store.AuditFilter{Limit: 100, IncludeHTTP: true})
		for _, e := range all {
			b, _ := json.Marshal(e)
			trail.Write(b)
		}
		return err
	})
	if strings.Contains(trail.String(), secret) || !strings.Contains(trail.String(), ActionCreated) {
		t.Error("the audit trail leaks the secret or lacks the created event")
	}
	// an update without credentials keeps them; one with replaces them
	h.tx(func(c *store.TenantTx) error {
		name := "renamed"
		u, err := h.svc.Update(c, k.ID, UpdateInput{Name: &name}, "alice", h.now)
		if err != nil || len(u.SecretEnc) == 0 {
			t.Errorf("rename: %v, secret kept: %v", err, u != nil && len(u.SecretEnc) > 0)
		}
		return err
	})
	var ve *Error
	err := h.db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
		_, err := h.svc.Update(c, k.ID, UpdateInput{Creds: &Credentials{Username: "svc"}}, "alice", h.now)
		return err
	})
	if !errors.As(err, &ve) || ve.Kind != "invalid" {
		t.Errorf("an update that drops the password = %v", err)
	}
}

func TestService_Refusals(t *testing.T) {
	h := newHarness(t)
	h.sink(CreateInput{})
	kafka := Config{Brokers: []string{"k.example.com:9093"}, Topic: "groups"}
	for name, in := range map[string]CreateInput{
		"duplicate name": {Name: "main", Kind: KindKafka, Config: kafka},
		"no name":        {Name: " ", Kind: KindKafka, Config: kafka},
		"bad kind":       {Name: "x", Kind: "nats", Config: kafka},
		"bad filter":     {Name: "x", Kind: KindKafka, Config: kafka, EventTypes: []string{"group.exploded"}},
		"bad prefix":     {Name: "x", Kind: KindKafka, Config: kafka, EventTypes: []string{"Group."}},
		"bad from":       {Name: "x", Kind: KindKafka, Config: kafka, From: "yesterday"},
		"plain kafka":    {Name: "x", Kind: KindKafka, Config: Config{Brokers: kafka.Brokers, Topic: "t", Plaintext: true}},
	} {
		err := h.db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
			_, err := h.svc.Create(c, in, "alice", h.now)
			return err
		})
		var se *Error
		if !errors.As(err, &se) {
			t.Errorf("%s: Create = %v, want a refusal", name, err)
		}
	}
	// credentials need a sealer
	noSeal := &Service{}
	err := h.db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
		_, err := noSeal.Create(c, CreateInput{Name: "y", Kind: KindRabbitMQ, Config: Config{URL: "amqps://mq.example.com/", Exchange: "e"},
			Creds: Credentials{Username: "u", Password: "p"}}, "alice", h.now)
		return err
	})
	var se *Error
	if !errors.As(err, &se) || se.Kind != "unavailable" {
		t.Errorf("Create without a sealer = %v", err)
	}
	// the limit
	err = h.db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
		for i := 0; i < MaxSinks; i++ {
			if _, err := h.svc.Create(c, CreateInput{Name: fmt.Sprintf("s%d", i), Kind: KindKafka, Config: kafka}, "alice", h.now); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.As(err, &se) || se.Code != "too_many_sinks" {
		t.Errorf("past the limit = %v", err)
	}
}

func TestService_DeleteRemovesCursorAndDeadLetters(t *testing.T) {
	h := newHarness(t)
	k := h.sink(CreateInput{})
	h.emit(events.GroupCreated, "g1")
	h.pass(k.ID)
	h.tx(func(c *store.TenantTx) error { return h.svc.Delete(c, k.ID, "alice", h.now) })
	h.tx(func(c *store.TenantTx) error {
		if _, err := c.GrpSink(k.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpSink = %v", err)
		}
		if cur, err := c.GrpCursor(Consumer(k.ID)); err != nil || cur != 0 {
			t.Errorf("cursor after delete = %d, %v", cur, err)
		}
		return nil
	})
	if len(h.audited(ActionDeleted)) != 1 {
		t.Error("the delete is not audited")
	}
	// the runner copes with a sink deleted between its listing and its pass
	if err := h.run.Sink(context.Background(), tid, k.ID); err != nil {
		t.Errorf("Sink on a deleted sink = %v", err)
	}
}
