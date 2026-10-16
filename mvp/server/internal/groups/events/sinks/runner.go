package sinks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Defaults of the delivery loop.
const (
	DefaultBatch          = 100
	DefaultMaxAttempts    = 8
	DefaultPublishTimeout = 15 * time.Second
	maxBackoff            = 5 * time.Minute
)

// Backoff is the wait after attempts failed attempts at one event: 1 s, 2 s,
// 4 s, ... up to 5 minutes.
func Backoff(attempts int) time.Duration {
	if attempts < 1 {
		return 0
	}
	if attempts > 10 {
		return maxBackoff
	}
	d := time.Second << (attempts - 1)
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// Runner delivers the outbox to every enabled sink of every active tenant. It
// is started next to the engine and history runners in cmd/tessera.
//
// For a sink it takes the events after the sink's cursor in seq order, skips
// those the sink's filter does not select, and publishes the rest one at a
// time. Nothing is sent before the event ahead of it has been accepted, which
// keeps each group's events in order. A refused event is retried on the next
// passes after Backoff (the sink shows "retrying"); after MaxAttempts it is
// written to grp_sink_dead_letters, audited, and the stream goes on. The cursor
// moves only after the broker has accepted the events, in one transaction with
// the sink's health, so a crash between the two replays the batch: delivery is
// at least once, and the CloudEvents id lets a receiver drop the repeat.
// Dead letters that an admin requeued are sent first.
//
// The network is never used with a database transaction open.
type Runner struct {
	DB     *store.DB
	Svc    *Service
	Open   OpenFunc
	Clock  timeutil.Clock
	Log    *slog.Logger
	Tick   time.Duration // default 2 s
	Batch  int           // events per sink per pass (default 100)
	Max    int           // attempts before a dead letter (default 8)
	Wait   func(attempts int) time.Duration
	PubTTL time.Duration // timeout of one publish (default 15 s)

	mu   sync.Mutex
	pubs map[string]*openPub // by sink id
}

type openPub struct {
	p       Publisher
	updated time.Time // the sink's updated_at the publisher was built from
}

func (r *Runner) defaults() {
	if r.Tick <= 0 {
		r.Tick = 2 * time.Second
	}
	if r.Batch <= 0 {
		r.Batch = DefaultBatch
	}
	if r.Max <= 0 {
		r.Max = DefaultMaxAttempts
	}
	if r.Wait == nil {
		r.Wait = Backoff
	}
	if r.PubTTL <= 0 {
		r.PubTTL = DefaultPublishTimeout
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Clock == nil {
		r.Clock = timeutil.System
	}
	r.mu.Lock()
	if r.pubs == nil {
		r.pubs = map[string]*openPub{}
	}
	r.mu.Unlock()
}

// Close closes the cached publishers.
func (r *Runner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, p := range r.pubs {
		_ = p.p.Close()
		delete(r.pubs, id)
	}
}

// Once runs one pass over every active tenant. An error in one tenant or sink
// does not stop the others; the first is returned.
func (r *Runner) Once(ctx context.Context) error {
	r.defaults()
	ctx = audit.WithSystemActor(ctx, "groups.sinks")
	tenants, err := r.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, t := range tenants {
		if err := r.tenant(ctx, t); err != nil {
			r.Log.Error("groups sink pass failed", "tenant", t.Slug, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (r *Runner) tenant(ctx context.Context, t store.Tenant) error {
	var list []*store.GrpSink
	if err := r.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) (err error) {
		list, err = tx.GrpSinks()
		return err
	}); err != nil {
		return err
	}
	var first error
	for _, k := range list {
		if !k.Enabled {
			r.drop(k.ID)
			continue
		}
		if err := r.Sink(ctx, t.ID, k.ID); err != nil && ctx.Err() == nil {
			r.Log.Error("groups sink delivery failed", "tenant", t.Slug, "sink", k.ID, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (r *Runner) drop(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pubs[id]; ok {
		_ = p.p.Close()
		delete(r.pubs, id)
	}
}

// publisher returns the sink's open publisher, building it again when the sink
// was changed.
func (r *Runner) publisher(ctx context.Context, spec Spec, id string, updated time.Time) (Publisher, error) {
	r.mu.Lock()
	cur := r.pubs[id]
	r.mu.Unlock()
	if cur != nil && cur.updated.Equal(updated) {
		return cur.p, nil
	}
	r.drop(id)
	p, err := r.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.pubs[id] = &openPub{p: p, updated: updated}
	r.mu.Unlock()
	return p, nil
}

// work is what one pass reads about a sink.
type work struct {
	sink    *store.GrpSink
	spec    Spec
	specErr error
	cursor  int64
	events  []*events.Event
	requeue []*store.GrpDeadLetter
}

// Sink runs one delivery pass for one sink.
func (r *Runner) Sink(ctx context.Context, tenant tenancy.ID, id string) error {
	r.defaults()
	now := r.Clock()
	w := &work{}
	err := r.DB.ReadTenant(ctx, tenant, func(tx *store.TenantTx) (err error) {
		if w.sink, err = tx.GrpSink(id); err != nil {
			return err
		}
		if !w.sink.Enabled || (w.sink.NextAttemptAt != nil && w.sink.NextAttemptAt.After(now)) {
			return nil
		}
		if w.requeue, err = tx.GrpDeadLetters(id, store.DeadLetterRequeued, r.Batch); err != nil {
			return err
		}
		if w.events, err = events.Poll(tx, Consumer(id), r.Batch); err != nil {
			return err
		}
		if len(w.requeue) == 0 && len(w.events) == 0 {
			return nil
		}
		if w.cursor, err = tx.GrpCursor(Consumer(id)); err != nil {
			return err
		}
		w.spec, w.specErr = r.Svc.Spec(tx, w.sink)
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		r.drop(id) // deleted meanwhile
		return nil
	}
	if err != nil {
		return err
	}
	if len(w.requeue) == 0 && len(w.events) == 0 {
		return nil
	}
	k := w.sink
	if k.NextAttemptAt != nil && k.NextAttemptAt.After(now) {
		return nil
	}
	pub, err := r.pub(ctx, w, id)
	if err != nil {
		// the sink cannot be opened (bad credentials, a blocked address): that
		// is a failed attempt, but no event is to blame, so nothing is dead-lettered
		return r.fail(ctx, tenant, k, k.Attempts+1, err, now)
	}

	attempts := k.Attempts
	if failed, err := r.redeliver(ctx, tenant, pub, w); err != nil || failed {
		return err // a broker that refuses a requeued letter is not sent the events behind the cursor either
	}
	var (
		delivered int64
		lastSeq   int64
		ackSeq    = w.cursor
	)
	flush := func(h store.GrpSinkHealth, dead *deadLetter) error {
		return r.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
			if dead != nil {
				if err := dead.record(tx, k.ID, now); err != nil {
					return err
				}
			}
			if ackSeq > w.cursor {
				if err := events.Ack(tx, Consumer(k.ID), ackSeq, now); err != nil {
					return err
				}
			}
			h.Delivered, h.LastDeliveredSeq, h.LastDeliveredAt = delivered, lastSeq, now
			return tx.SetGrpSinkHealth(k.ID, h)
		})
	}
	for _, e := range w.events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !Matches(k.EventTypes, e.Type) {
			ackSeq = e.Seq
			continue
		}
		msg, err := message(tenant, e)
		if err != nil {
			return err
		}
		pctx, cancel := context.WithTimeout(ctx, r.PubTTL)
		err = pub.Publish(pctx, msg)
		cancel()
		if err == nil {
			attempts = 0
			delivered++
			lastSeq = e.Seq
			ackSeq = e.Seq
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err() // shutting down: nothing is recorded, the batch is replayed
		}
		attempts++
		r.drop(id) // a broker that failed may have a broken connection: reconnect next time
		if attempts < r.Max {
			next := now.Add(r.Wait(attempts))
			r.Log.Warn("groups sink delivery failed", "sink", k.ID, "seq", e.Seq, "attempt", attempts, "err", err)
			return flush(store.GrpSinkHealth{State: store.SinkRetrying, Attempts: attempts, NextAttemptAt: &next, LastError: errText(err)}, nil)
		}
		// out of attempts: the event becomes a dead letter and the stream moves on
		r.Log.Error("groups sink event dead-lettered", "sink", k.ID, "seq", e.Seq, "attempts", attempts, "err", err)
		ackSeq = e.Seq
		dl := &deadLetter{event: e, payload: msg.Body, attempts: attempts, err: errText(err)}
		// the pass ends here; the next one starts the following event with fresh attempts
		return flush(store.GrpSinkHealth{State: store.SinkOK, Attempts: 0, LastError: dl.err}, dl)
	}
	if ackSeq == w.cursor && delivered == 0 && k.State == store.SinkOK && k.LastError == "" {
		return nil
	}
	return flush(store.GrpSinkHealth{State: store.SinkOK, Attempts: 0}, nil)
}

// pub opens the sink's publisher, or reports why it cannot be.
func (r *Runner) pub(ctx context.Context, w *work, id string) (Publisher, error) {
	if w.specErr != nil {
		return nil, w.specErr
	}
	return r.publisher(ctx, w.spec, id, w.sink.UpdatedAt)
}

// fail records a failed attempt that is not tied to one event.
func (r *Runner) fail(ctx context.Context, tenant tenancy.ID, k *store.GrpSink, attempts int, cause error, now time.Time) error {
	next := now.Add(r.Wait(attempts))
	r.Log.Warn("groups sink cannot be opened", "sink", k.ID, "attempt", attempts, "err", cause)
	return r.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		return tx.SetGrpSinkHealth(k.ID, store.GrpSinkHealth{State: store.SinkRetrying, Attempts: attempts, NextAttemptAt: &next,
			LastError: errText(cause)})
	})
}

// redeliver sends the dead letters an admin requeued. A failure puts the
// letter back to dead (with the new error) and ends the pass (failed).
func (r *Runner) redeliver(ctx context.Context, tenant tenancy.ID, pub Publisher, w *work) (failed bool, _ error) {
	for _, d := range w.requeue {
		msg := Message{ID: fmt.Sprintf("%s/%d", tenant, d.Seq), Seq: d.Seq, Type: d.EventType, Key: d.ObjectID, Body: []byte(d.Payload)}
		pctx, cancel := context.WithTimeout(ctx, r.PubTTL)
		perr := pub.Publish(pctx, msg)
		cancel()
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		now := r.Clock()
		if err := r.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
			if perr == nil {
				if err := tx.SetGrpDeadLetterStatus(w.sink.ID, d.Seq, store.DeadLetterDelivered, d.Attempts, "", now); err != nil {
					return err
				}
				return tx.Audit(now, "groups.sinks", ActionRedelivered, ojson.Object{{Key: "sink_id", Value: w.sink.ID}, {Key: "seq", Value: d.Seq}})
			}
			return tx.SetGrpDeadLetterStatus(w.sink.ID, d.Seq, store.DeadLetterDead, d.Attempts+1, errText(perr), now)
		}); err != nil {
			return false, err
		}
		if perr != nil {
			r.drop(w.sink.ID)
			return true, nil // the broker is failing: leave the rest to the next pass
		}
	}
	return false, nil
}

type deadLetter struct {
	event    *events.Event
	payload  []byte
	attempts int
	err      string
}

func (d *deadLetter) record(tx *store.TenantTx, sinkID string, now time.Time) error {
	if err := tx.InsertGrpDeadLetter(&store.GrpDeadLetter{SinkID: sinkID, Seq: d.event.Seq, EventType: d.event.Type, ObjectID: d.event.ObjectID,
		Payload: string(d.payload), Attempts: d.attempts, LastError: d.err, CreatedAt: now}); err != nil {
		return err
	}
	return tx.Audit(now, "groups.sinks", ActionDeadLetter, ojson.Object{{Key: "sink_id", Value: sinkID}, {Key: "seq", Value: d.event.Seq},
		{Key: "type", Value: d.event.Type}, {Key: "attempts", Value: d.attempts}, {Key: "error", Value: d.err}})
}

func message(tenant tenancy.ID, e *events.Event) (Message, error) {
	body, err := events.ToCloudEvent(tenant, e)
	if err != nil {
		return Message{}, err
	}
	return Message{ID: fmt.Sprintf("%s/%d", tenant, e.Seq), Seq: e.Seq, Type: e.Type, Key: e.ObjectID, Body: body}, nil
}

// errText is the error as stored in a sink's health: one short line.
func errText(err error) string {
	return oneLine([]byte(err.Error()), 300)
}

// Loop runs Once every Tick until ctx is done.
func (r *Runner) Loop(ctx context.Context) {
	r.defaults()
	defer r.Close()
	tick := time.NewTicker(r.Tick)
	defer tick.Stop()
	for {
		if err := r.Once(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("groups sinks failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
