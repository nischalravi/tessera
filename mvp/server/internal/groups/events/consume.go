package events

import (
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Consumers read the outbox with a cursor. The PIT writer is a synchronous
// consumer: it applies each event in the transaction that wrote it and moves
// its cursor ("pit") with it. Asynchronous consumers (the graph projection,
// provisioners, webhooks) call Poll in their own transactions and Ack once
// they have handled a batch, so a crash replays the batch rather than losing it.

// MaxBatch bounds one Poll.
const MaxBatch = 1000

// Poll returns up to limit events after the consumer's cursor, oldest first.
// Events are never visible out of order: seq is gap-free and assigned while the
// writer holds the tenant's write lock, so once a seq is readable every lower
// seq is too.
func Poll(tx *store.TenantTx, consumer string, limit int) ([]*Event, error) {
	if limit < 1 || limit > MaxBatch {
		limit = MaxBatch
	}
	after, err := tx.GrpCursor(consumer)
	if err != nil {
		return nil, err
	}
	head, err := tx.GrpEventHead()
	if err != nil {
		return nil, err
	}
	return tx.GrpEventsAfter(after, head.LastSeq, limit)
}

// Ack moves the consumer's cursor to seq. A cursor only moves forward: acking
// an older seq is a no-op, and a seq beyond the head is an error.
func Ack(tx *store.TenantTx, consumer string, seq int64, now time.Time) error {
	cur, err := tx.GrpCursor(consumer)
	if err != nil {
		return err
	}
	if seq <= cur {
		return nil
	}
	head, err := tx.GrpEventHead()
	if err != nil {
		return err
	}
	if seq > head.LastSeq {
		return fmt.Errorf("events: cursor %q cannot move to %d, the last event is %d", consumer, seq, head.LastSeq)
	}
	return tx.SetGrpCursor(consumer, seq, now)
}

// Lag is how many events a consumer has not yet acknowledged.
func Lag(tx *store.TenantTx, consumer string) (int64, error) {
	cur, err := tx.GrpCursor(consumer)
	if err != nil {
		return 0, err
	}
	head, err := tx.GrpEventHead()
	return head.LastSeq - cur, err
}
