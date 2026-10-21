package worker_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// cpConnector is a connector that keeps a checkpoint through the context's
// store, as the okta and entra connectors do, and can be made slow or failing.
type cpConnector struct {
	connectors.Connector
	system string
	block  chan struct{}
	err    error
	loaded chan *connsync.Checkpoint
}

func (c *cpConnector) System() string { return c.system }
func (c *cpConnector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	st := connsync.StoreFrom(ctx)
	cp, err := st.Load(ctx, c.system, "users")
	if err != nil {
		return nil, err
	}
	if c.loaded != nil {
		c.loaded <- cp
	}
	if c.block != nil {
		<-c.block
	}
	if err := st.Save(ctx, c.system, "users", &connsync.Checkpoint{Cursor: "cursor-2", UpdatedAt: testkit.Now}); err != nil {
		return nil, err
	}
	return &connectors.DiscoveryResult{}, c.err
}

func (e *env) checkpoint(t *testing.T, system string) *store.ConnectorCheckpoint {
	t.Helper()
	var k *store.ConnectorCheckpoint
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) (err error) {
		k, err = tx.ConnectorCheckpoint(system, "users")
		if errors.Is(err, store.ErrNotFound) {
			k, err = nil, nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSyncJobHoldsNoWriteLockWhileReadingTheSource: a source that is slow to
// answer must not stop the database's other writers (on SQLite one write
// transaction at a time, the worker's own lease heartbeat among them); and the
// checkpoint the connector moves is written with the records, kept across
// runs and dropped when the sync fails.
func TestSyncJobHoldsNoWriteLockWhileReadingTheSource(t *testing.T) {
	e := newEnv(t)
	slow := &cpConnector{system: "slow", block: make(chan struct{}), loaded: make(chan *connsync.Checkpoint, 4)}
	deps := &worker.Deps{Connectors: func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{slow}, nil }}
	q := e.queue(t, "w", time.Minute, deps, jobs.ConnectorSync)
	e.enqueue(t, q, tenantA, jobs.ConnectorSync, "k1")
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if cp := <-slow.loaded; cp != nil {
		t.Fatalf("a first sync found a checkpoint: %+v", cp)
	}
	// the source is still being read; other writers go through at once
	done := make(chan error, 1)
	go func() {
		_, err := q.Enqueue(t.Context(), tenantA, jobs.ConnectorSync, "{}", "k2", time.Time{}, 3)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write was blocked while a sync waited on its source")
	}
	close(slow.block)
	q.Wait()
	if k := e.checkpoint(t, "slow"); k == nil || k.Cursor != "cursor-2" {
		t.Fatalf("the checkpoint was not kept: %+v", k)
	}
	// the next run (the second job) starts from it
	slow.block = nil
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	q.Wait()
	if cp := <-slow.loaded; cp == nil || cp.Cursor != "cursor-2" {
		t.Fatalf("the second sync did not load the checkpoint: %+v", cp)
	}
	// a failing source keeps nothing
	failing := &cpConnector{system: "failing", err: errors.New("source rejected the page")}
	deps.Connectors = func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{failing}, nil }
	if _, err := q.Enqueue(t.Context(), tenantA, jobs.ConnectorSync, `{"mode":"full"}`, "k3", time.Time{}, 1); err != nil {
		t.Fatal(err)
	}
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	q.Wait()
	if k := e.checkpoint(t, "failing"); k != nil {
		t.Errorf("a failed sync left a checkpoint: %+v", k)
	}
}
