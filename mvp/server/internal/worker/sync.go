package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// RunSync discovers every connector and ingests the result in tx, audits it
// (connectors.sync) and reconciles intended with observed access (issue
// #301). full ignores the connectors' checkpoints. It is the body of the
// on-demand POST /api/connectors/sync, whose request holds tx throughout; the
// connector_sync job uses syncTenant, which holds no transaction while it
// waits on the sources.
func RunSync(ctx context.Context, tx *store.TenantTx, now time.Time, conns []connectors.Connector, full bool, actor string) (ojson.Object, error) {
	results, err := discoverAll(ingest.WithCheckpoints(ctx, tx), conns, full)
	if err != nil {
		return nil, err
	}
	return ingestResults(tx, now, results, actor)
}

// MergeGoverned appends the connectors of a tenant's governed connections to the
// configured ones, except those of a system a configured connector already reads:
// the env-configured connector of a system keeps working as it did, and is not
// read twice because a governed connection of the same system was also activated.
func MergeGoverned(conns, governed []connectors.Connector) []connectors.Connector {
	have := map[string]bool{}
	for _, c := range conns {
		have[c.System()] = true
	}
	out := append([]connectors.Connector(nil), conns...)
	for _, g := range governed {
		if !have[g.System()] {
			have[g.System()] = true
			out = append(out, g)
		}
	}
	return out
}

func discoverAll(ctx context.Context, conns []connectors.Connector, full bool) ([]*connectors.DiscoveryResult, error) {
	results, _, err := discoverGuarded(ctx, conns, full, nil)
	return results, err
}

// callGuard is what discoverGuarded needs of a Guard: connection ids by system
// name, and the guarded call. A system with no connection is called unguarded
// (a demo connector, a flat file).
type callGuard struct {
	do  func(ctx context.Context, connID string, fn func(context.Context) error) error
	ids map[string]string
}

// discoverGuarded is discoverAll under per-target limits. A connector whose
// breaker is open, or whose rate limit is spent, is skipped (named in the
// second result) instead of failing the whole sync: the others are read, and
// the skipped one is read again by the next sync once the breaker closes.
func discoverGuarded(ctx context.Context, conns []connectors.Connector, full bool, g *callGuard) ([]*connectors.DiscoveryResult, []string, error) {
	if full {
		ctx = connsync.WithMode(ctx, connsync.Full)
	}
	var results []*connectors.DiscoveryResult
	var skipped []string
	for _, cn := range conns {
		var res *connectors.DiscoveryResult
		discover := func(ctx context.Context) (err error) {
			res, err = cn.Discover(ctx)
			return err
		}
		var err error
		if id := g.id(cn.System()); id != "" {
			err = g.do(ctx, id, discover)
			if errors.Is(err, ErrBreakerOpen) || errors.Is(err, ErrRateLimited) {
				skipped = append(skipped, cn.System())
				continue
			}
		} else {
			err = discover(ctx)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: discover: %w", cn.System(), err)
		}
		if res != nil && res.System == "" {
			res.System = cn.System()
		}
		results = append(results, res)
	}
	return results, skipped, nil
}

func (g *callGuard) id(system string) string {
	if g == nil || g.do == nil {
		return ""
	}
	return g.ids[system]
}

func ingestResults(tx *store.TenantTx, now time.Time, results []*connectors.DiscoveryResult, actor string) (ojson.Object, error) {
	stats, err := ingest.Discovery(tx, now, results, false)
	if err != nil {
		return nil, err
	}
	out := stats.Object()
	if stats.HeldIdentities+stats.HeldAccounts > 0 {
		// the deletion guard held status changes the sources reported (Admin → Held deletions)
		out = append(out, ojson.KV{Key: "held_identities", Value: stats.HeldIdentities}, ojson.KV{Key: "held_accounts", Value: stats.HeldAccounts})
	}
	if err := tx.Audit(now, actor, "connectors.sync", out); err != nil {
		return nil, err
	}
	if _, err := reconcile.RunDrift(tx, now, actor); err != nil {
		return nil, err
	}
	return out, nil
}

// syncTenant is RunSync for a worker. The sources are read with no transaction
// open: a slow source must not hold the database's write lock (on SQLite that
// stops every other writer, the worker's own lease heartbeat included) or sit
// in an open Postgres transaction. Then the results, the checkpoints the
// connectors moved and the sync jobs of the agent-bound connections are written
// in one transaction, so a failed ingest still rolls the checkpoints back with
// the records. window keys the agent jobs (the queue job's id).
func (d *Deps) syncTenant(ctx context.Context, t tenancy.ID, now time.Time, conns []connectors.Connector, full bool, actor, window string) (ojson.Object, error) {
	cps := &bufferedCheckpoints{db: d.DB, tenant: t, pending: map[[2]string]*pendingCheckpoint{}}
	g, err := d.callGuard(ctx, t)
	if err != nil {
		return nil, err
	}
	results, skipped, err := discoverGuarded(connsync.WithStore(ctx, cps), conns, full, g)
	if err != nil {
		return nil, err
	}
	var out ojson.Object
	err = d.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if err := cps.apply(tx); err != nil {
			return err
		}
		var err error
		if out, err = ingestResults(tx, now, results, actor); err != nil {
			return err
		}
		n, err := QueueAgentSyncs(tx, now, window)
		if err != nil {
			return err
		}
		if n > 0 {
			out = append(out, ojson.KV{Key: "agent_jobs_queued", Value: n})
		}
		if len(skipped) > 0 {
			out = append(out, ojson.KV{Key: "skipped_by_limits", Value: skipped})
			if err := tx.Audit(now, actor, "connectors.sync_skipped", ojson.Object{{Key: "systems", Value: skipped},
				{Key: "reason", Value: "circuit breaker open or rate limit spent"}, {Key: "job_id", Value: window}}); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// callGuard builds the tenant's guard for one sync: nil when the worker has
// no Guard.
func (d *Deps) callGuard(ctx context.Context, t tenancy.ID) (*callGuard, error) {
	if d.Guard == nil {
		return nil, nil
	}
	ids := map[string]string{}
	err := d.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		cs, err := tx.Connections()
		if err != nil {
			return err
		}
		for _, c := range cs {
			if c.RetiredAt == nil {
				ids[c.System] = c.ID
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &callGuard{ids: ids, do: func(ctx context.Context, connID string, fn func(context.Context) error) error {
		return d.Guard.Do(ctx, t, connID, fn)
	}}, nil
}

type pendingCheckpoint struct {
	cp      *connsync.Checkpoint
	deleted bool
}

// bufferedCheckpoints is the connsync.Store of a worker's sync: it reads the
// stored checkpoints in short read transactions, keeps what the connectors
// save or delete in memory (and serves it back to them), and apply writes it
// in the ingest transaction.
type bufferedCheckpoints struct {
	db     *store.DB
	tenant tenancy.ID

	mu      sync.Mutex
	pending map[[2]string]*pendingCheckpoint
}

func (b *bufferedCheckpoints) Load(ctx context.Context, system, name string) (*connsync.Checkpoint, error) {
	b.mu.Lock()
	p, ok := b.pending[[2]string{system, name}]
	b.mu.Unlock()
	if ok {
		if p.deleted {
			return nil, nil
		}
		return p.cp, nil
	}
	var cp *connsync.Checkpoint
	err := b.db.ReadTenant(ctx, b.tenant, func(tx *store.TenantTx) error {
		k, err := tx.ConnectorCheckpoint(system, name)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		cp = &connsync.Checkpoint{Cursor: k.Cursor, State: k.State, FullSyncAt: k.FullSyncAt, UpdatedAt: k.UpdatedAt}
		return nil
	})
	return cp, err
}

func (b *bufferedCheckpoints) Save(_ context.Context, system, name string, cp *connsync.Checkpoint) error {
	b.mu.Lock()
	b.pending[[2]string{system, name}] = &pendingCheckpoint{cp: cp}
	b.mu.Unlock()
	return nil
}

func (b *bufferedCheckpoints) Delete(_ context.Context, system, name string) error {
	b.mu.Lock()
	b.pending[[2]string{system, name}] = &pendingCheckpoint{deleted: true}
	b.mu.Unlock()
	return nil
}

func (b *bufferedCheckpoints) apply(tx *store.TenantTx) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, p := range b.pending {
		if p.deleted {
			if err := tx.DeleteConnectorCheckpoint(k[0], k[1]); err != nil {
				return err
			}
			continue
		}
		if err := tx.PutConnectorCheckpoint(&store.ConnectorCheckpoint{System: k[0], Name: k[1], Cursor: p.cp.Cursor,
			State: p.cp.State, FullSyncAt: p.cp.FullSyncAt, UpdatedAt: p.cp.UpdatedAt}); err != nil {
			return err
		}
	}
	return nil
}
