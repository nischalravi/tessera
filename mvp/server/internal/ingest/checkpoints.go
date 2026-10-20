package ingest

import (
	"context"
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// checkpointStore adapts a tenant transaction to connsync.Store. A connector's
// checkpoint is therefore written in the same transaction as the records it
// produced, and is rolled back with them if the ingest fails.
type checkpointStore struct{ c *store.TenantTx }

// WithCheckpoints returns ctx carrying the tenant's connector checkpoints.
// Callers that run a connector's Discover or StreamEvents for ingest pass the
// result as the context, so connectors can sync incrementally.
func WithCheckpoints(ctx context.Context, c *store.TenantTx) context.Context {
	return connsync.WithStore(ctx, checkpointStore{c})
}

func (s checkpointStore) Load(_ context.Context, system, name string) (*connsync.Checkpoint, error) {
	k, err := s.c.ConnectorCheckpoint(system, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &connsync.Checkpoint{Cursor: k.Cursor, State: k.State, FullSyncAt: k.FullSyncAt, UpdatedAt: k.UpdatedAt}, nil
}

func (s checkpointStore) Save(_ context.Context, system, name string, cp *connsync.Checkpoint) error {
	return s.c.PutConnectorCheckpoint(&store.ConnectorCheckpoint{System: system, Name: name, Cursor: cp.Cursor,
		State: cp.State, FullSyncAt: cp.FullSyncAt, UpdatedAt: cp.UpdatedAt})
}

func (s checkpointStore) Delete(_ context.Context, system, name string) error {
	return s.c.DeleteConnectorCheckpoint(system, name)
}
