// Package connsync is the framework shared by the production read connectors
// (Okta, Entra ID, and later Google Workspace and Workday). It holds what
// every one of them needs and none should write twice:
//
//   - checkpoints: where an incremental sync resumes, loaded and saved through
//     a Store that ingest places in the context, so a connector never touches
//     the database (internal/archtest) and a failed ingest rolls the checkpoint
//     back with the rest of its transaction;
//   - Mode: full versus incremental, with a full re-sync on demand;
//   - Backoff: a bounded wait that honours Retry-After;
//   - Client: a retrying, size-bounded JSON client over an internal/safehttp
//     client (never http.DefaultClient);
//   - base URL validation, same-origin checks for server-supplied page links,
//     and secret references that never print their value.
package connsync

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Mode says how much a sync reads.
type Mode int

const (
	// Incremental (the zero value) resumes from the checkpoint when there is
	// a usable one, and reads everything otherwise.
	Incremental Mode = iota
	// Full ignores the checkpoint and reads everything.
	Full
)

func (m Mode) String() string {
	if m == Full {
		return "full"
	}
	return "incremental"
}

type modeKey struct{}

// WithMode returns ctx asking connectors for the given mode. This is how a
// full re-sync is requested on demand.
func WithMode(ctx context.Context, m Mode) context.Context {
	return context.WithValue(ctx, modeKey{}, m)
}

// ModeFrom returns the requested mode (Incremental when none was set).
func ModeFrom(ctx context.Context) Mode {
	m, _ := ctx.Value(modeKey{}).(Mode)
	return m
}

// Checkpoint is where an incremental sync of one named stream resumes.
type Checkpoint struct {
	// Cursor is an opaque position: a timestamp watermark or a delta link.
	Cursor string
	// State is the snapshot the cursor applies to (see EncodeState).
	State []byte
	// FullSyncAt is when the last full read finished.
	FullSyncAt *time.Time
	UpdatedAt  time.Time
}

// Store persists checkpoints for one tenant. Load returns (nil, nil) when
// there is none. ingest provides an implementation over the tenant
// transaction (ingest.Sync puts it in the context).
type Store interface {
	Load(ctx context.Context, system, name string) (*Checkpoint, error)
	Save(ctx context.Context, system, name string, cp *Checkpoint) error
	Delete(ctx context.Context, system, name string) error
}

type storeKey struct{}

// WithStore returns ctx carrying the checkpoint store.
func WithStore(ctx context.Context, s Store) context.Context {
	return context.WithValue(ctx, storeKey{}, s)
}

// StoreFrom returns the checkpoint store in ctx, or nil (the connector then
// always reads everything and keeps nothing).
func StoreFrom(ctx context.Context) Store {
	s, _ := ctx.Value(storeKey{}).(Store)
	return s
}

// Plan is the decision for one sync of one stream.
type Plan struct {
	Full   bool
	Reason string // why a full read was chosen, for the connector's own status
	Prior  *Checkpoint
}

// Decide chooses full or incremental for a stream. A full read is chosen when
// it was asked for, when nothing usable is stored, or when the last full read
// is older than maxAge (an incremental read cannot see deletions for sources
// without a deletion feed, so it is repaired by periodic full reads). maxAge
// zero disables that rule.
func Decide(ctx context.Context, system, name string, now time.Time, maxAge time.Duration) (Plan, error) {
	if ModeFrom(ctx) == Full {
		return Plan{Full: true, Reason: "requested"}, nil
	}
	st := StoreFrom(ctx)
	if st == nil {
		return Plan{Full: true, Reason: "no checkpoint store"}, nil
	}
	cp, err := st.Load(ctx, system, name)
	if err != nil {
		return Plan{}, fmt.Errorf("connsync: load checkpoint: %w", err)
	}
	switch {
	case cp == nil:
		return Plan{Full: true, Reason: "no checkpoint"}, nil
	case cp.Cursor == "" || len(cp.State) == 0:
		return Plan{Full: true, Reason: "checkpoint is empty", Prior: cp}, nil
	case maxAge > 0 && (cp.FullSyncAt == nil || now.Sub(*cp.FullSyncAt) > maxAge):
		return Plan{Full: true, Reason: "last full sync is too old", Prior: cp}, nil
	}
	return Plan{Prior: cp}, nil
}

// MemoryStore is an in-memory Store for tests and tools.
type MemoryStore struct {
	mu sync.Mutex
	m  map[[2]string]Checkpoint
}

func (s *MemoryStore) Load(_ context.Context, system, name string) (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp, ok := s.m[[2]string{system, name}]
	if !ok {
		return nil, nil
	}
	return &cp, nil
}

func (s *MemoryStore) Save(_ context.Context, system, name string, cp *Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[[2]string]Checkpoint{}
	}
	s.m[[2]string{system, name}] = *cp
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, system, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, [2]string{system, name})
	return nil
}

// MaxStateBytes bounds a stored snapshot, compressed. A source too large to
// keep a snapshot of is simply read in full every time.
const MaxStateBytes = 48 << 20

// maxStateInflated bounds a snapshot after decompression.
const maxStateInflated = 512 << 20

// ErrStateTooLarge is returned by EncodeState when the snapshot exceeds MaxStateBytes.
var ErrStateTooLarge = errors.New("connsync: snapshot too large to checkpoint")

// EncodeState serialises a snapshot as gzip-compressed JSON.
func EncodeState(v any) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxStateBytes {
		return nil, ErrStateTooLarge
	}
	return buf.Bytes(), nil
}

// DecodeState is the inverse of EncodeState. Decompression is bounded, so a
// corrupt or hostile row cannot exhaust memory; any error means "read in full".
func DecodeState(b []byte, v any) error {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer zr.Close()
	lr := &io.LimitedReader{R: zr, N: maxStateInflated + 1}
	if err := json.NewDecoder(lr).Decode(v); err != nil {
		return err
	}
	if lr.N <= 0 {
		return errors.New("connsync: snapshot too large")
	}
	return nil
}
