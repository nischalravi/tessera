package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ObjectStore keeps segments in a cloud object store: S3, Azure Blob or GCS
// (internal/objstore), reached through the safehttp client with the
// workload's own credentials. Writes are create-only and read back.
type ObjectStore struct{ S objstore.Store }

// Location implements BlobStore.
func (o *ObjectStore) Location() string { return store.LocationRemote }

// Put implements BlobStore: create-only, then read back and compare, so a
// store that dropped or altered the write is caught here.
func (o *ObjectStore) Put(ctx context.Context, key string, data []byte) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if len(data) > MaxBlobBytes {
		return fmt.Errorf("archive: segment of %d bytes is over the %d byte limit", len(data), MaxBlobBytes)
	}
	_, err := o.S.Put(ctx, key, data, objstore.PutOptions{ContentType: "application/octet-stream"})
	if errors.Is(err, objstore.ErrExists) {
		// fine only for a retry of the very same bytes
		if old, gerr := o.Get(ctx, key); gerr == nil && bytes.Equal(old, data) {
			return nil
		}
		return ErrExists
	}
	if err != nil {
		return fmt.Errorf("archive: upload: %w", err)
	}
	got, err := o.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("archive: verify after upload: %w", err)
	}
	if !bytes.Equal(got, data) {
		return errors.New("archive: verify after upload: the stored object differs from what was written")
	}
	return nil
}

// Get implements BlobStore.
func (o *ObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	b, err := o.S.Get(ctx, key)
	if errors.Is(err, objstore.ErrNotFound) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, fmt.Errorf("archive: download: %w", err)
	}
	if len(b) > MaxBlobBytes {
		return nil, fmt.Errorf("archive: object %s is over the %d byte limit", key, MaxBlobBytes)
	}
	return b, nil
}
