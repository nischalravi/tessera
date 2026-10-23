package archive_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

type fakeObj struct {
	objs    map[string][]byte
	corrupt bool // Put stores something else
}

func (f *fakeObj) Location() string { return "s3://b" }
func (f *fakeObj) Put(_ context.Context, k string, b []byte, _ objstore.PutOptions) (string, error) {
	if _, ok := f.objs[k]; ok {
		return "", objstore.ErrExists
	}
	if f.corrupt {
		b = append([]byte("x"), b...)
	}
	f.objs[k] = b
	return "", nil
}
func (f *fakeObj) Get(_ context.Context, k string) ([]byte, error) {
	if b, ok := f.objs[k]; ok {
		return b, nil
	}
	return nil, objstore.ErrNotFound
}

const objKey = "00000000-0000-4000-8000-000000000001/audit/00000000-0000-4000-8000-0000000000aa.seg"

func TestObjectStore_WriteOnceAndReadBack(t *testing.T) {
	f := &fakeObj{objs: map[string][]byte{}}
	o := &archive.ObjectStore{S: f}
	ctx := context.Background()
	if o.Location() != store.LocationRemote {
		t.Fatalf("location %q", o.Location())
	}
	if err := o.Put(ctx, objKey, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := o.Put(ctx, objKey, []byte("sealed")); err != nil { // a retry of the same bytes
		t.Fatalf("retry: %v", err)
	}
	if err := o.Put(ctx, objKey, []byte("other")); !errors.Is(err, archive.ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	if b, err := o.Get(ctx, objKey); err != nil || !bytes.Equal(b, []byte("sealed")) {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := o.Get(ctx, "00000000-0000-4000-8000-000000000001/audit/00000000-0000-4000-8000-0000000000bb.seg"); !errors.Is(err, archive.ErrMissing) {
		t.Fatalf("missing: %v", err)
	}
	if err := o.Put(ctx, "../etc/passwd", []byte("x")); err == nil {
		t.Fatal("a bad key was accepted")
	}
	bad := &archive.ObjectStore{S: &fakeObj{objs: map[string][]byte{}, corrupt: true}}
	if err := bad.Put(ctx, objKey, []byte("sealed")); err == nil {
		t.Fatal("a store that altered the write passed the read-back")
	}
}
