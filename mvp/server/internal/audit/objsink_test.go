package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
)

// memStore is an in-memory create-only object store that records the options.
type memStore struct {
	objs map[string][]byte
	opts map[string]objstore.PutOptions
	loc  string
	// retention (a Verifier) when set
	verify func() error
}

func (m *memStore) Location() string { return m.loc }
func (m *memStore) Put(_ context.Context, k string, b []byte, o objstore.PutOptions) (string, error) {
	if _, ok := m.objs[k]; ok {
		return "", objstore.ErrExists
	}
	m.objs[k], m.opts[k] = b, o
	return "ver1", nil
}
func (m *memStore) Get(_ context.Context, k string) ([]byte, error) {
	if b, ok := m.objs[k]; ok {
		return b, nil
	}
	return nil, objstore.ErrNotFound
}

type verifyingStore struct{ *memStore }

func (v verifyingStore) VerifyRetention(context.Context) error { return v.verify() }

const sinkTID = "0a1b2c3d-0000-4000-8000-000000000001"

func TestObjectSink_AnchorsOnceWithRetention(t *testing.T) {
	m := &memStore{objs: map[string][]byte{}, opts: map[string]objstore.PutOptions{}, loc: "azure://acct123/cont/anch"}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s := &audit.ObjectSink{Store: m, Retain: true, Now: func() time.Time { return now }}
	a := audit.Anchor{TID: sinkTID, Seq: 5, HeadHash: "hh", JWS: "a.b.c"}
	ref, err := s.Anchor(context.Background(), a)
	if err != nil || ref != "azure://acct123/cont/anch/"+sinkTID+"/5.jws?versionId=ver1" {
		t.Fatalf("%q %v", ref, err)
	}
	o := m.opts[sinkTID+"/5.jws"]
	if !o.RetainUntil.Equal(now.AddDate(audit.S3RetentionYears, 0, 0)) || o.Metadata["head-hash"] != "hh" || o.Metadata["seq"] != "5" {
		t.Errorf("options: %+v", o)
	}
	// a retry of the same anchor is fine; a different JWS under the same key is refused
	if _, err := s.Anchor(context.Background(), a); err != nil {
		t.Fatalf("retry: %v", err)
	}
	a.JWS = "forged"
	if _, err := s.Anchor(context.Background(), a); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("forged anchor: %v", err)
	}
	// keys are built from fixed-alphabet fields only
	for _, bad := range []audit.Anchor{{TID: "../x", Seq: 1}, {TID: sinkTID, Seq: 0}} {
		if _, err := s.Anchor(context.Background(), bad); err == nil {
			t.Errorf("%+v was anchored", bad)
		}
	}
}

func TestObjectSink_GCSNeedsLockedRetention(t *testing.T) {
	m := &memStore{objs: map[string][]byte{}, opts: map[string]objstore.PutOptions{}, loc: "gs://bkt/anch"}
	var verr error = errors.New("no locked retention policy")
	vs := verifyingStore{m}
	m.verify = func() error { return verr }
	sink := &audit.ObjectSink{Store: vs}
	a := audit.Anchor{TID: sinkTID, Seq: 1, JWS: "j"}
	if _, err := sink.Anchor(context.Background(), a); err == nil || len(m.objs) != 0 {
		t.Fatalf("anchored into an unlocked bucket: %v", err)
	}
	verr = nil
	if _, err := sink.Anchor(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if m.opts[sinkTID+"/1.jws"].RetainUntil != (time.Time{}) {
		t.Error("GCS retention is the bucket's, not a per-object date")
	}
}

func TestNewSink_CloudSchemes(t *testing.T) {
	if _, err := audit.NewSink("azure://acct123/cont/p"); err == nil {
		t.Error("an azure sink without credentials sources was built")
	}
	if _, err := audit.NewSink("gopher://x"); err == nil || !strings.Contains(err.Error(), "azure://") {
		t.Errorf("unsupported scheme message: %v", err)
	}
}
