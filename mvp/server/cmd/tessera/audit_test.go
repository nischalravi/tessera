package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var acme = tenancy.MustParse("00000000-0000-4000-8000-00000000ac3e")

// auditDB builds a database with tenant "acme" holding 5 events and one
// checkpoint made by `tessera audit checkpoint`, anchored in anchors.
func auditDB(t *testing.T) (db, anchors string) {
	t.Helper()
	dir := t.TempDir()
	db, anchors = filepath.Join(dir, "audit.db"), filepath.Join(dir, "anchors.jsonl")
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_AUDIT_ANCHOR", "file://"+anchors)
	ctx := context.Background()
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: acme, Slug: "acme", Name: "Acme", CreatedAt: time.Now()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InTenant(ctx, acme, func(tx *store.TenantTx) error {
		for i := range 5 {
			if err := tx.Audit(time.Now(), "system", "test.event", ojson.Object{{Key: "i", Value: i}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(db))
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.EnsureAll(ctx, st, sealer, time.Now()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(ctx, []string{"audit", "checkpoint", "-tenant", "acme", "-db", db}, &out, &out); err != nil {
		t.Fatalf("checkpoint: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "created=1 anchored=1") {
		t.Fatalf("checkpoint output: %s", out.String())
	}
	return db, anchors
}

func withStore(t *testing.T, db string, fn func(*store.DB, *store.AuditTamper)) {
	t.Helper()
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tp, err := st.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.DropTriggers(context.Background()); err != nil {
		t.Fatal(err)
	}
	fn(st, tp)
}

func exitCode(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if err != nil {
		return 1
	}
	return 0
}

// TestAuditVerify_ExitCodes runs `tessera audit verify` against each kind of
// tampering (design §19 PR3): edited row 2, deleted middle row 3, truncated
// tail 3 (even with the head rewound and the checkpoint row deleted, since
// the anchor remains), forged checkpoint 4, missing anchor line 5.
func TestAuditVerify_ExitCodes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		apply func(t *testing.T, db, anchors string)
		want  int
	}{
		{"clean", func(*testing.T, string, string) {}, 0},
		{"edited row", func(t *testing.T, db, _ string) {
			withStore(t, db, func(_ *store.DB, tp *store.AuditTamper) {
				if err := tp.EditDetail(ctx, acme, 2, `{"i":42}`); err != nil {
					t.Fatal(err)
				}
			})
		}, 2},
		{"deleted middle row", func(t *testing.T, db, _ string) {
			withStore(t, db, func(_ *store.DB, tp *store.AuditTamper) {
				if err := tp.DeleteEvent(ctx, acme, 3); err != nil {
					t.Fatal(err)
				}
			})
		}, 3},
		{"deleted the last 2 rows", func(t *testing.T, db, _ string) {
			withStore(t, db, func(_ *store.DB, tp *store.AuditTamper) {
				if err := tp.TruncateTail(ctx, acme, 4, false, false); err != nil {
					t.Fatal(err)
				}
			})
		}, 3},
		{"deleted the last 2 rows, their checkpoint, and rewound the head", func(t *testing.T, db, _ string) {
			withStore(t, db, func(_ *store.DB, tp *store.AuditTamper) {
				if err := tp.TruncateTail(ctx, acme, 4, true, true); err != nil {
					t.Fatal(err)
				}
			})
		}, 3},
		{"forged checkpoint", func(t *testing.T, db, _ string) {
			withStore(t, db, func(st *store.DB, tp *store.AuditTamper) {
				pub, err := audit.PlatformPublicKeys(ctx, st)
				if err != nil {
					t.Fatal(err)
				}
				var kid string
				for k := range pub {
					kid = k
				}
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				jws, err := audit.SignCheckpoint(&keys.SigningKey{KID: kid, Alg: keys.AlgEdDSA, Key: priv},
					audit.CheckpointPayload{TID: acme.String(), Slug: "acme", Seq: 6, HeadHash: strings.Repeat("f", 64)})
				if err != nil {
					t.Fatal(err)
				}
				if err := tp.ReplaceCheckpointJWS(ctx, acme, 6, jws); err != nil {
					t.Fatal(err)
				}
			})
		}, 4},
		{"missing anchor line", func(t *testing.T, _, anchors string) {
			if err := os.WriteFile(anchors, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, anchors := auditDB(t)
			tc.apply(t, db, anchors)
			var out bytes.Buffer
			err := run(ctx, []string{"audit", "verify", "-tenant", "acme", "-db", db, "-anchors", "file://" + anchors}, &out, &out)
			if got := exitCode(err); got != tc.want {
				t.Errorf("exit %d, want %d (%v)\n%s", got, tc.want, err, out.String())
			}
			// -all covers the same tenant (and the empty platform chain)
			err = run(ctx, []string{"audit", "verify", "-all", "-json", "-db", db, "-anchors", "file://" + anchors}, &out, &out)
			if got := exitCode(err); got != tc.want {
				t.Errorf("-all: exit %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAuditExportAndUsage(t *testing.T) {
	ctx := context.Background()
	db, _ := auditDB(t)
	var out bytes.Buffer
	if err := run(ctx, []string{"audit", "export", "-tenant", "acme", "-db", db}, &out, &out); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&out)
	n := 0
	for sc.Scan() {
		n++
		if ok, _, err := audit.VerifyRecord(sc.Bytes()); err != nil || !ok {
			t.Errorf("line %d does not verify: %v", n, err)
		}
	}
	if n != 6 {
		t.Errorf("exported %d events, want 6 (5 + the checkpoint's)", n)
	}
	for _, args := range [][]string{
		{"audit"},
		{"audit", "rewrite", "-all"},
		{"audit", "verify", "-db", db},
		{"audit", "verify", "-all", "-tenant", "acme", "-db", db},
		{"audit", "export", "-all", "-db", db},
		{"audit", "verify", "-tenant", "nope", "-db", db},
		{"audit", "verify", "-tenant", "acme", "-from-seq", "5", "-to-seq", "2", "-db", db},
		{"audit", "verify", "-tenant", "acme", "-db", filepath.Join(t.TempDir(), "missing.db")},
	} {
		if err := run(ctx, args, &out, &out); err == nil || exitCode(err) != 1 {
			t.Errorf("%v: %v", args, err)
		}
	}
}
