package audit_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

func (f *ledgerFixture) checkpointer(now time.Time) *audit.Checkpointer {
	return &audit.Checkpointer{DB: f.db, Sealer: f.sealer, Sink: &audit.FileSink{Path: f.anchors},
		Clock: timeutil.Frozen(now), Issuer: "http://localhost:5173", Every: 5 * time.Minute, EveryEvents: 1000}
}

// checkpointed is a ledger with two anchored checkpoints in tenant A:
// events 1..5, checkpoint at 6 (its own event), events 7..9, checkpoint at 10.
func checkpointed(t *testing.T) *ledgerFixture {
	t.Helper()
	f := newLedger(t)
	f.record(t, tenantA, 5)
	f.record(t, tenantB, 3)
	if res, err := f.checkpointer(t0).Run(context.Background(), true); err != nil || res.Created != 2 || res.Anchored != 2 {
		t.Fatalf("checkpoint run: %+v %v", res, err)
	}
	f.record(t, tenantA, 3)
	if res, err := f.checkpointer(t0.Add(time.Minute)).Run(context.Background(), true); err != nil || res.Created != 1 {
		t.Fatalf("second checkpoint run: %+v %v", res, err)
	}
	return f
}

func (f *ledgerFixture) verify(t *testing.T, tn tenancy.ID, o audit.VerifyOptions) audit.Report {
	t.Helper()
	ctx := context.Background()
	if o.Keys == nil {
		pub, err := audit.PlatformPublicKeys(ctx, f.db)
		if err != nil {
			t.Fatal(err)
		}
		o.Keys = pub
	}
	var rep audit.Report
	if err := f.db.ReadTenant(ctx, tn, func(tx *store.TenantTx) error {
		var err error
		rep, err = audit.Verify(tx, "t", o)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rep
}

func (f *ledgerFixture) anchorSet(t *testing.T) *audit.AnchorSet {
	t.Helper()
	s, err := audit.ReadAnchors(f.anchors)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tamper(t *testing.T, f *ledgerFixture) *store.AuditTamper {
	t.Helper()
	tp, err := f.db.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.DropTriggers(context.Background()); err != nil {
		t.Fatal(err)
	}
	return tp
}

func TestVerify_Clean(t *testing.T) {
	f := checkpointed(t)
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		rep := f.verify(t, tn, audit.VerifyOptions{Anchors: f.anchorSet(t), Now: t0.Add(2 * time.Minute)})
		if rep.ExitCode != 0 || rep.Result != "ok" || len(rep.Problems) != 0 {
			t.Errorf("%s: %+v", tn, rep)
		}
	}
	rep := f.verify(t, tenantA, audit.VerifyOptions{Anchors: f.anchorSet(t)})
	if rep.Events != 10 || rep.Checkpoints != 2 || rep.Anchored != 2 || rep.FirstSeq != 1 || rep.LastSeq != 10 {
		t.Errorf("report: %+v", rep)
	}
	// a sub-range links to the event before it
	if rep := f.verify(t, tenantA, audit.VerifyOptions{FromSeq: 4, ToSeq: 8}); rep.ExitCode != 0 || rep.Events != 5 {
		t.Errorf("range: %+v", rep)
	}
	// an idle chain is not checkpointed again
	if res, err := f.checkpointer(t0.Add(time.Hour)).Run(context.Background(), false); err != nil || res.Created != 0 {
		t.Errorf("idle run created %d (%v)", res.Created, err)
	}
}

// TestVerify_Tamper is the design's tamper suite (§19 PR3, §20 E2.5): each
// kind of tampering is detected with its exit code.
func TestVerify_Tamper(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		apply func(t *testing.T, f *ledgerFixture)
		code  int
		kind  string
	}{
		{"edited row", func(t *testing.T, f *ledgerFixture) {
			if err := tamper(t, f).EditDetail(ctx, tenantA, 3, `{"i":99}`); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitHashMismatch, "hash_mismatch"},
		{"edited row after the first checkpoint", func(t *testing.T, f *ledgerFixture) {
			tp := tamper(t, f)
			if err := tp.EditDetail(ctx, tenantA, 8, `{"i":99}`); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitHashMismatch, "hash_mismatch"},
		{"deleted middle row", func(t *testing.T, f *ledgerFixture) {
			if err := tamper(t, f).DeleteEvent(ctx, tenantA, 4); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitSeqGap, "seq_gap"},
		{"deleted last row", func(t *testing.T, f *ledgerFixture) {
			if err := tamper(t, f).DeleteEvent(ctx, tenantA, 10); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitSeqGap, "truncated"},
		{"deleted the last 3 rows", func(t *testing.T, f *ledgerFixture) {
			if err := tamper(t, f).TruncateTail(ctx, tenantA, 7, false, false); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitSeqGap, "truncated"},
		{"deleted the last 3 rows and rewound the head", func(t *testing.T, f *ledgerFixture) {
			// the checkpoint row at 10 still certifies the removed tail
			if err := tamper(t, f).TruncateTail(ctx, tenantA, 7, false, true); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitSeqGap, "truncated"},
		{"deleted the last 3 rows and their checkpoint, rewound the head", func(t *testing.T, f *ledgerFixture) {
			// the database is consistent again; only the anchor of seq 10 remains
			if err := tamper(t, f).TruncateTail(ctx, tenantA, 7, true, true); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitSeqGap, "truncated"},
		{"forged checkpoint", func(t *testing.T, f *ledgerFixture) {
			// signed with an attacker's key under the real kid
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			var kid string
			pub, _ := audit.PlatformPublicKeys(ctx, f.db)
			for k := range pub {
				kid = k
			}
			jws, err := audit.SignCheckpoint(&keys.SigningKey{KID: kid, Alg: keys.AlgEdDSA, Key: priv},
				audit.CheckpointPayload{TID: tenantA.String(), Seq: 6, HeadHash: strings.Repeat("0", 64)})
			if err != nil {
				t.Fatal(err)
			}
			if err := tamper(t, f).ReplaceCheckpointJWS(ctx, tenantA, 6, jws); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitCheckpointInvalid, "checkpoint_signature"},
		{"checkpoint from another tenant", func(t *testing.T, f *ledgerFixture) {
			var bJWS string
			_ = f.db.ReadTenant(ctx, tenantB, func(tx *store.TenantTx) error {
				c, err := tx.LatestAuditCheckpoint()
				if err == nil {
					bJWS = c.JWS
				}
				return err
			})
			if err := tamper(t, f).ReplaceCheckpointJWS(ctx, tenantA, 6, bJWS); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitCheckpointInvalid, "checkpoint_payload"},
		{"missing anchor line", func(t *testing.T, f *ledgerFixture) {
			raw, err := os.ReadFile(f.anchors)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.SplitAfter(string(raw), "\n")
			var kept []string
			for _, l := range lines {
				if !strings.Contains(l, tenantA.String()) || !strings.Contains(l, `"seq":10`) {
					kept = append(kept, l)
				}
			}
			if len(kept) == len(lines) {
				t.Fatal("anchor line not found")
			}
			if err := os.WriteFile(f.anchors, []byte(strings.Join(kept, "")), 0o600); err != nil {
				t.Fatal(err)
			}
		}, audit.ExitAnchorMissing, "anchor_missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := checkpointed(t)
			tc.apply(t, f)
			rep := f.verify(t, tenantA, audit.VerifyOptions{Anchors: f.anchorSet(t), Now: t0.Add(2 * time.Minute)})
			if rep.ExitCode != tc.code || rep.Result != "failed" {
				t.Fatalf("exit %d (%s), want %d: %+v", rep.ExitCode, rep.Result, tc.code, rep.Problems)
			}
			found := false
			for _, p := range rep.Problems {
				found = found || p.Kind == tc.kind
			}
			if !found {
				t.Errorf("no %s problem in %+v", tc.kind, rep.Problems)
			}
			// the other tenant's chain is unaffected
			if rb := f.verify(t, tenantB, audit.VerifyOptions{Anchors: f.anchorSet(t), Now: t0.Add(2 * time.Minute)}); rb.ExitCode != 0 {
				t.Errorf("tenant B affected: %+v", rb)
			}
		})
	}
}

// TestVerify_TruncationWindow documents what truncation verify cannot see
// (see the Truncation comment in verify.go): without the anchor source, a
// tail removed together with its checkpoint rows and a rewound head; with it,
// only the events after the newest anchored checkpoint.
func TestVerify_TruncationWindow(t *testing.T) {
	ctx := context.Background()
	f := checkpointed(t)
	if err := tamper(t, f).TruncateTail(ctx, tenantA, 7, true, true); err != nil {
		t.Fatal(err)
	}
	if rep := f.verify(t, tenantA, audit.VerifyOptions{}); rep.ExitCode != 0 || rep.LastSeq != 7 {
		t.Errorf("without anchors a covered-up truncation is invisible to the database alone: %+v", rep)
	}
	if rep := f.verify(t, tenantA, audit.VerifyOptions{Anchors: f.anchorSet(t)}); rep.ExitCode != audit.ExitSeqGap {
		t.Errorf("with anchors: %+v", rep)
	}

	g := checkpointed(t)
	g.record(t, tenantA, 3) // 11..13, after the newest anchored checkpoint (10)
	if err := tamper(t, g).TruncateTail(ctx, tenantA, 10, true, true); err != nil {
		t.Fatal(err)
	}
	rep := g.verify(t, tenantA, audit.VerifyOptions{Anchors: g.anchorSet(t), Now: t0.Add(2 * time.Minute)})
	if rep.ExitCode != 0 || rep.LastSeq != 10 {
		t.Errorf("the unanchored tail is the documented window: %+v", rep)
	}

	// a range that ends before the newest checkpoint is not a truncation
	h := checkpointed(t)
	if rep := h.verify(t, tenantA, audit.VerifyOptions{Anchors: h.anchorSet(t), ToSeq: 5}); rep.ExitCode != 0 {
		t.Errorf("sub-range: %+v", rep)
	}
}

// TestVerify_IgnoresUnverifiableAnchors: anchor lines no platform key
// verifies (another database's, after a dev reseed) cannot claim a longer
// chain; they are counted and ignored.
func TestVerify_IgnoresUnverifiableAnchors(t *testing.T) {
	f := checkpointed(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	jws, err := audit.SignCheckpoint(&keys.SigningKey{KID: "other-db", Alg: keys.AlgEdDSA, Key: priv},
		audit.CheckpointPayload{TID: tenantA.String(), Seq: 99, HeadHash: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&audit.FileSink{Path: f.anchors}).Anchor(context.Background(), audit.Anchor{TID: tenantA.String(),
		Seq: 99, HeadHash: strings.Repeat("0", 64), JWS: jws}); err != nil {
		t.Fatal(err)
	}
	rep := f.verify(t, tenantA, audit.VerifyOptions{Anchors: f.anchorSet(t), Now: t0.Add(2 * time.Minute)})
	if rep.ExitCode != 0 || rep.AnchorsUnverified != 1 {
		t.Errorf("%+v", rep)
	}
}

// TestVerify_StaleAnchoring: events older than 10 minutes with no anchored
// checkpoint are a warning, or exit 6 with Strict.
func TestVerify_StaleAnchoring(t *testing.T) {
	f := checkpointed(t)
	f.record(t, tenantA, 1) // at t0, after the last checkpoint
	o := audit.VerifyOptions{Anchors: f.anchorSet(t), Now: t0.Add(time.Hour)}
	rep := f.verify(t, tenantA, o)
	if rep.ExitCode != 0 || rep.Result != "warning" || len(rep.Problems) != 1 || rep.Problems[0].Code != audit.ExitStaleAnchoring {
		t.Errorf("non-strict: %+v", rep)
	}
	o.Strict = true
	if rep := f.verify(t, tenantA, o); rep.ExitCode != audit.ExitStaleAnchoring {
		t.Errorf("strict: %+v", rep)
	}
}

// TestVerify_WithoutKeysFailsCheckpoints: a verifier without the platform
// keys (or with a revoked key) cannot accept any checkpoint.
func TestVerify_WithoutKeysFailsCheckpoints(t *testing.T) {
	f := checkpointed(t)
	rep := f.verify(t, tenantA, audit.VerifyOptions{Keys: map[string]ed25519.PublicKey{}})
	if rep.ExitCode != audit.ExitCheckpointInvalid {
		t.Errorf("%+v", rep)
	}
}

func TestCheckpointJWS(t *testing.T) {
	f := newLedger(t)
	ctx := context.Background()
	var key *keys.SigningKey
	if err := f.db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		var err error
		key, err = keys.ActivePlatformKey(s, f.sealer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pub, err := audit.PlatformPublicKeys(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	p := audit.CheckpointPayload{Iss: "https://t.example", TID: tenantA.String(), Slug: "tenant-a", Seq: 7, HeadHash: strings.Repeat("a", 64), IAT: 1}
	jws, err := audit.SignCheckpoint(key, p)
	if err != nil {
		t.Fatal(err)
	}
	got, kid, err := audit.VerifyCheckpointJWS(jws, pub)
	if err != nil || got != p || kid != key.KID {
		t.Fatalf("round trip: %+v %s %v", got, kid, err)
	}
	parts := strings.Split(jws, ".")
	for name, bad := range map[string]string{
		"payload swapped":   parts[0] + "." + strings.TrimRight(parts[1], "A") + "B." + parts[2],
		"signature cut":     parts[0] + "." + parts[1] + ".",
		"alg none":          "eyJhbGciOiJub25lIiwidHlwIjoidGVzc2VyYS1hdWRpdC1jaGVja3BvaW50K2p3dCJ9." + parts[1] + ".",
		"not a jws":         "garbage",
		"too large":         strings.Repeat("a", 5000),
		"wrong typ (HS256)": "eyJhbGciOiJIUzI1NiJ9." + parts[1] + "." + parts[2],
	} {
		if _, _, err := audit.VerifyCheckpointJWS(bad, pub); !errors.Is(err, audit.ErrCheckpointSignature) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// TestAnchorSinks: the file sink appends one fsynced line per checkpoint and
// numbers them; the S3 stub fails, and a failing sink leaves the checkpoint
// "failed" for the next run.
func TestAnchorSinks(t *testing.T) {
	f := newLedger(t)
	f.record(t, tenantA, 2)
	ck := f.checkpointer(t0)
	ck.Sink = audit.S3Sink{URL: "s3://bucket/prefix"}
	res, err := ck.Run(context.Background(), true)
	if err != nil || res.Created != 1 || res.Failed != 1 || res.Anchored != 0 {
		t.Fatalf("s3 stub: %+v %v", res, err)
	}
	// the next run with a working sink anchors the failed checkpoint
	res, err = f.checkpointer(t0).Run(context.Background(), false)
	if err != nil || res.Created != 0 || res.Anchored != 1 {
		t.Fatalf("retry: %+v %v", res, err)
	}
	var cks []*store.AuditCheckpoint
	_ = f.db.ReadTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		var err error
		cks, err = tx.AuditCheckpoints(0, 0)
		return err
	})
	if len(cks) != 1 || cks[0].AnchorStatus != store.AnchorAnchored || cks[0].AnchorRef == nil || *cks[0].AnchorRef != "file:1" ||
		cks[0].AnchorAttempts != 2 {
		t.Errorf("checkpoint after retry: %+v", cks[0])
	}
	fi, err := os.Stat(f.anchors)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("anchor file: %v %v", fi, err)
	}
	for _, u := range []string{"http://x", "ftp://y", "file://"} {
		if _, err := audit.NewSink(u); err == nil {
			t.Errorf("NewSink(%q) accepted", u)
		}
	}
	if s, err := audit.NewSink(""); s != nil || err != nil {
		t.Errorf("empty anchor URL: %v %v", s, err)
	}
	if _, err := audit.ParseAnchors(strings.NewReader("{\"tid\":1}\n")); err == nil {
		t.Error("malformed anchor line accepted")
	}
}
