package lp_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/lp_evidence_v1.json")

// what the candidate carries (internal/api lp.go, lpPropose): the confidence, the evaluator's check, the diff summary.
const candidateEvidence = `{"confidence":{"level":"high","reasons":["no call in 120 days","CloudTrail management events cover the window"]},` +
	`"verification":{"kept":[{"action":"s3:GetObject","resource":"arn:aws:s3:::reports/*"}],"broken":[],"inexact":[],"added":0,"removed":3,"ok":true,` +
	`"auto_applicable":true,"reasons":[]},"diff_summary":{"gained":0,"lost":3,"conditional_changed":0,"fidelity_changed":0,"principals_affected":1,"groups":1,"recomputed":1,"global":false},"unused_days":120,"snapshot":"snap"}`

// revoke carries one candidate through the loop to revoked (every step at its own instant) and returns the revocation
// and the time it was revoked.
func revoke(t *testing.T, tx *store.TenantTx, ex *fakeExec, n int) (*store.LPRevocation, time.Time) {
	t.Helper()
	staged(t, tx, nil)
	c := cand(n, role(n), "111122223333")
	c.Evidence = candidateEvidence
	must(t, lp.Propose(tx, now, "alice", c))
	_, err := lp.Approve(tx, now.Add(time.Minute), "alice", []string{c.ID}, nil, false, ex)
	must(t, err)
	at := now.AddDate(0, 0, 8).Add(time.Duration(n) * time.Hour)
	ok := map[string]lp.Recheck{c.ID: {OK: true}}
	_, err = lp.Run(tx, at, ex, false, ok)
	must(t, err)
	ex.status["op-"+c.ID] = "verified"
	_, err = lp.Run(tx, at.Add(time.Minute), ex, false, ok)
	must(t, err)
	r, err := tx.LPRevocation(c.ID)
	must(t, err)
	if r.State != store.LPRevoked {
		t.Fatalf("state = %s, want revoked", r.State)
	}
	return r, at.Add(time.Minute)
}

func finalize(t *testing.T, tx *store.TenantTx, ex *fakeExec, r *store.LPRevocation) {
	t.Helper()
	_, err := lp.Run(tx, r.RestoreUntil.Add(time.Second), ex, false, nil)
	must(t, err)
}

// restoreByDenial records a denial for r, restores it and lets the engine verify the restore.
func restoreByDenial(t *testing.T, tx *store.TenantTx, ex *fakeExec, r *store.LPRevocation, at time.Time) {
	t.Helper()
	must(t, tx.InsertLPDenial(&store.LPDenial{Source: store.LPDenialCloudTrail, EventID: "evt-" + r.ID, Principal: r.Principal, Action: "s3:GetObject",
		Resource: "arn:aws:s3:::reports/q3.csv", ArrivedAt: at, Outcome: store.LPDenialRestoreRequested, RevocationID: r.ID}))
	_, err := lp.Restore(tx, at, lp.ActorDenial, "denial", r.ID, ex)
	must(t, err)
	ex.status["rop-"+r.ID] = "verified"
	_, err = lp.Run(tx, at.Add(4*time.Minute), ex, false, nil)
	must(t, err)
}

// auditEvidence maps the action of each lp.revocation.* audit event of one revocation to its evidence_sha256.
func auditEvidence(t *testing.T, tx *store.TenantTx, id string) map[string]string {
	t.Helper()
	log, err := tx.AuditLog(-1)
	must(t, err)
	out := map[string]string{}
	for _, e := range log {
		if !strings.HasPrefix(e.Action, "lp.revocation.") {
			continue
		}
		var d struct {
			ID       string `json:"id"`
			Evidence string `json:"evidence_sha256"`
		}
		must(t, json.Unmarshal(e.Detail, &d))
		if d.ID == id && d.Evidence != "" {
			out[e.Action] = d.Evidence
		}
	}
	return out
}

func verifyChain(t *testing.T, tx *store.TenantTx) {
	t.Helper()
	rep, err := audit.Verify(tx, "t", audit.VerifyOptions{})
	must(t, err)
	if rep.ExitCode != 0 || rep.Events == 0 || rep.FirstSeq != 1 {
		t.Fatalf("the audit hash chain is not intact: %+v", rep)
	}
}

// The evidence of a finalized revocation holds the usage window, confidence, simulation diff and verified re-read, and
// its digest is the one the audit event of the finalize carries; the hash chain verifies with the evidence in it.
func TestEvidenceFinalized(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		r, revokedAt := revoke(t, tx, ex, 1)
		finalize(t, tx, ex, r)
		e, err := lp.EvidenceFor(tx, r.ID)
		must(t, err)
		if e.State != store.LPFinalized || e.UsageWindow.UnusedDays != 120 || e.UsageWindow.SnapshotID != "snap" {
			t.Fatalf("record = %+v", e)
		}
		if !strings.Contains(string(e.Confidence), `"level":"high"`) || !strings.Contains(string(e.Verification), `"s3:GetObject"`) ||
			!strings.Contains(string(e.Simulation), `"lost":3`) {
			t.Errorf("sections: %s | %s | %s", e.Confidence, e.Verification, e.Simulation)
		}
		if !e.Reread.Verified || e.Reread.At != store.RT(revokedAt) || e.Reread.ExpectedSHA256 != r.CandidateSHA256 {
			t.Errorf("reread = %+v", e.Reread)
		}
		if e.Approval.Path != "staged" || e.Approval.ApprovedBy != "alice" || e.Revoke.OpID != "op-"+r.ID || e.Restore != nil || e.FalsePositive != nil || e.FinalizedAt == "" {
			t.Errorf("record = %+v", e)
		}
		if len(e.Timeline) != 5 || e.Timeline[0].To != store.LPCandidate || e.Timeline[4].To != store.LPFinalized {
			t.Errorf("timeline = %+v", e.Timeline)
		}
		if len(e.SHA256) != 64 {
			t.Fatalf("sha256 = %q", e.SHA256)
		}
		// the record is a pure function of the rows
		if again, err := lp.EvidenceFor(tx, r.ID); err != nil || again.SHA256 != e.SHA256 {
			t.Errorf("a second build differs: %v", err)
		}
		got := auditEvidence(t, tx, r.ID)
		if got["lp.revocation.finalized"] != e.SHA256 || got["lp.revocation.revoked"] == "" || got["lp.revocation.revoked"] == e.SHA256 {
			t.Errorf("audit evidence digests = %v, record %s", got, e.SHA256)
		}
		verifyChain(t, tx)
	})
}

// A restore on a denial is in the record with its trigger, latency and the denial, and the revocation is labelled a
// false positive; the digest is again the one in the chain.
func TestEvidenceRestored(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		r, revokedAt := revoke(t, tx, ex, 1)
		at := revokedAt.Add(2 * time.Hour)
		restoreByDenial(t, tx, ex, r, at)
		e, err := lp.EvidenceFor(tx, r.ID)
		must(t, err)
		if e.State != store.LPRestored || e.Restore == nil || e.Restore.Trigger != "denial" || e.Restore.LatencySeconds == nil || *e.Restore.LatencySeconds != 240 {
			t.Fatalf("record = %+v restore %+v", e, e.Restore)
		}
		if len(e.Restore.Denials) != 1 || e.Restore.Denials[0].EventID != "evt-"+r.ID || e.Restore.Denials[0].Action != "s3:GetObject" {
			t.Errorf("denials = %+v", e.Restore.Denials)
		}
		if e.FalsePositive == nil || e.FalsePositive.Source != "denial" {
			t.Errorf("false positive = %+v", e.FalsePositive)
		}
		if got := auditEvidence(t, tx, r.ID); got["lp.revocation.restored"] != e.SHA256 {
			t.Errorf("audit evidence digests = %v, record %s", got, e.SHA256)
		}
		verifyChain(t, tx)
	})
}

// The metrics: removals that stand, the false-positive and restore rate per confidence level, the median restore
// latency and the auto against staged counts.
func TestMetrics(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		a, _ := revoke(t, tx, ex, 1)
		b, revokedAt := revoke(t, tx, ex, 2)
		finalize(t, tx, ex, a)
		restoreByDenial(t, tx, ex, b, revokedAt.Add(time.Hour))

		at := now.AddDate(0, 0, 45)
		m, err := lp.MetricsFor(tx, at, 60)
		must(t, err)
		if m.Executed != 2 || m.Staged != 2 || m.Auto != 0 || m.ByState["finalized"] != 1 || m.ByState["restored"] != 1 || m.UnusedPermissionsRemoved != 3 {
			t.Errorf("metrics = %+v", m)
		}
		hi := m.Levels[0]
		if hi.Confidence != "high" || hi.Revoked != 2 || hi.Restored != 1 || hi.FalsePositives != 1 || hi.FalsePositivePercent != 50 || hi.RestorePercent != 50 || !hi.Review {
			t.Errorf("high = %+v", hi)
		}
		if med := m.Levels[1]; med.Confidence != "medium" || med.Revoked != 0 || med.FalsePositivePercent != 0 {
			t.Errorf("medium = %+v", med)
		}
		if m.FalsePositivePercent != 50 || m.Restores != 1 || m.RestoresWithinSLO != 1 || m.MedianRestoreSeconds == nil || *m.MedianRestoreSeconds != 240 {
			t.Errorf("rates = %+v", m)
		}
		// outside the window nothing counts
		old, err := lp.MetricsFor(tx, now.AddDate(0, 0, 400), 60)
		must(t, err)
		if old.Executed != 0 || old.MedianRestoreSeconds != nil || old.FalsePositivePercent != 0 {
			t.Errorf("an empty window = %+v", old)
		}
	})
}

// One tenant never sees another's evidence or counts.
func TestEvidenceTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	ex := newExec()
	var id string
	if err := f.DB.InTenant(ctx, f.A.ID, func(tx *store.TenantTx) error {
		r, _ := revoke(t, tx, ex, 1)
		id = r.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.InTenant(ctx, f.B.ID, func(tx *store.TenantTx) error {
		if _, err := lp.EvidenceFor(tx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("another tenant's evidence = %v", err)
		}
		es, err := lp.EvidenceBetween(tx, now, now.AddDate(0, 0, 400), 0)
		if err != nil || len(es) != 0 {
			t.Errorf("another tenant's export = %d, %v", len(es), err)
		}
		m, err := lp.MetricsFor(tx, now.AddDate(0, 0, 45), 60)
		if err != nil || m.Executed != 0 {
			t.Errorf("another tenant's metrics = %+v, %v", m, err)
		}
		if d, err := tx.LPDenialsFor(id); err != nil || len(d) != 0 {
			t.Errorf("another tenant's denials = %v, %v", d, err)
		}
		if _, err := tx.LPFalsePositive(id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("another tenant's label = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

const goldenPath = "../../testdata/golden/lp_evidence_v1.json"

type goldenFile struct {
	Description string `json:"description"`
	Schema      string `json:"schema"`
	// Audit is, per revocation, the evidence_sha256 of each lp.revocation.* audit event that carries one.
	Audit   map[string]map[string]string `json:"audit_evidence_sha256"`
	Records []*lp.Evidence               `json:"records"`
}

// The export of two revocations (one finalized, one restored after a denial) is the golden file: any change to the
// record layout or its digest changes it. The hash chain verifies with the evidence in it.
// Regenerate with: go test ./internal/lp -run TestEvidenceGolden -update
func TestEvidenceGolden(t *testing.T) {
	tenant(t, func(tx *store.TenantTx) {
		ex := newExec()
		a, _ := revoke(t, tx, ex, 1)
		b, revokedAt := revoke(t, tx, ex, 2)
		finalize(t, tx, ex, a)
		restoreByDenial(t, tx, ex, b, revokedAt.Add(time.Hour))
		recs, err := lp.EvidenceBetween(tx, now, now.AddDate(0, 0, 60), 0)
		must(t, err)
		g := goldenFile{Description: "Tessera least-privilege evidence export v1 (LP-10, #666): the records of two revocations of unused AWS access, " +
			"one finalized and one restored after a denial. sha256 is the digest of the record with sha256 empty, marshalled as the server does; " +
			"audit_evidence_sha256 is what the hash-chained audit events of each transition carry.",
			Schema: lp.EvidenceSchema, Records: recs, Audit: map[string]map[string]string{a.ID: auditEvidence(t, tx, a.ID), b.ID: auditEvidence(t, tx, b.ID)}}
		got, err := json.MarshalIndent(g, "", "  ")
		must(t, err)
		got = append(got, '\n')
		if *update {
			must(t, os.WriteFile(goldenPath, got, 0o644))
		}
		want, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(want) != string(got) {
			t.Errorf("the export differs from %s; if the change is intended, regenerate with -update and explain it in the PR\n got: %s", goldenPath, got)
		}
		// every exported record's digest is the one in the chain for a terminal revocation
		for _, e := range recs {
			if e.SHA256 != g.Audit[e.RevocationID]["lp.revocation."+e.State] {
				t.Errorf("%s: record %s is not the digest in the chain %v", e.RevocationID, e.SHA256, g.Audit[e.RevocationID])
			}
		}
		verifyChain(t, tx)
	})
}
