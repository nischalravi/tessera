package evidence_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/evidence"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// The revocations of the least-privilege loop carried out in the period are in the pack with their whole evidence
// record and its digest; one carried out after the period is not (issue #666).
func TestPackHasLeastPrivilegeEvidence(t *testing.T) {
	st, ids := testkit.Tiny(t)
	const ev = `{"confidence":{"level":"high","reasons":["no call in 120 days"]},"verification":{"kept":[],"broken":[],"removed":3,"ok":true},` +
		`"diff_summary":{"lost":3},"unused_days":120,"snapshot":"snap"}`
	testkit.Write(t, st, func(c *store.TenantTx) error {
		put := func(id string, executed float64) error {
			payload := `{"prior":"{}"}`
			r := &store.LPRevocation{ID: id, State: store.LPCandidate, Kind: "aws_set_policy_version", Eligibility: store.LPEligAuto, ConnectorID: "conn",
				SnapshotID: "snap", AccountID: "111122223333", Principal: "arn:aws:iam::111122223333:role/" + id, PolicyARN: "arn:aws:iam::111122223333:policy/p",
				UnusedDays: 120, Confidence: "high", Evidence: ev, CandidateSHA256: strings.Repeat("c", 64), RestorePayload: payload,
				RestoreSHA256: lp.DigestPayload(payload), CreatedBy: "alice", CreatedAt: h(0)}
			if err := c.InsertLPRevocation(r); err != nil {
				return err
			}
			at := h(executed)
			r.State, r.ApprovedBy, r.ApprovedAt, r.ExecutedAt, r.RevokedAt, r.OpID = store.LPRevoked, "alice", &at, &at, &at, "op-"+id
			return c.UpdateLPRevocation(r, store.LPCandidate, at)
		}
		if err := put("in", 2); err != nil {
			return err
		}
		return put("late", 60)
	})
	res := generate(t, st, ids, "soc2", nil)
	rows := records(t, unzip(t, res.Zip)[evidence.FileLeastPrivilege])
	if len(rows) != 1 || rows[0]["revocation_id"] != "in" || rows[0]["state"] != "revoked" || rows[0]["confidence"] != "high" ||
		rows[0]["unused_days"] != "120" || rows[0]["approval_path"] != "staged" || rows[0]["reread_verified"] != "false" || len(rows[0]["evidence_sha256"]) != 64 {
		t.Fatalf("rows = %v", rows)
	}
	for _, want := range []string{`"lost":3`, `"usage_window"`, `"sha256":"` + rows[0]["evidence_sha256"] + `"`} {
		if !strings.Contains(rows[0]["evidence"], want) {
			t.Errorf("the evidence cell lacks %s: %s", want, rows[0]["evidence"])
		}
	}
	// a framework that maps least privilege lists the file
	for _, fw := range []string{"soc2", "iso27001", "pci_dss_v4"} {
		listed := false
		for _, c := range generate(t, st, ids, fw, nil).Manifest.Controls {
			for _, f := range c.Files {
				listed = listed || f == evidence.FileLeastPrivilege
			}
		}
		if !listed {
			t.Errorf("no %s control lists the least-privilege evidence", fw)
		}
	}
}
