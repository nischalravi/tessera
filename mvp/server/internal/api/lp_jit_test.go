package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// jitFor seeds a person whose AWS account is alice's principal and a requestable group that is the revoked policy,
// and returns their ids.
func (w *awsWB) jitFor(group string) (identity, groupID int64) {
	w.t.Helper()
	testkit.Write(w.t, w.st, func(tx *store.TenantTx) error {
		id, err := tx.InsertIdentity(&store.Identity{TenantID: w.st.Tenant, ExternalID: "alice-aws", Name: "Alice Aws", Type: "human", Status: "active", CreatedAt: testkit.Now})
		if err != nil {
			return err
		}
		identity = id
		if err := tx.UpsertGroup(&store.Group{TenantID: w.st.Tenant, System: "aws", ExternalID: group, Name: "S3 read (JIT)", Kind: "group", Requestable: true}); err != nil {
			return err
		}
		g, err := tx.GroupByXID("aws", group)
		if err != nil {
			return err
		}
		groupID = g.ID
		_, err = tx.InsertAccount(&store.Account{TenantID: w.st.Tenant, System: "aws", ExternalID: awstest.EstateAlice, IdentityID: &identity,
			Username: "alice", Kind: "human", Status: "active", CreatedAt: &testkit.Now})
		return err
	})
	return identity, groupID
}

func calibrationOf(t *testing.T, w *awsWB, level string) map[string]any {
	t.Helper()
	v := w.c.json("GET", "/api/lp/calibration", "", http.StatusOK).(map[string]any)
	for _, l := range v["levels"].([]any) {
		if m := l.(map[string]any); m["confidence"] == level {
			return m
		}
	}
	t.Fatalf("no %s level in %v", level, v)
	return nil
}

// A JIT request for access revoked in the window labels the revocation a false positive and feeds the calibration;
// the JIT grant is the ordinary time-bound one (approved and expiring as any other: nothing here approves it) and
// the standing grant stays revoked.
func TestLPJIT_ReRequestLabelsFalsePositive(t *testing.T) {
	w := lpOn(t)
	id, _ := w.lpRevoked()
	identity, group := w.jitFor(awstest.EstateS3Read)
	if c := calibrationOf(t, w, "high"); c["revocations"].(float64) != 1 || c["false_positives"].(float64) != 0 {
		t.Fatalf("before: %v", c)
	}

	body := fmt.Sprintf(`{"identity_id":%d,"group_id":%d,"justification":"quarterly export","duration_hours":4}`, identity, group)
	rq := w.c.json("POST", "/api/jit/requests", body, http.StatusOK).(map[string]any)
	if rq["status"] != "pending" {
		t.Fatalf("request = %v", rq)
	}
	if st := w.lpState(id); st != "revoked" {
		t.Errorf("the standing grant must stay revoked, it is %s", st)
	}
	c := calibrationOf(t, w, "high")
	if c["false_positives"].(float64) != 1 || c["false_positive_percent"].(float64) != 100 || c["review"] != true {
		t.Errorf("after: %v", c)
	}
}

// A JIT request for a group that is not a revoked grant labels nothing.
func TestLPJIT_UnrelatedRequestLabelsNothing(t *testing.T) {
	w := lpOn(t)
	w.lpRevoked()
	identity, group := w.jitFor("arn:aws:iam::111111111111:policy/Unrelated")
	body := fmt.Sprintf(`{"identity_id":%d,"group_id":%d,"justification":"x"}`, identity, group)
	w.c.json("POST", "/api/jit/requests", body, http.StatusOK)
	if c := calibrationOf(t, w, "high"); c["false_positives"].(float64) != 0 || c["review"] != false {
		t.Errorf("calibration = %v", c)
	}
}
