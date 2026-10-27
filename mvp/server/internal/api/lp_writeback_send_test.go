package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var _ = awstest.EstateAlice

// Issue #706: an LP-5 revocation queued while write-back was on is not sent once it is off, and the loop
// supersedes it; a restore of a verified revocation is still sent with write-back off.
func TestLPAPI_WriteBackOffAtSend(t *testing.T) {
	setOff := func(w *awsWB) {
		testkit.Write(w.t, w.st, func(tx *store.TenantTx) error { return tx.SetProvTargetWriteBack(w.conn, false, testkit.Now) })
	}
	later := testkit.Now.Add(8 * 24 * time.Hour)

	w := lpOn(t)
	c := w.lpPropose()
	id := asString(c["id"])
	w.lpApprove(c)
	w.lpTick(later)
	if w.lpState(id) != "revoking" || len(w.ops()) != 1 {
		t.Fatalf("revoking: %s, %d ops", w.lpState(id), len(w.ops()))
	}
	setOff(w)
	w.srv.clock = func() time.Time { return later }
	if st := w.run(); st.Verified != 0 || st.Processed != 1 {
		t.Fatalf("stats = %+v", st)
	}
	w.srv.clock = func() time.Time { return testkit.Now }
	w.lpTick(later.Add(time.Minute))
	if calls := w.stub.calls(); len(calls) != 0 {
		t.Fatalf("sent with write-back off: %+v", calls)
	}
	if st := w.lpState(id); st != "superseded" {
		t.Errorf("state = %s, want superseded", st)
	}
	if !strings.Contains(w.audit(), "provision.cancelled_write_back_off") {
		t.Errorf("audit: %s", w.audit())
	}

	// a restore still goes out with write-back off
	w2 := lpOn(t)
	c2 := w2.lpPropose()
	id2 := asString(c2["id"])
	w2.lpApprove(c2)
	w2.lpTick(later)
	w2.runAt(later)
	w2.lpTick(later.Add(time.Minute))
	if st := w2.lpState(id2); st != "revoked" {
		t.Fatalf("revoked: %s", st)
	}
	setOff(w2)
	w2.c.json("POST", "/api/lp/revocations/"+id2+"/restore", `{}`, http.StatusAccepted)
	w2.runAt(later.Add(time.Minute))
	w2.lpTick(later.Add(2 * time.Minute))
	if st := w2.lpState(id2); st != "restored" {
		t.Fatalf("restore with write-back off: %s", st)
	}
}
