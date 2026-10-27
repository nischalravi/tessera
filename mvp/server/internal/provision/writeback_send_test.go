package provision_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Issue #706: write-back is checked when the worker sends, not only when the op is queued.
func TestEngine_QueuedOpNotSentAfterWriteBackOff(t *testing.T) {
	e := setup(t, fake.Options{})
	e.fake.AddUser(aliceName, "Alice", true)
	completed = 0
	op := e.submit(target.DisableAccount, "k:off")
	e.setTarget(false, provision.Settings{})
	e.run()
	got := e.op(op.ID)
	if got.Status != provision.Cancelled || got.LastError == nil || !strings.HasPrefix(*got.LastError, "write_back_disabled") {
		t.Fatalf("an op queued before write-back went off must be cancelled, got %+v", got)
	}
	if completed != 0 {
		t.Fatal("a cancelled op must not complete")
	}
	found := false
	for _, a := range e.auditActions() {
		found = found || a == "provision.cancelled_write_back_off"
	}
	if !found {
		t.Fatalf("the cancellation is audited: %v", e.auditActions())
	}
	// re-enabling does not resurrect it; only an explicit retry queues it again
	e.setTarget(true, provision.Settings{})
	e.run()
	if got := e.op(op.ID); got.Status != provision.Cancelled {
		t.Fatalf("re-enable must not resurrect a cancelled op: %s", got.Status)
	}
}

// Restores of a verified AWS change are never blocked by write-back being off.
func TestIsAWSRestore(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want bool
	}{
		{target.AWSAttachPolicy, true}, {target.AWSPutInlinePolicy, true}, {target.AWSRestorePolicyVersion, true},
		{target.AWSAddToGroup, true}, {target.AWSCreateAssignment, true},
		{target.AWSDetachPolicy, false}, {target.AWSDeleteInlinePolicy, false}, {target.AWSSetPolicyVersion, false},
		{target.AWSRemoveFromGroup, false}, {target.AWSDeleteAssignment, false}, {target.DisableAccount, false},
	} {
		if got := provision.IsAWSRestore(tc.kind); got != tc.want {
			t.Errorf("IsAWSRestore(%s) = %v, want %v", tc.kind, got, tc.want)
		}
	}
}
