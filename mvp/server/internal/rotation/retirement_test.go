package rotation

import (
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// toVerified walks a fake-provider job to verified, the step before the old
// credential is deleted.
func toVerified(t *testing.T, cfg map[string]string, ext string) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	fakePolicy(h, 0, cfg)
	sid := h.addSecret("aws", "access_key", "AKIA"+ext, ext+"EXAMPLE0000000001", 100*24*time.Hour)
	id := h.startRotation(sid)
	h.step(id, store.RotHandedOver)
	h.step(id, store.RotOldDisabled)
	h.step(id, store.RotVerified)
	return h, id
}

func completedDetail(h *harness) string {
	for _, line := range strings.Split(h.auditText(), "\n") {
		if strings.HasPrefix(line, "rotation.completed ") {
			return line
		}
	}
	return ""
}

// A delete the provider accepts but that keeps showing the key (exists,
// inactive) is not a deletion: the job retries and never reports old_deleted.
func TestEngine_RetirementIneffectiveDeleteNeverCompletes(t *testing.T) {
	h, id := toVerified(t, map[string]string{"delete_lag": "1000"}, "STUCK")
	for i := 1; i <= 4; i++ {
		h.step(id, store.RotVerified)
		if j := h.job(id); j.Attempts != i || j.LastError == nil || !strings.Contains(*j.LastError, "old_credential_still_present") {
			t.Fatalf("attempt %d: attempts %d error %v", i, j.Attempts, j.LastError)
		}
		h.advance(time.Hour)
	}
	j := h.step(id, store.RotFailed) // the retry budget is spent
	if j.FailedState == nil || *j.FailedState != store.RotVerified || j.CompletedAt != nil {
		t.Errorf("failed state %v completed %v", j.FailedState, j.CompletedAt)
	}
	if completedDetail(h) != "" || len(h.actions("rotation.completed")) != 0 {
		t.Error("rotation.completed was recorded although the key was never observed absent")
	}
	if got := h.notes.events(); len(got) != 1 || got[0] != EventFailed {
		t.Errorf("notifications %v, want one failure for the owner", got)
	}
	if s := h.secret(j.SecretID); s.ExternalID != j.OldRef {
		t.Error("the inventory moved to the new credential before the old one was gone")
	}
}

// The key shows exists/inactive for two more reads, then is absent: the job
// retries and completes once absence is observed.
func TestEngine_RetirementCompletesWhenKeyBecomesAbsent(t *testing.T) {
	h, id := toVerified(t, map[string]string{"delete_lag": "2"}, "LAGGY")
	h.step(id, store.RotVerified)
	h.advance(time.Hour)
	h.step(id, store.RotVerified)
	h.advance(time.Hour)
	j := h.step(id, store.RotOldDeleted)
	if j.CompletedAt == nil {
		t.Fatal("no completion time")
	}
	d := completedDetail(h)
	for _, want := range []string{`"old_disposition":"deleted"`, `"old_deleted":true`} {
		if !strings.Contains(d, want) {
			t.Errorf("completion %s lacks %s", d, want)
		}
	}
}

// A stale first read (still listed) followed by an absent read completes.
func TestEngine_RetirementStaleFirstReadThenAbsent(t *testing.T) {
	h, id := toVerified(t, map[string]string{"delete_lag": "1"}, "STALE")
	h.step(id, store.RotVerified)
	if j := h.job(id); j.Attempts != 1 {
		t.Fatalf("attempts %d after the stale read", j.Attempts)
	}
	h.advance(time.Hour)
	h.step(id, store.RotOldDeleted)
	if len(h.actions("rotation.job.step_failed")) == 0 {
		t.Error("the stale read was not audited as a retried step")
	}
}

// Secrets Manager cannot delete a version: retirement is the old version
// losing AWSCURRENT/AWSPENDING, recorded as retired (deprecated), not deleted.
func TestEngine_RetirementSecretsManagerVersionBecomesPrevious(t *testing.T) {
	h, id := toVerified(t, map[string]string{"retirement": RetireDeprecated}, "SMVER")
	h.step(id, store.RotOldDeleted) // AWSPENDING -> AWSPREVIOUS on the first read after the call
	d := completedDetail(h)
	for _, want := range []string{`"old_disposition":"retired_deprecated"`, `"old_deleted":false`} {
		if !strings.Contains(d, want) {
			t.Errorf("completion %s lacks %s", d, want)
		}
	}
	if n := h.notes.list; len(n) == 0 || !strings.Contains(n[len(n)-1].Body, "not deleted") {
		t.Errorf("owner notifications %+v do not say the version was not deleted", n)
	}
}

// While the old version still carries AWSPENDING the job keeps waiting.
func TestEngine_RetirementSecretsManagerStageStillHeld(t *testing.T) {
	h, id := toVerified(t, map[string]string{"retirement": RetireDeprecated, "delete_lag": "1"}, "SMSTAGE")
	h.step(id, store.RotVerified)
	if j := h.job(id); j.Attempts != 1 {
		t.Fatalf("attempts %d: a version still holding AWSPENDING must not count as retired", j.Attempts)
	}
	h.advance(time.Hour)
	h.step(id, store.RotOldDeleted)
}

func TestRetired(t *testing.T) {
	del, dep := Capabilities{}, Capabilities{Retirement: RetireDeprecated}
	tests := []struct {
		name string
		caps Capabilities
		obs  Observation
		ok   bool
		disp string
	}{
		{"deletable absent", del, Observation{}, true, DispositionDeleted},
		{"deletable exists inactive", del, Observation{Exists: true}, false, DispositionDeleted},
		{"deletable exists active", del, Observation{Exists: true, Active: true}, false, DispositionDeleted},
		{"sm current", dep, Observation{Exists: true, Active: true, Stages: []string{"AWSCURRENT"}}, false, DispositionDeprecated},
		{"sm pending", dep, Observation{Exists: true, Active: true, Stages: []string{"AWSPENDING"}}, false, DispositionDeprecated},
		{"sm previous", dep, Observation{Exists: true, Active: true, Stages: []string{"AWSPREVIOUS"}}, true, DispositionDeprecated},
		{"sm no stage", dep, Observation{Exists: true}, true, DispositionDeprecated},
		{"sm version gone", dep, Observation{}, true, DispositionDeprecated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if ok, disp := retired(tt.caps, tt.obs); ok != tt.ok || disp != tt.disp {
				t.Errorf("retired = %v, %q; want %v, %q", ok, disp, tt.ok, tt.disp)
			}
		})
	}
}
