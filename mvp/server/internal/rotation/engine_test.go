package rotation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// fakePolicy registers a simulated adapter pair and a policy that uses them.
func fakePolicy(h *harness, grace int, cfg map[string]string) {
	h.t.Helper()
	h.putAdapter(AdapterInput{Name: "sim", Type: TypeFake, Config: cfg})
	h.putAdapter(AdapterInput{Name: "sim-vault", Type: TypeFake})
	sim, vault := "sim", "sim-vault"
	h.putPolicy(PolicyInput{Kind: "access_key", MaxAgeDays: 90, GraceHours: grace, Adapter: &sim, Destination: &vault,
		DestPath: "kv/{system}/{name}"})
}

func (h *harness) expectState(id, want string) *store.RotationJob {
	h.t.Helper()
	j := h.job(id)
	if j.State != want {
		h.t.Fatalf("state %s (error %v), want %s", j.State, j.LastError, want)
	}
	return j
}

// step runs one engine pass that must step exactly one job, and checks its new state.
func (h *harness) step(id, want string) *store.RotationJob {
	h.t.Helper()
	if n := h.tick(); n != 1 {
		h.t.Fatalf("tick ran %d jobs, want 1 (state %s)", n, h.job(id).State)
	}
	return h.expectState(id, want)
}

// TestEngine_HappyPath walks a job through every state with the simulated
// provider: the old credential is verified by a re-read before it is deleted,
// the new one is handed over (never stored) and the inventory follows it.
func TestEngine_HappyPath(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 24, nil)
	sid := h.addSecret("aws", "access_key", "AKIAHAPPY", "AKIAHAPPYEXAMPLE0001", 100*24*time.Hour)
	id := h.startRotation(sid)
	t0 := h.clock()

	j := h.step(id, store.RotHandedOver) // create + hand over in one step
	if j.NewRef == nil || *j.NewRef == j.OldRef || j.OldRef != "AKIAHAPPYEXAMPLE0001" {
		t.Fatalf("refs old=%s new=%v", j.OldRef, j.NewRef)
	}
	if !j.NextStepAt.Equal(t0.Add(24 * time.Hour)) {
		t.Errorf("next step %v, want the end of the 24 h grace period", j.NextStepAt)
	}
	if got := FakeWrites(*j.DestAdapterID); !slices.Equal(got, []string{"kv/aws/akiahappy"}) {
		t.Errorf("hand-over writes %v", got)
	}
	if n := h.tick(); n != 0 {
		t.Fatal("a job ran during the grace period")
	}
	h.advance(23 * time.Hour)
	if n := h.tick(); n != 0 {
		t.Fatal("a job ran an hour early")
	}
	h.advance(time.Hour)
	h.step(id, store.RotOldDisabled)
	j = h.step(id, store.RotVerified)
	if j.Verification == nil || j.VerifiedAt == nil {
		t.Fatal("verified without a recorded re-read")
	}
	for _, want := range []string{`"verdict":"ok"`, `"evidence":"age_and_last_use"`, `"old_age_days":120`, `"last_used_known":true`} {
		if !strings.Contains(*j.Verification, want) {
			t.Errorf("verification %s lacks %s", *j.Verification, want)
		}
	}
	if s := h.secret(sid); s.ExternalID != "AKIAHAPPYEXAMPLE0001" {
		t.Errorf("the inventory changed before the old credential was deleted: %s", s.ExternalID)
	}
	j = h.step(id, store.RotOldDeleted)
	if j.CompletedAt == nil {
		t.Error("no completion time")
	}
	s := h.secret(sid)
	if s.ExternalID != *j.NewRef || s.LastRotatedAt == nil || !s.LastRotatedAt.Equal(h.clock()) || s.LastUsedAt != nil {
		t.Errorf("inventory after rotation: %+v, want the new credential", s)
	}
	got := h.actions("rotation.")
	for _, w := range []string{"rotation.job.queued", "rotation.job.created", "rotation.job.handed_over", "rotation.job.old_disabled",
		"rotation.job.verified", "rotation.completed", "rotation.owner_notified"} {
		if !slices.Contains(got, w) {
			t.Errorf("audit lacks %s (have %v)", w, got)
		}
	}
	if !slices.Equal(h.notes.events(), []string{EventCompleted}) {
		t.Errorf("notifications %v", h.notes.events())
	}
	if n := h.tick(); n != 0 {
		t.Error("a finished job ran again")
	}
}

// The re-read finds a consumer still using the old credential after the
// grace period: nothing is deleted, the job fails with the evidence recorded,
// the owner is told, and once the problem is gone a retry finishes it.
func TestEngine_VerifyFailureBlocksDeletionAndRetryResumes(t *testing.T) {
	h := newHarness(t)
	fakePolicy(h, 0, map[string]string{"consumer_still_uses": "true"})
	sid := h.addSecret("aws", "access_key", "AKIABUSY", "AKIABUSYEXAMPLE000001", 100*24*time.Hour)
	id := h.startRotation(sid)
	h.step(id, store.RotHandedOver)
	h.step(id, store.RotOldDisabled)
	h.advance(time.Minute)
	j := h.step(id, store.RotFailed)
	if j.FailedState == nil || *j.FailedState != store.RotOldDisabled {
		t.Fatalf("failed state %v", j.FailedState)
	}
	if j.LastError == nil || !strings.Contains(*j.LastError, VerdictUsedAfterDisable) {
		t.Errorf("error %v", j.LastError)
	}
	if j.Verification == nil || !strings.Contains(*j.Verification, `"verdict":"used_after_disable"`) {
		t.Errorf("the evidence of the failed re-read was not kept: %v", j.Verification)
	}
	if s := h.secret(sid); s.ExternalID != "AKIABUSYEXAMPLE000001" {
		t.Error("the inventory moved to the new credential although the old one was never deleted")
	}
	if !slices.Equal(h.notes.events(), []string{EventFailed}) {
		t.Errorf("notifications %v", h.notes.events())
	}
	if n := h.tick(); n != 0 {
		t.Error("a failed job was stepped again without a retry")
	}
	// the consumer moved: the provider no longer reports a late use
	w := worldFor(j.AdapterID)
	w.mu.Lock()
	w.keys[j.OldRef].lastUsed = nil
	w.mu.Unlock()
	h.write(func(tx *store.TenantTx, now time.Time) error {
		_, err := h.svc.RetryJob(tx, id, "tester", now)
		return err
	})
	h.expectState(id, store.RotOldDisabled)
	h.step(id, store.RotVerified)
	h.step(id, store.RotOldDeleted)
	if !slices.Contains(h.actions("rotation."), "rotation.job.retried") {
		t.Error("the retry was not audited")
	}
}

// scripted is an adapter that logs its calls and fails on cue, for the
// failure-handling paths a real provider reaches only by accident.
type scripted struct {
	mu        sync.Mutex
	calls     []string
	caps      Capabilities
	errs      map[string][]error // call name -> errors returned by successive calls
	obs       Observation
	block     chan struct{} // when set, Create waits on it
	entered   chan struct{}
	handedOut []string
}

func (s *scripted) log(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name)
	if q := s.errs[name]; len(q) > 0 {
		err := q[0]
		s.errs[name] = q[1:]
		return err
	}
	return nil
}

func (s *scripted) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func (s *scripted) Type() string               { return TypeFake }
func (s *scripted) Capabilities() Capabilities { return s.caps }
func (s *scripted) Validate(Target) error      { return nil }
func (s *scripted) Create(_ context.Context, t Target) (*Minted, error) {
	if s.block != nil {
		s.entered <- struct{}{}
		<-s.block
	}
	if err := s.log("Create"); err != nil {
		return nil, err
	}
	return &Minted{Ref: "NEW-" + t.Ref, Material: map[string]string{"k": "v"}}, nil
}
func (s *scripted) HandOver(_ context.Context, _ Target, m *Minted, _ Destination, path string) error {
	if err := s.log("HandOver"); err != nil {
		return err
	}
	if m != nil {
		s.handedOut = append(s.handedOut, path)
	}
	return nil
}
func (s *scripted) DisableOld(context.Context, Target) error {
	if err := s.log("DisableOld"); err != nil {
		return err
	}
	if !s.caps.CanDisable {
		return ErrUnsupported
	}
	return nil
}
func (s *scripted) ObserveOld(context.Context, Target) (Observation, error) {
	if err := s.log("ObserveOld"); err != nil {
		return Observation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.obs
	n := 0
	for _, c := range s.calls {
		if c == "DeleteOld" {
			n++
		}
	}
	if n > 0 {
		o = Observation{LastUsedKnown: true} // gone once deleted
	}
	return o, nil
}
func (s *scripted) DeleteOld(context.Context, Target) error         { return s.log("DeleteOld") }
func (s *scripted) DeleteNew(context.Context, Target, string) error { return s.log("DeleteNew") }
func (s *scripted) InventoryRef(_, newRef string) string            { return newRef }
func (s *scripted) ValidatePath(string) error                       { return nil }
func (s *scripted) Put(context.Context, string, map[string]string) error {
	return nil
}

// scriptedHarness is a harness whose factory returns ad for every adapter row.
func scriptedHarness(t *testing.T, ad *scripted) (*harness, int64, string) {
	t.Helper()
	h := newHarness(t)
	fakePolicy(h, 0, nil)
	h.eng.Factory.Override = func(*store.RotationAdapter) (*Built, error) { return &Built{Adapter: ad, Destination: ad}, nil }
	sid := h.addSecret("aws", "access_key", "AKIASCRIPT", "AKIASCRIPTEXAMPLE00001", 100*24*time.Hour)
	return h, sid, h.startRotation(sid)
}

var oldObs = func() Observation {
	created := storetestNow().Add(-100 * 24 * time.Hour)
	return Observation{Exists: true, CreatedAt: &created, LastUsedKnown: true}
}

func TestEngine_CallOrderDeletesOnlyAfterVerification(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, ReportsLastUsed: true, NeedsDestination: true}, obs: oldObs()}
	h, _, id := scriptedHarness(t, ad)
	for _, want := range []string{store.RotHandedOver, store.RotOldDisabled, store.RotVerified, store.RotOldDeleted} {
		h.step(id, want)
	}
	want := []string{"Create", "HandOver", "DisableOld", "ObserveOld", "DeleteOld", "ObserveOld"}
	if got := ad.called(); !slices.Equal(got, want) {
		t.Errorf("calls %v, want %v", got, want)
	}
}

func TestEngine_VerificationFailureNeverDeletes(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, ReportsLastUsed: true, NeedsDestination: true}}
	created := storetestNow().Add(-time.Hour)
	ad.obs = Observation{Exists: true, Active: true, CreatedAt: &created, LastUsedKnown: true} // disable did not take
	h, _, id := scriptedHarness(t, ad)
	h.step(id, store.RotHandedOver)
	h.step(id, store.RotOldDisabled)
	h.step(id, store.RotFailed)
	if slices.Contains(ad.called(), "DeleteOld") {
		t.Errorf("the old credential was deleted although it was still active: %v", ad.called())
	}
}

func TestEngine_ProviderThatCannotDisableSkipsTheStep(t *testing.T) {
	ad := &scripted{caps: Capabilities{NeedsDestination: true}, obs: oldObs()}
	h, _, id := scriptedHarness(t, ad)
	h.step(id, store.RotHandedOver)
	h.step(id, store.RotOldDisabled)
	j := h.step(id, store.RotVerified)
	if !strings.Contains(*j.Verification, `"evidence":"age_only"`) && !strings.Contains(*j.Verification, `"evidence":"age_and_last_use"`) {
		t.Errorf("verification %s", *j.Verification)
	}
	h.step(id, store.RotOldDeleted)
	var disabled any
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		evs, _ := tx.AuditLog(-1)
		for _, e := range evs {
			if e.Action == "rotation.job.old_disabled" {
				disabled = string(e.Detail)
			}
		}
		return nil
	})
	if s, _ := disabled.(string); !strings.Contains(s, `"disabled":false`) {
		t.Errorf("the skipped disable was not recorded as such: %v", disabled)
	}
}

func TestEngine_TransientCreateFailureBacksOffThenFails(t *testing.T) {
	transient := &Error{Op: "create", Code: "Throttling", Transient: true}
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, obs: oldObs(), errs: map[string][]error{
		"Create": {transient, transient, transient, transient, transient}}}
	h, _, id := scriptedHarness(t, ad)
	h.eng.MaxAttempts = 3
	h.step(id, store.RotPending)
	j := h.job(id)
	if j.Attempts != 1 || !j.NextStepAt.After(h.clock()) {
		t.Fatalf("attempts %d next %v", j.Attempts, j.NextStepAt)
	}
	if n := h.tick(); n != 0 {
		t.Fatal("the job was retried before its backoff")
	}
	h.advance(time.Minute)
	h.step(id, store.RotPending)
	h.advance(10 * time.Minute)
	j = h.step(id, store.RotFailed)
	if j.Attempts != 3 || j.FailedState == nil || *j.FailedState != store.RotPending {
		t.Errorf("attempts %d failed state %v", j.Attempts, j.FailedState)
	}
	if got := h.actions("rotation.job."); !slices.Contains(got, "rotation.job.step_failed") || !slices.Contains(got, "rotation.job.failed") {
		t.Errorf("audit %v", got)
	}
}

func TestEngine_PermanentErrorFailsAtOnce(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, errs: map[string][]error{
		"Create": {&Error{Op: "iam CreateAccessKey", Code: "LimitExceeded", Msg: "Cannot exceed quota for AccessKeysPerUser: 2"}}}}
	h, _, id := scriptedHarness(t, ad)
	j := h.step(id, store.RotFailed)
	if j.Attempts != 1 || !strings.Contains(*j.LastError, "LimitExceeded") {
		t.Errorf("attempts %d error %v", j.Attempts, j.LastError)
	}
}

// A hand-over that cannot be completed removes the new credential again, so
// nothing is left behind and the old one is untouched.
func TestEngine_HandOverFailureRollsBackTheNewCredential(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, obs: oldObs(), errs: map[string][]error{
		"HandOver": {&Error{Op: "vault kv put", Code: "Forbidden", Msg: "permission denied"}}}}
	h, _, id := scriptedHarness(t, ad)
	j := h.step(id, store.RotFailed)
	if j.FailedState == nil || *j.FailedState != store.RotPending || j.NewRef != nil {
		t.Errorf("failed state %v new ref %v: the job should restart from pending", j.FailedState, j.NewRef)
	}
	if got := ad.called(); !slices.Equal(got, []string{"Create", "HandOver", "DeleteNew"}) {
		t.Errorf("calls %v", got)
	}
	if got := h.actions("rotation.job."); !slices.Contains(got, "rotation.job.created") {
		t.Errorf("audit %v", got)
	}
	// retry from the start succeeds
	h.write(func(tx *store.TenantTx, now time.Time) error {
		_, err := h.svc.RetryJob(tx, id, "tester", now)
		return err
	})
	h.step(id, store.RotHandedOver)
}

func TestEngine_TransientHandOverRollsBackAndRetries(t *testing.T) {
	tr := &Error{Op: "vault kv put", Code: "Service Unavailable", Transient: true}
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, obs: oldObs(), errs: map[string][]error{
		"HandOver": {tr, tr, tr}}} // the three in-step attempts
	h, _, id := scriptedHarness(t, ad)
	j := h.step(id, store.RotPending)
	if j.NewRef != nil || j.Attempts != 1 {
		t.Errorf("new ref %v attempts %d", j.NewRef, j.Attempts)
	}
	if got := ad.called(); !slices.Equal(got, []string{"Create", "HandOver", "HandOver", "HandOver", "DeleteNew"}) {
		t.Errorf("calls %v", got)
	}
	h.advance(time.Minute)
	h.step(id, store.RotHandedOver)
}

func TestEngine_OrphanedNewCredentialIsReported(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, errs: map[string][]error{
		"HandOver":  {&Error{Op: "vault kv put", Code: "Forbidden"}},
		"DeleteNew": {&Error{Op: "iam DeleteAccessKey", Code: "AccessDenied"}}}}
	h, _, id := scriptedHarness(t, ad)
	j := h.step(id, store.RotFailed)
	if j.NewRef == nil || !strings.Contains(*j.LastError, "delete it by hand") {
		t.Errorf("new ref %v error %v: the orphan must stay on record", j.NewRef, j.LastError)
	}
	if j.FailedState == nil || *j.FailedState != store.RotCreated {
		t.Errorf("failed state %v", j.FailedState)
	}
}

// A worker that died between Create and HandOver leaves a job in state
// created. The new secret was only in memory, so it is removed and the job restarts.
func TestEngine_CreatedJobFromACrashIsRecovered(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, obs: oldObs()}
	h, sid, id := scriptedHarness(t, ad)
	h.write(func(tx *store.TenantTx, now time.Time) error { // as if the worker died right after Create committed
		j, err := tx.RotationJob(id)
		if err != nil {
			return err
		}
		ref := "ORPHAN-NEW"
		j.State, j.NewRef = store.RotCreated, &ref
		return tx.UpdateRotationJob(j, store.RotPending, now)
	})
	_ = sid
	h.step(id, store.RotPending)
	if got := ad.called(); !slices.Equal(got, []string{"DeleteNew"}) {
		t.Errorf("calls %v", got)
	}
	if !slices.Contains(h.actions("rotation.job."), "rotation.job.recovered") {
		t.Error("the recovery was not audited")
	}
	h.step(id, store.RotHandedOver)
}

// A provider that rotates in place (Secrets Manager) needs no material, so an
// interrupted hand-over resumes instead of starting over.
func TestEngine_MaterialFreeCreatedJobResumes(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, MaterialFree: true}, obs: oldObs()}
	h, _, id := scriptedHarness(t, ad)
	h.write(func(tx *store.TenantTx, now time.Time) error {
		j, err := tx.RotationJob(id)
		if err != nil {
			return err
		}
		ref := "secret#v2"
		j.State, j.NewRef = store.RotCreated, &ref
		return tx.UpdateRotationJob(j, store.RotPending, now)
	})
	h.step(id, store.RotHandedOver)
	if got := ad.called(); !slices.Equal(got, []string{"HandOver"}) {
		t.Errorf("calls %v", got)
	}
}

// Two workers cannot step the same job.
func TestEngine_OneWorkerPerJob(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, obs: oldObs(),
		block: make(chan struct{}), entered: make(chan struct{}, 1)}
	h, _, id := scriptedHarness(t, ad)
	done := make(chan error, 1)
	go func() { _, err := h.eng.Step(h.ctx(), h.tenant, id); done <- err }()
	<-ad.entered // the first worker holds the lease and is inside Create
	ran, err := h.eng.Step(h.ctx(), h.tenant, id)
	if err != nil || ran {
		t.Errorf("second worker: ran=%v err=%v, want it to stand aside", ran, err)
	}
	close(ad.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	h.expectState(id, store.RotHandedOver)
	if n := len(ad.called()); n != 2 { // Create and HandOver, once
		t.Errorf("%d calls, want 2: %v", n, ad.called())
	}
}

// A policy with auto_rotate queues the rotation of a secret once it is older than its maximum.
func TestEngine_AutoRotateQueuesOverdueSecrets(t *testing.T) {
	h := newHarness(t)
	h.putAdapter(AdapterInput{Name: "sim", Type: TypeFake})
	sim := "sim"
	h.putPolicy(PolicyInput{Kind: "access_key", MaxAgeDays: 90, GraceHours: 0, Adapter: &sim, Destination: &sim, DestPath: "kv/{name}", AutoRotate: true})
	old := h.addSecret("aws", "access_key", "AKIAOLD", "AKIAOLDEXAMPLE0000001", 120*24*time.Hour)
	young := h.addSecret("aws", "access_key", "AKIANEW", "AKIANEWEXAMPLE0000001", 10*24*time.Hour)
	h.tick()
	var jobs []*store.RotationJob
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		var err error
		jobs, err = tx.RotationJobs(store.RotationJobFilter{})
		return err
	})
	var queued []int64
	for _, j := range jobs {
		if j.Origin != store.RotOriginPolicy {
			t.Errorf("job origin %s", j.Origin)
		}
		queued = append(queued, j.SecretID)
	}
	if !slices.Contains(queued, old) || slices.Contains(queued, young) {
		t.Errorf("queued %v; want the 120-day-old secret %d and not the 10-day-old %d", queued, old, young)
	}
	// ticking again does not queue a second job for the same secret
	h.tick()
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		all, _ := tx.RotationJobs(store.RotationJobFilter{SecretID: old})
		if len(all) != 1 {
			t.Errorf("%d jobs for the old secret", len(all))
		}
		return nil
	})
}

// No secret material in the database or the audit ledger.
func TestEngine_NoSecretMaterialPersisted(t *testing.T) {
	ad := &scripted{caps: Capabilities{CanDisable: true, NeedsDestination: true}, obs: oldObs()}
	h, _, id := scriptedHarness(t, ad)
	h.step(id, store.RotHandedOver)
	text := h.auditText()
	if strings.Contains(text, `"k":"v"`) || strings.Contains(text, "secret_access_key") {
		t.Errorf("audit ledger holds secret material:\n%s", text)
	}
	j := h.job(id)
	if strings.Contains(*j.NewRef, "v") && strings.Contains(strings.ToLower(*j.NewRef), "secret") {
		t.Errorf("new ref %s", *j.NewRef)
	}
}

func TestBackoff(t *testing.T) {
	for attempt, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 8: time.Hour, 20: time.Hour} {
		if got := backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
}

var _ = errors.New
