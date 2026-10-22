package provision_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// A target that keeps failing opens its breaker; the operations queued behind
// it are put back, with their attempts given back (they were not sent), and go
// through once the target recovers and the cooldown has passed.
func TestEngine_OpenBreakerDefersOperationsWithoutBurningAttempts(t *testing.T) {
	e := setup(t, fake.Options{Fault: fake.FailWrites})
	e.fake.AddUser(aliceName, "Alice", true)
	e.eng.Guard = &worker.Guard{DB: e.f.DB, Clock: func() time.Time { return e.now },
		Defaults: &worker.Limits{MaxConcurrency: 2, BreakerThreshold: 2, BreakerCooldown: time.Minute}}
	completed = 0
	ops := []*string{}
	for _, k := range []string{"g:1", "g:2", "g:3"} {
		ops = append(ops, &e.submit(target.DisableAccount, k).ID)
	}
	st := e.run() // two sends fail and open the breaker; the third is not sent
	if st.Processed != 3 || st.Retrying != 3 || st.Failed != 0 {
		t.Fatalf("stats = %+v", st)
	}
	attempts := map[string]int{}
	var deferred int
	for _, id := range ops {
		o := e.op(*id)
		attempts[o.IdempotencyKey] = o.Attempts
		if o.Status != provision.Queued {
			t.Errorf("%s: status = %s", o.IdempotencyKey, o.Status)
		}
		if o.LastError != nil && strings.HasPrefix(*o.LastError, "waiting: ") {
			deferred++
			if !strings.Contains(*o.LastError, "circuit breaker is open") || !o.NextAttemptAt.Equal(e.now.Add(time.Minute)) {
				t.Errorf("deferred op: %v, next %s", *o.LastError, o.NextAttemptAt)
			}
		}
	}
	if deferred != 1 || attempts["g:1"] != 1 || attempts["g:2"] != 1 || attempts["g:3"] != 0 {
		t.Errorf("deferred = %d, attempts = %v (want the third given back its attempt)", deferred, attempts)
	}
	// the two failed ones are due again at once (no backoff here): the open breaker refuses them
	// without sending, and their attempts are given back instead of running out at 3
	for i := 0; i < 5; i++ {
		e.run()
	}
	for _, id := range ops {
		if o := e.op(*id); o.Status != provision.Queued || o.Attempts > 1 {
			t.Errorf("%s after waiting out the breaker: %+v", o.IdempotencyKey, o)
		}
	}
	writes := 0
	for _, r := range e.fake.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			writes++
		}
	}
	if n := writes; n != 2 {
		t.Errorf("the target received %d writes, want 2 (the breaker held the rest back)", n)
	}
	// the target recovers; after the cooldown a probe goes through and the rest follow
	e.fake.SetFault("")
	e.now = e.now.Add(2 * time.Minute)
	for i := 0; i < 3; i++ {
		e.run()
	}
	for _, id := range ops {
		if o := e.op(*id); o.Status != provision.Verified {
			t.Errorf("%s after recovery: %s (%v)", o.IdempotencyKey, o.Status, o.LastError)
		}
	}
	if completed != 3 {
		t.Errorf("completions = %d", completed)
	}
}
