package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Errors of the job queue.
var (
	// ErrOffline: the agent has not polled recently, so a job would never be
	// picked up.
	ErrOffline = fmt.Errorf("%w: it is offline (it has not polled recently)", connectors.ErrAgentUnavailable)
	// ErrBusy: the agent's queue is full.
	ErrBusy = fmt.Errorf("%w: too many operations are queued", connectors.ErrAgentUnavailable)
	// ErrRevoked: the agent was revoked while the operation was pending.
	ErrRevoked = fmt.Errorf("%w: it was revoked", connectors.ErrAgentUnavailable)
	// ErrUnknownJob: a result for a job that is not pending for that agent.
	ErrUnknownJob = errors.New("agent: no such pending job for this agent")
)

const (
	queueSize = 8
	// onlineWindow: an agent that polled within this window is online. A poll
	// lasts PollWait, so two of them fit.
	onlineWindow = 2*PollWait + 5*time.Second
)

type agentKey struct {
	tenant tenancy.ID
	id     string
}

type pending struct {
	key  agentKey
	res  chan Result
	once sync.Once
}

func (p *pending) deliver(r Result) { p.once.Do(func() { p.res <- r }) }

type queue struct {
	jobs     chan Job
	lastPoll time.Time
}

// Hub carries typed jobs from Tessera to agents that poll for them. It is the
// only path to an agent: a job is addressed to (tenant, agent id), a poll or a
// result from an authenticated agent can reach only its own queue and its own
// pending jobs. It lives in memory; a restart drops queued operations, which
// readiness reports as a failed check.
type Hub struct {
	mu      sync.Mutex
	queues  map[agentKey]*queue
	pending map[string]*pending
	revoked map[agentKey]bool
	now     func() time.Time
}

// NewHub returns an empty Hub. now is the clock (nil: time.Now).
func NewHub(now func() time.Time) *Hub {
	if now == nil {
		now = time.Now
	}
	return &Hub{queues: map[agentKey]*queue{}, pending: map[string]*pending{}, revoked: map[agentKey]bool{}, now: now}
}

func (h *Hub) queue(k agentKey) *queue {
	q := h.queues[k]
	if q == nil {
		q = &queue{jobs: make(chan Job, queueSize)}
		h.queues[k] = q
	}
	return q
}

// Online reports whether the agent polled recently.
func (h *Hub) Online(t tenancy.ID, agentID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	q := h.queues[agentKey{t, agentID}]
	return q != nil && h.now().Sub(q.lastPoll) < onlineWindow
}

// Do queues j for the agent and waits for its result. The job id is assigned
// here; j.Deadline is set to the operation's time limit. It returns
// ErrOffline at once for an agent that is not polling.
func (h *Hub) Do(ctx context.Context, t tenancy.ID, agentID string, j Job) (Result, error) {
	k := agentKey{t, agentID}
	j.ID = store.NewID()
	ctx, cancel := context.WithTimeout(ctx, JobTimeout)
	defer cancel()
	if dl, ok := ctx.Deadline(); ok {
		j.Deadline = dl
	}
	if err := ValidateJob(j); err != nil {
		return Result{}, err
	}
	p := &pending{key: k, res: make(chan Result, 1)}

	h.mu.Lock()
	q := h.queues[k]
	if q == nil || h.now().Sub(q.lastPoll) >= onlineWindow {
		h.mu.Unlock()
		return Result{}, ErrOffline
	}
	select {
	case q.jobs <- j:
		h.pending[j.ID] = p
	default:
		h.mu.Unlock()
		return Result{}, ErrBusy
	}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.pending, j.ID)
		h.mu.Unlock()
	}()
	select {
	case r := <-p.res:
		if r.Error != nil && r.Error.Code == "revoked" {
			return Result{}, ErrRevoked
		}
		return r, nil
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

// Poll returns the agent's next job, waiting up to wait for one. It returns
// (nil, nil) when none arrived, and records that the agent is online.
func (h *Hub) Poll(ctx context.Context, t tenancy.ID, agentID string, wait time.Duration) (*Job, error) {
	k := agentKey{t, agentID}
	h.mu.Lock()
	if h.revoked[k] {
		h.mu.Unlock()
		return nil, ErrRevoked
	}
	q := h.queue(k)
	q.lastPoll = h.now()
	jobs := q.jobs
	h.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case j := <-jobs:
			// Skip jobs whose caller has already gone away.
			h.mu.Lock()
			p := h.pending[j.ID]
			h.mu.Unlock()
			if p == nil || (!j.Deadline.IsZero() && h.now().After(j.Deadline)) {
				continue
			}
			h.mu.Lock()
			q.lastPoll = h.now()
			h.mu.Unlock()
			return &j, nil
		case <-timer.C:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Complete delivers an agent's result. The job must be pending for exactly
// this tenant and agent; a result for anyone else's job is ErrUnknownJob.
func (h *Hub) Complete(t tenancy.ID, agentID string, r Result) error {
	h.mu.Lock()
	p := h.pending[r.JobID]
	h.mu.Unlock()
	if p == nil || p.key != (agentKey{t, agentID}) {
		return ErrUnknownJob
	}
	p.deliver(r)
	return nil
}

// Revoke fails every pending operation of the agent and forgets its queue.
func (h *Hub) Revoke(t tenancy.ID, agentID string) {
	k := agentKey{t, agentID}
	h.mu.Lock()
	var ps []*pending
	for _, p := range h.pending {
		if p.key == k {
			ps = append(ps, p)
		}
	}
	delete(h.queues, k)
	h.revoked[k] = true // ids are never reused, so this set stays small
	h.mu.Unlock()
	for _, p := range ps {
		p.deliver(Result{Error: &ResultError{Code: "revoked"}})
	}
}
