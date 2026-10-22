package agent

import (
	"context"
	"crypto/ecdh"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Runner is the agent's main loop: a heartbeat every HeartbeatEvery and a
// long poll for jobs, each executed by the Executor (at most MaxParallel at a
// time) and answered with a typed Result.
type Runner struct {
	Client    *Client
	Exec      *Executor
	Telemetry Telemetry
	Log       *slog.Logger

	// SealKey is the agent's private sealing key; its public half is registered
	// with Tessera so that a server-held credential can be sealed to this agent
	// (push.go). Nil: the agent registers none and cannot take a sealed credential.
	SealKey *ecdh.PrivateKey

	HeartbeatEvery time.Duration // default 30 s
	MaxParallel    int           // default 2
}

// Run blocks until ctx ends (nil) or Tessera refuses the agent
// (ErrAgentRefused: the agent stops instead of retrying).
func (r *Runner) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.HeartbeatEvery <= 0 {
		r.HeartbeatEvery = 30 * time.Second
	}
	if r.MaxParallel <= 0 {
		r.MaxParallel = 2
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	revoked := make(chan struct{}, 1)
	refused := func(err error) bool {
		if IsUnauthorized(err) {
			select {
			case revoked <- struct{}{}:
			default:
			}
			cancel()
			return true
		}
		return false
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // heartbeat
		defer wg.Done()
		t := time.NewTicker(r.HeartbeatEvery)
		defer t.Stop()
		var keyAt time.Time
		for {
			if err := r.Client.Heartbeat(ctx, r.Telemetry); err != nil && ctx.Err() == nil {
				if refused(err) {
					return
				}
				r.Log.Warn("heartbeat failed", "err", err)
			} else if err == nil && r.SealKey != nil && time.Since(keyAt) > sealKeyRefresh {
				// idempotent: the same key changes nothing on the server, and a restored database
				// that lost it gets it back within the refresh period
				if _, err := r.Client.RegisterSealKey(ctx, r.SealKey.PublicKey().Bytes()); err != nil {
					if ctx.Err() == nil && !refused(err) {
						r.Log.Warn("registering the sealing key failed", "err", err)
					}
				} else {
					keyAt = time.Now()
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	// pulled jobs (syncs, provisioning pushes), one at a time. An agent that cannot run a kind
	// answers it "unsupported" or "target_not_allowed" at once rather than let its lease run out.
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.pullLoop(ctx, refused)
	}()

	sem := make(chan struct{}, r.MaxParallel)
	backoff := time.Second
	for ctx.Err() == nil {
		sem <- struct{}{} // wait for a free slot before taking a job
		j, err := r.Client.Poll(ctx)
		if err != nil || j == nil {
			<-sem
			if err != nil && ctx.Err() == nil {
				if refused(err) {
					break
				}
				r.Log.Warn("poll failed", "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
			} else {
				backoff = time.Second
			}
			continue
		}
		backoff = time.Second
		wg.Add(1)
		go func(j Job) {
			defer wg.Done()
			defer func() { <-sem }()
			res := r.Exec.Execute(ctx, j)
			if err := r.Client.SendResult(ctx, res); err != nil && ctx.Err() == nil {
				if !refused(err) {
					r.Log.Warn("sending a result failed", "op", j.Op, "err", err)
				}
			}
		}(*j)
	}
	cancel()
	wg.Wait()
	select {
	case <-revoked:
		return ErrAgentRefused
	default:
		return nil
	}
}

// sealKeyRefresh is how often the agent registers its sealing key again.
const sealKeyRefresh = 6 * time.Hour

// pullLoop long-polls PathClaim, runs each pulled job and reports it. It is
// outbound only, like the probe poll, and runs one sync at a time (a sync reads
// a whole directory).
func (r *Runner) pullLoop(ctx context.Context, refused func(error) bool) {
	backoff := time.Second
	wait := func() {
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	for ctx.Err() == nil {
		j, err := r.Client.Claim(ctx)
		if err != nil {
			if ctx.Err() == nil && !refused(err) {
				r.Log.Warn("claiming a job failed", "err", err)
				wait()
			}
			continue
		}
		backoff = time.Second
		if j == nil {
			continue
		}
		res := r.Exec.ExecutePulled(ctx, *j)
		if err := r.Client.Report(ctx, res); err != nil && ctx.Err() == nil {
			if !refused(err) {
				// the lease expires and the job is claimed again
				r.Log.Warn("reporting a job failed", "job", j.ID, "err", err)
			}
		}
	}
}

// ErrAgentRefused: Tessera answered 401 to the agent.
var ErrAgentRefused = errors.New("agent: Tessera no longer accepts this agent (revoked or not enrolled)")
