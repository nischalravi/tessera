package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Dispatcher sends one typed job to an agent and returns its result. *Hub
// implements it; tests record what is sent.
type Dispatcher interface {
	Do(ctx context.Context, t tenancy.ID, agentID string, j Job) (Result, error)
}

var _ Dispatcher = (*Hub)(nil)

// RemoteProber is a connectors.Prober whose every method is one typed job for
// a Directory Agent. It can only do what the Prober interface can do (read,
// bounded), and the agent re-validates every job.
type RemoteProber struct {
	d       Dispatcher
	tenant  tenancy.ID
	agentID string
	target  Target
	cfg     ProbeConfig
}

var _ connectors.Prober = (*RemoteProber)(nil)

// NewRemoteProber returns the Prober for one connection that reaches its
// directory through the agent. cfg.CredName names the credential on the agent.
func NewRemoteProber(d Dispatcher, t tenancy.ID, agentID string, target Target, cfg ProbeConfig) (*RemoteProber, error) {
	if !ValidCredName(cfg.CredName) {
		return nil, fmt.Errorf("agent: %q is not a valid credential name", cfg.CredName)
	}
	return &RemoteProber{d: d, tenant: t, agentID: agentID, target: target, cfg: cfg}, nil
}

func (p *RemoteProber) do(ctx context.Context, j Job, out any) error {
	j.Target, j.Config = p.target, p.cfg
	res, err := p.d.Do(ctx, p.tenant, p.agentID, j)
	if err != nil {
		return err
	}
	if err := res.Err(); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if len(res.Payload) == 0 {
		return fmt.Errorf("directory agent: empty result for %s", j.Op)
	}
	if err := json.Unmarshal(res.Payload, out); err != nil {
		return fmt.Errorf("directory agent: malformed %s result", j.Op)
	}
	return nil
}

// Connect implements connectors.Prober.
func (p *RemoteProber) Connect(ctx context.Context) (v connectors.ConnInfo, err error) {
	err = p.do(ctx, Job{Op: OpConnect}, &v)
	return
}

// Authenticate implements connectors.Prober.
func (p *RemoteProber) Authenticate(ctx context.Context) (v connectors.AuthInfo, err error) {
	err = p.do(ctx, Job{Op: OpAuthenticate}, &v)
	return
}

// RootInfo implements connectors.Prober.
func (p *RemoteProber) RootInfo(ctx context.Context) (v connectors.RootInfo, err error) {
	err = p.do(ctx, Job{Op: OpRootInfo}, &v)
	return
}

// ObjectExists implements connectors.Prober.
func (p *RemoteProber) ObjectExists(ctx context.Context, ref string) (v bool, err error) {
	err = p.do(ctx, Job{Op: OpObjectExists, Arg: ref}, &v)
	return
}

// Sample implements connectors.Prober. The limit is capped here as well as on
// the agent.
func (p *RemoteProber) Sample(ctx context.Context, q connectors.SampleQuery) (v connectors.SampleStats, err error) {
	if q.Limit <= 0 || q.Limit > connectors.MaxSample {
		q.Limit = connectors.MaxSample
	}
	err = p.do(ctx, Job{Op: OpSample, Sample: &q}, &v)
	return
}

// EffectiveRights implements connectors.Prober.
func (p *RemoteProber) EffectiveRights(ctx context.Context, ref string) (v connectors.Rights, err error) {
	err = p.do(ctx, Job{Op: OpEffectiveRights, Arg: ref}, &v)
	return
}

// ChangeFeed implements connectors.Prober.
func (p *RemoteProber) ChangeFeed(ctx context.Context) (v connectors.FeedInfo, err error) {
	err = p.do(ctx, Job{Op: OpChangeFeed}, &v)
	return
}

// RateLimits implements connectors.Prober.
func (p *RemoteProber) RateLimits(ctx context.Context) (v connectors.RateInfo, err error) {
	err = p.do(ctx, Job{Op: OpRateLimits}, &v)
	return
}

// Time implements connectors.Prober.
func (p *RemoteProber) Time(ctx context.Context) (v time.Time, err error) {
	err = p.do(ctx, Job{Op: OpTime}, &v)
	return
}
