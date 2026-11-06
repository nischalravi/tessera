package ibmi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// The readiness prober of the module (issue #888). A probe job that names the
// "ibmi" module runs this instead of the LDAP prober. It implements only the
// operations IBM i has: Connect (TCP and TLS), Authenticate (sign in and start
// the read-only job) and Sample (read QSYS2.USER_INFO through the same
// read-only query a sync uses, reporting a count). Every other operation is
// ErrUnsupported. It reaches the system only through the agent's safedial
// Dialer, and its errors have the transport's fixed text.

// NewProber is the agent.ProberFactory of the module.
func NewProber(open Opener) agent.ProberFactory {
	return func(s agent.ProberSpec) (connectors.Prober, error) {
		if open == nil {
			return nil, ErrNoDriver
		}
		return &prober{spec: s, open: open, now: time.Now}, nil
	}
}

type prober struct {
	spec agent.ProberSpec
	open Opener
	now  func() time.Time
}

var _ connectors.Prober = (*prober)(nil)

// fixed reduces err to an error whose text is fixed: a context error or one of
// the transport's own errors, else the generic read error.
func fixed(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrNoTransport), errors.Is(err, ErrNoDriver):
		return err
	}
	for _, f := range transportErrors {
		if errors.Is(err, f) {
			return f
		}
	}
	return errRead
}

// Connect dials the system over TLS and reports the handshake, then closes the
// connection without sending anything.
func (p *prober) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	s := p.spec
	if s.Dialer == nil {
		return connectors.ConnInfo{}, ErrNoDriver
	}
	port := s.Target.Port
	if port == 0 {
		port = DefaultPort
	}
	if !validHost(s.Target.Host) {
		return connectors.ConnInfo{}, errRefused
	}
	// inspect defers verification so a bad chain is reported as a failed check.
	c, err := s.Dialer.DialMode(ctx, s.Target.Host, port, safedial.ModeLDAPS, true)
	switch {
	case err == nil:
	case errors.Is(err, safedial.ErrHandshake):
		return connectors.ConnInfo{Reachable: true}, nil // reachable, but not a TLS server
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return connectors.ConnInfo{}, ctx.Err()
	case errors.Is(err, safedial.ErrBlockedAddress), errors.Is(err, safedial.ErrPort),
		errors.Is(err, safedial.ErrHost), errors.Is(err, safedial.ErrTLSMode):
		return connectors.ConnInfo{}, errRefused
	default:
		return connectors.ConnInfo{}, errConnect
	}
	defer c.Close()
	st, ok := c.TLSState()
	if !ok {
		return connectors.ConnInfo{Reachable: true}, nil
	}
	rep := safedial.Inspect(st, strings.TrimSuffix(s.Target.Host, "."), s.RootCAs, p.now())
	return connectors.ConnInfo{Reachable: true, TLSVersion: rep.TLSVersion, ChainValid: rep.ChainValid,
		HostnameMatch: rep.HostnameMatch, NotAfter: rep.NotAfter, Issuer: rep.Issuer}, nil
}

// Authenticate signs in as the job's profile and starts the read-only job. A
// refused sign-in is an answer (OK false), not an error.
func (p *prober) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	info := connectors.AuthInfo{Mode: "basic", Identity: p.spec.Config.BindDN}
	src, err := p.open(ctx, p.spec)
	if errors.Is(err, ErrLogin) {
		return info, nil
	}
	if err != nil {
		return info, fixed(err)
	}
	src.Close()
	info.OK = true
	return info, nil
}

// Sample reads the profile list through the one fixed statement and reports how
// many there are (at most q.Limit, or MaxSample), never a name. Only the
// "search" sample exists on this system.
func (p *prober) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	if q.Op != "search" {
		return connectors.SampleStats{}, connectors.ErrUnsupported
	}
	src, err := p.open(ctx, p.spec)
	if err != nil {
		return connectors.SampleStats{}, fixed(err)
	}
	defer src.Close()
	ps, err := src.Profiles(ctx, agent.MaxSyncAccounts)
	if err != nil {
		return connectors.SampleStats{}, fixed(err)
	}
	limit := q.Limit
	if limit <= 0 || limit > connectors.MaxSample {
		limit = connectors.MaxSample
	}
	n := min(len(ps), limit)
	return connectors.SampleStats{Objects: n, Available: n > 0,
		PerClass: map[string]int{"profile": n}}, nil
}

// RootInfo implements connectors.Prober: IBM i exposes none.
func (p *prober) RootInfo(context.Context) (connectors.RootInfo, error) {
	return connectors.RootInfo{}, connectors.ErrUnsupported
}

// ObjectExists implements connectors.Prober.
func (p *prober) ObjectExists(context.Context, string) (bool, error) {
	return false, connectors.ErrUnsupported
}

// EffectiveRights implements connectors.Prober.
func (p *prober) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return connectors.Rights{}, connectors.ErrUnsupported
}

// ChangeFeed implements connectors.Prober.
func (p *prober) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{}, connectors.ErrUnsupported
}

// RateLimits implements connectors.Prober.
func (p *prober) RateLimits(context.Context) (connectors.RateInfo, error) {
	return connectors.RateInfo{}, connectors.ErrUnsupported
}

// Time implements connectors.Prober.
func (p *prober) Time(context.Context) (time.Time, error) {
	return time.Time{}, connectors.ErrUnsupported
}
