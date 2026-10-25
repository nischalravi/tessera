package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// ProberSpec is what the agent hands its prober factory: the connection
// settings of the job plus the credential read from the agent's own store.
// Dialer is the agent-local safedial Dialer (allowlist enforced).
type ProberSpec struct {
	Target   Target
	Config   ProbeConfig
	Password string
	RootCAs  *x509.CertPool
	Dialer   *safedial.Dialer
}

// ProberFactory builds the read-only Prober for a job. cmd/tessera-agent
// supplies the LDAP one; this package imports no directory library.
type ProberFactory func(ProberSpec) (connectors.Prober, error)

// CredentialStore is the agent's local secret store. Get returns the secret
// named by a job; ErrNoCredential if there is none.
type CredentialStore interface {
	Get(name string) (string, error)
}

// ErrNoCredential: the agent's store has no credential of that name.
var ErrNoCredential = errors.New("agent: no such credential in the local store")

// Executor runs jobs on the agent. It is the agent-side enforcement point:
// the closed operation set, the local allowlist, bounded arguments and time.
type Executor struct {
	// Allow is the local allowlist (allowed_targets of the agent's own
	// configuration file). Empty means no target at all.
	Allow []safedial.AllowEntry
	Creds CredentialStore
	New   ProberFactory
	// NewSyncer builds the directory reader of pulled sync jobs (nil: the
	// agent answers them "unsupported").
	NewSyncer SyncerFactory
	// Modules are the plug-ins this agent build carries, by module name
	// (modules.go). A sync job that names another module is answered
	// "unsupported" before anything is dialed.
	Modules map[string]SyncerFactory
	// AllowPush is the local allowlist of HTTPS provisioning targets
	// (allowed_push_targets of the agent's own configuration file; ports 443
	// and 8443). Empty means no push target at all.
	AllowPush []safedial.AllowEntry
	// PushRoots are the CAs push targets are verified against (push_ca_file;
	// nil: the system roots).
	PushRoots *x509.CertPool
	// SealKey is the agent's private sealing key: credentials sealed to it open
	// here only. Nil: the agent cannot take a sealed credential.
	SealKey *ecdh.PrivateKey
	// PushVerifyWait is the pause between re-reads of a push (2 s).
	PushVerifyWait time.Duration
	// Resolver replaces DNS (tests); nil means the system resolver.
	Resolver safehttp.Resolver
	// TestDial is safedial.Options.TestDial, for tests only.
	TestDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxJob caps one operation (default 20 s).
	MaxJob time.Duration
}

// Execute runs one job and returns its result. It never panics out and never
// returns the credential in a result.
func (e *Executor) Execute(ctx context.Context, j Job) (res Result) {
	res.JobID = j.ID
	fail := func(code, msg string) Result {
		res.Error = &ResultError{Code: code, Message: msg}
		return res
	}
	// 1. The closed set of operations, with bounded typed arguments.
	if !j.Op.Valid() {
		return fail(CodeUnknownOp, "not a Directory Agent operation")
	}
	if err := ValidateJob(j); err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	// 2. The local allowlist, before anything is resolved or dialed. A target
	// that is not listed fails here whatever it is (public ones included).
	if !safedial.Listed(e.Allow, j.Target.Host, j.Target.Port) {
		return fail(CodeTargetNotAllowed, "target is not on this agent's local allowlist")
	}
	// 3. The credential, from the local store only.
	pw, err := e.Creds.Get(j.Config.CredName)
	if err != nil {
		if errors.Is(err, ErrNoCredential) {
			return fail(CodeNoCredential, "no credential of that name on this agent")
		}
		return fail(CodeFailed, "the local credential store could not be read")
	}
	var roots *x509.CertPool
	if j.Config.CABundle != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(j.Config.CABundle)) {
			return fail(CodeBadRequest, "ca_bundle holds no certificate")
		}
	}
	// 4. A dialer that allows only the listed private targets (and the
	// public ones the shared address policy allows, which are also listed).
	d, err := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: e.Allow, RootCAs: roots,
		Resolver: e.Resolver, TestDial: e.TestDial})
	if err != nil {
		return fail(CodeFailed, "dialer: "+err.Error())
	}
	p, err := e.New(ProberSpec{Target: j.Target, Config: j.Config, Password: pw, RootCAs: roots, Dialer: d})
	if err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	limit := e.MaxJob
	if limit <= 0 {
		limit = 20 * time.Second
	}
	if !j.Deadline.IsZero() {
		if rem := time.Until(j.Deadline); rem < limit {
			limit = rem
		}
	}
	if limit <= 0 {
		return fail(CodeFailed, "the job's deadline has passed")
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	payload, err := run(ctx, p, j)
	if err != nil {
		return fail(codeOf(err), safeMessage(err, pw))
	}
	b, err := json.Marshal(payload)
	if err != nil || len(b) > MaxResultBytes {
		return fail(CodeFailed, "result could not be encoded")
	}
	res.Payload = b
	return res
}

// SyncLimits are the bounds a Syncer must stay within.
type SyncLimits struct{ Accounts, Groups, Members int }

// Syncer reads the whole directory of one connection (read-only) and returns
// the typed listing. cmd/tessera-agent supplies the LDAP one; a Syncer that
// finds more than a limit returns an error rather than a partial listing.
type Syncer interface {
	Discover(ctx context.Context, lim SyncLimits) (*SyncResult, error)
}

// SyncerFactory builds the Syncer for a pulled job, like ProberFactory.
type SyncerFactory func(ProberSpec) (Syncer, error)

// pushDialer is the dialer of provisioning pushes: the agent-local policy, the
// push allowlist and the push CAs.
func (e *Executor) pushDialer() (*safedial.Dialer, error) {
	return safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: e.AllowPush, RootCAs: e.PushRoots,
		Resolver: e.Resolver, TestDial: e.TestDial})
}

// ExecutePulled runs one pulled job of any kind.
func (e *Executor) ExecutePulled(ctx context.Context, j PulledJob) PullResult {
	if j.Kind == KindPush {
		return e.ExecutePush(ctx, j)
	}
	return e.ExecuteSync(ctx, j)
}

// ExecuteSync runs one pulled sync job and returns the report to send. Like
// Execute it checks the typed arguments, then the local allowlist, before
// anything is resolved or dialed, reads the credential only from the local
// store, and never puts the credential in the report.
func (e *Executor) ExecuteSync(ctx context.Context, j PulledJob) (res PullResult) {
	res.JobID = j.ID
	fail := func(code, msg string) PullResult {
		res.Error = &ResultError{Code: code, Message: msg}
		return res
	}
	if j.Kind != KindSync {
		return fail(CodeUnknownOp, "not a Directory Agent job kind")
	}
	if j.ID == "" || len(j.ID) > 64 {
		return fail(CodeBadRequest, "job id is required")
	}
	if err := j.Spec.Validate(); err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	newSyncer, ok := e.syncerFor(j.Spec.Module)
	if !ok {
		return fail(CodeUnsupported, "this agent build cannot run that module")
	}
	if !safedial.Listed(e.Allow, j.Spec.Target.Host, j.Spec.Target.Port) {
		return fail(CodeTargetNotAllowed, "target is not on this agent's local allowlist")
	}
	pw, err := e.Creds.Get(j.Spec.Config.CredName)
	if err != nil {
		if errors.Is(err, ErrNoCredential) {
			return fail(CodeNoCredential, "no credential of that name on this agent")
		}
		return fail(CodeFailed, "the local credential store could not be read")
	}
	var roots *x509.CertPool
	if j.Spec.Config.CABundle != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(j.Spec.Config.CABundle)) {
			return fail(CodeBadRequest, "ca_bundle holds no certificate")
		}
	}
	d, err := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: e.Allow, RootCAs: roots,
		Resolver: e.Resolver, TestDial: e.TestDial})
	if err != nil {
		return fail(CodeFailed, "dialer: "+err.Error())
	}
	sy, err := newSyncer(ProberSpec{Target: j.Spec.Target, Config: j.Spec.Config, Password: pw, RootCAs: roots, Dialer: d})
	if err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	limit := SyncTimeout
	if t := time.Duration(j.TimeoutSecs) * time.Second; t > 0 && t < limit {
		limit = t
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	out, err := sy.Discover(ctx, SyncLimits{Accounts: MaxSyncAccounts, Groups: MaxSyncGroups, Members: MaxSyncMembers})
	if err != nil {
		return fail(codeOf(err), safeMessage(err, pw))
	}
	if out == nil {
		return fail(CodeFailed, "the directory returned no listing")
	}
	if err := out.Validate(); err != nil {
		return fail(CodeFailed, err.Error())
	}
	res.Sync = out
	return res
}

// run dispatches a validated job to the matching read-only Prober method. The
// switch is the whole of what the agent can do.
func run(ctx context.Context, p connectors.Prober, j Job) (any, error) {
	switch j.Op {
	case OpConnect:
		return p.Connect(ctx)
	case OpAuthenticate:
		return p.Authenticate(ctx)
	case OpRootInfo:
		return p.RootInfo(ctx)
	case OpObjectExists:
		return p.ObjectExists(ctx, j.Arg)
	case OpSample:
		return p.Sample(ctx, *j.Sample)
	case OpEffectiveRights:
		return p.EffectiveRights(ctx, j.Arg)
	case OpChangeFeed:
		return p.ChangeFeed(ctx)
	case OpRateLimits:
		return p.RateLimits(ctx)
	case OpTime:
		return p.Time(ctx)
	}
	return nil, fmt.Errorf("unknown operation %q", j.Op)
}

func codeOf(err error) string {
	switch {
	case errors.Is(err, connectors.ErrUnsupported):
		return CodeUnsupported
	case errors.Is(err, connectors.ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, connectors.ErrTargetNotAllowed), errors.Is(err, safedial.ErrBlockedAddress), errors.Is(err, safedial.ErrPort):
		return CodeTargetNotAllowed
	}
	return CodeFailed
}

// safeMessage is the error text sent to Tessera, with the credential removed
// should a library ever echo it.
func safeMessage(err error, secret string) string {
	msg := err.Error()
	if secret != "" {
		msg = strings.ReplaceAll(msg, secret, "[redacted]")
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}
