package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Jobs the agent pulls (issue #302).
//
// The probe jobs of protocol.go are pushed through the in-memory Hub to an
// agent that is polling: Tessera waits for the answer. A sync is different:
// it is long, its answer is a whole directory listing, and the process that
// asks for it (a `tessera worker`) is not the process that holds the agent's
// connection. So a sync is a row (agent_jobs). The agent long-polls
// PathClaim, receives the rows addressed to its own id, reads its directory
// in its own network and posts the typed answer to PathReport; the API
// records it through the ingest path in the transaction that finishes the row.
//
// What keeps it narrow, in addition to the rules of protocol.go:
//
//   - An agent is addressed by the pin of its client certificate. The tenant
//     and agent id of a claim or a report come from that pin; a job id in a
//     report that does not belong to that (tenant, agent) is "unknown job".
//   - A job names one connection. The agent never sees another connection's
//     job, and never a job of another tenant (agent_jobs is tenant-scoped).
//   - The job carries no secret: the directory credential is read from the
//     agent's local store by name (the existing Directory Agent design).
//   - The result is typed and bounded (SyncResult): accounts, groups and
//     memberships, never raw LDAP entries or attribute values beyond the
//     fields below, and every field is validated before it is ingested.

// KindSync is the kind of a job that reads a connection's directory.
const KindSync = store.AgentJobSync

// Paths of the pull API (served on the mTLS listener only).
const (
	PathClaim  = "/agent/v1/jobs/claim"
	PathReport = "/agent/v1/jobs/report"
)

// Bounds of a pulled sync.
const (
	// JobLease is how long a claimed job is the agent's before it is claimed
	// again (the agent crashed or lost the network).
	JobLease = 10 * time.Minute
	// SyncTimeout bounds one sync on the agent.
	SyncTimeout = 8 * time.Minute
	// MaxSyncResultBytes bounds a report (a directory listing).
	MaxSyncResultBytes = 32 << 20

	MaxSyncAccounts = 20000
	MaxSyncGroups   = 5000
	MaxSyncMembers  = 100000

	maxSyncText = 256
	// maxExtra bounds the mapped attributes of one account.
	maxExtra = 32
	// pullPollEvery is how often a long-poll looks for a new job.
	pullPollEvery = 2 * time.Second
)

// SyncSpec is the payload of a sync job: the directory, the non-secret
// settings and the system name the records belong to.
type SyncSpec struct {
	System string `json:"system"`
	// Module names the plug-in that reads the directory (see Executor.Modules):
	// empty is the built-in LDAP reader, otherwise one of the closed set of
	// ModuleNames. An agent that does not carry the module answers
	// "unsupported".
	Module string      `json:"module,omitempty"`
	Target Target      `json:"target"`
	Config ProbeConfig `json:"config"`
}

// Validate bounds a spec. The server builds it; the agent checks it again.
func (s SyncSpec) Validate() error {
	if s.System == "" || len(s.System) > maxSyncText || strings.ContainsAny(s.System, "\r\n\x00") {
		return errors.New("system is not valid")
	}
	if s.Module != "" && !ValidModuleName(s.Module) {
		return errors.New("module is not valid")
	}
	return validateTarget(s.Target, s.Config)
}

// PulledJob is what a claim returns: one sync for one connection.
type PulledJob struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	ConnectionID string   `json:"connection_id"`
	Attempt      int      `json:"attempt"`
	Spec         SyncSpec `json:"spec,omitzero"`  // a sync job
	Push         *PushJob `json:"push,omitempty"` // a provision_push job
	// TimeoutSecs is how long the agent may spend (relative, so a clock
	// difference between the agent and Tessera cannot make a job late).
	TimeoutSecs int `json:"timeout_seconds"`
}

// SyncAccount is an account read from the directory. Status is "active" or
// "disabled". Email is optional and only used to correlate with a person.
type SyncAccount struct {
	ExternalID string `json:"external_id"`
	Username   string `json:"username"`
	Email      string `json:"email,omitempty"`
	Status     string `json:"status"`
	// Extra are the values of the connection's attribute map.
	Extra []SyncExtra `json:"extra,omitempty"`
}

// SyncExtra is one mapped attribute value of an account.
type SyncExtra struct {
	Scope  string `json:"scope"` // account | identity
	Target string `json:"target"`
	Value  string `json:"value"`
}

// SyncGroup is a security group read from the directory.
type SyncGroup struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	Privileged bool   `json:"privileged,omitempty"`
}

// SyncMember says that an account is a member of a group (external ids).
type SyncMember struct {
	Account string `json:"account"`
	Group   string `json:"group"`
}

// SyncResult is the typed answer of a sync.
type SyncResult struct {
	Accounts []SyncAccount `json:"accounts"`
	Groups   []SyncGroup   `json:"groups"`
	Members  []SyncMember  `json:"members"`
}

// PullResult is the agent's report of one pulled job: an error or a result.
type PullResult struct {
	JobID string       `json:"job_id"`
	Error *ResultError `json:"error,omitempty"`
	Sync  *SyncResult  `json:"sync,omitempty"`
	Push  *PushResult  `json:"push,omitempty"`
}

// Validate bounds and checks a result before anything is ingested.
func (r *SyncResult) Validate() error {
	if len(r.Accounts) > MaxSyncAccounts || len(r.Groups) > MaxSyncGroups || len(r.Members) > MaxSyncMembers {
		return errors.New("the result is larger than the limits")
	}
	text := func(s string, required bool) bool {
		if (required && s == "") || len(s) > maxSyncText || strings.ContainsAny(s, "\r\n\x00") {
			return false
		}
		return true
	}
	accts := make(map[string]bool, len(r.Accounts))
	for _, a := range r.Accounts {
		if !text(a.ExternalID, true) || !text(a.Username, true) || !text(a.Email, false) || (a.Status != "active" && a.Status != "disabled") {
			return errors.New("an account is not valid")
		}
		if len(a.Extra) > maxExtra {
			return errors.New("an account is not valid")
		}
		for _, x := range a.Extra {
			if (x.Scope != "account" && x.Scope != "identity") || !validAttrName(x.Target) || !text(x.Value, true) {
				return errors.New("an account is not valid")
			}
		}
		accts[a.ExternalID] = true
	}
	groups := make(map[string]bool, len(r.Groups))
	for _, g := range r.Groups {
		if !text(g.ExternalID, true) || !text(g.Name, true) {
			return errors.New("a group is not valid")
		}
		groups[g.ExternalID] = true
	}
	for _, m := range r.Members {
		if !accts[m.Account] || !groups[m.Group] {
			return errors.New("a membership names an account or group that is not in the result")
		}
	}
	return nil
}

// SyncRecorder records a finished sync through the ingest path, inside tx,
// and returns the counts to keep on the job. It is set by the server wiring
// (internal/worker.RecordAgentSync) so that this package stays free of the
// ingest code.
type SyncRecorder func(tx *store.TenantTx, now time.Time, job *store.AgentJob, spec SyncSpec, res *SyncResult) (ojson.Object, error)

// ErrNoRecorder: the server was not given a way to record a sync.
var ErrNoRecorder = errors.New("agent: no sync recorder is configured")

// Claim leases the next due job of the agent, waiting up to wait for one. It
// returns (nil, nil) when none arrived. Only the agent's own jobs are visible.
func (s *Service) Claim(ctx context.Context, p *Principal, wait time.Duration) (*PulledJob, error) {
	every := s.PullPoll
	if every <= 0 {
		every = pullPollEvery
	}
	deadline := time.Now().Add(wait)
	for {
		j, err := s.claimOne(ctx, p)
		if err != nil || j != nil {
			return j, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(every, left)):
		}
	}
}

func (s *Service) claimOne(ctx context.Context, p *Principal) (*PulledJob, error) {
	now := s.Clock()
	var due bool
	if err := s.DB.ReadTenant(ctx, p.Tenant, func(c *store.TenantTx) (err error) {
		due, err = c.HasDueAgentJobs(p.AgentID, now)
		return err
	}); err != nil || !due {
		return nil, err
	}
	var out *PulledJob
	err := s.DB.InTenant(ctx, p.Tenant, func(c *store.TenantTx) error {
		a, err := c.DirectoryAgent(p.AgentID)
		if err != nil {
			return err
		}
		if a.Status != store.AgentActive {
			return ErrUnauthorized
		}
		claimed, dead, err := c.ClaimAgentJobs(p.AgentID, now, JobLease, 1)
		if err != nil {
			return err
		}
		for _, j := range dead {
			if err := s.auditJob(c, now, a, "agent.job_failed", j, ojson.Object{{Key: "error", Value: j.LastError}}); err != nil {
				return err
			}
			if j.Kind == KindPush && s.Push != nil {
				if err := s.Push.Failed(c, now, a, j, j.LastError, true); err != nil {
					return err
				}
			}
		}
		for _, j := range claimed {
			switch j.Kind {
			case KindSync:
				var spec SyncSpec
				if err := json.Unmarshal([]byte(j.Payload), &spec); err != nil || spec.Validate() != nil {
					// a malformed row can never run: fail it rather than hand it out
					if err := c.FailAgentJob(j, "the job payload is not valid", false, now); err != nil {
						return err
					}
					continue
				}
				out = &PulledJob{ID: j.ID, Kind: j.Kind, ConnectionID: j.ConnectionID, Attempt: j.Attempts, Spec: spec,
					TimeoutSecs: int(SyncTimeout / time.Second)}
			case KindPush:
				pj, err := s.pushJob(c, a, j)
				if err != nil {
					// a push that can never run as it is (no sealing key, bad spec, a credential that
					// cannot be opened) fails its operation now, with the reason, rather than at the lease
					msg := err.Error()
					if err := c.FailAgentJob(j, msg, false, now); err != nil {
						return err
					}
					if s.Push != nil {
						if err := s.Push.Failed(c, now, a, j, msg, true); err != nil {
							return err
						}
					}
					if err := s.auditJob(c, now, a, "agent.job_failed", j, ojson.Object{{Key: "error", Value: msg}}); err != nil {
						return err
					}
					continue
				}
				out = &PulledJob{ID: j.ID, Kind: j.Kind, ConnectionID: j.ConnectionID, Attempt: j.Attempts, Push: pj,
					TimeoutSecs: int(PushTimeout / time.Second)}
			default:
				if err := c.FailAgentJob(j, "unknown job kind", false, now); err != nil {
					return err
				}
				continue
			}
			break
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthorized
	}
	return out, err
}

func (s *Service) auditJob(c *store.TenantTx, now time.Time, a *store.DirectoryAgent, action string, j *store.AgentJob, extra ojson.Object) error {
	d := ojson.Object{{Key: "job_id", Value: j.ID}, {Key: "agent_id", Value: a.ID}, {Key: "connection_id", Value: j.ConnectionID},
		{Key: "attempts", Value: j.Attempts}}
	_, err := c.RecordAudit(store.AuditRecord{At: now, Action: action, LegacyActor: "agent:" + a.Name,
		TargetType: "agent_job", TargetID: j.ID, Detail: append(d, extra...)})
	return err
}

// retryable: a failure the agent may succeed at later. A refused target, a
// missing credential or a bad request fails the job for good.
func retryable(code string) bool { return code == CodeFailed || code == CodeRateLimited }

// Report records the agent's answer to a pulled job. The job must be leased
// to exactly this tenant and agent, else ErrUnknownJob. A result is ingested
// and the job finished in one transaction, with its audit event.
func (s *Service) Report(ctx context.Context, p *Principal, res PullResult) error {
	if s.Recorder == nil {
		return ErrNoRecorder
	}
	if res.Error == nil {
		if (res.Sync == nil) == (res.Push == nil) {
			return fmt.Errorf("%w: a report holds an error or one result", ErrBadInput)
		}
		if res.Sync != nil {
			if err := res.Sync.Validate(); err != nil {
				return fmt.Errorf("%w: %s", ErrBadInput, err)
			}
		}
	}
	now := s.Clock()
	err := s.DB.InTenant(ctx, p.Tenant, func(c *store.TenantTx) error {
		a, err := c.DirectoryAgent(p.AgentID)
		if err != nil {
			return err
		}
		if a.Status != store.AgentActive {
			return ErrUnauthorized
		}
		j, err := c.AgentJob(res.JobID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && (j.AgentID != p.AgentID || j.Status != store.AgentJobLeased)) {
			return ErrUnknownJob
		}
		if err != nil {
			return err
		}
		if res.Error != nil {
			willRetry := retryable(res.Error.Code) && j.Attempts < j.MaxAttempts
			msg := res.Error.Code
			if res.Error.Message != "" {
				msg += ": " + res.Error.Message
			}
			if err := c.FailAgentJob(j, msg, retryable(res.Error.Code), now); err != nil {
				return err
			}
			if j.Kind == KindPush && s.Push != nil {
				if err := s.Push.Failed(c, now, a, j, msg, !willRetry); err != nil {
					return err
				}
			}
			return s.auditJob(c, now, a, "agent.job_failed", j, ojson.Object{{Key: "code", Value: res.Error.Code},
				{Key: "will_retry", Value: willRetry}})
		}
		if j.Kind == KindPush {
			if res.Push == nil || s.Push == nil {
				return ErrBadInput
			}
			summary, err := s.Push.Done(c, now, a, j, res.Push)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(summary)
			if err != nil {
				return err
			}
			if err := c.CompleteAgentJob(j.ID, p.AgentID, string(raw), now); err != nil {
				return err
			}
			return s.auditJob(c, now, a, "agent.job_done", j, summary)
		}
		if res.Sync == nil {
			return ErrBadInput
		}
		var spec SyncSpec
		if err := json.Unmarshal([]byte(j.Payload), &spec); err != nil {
			return err
		}
		summary, err := s.Recorder(c, now, j, spec, res.Sync)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(summary)
		if err != nil {
			return err
		}
		if err := c.CompleteAgentJob(j.ID, p.AgentID, string(raw), now); err != nil {
			return err
		}
		return s.auditJob(c, now, a, "agent.job_done", j, summary)
	})
	var pae *PushApplyError
	if errors.As(err, &pae) {
		return s.failPush(ctx, p, res.JobID, pae.Error())
	}
	if errors.Is(err, store.ErrNotFound) {
		return ErrUnknownJob
	}
	return err
}
