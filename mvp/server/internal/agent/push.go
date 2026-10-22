package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Provisioning pushes through an agent (issue #302).
//
// A provision_push job carries one provisioning operation (target.PushSpec) to
// an agent that can reach a private SCIM or Okta-style HTTPS target. It
// follows the rules of pull.go: addressed to (tenant, agent) from the pinned
// key, claimed and reported over the same mTLS channel, validated again on the
// agent, and finished with its audit event in one transaction on the server.
// What is specific to a push:
//
//   - The credential. The server holds the target's bearer token sealed under
//     its KEK. When it hands the job to an agent it opens that token and seals
//     it to the agent's own X25519 key (internal/seal SealToAgent), bound to
//     tenant, agent, connection and job, so the job row, the log and the audit
//     trail never hold it in the clear and only that agent can open it. The
//     agent registers the public half of the key at PathSealKey over the
//     authenticated channel. (A job may instead name a credential in the
//     agent's own store; the server does not use that for provisioning targets.)
//   - The allowlist. The agent pushes only to host:port pairs on its own
//     allowed_push_targets (ports 443 and 8443), separate from the LDAP
//     allowlist, over HTTPS verified against its push CA, through the
//     policy-checked dialer (no redirects, no plain HTTP).
//   - The outcome. The agent applies the change, re-reads the target a few
//     times, and reports applied/verified with the expected and observed
//     values: no raw response, never the credential.

// PathSealKey registers the agent's public sealing key.
const PathSealKey = "/agent/v1/seal-key"

// KindPush is the job kind of a provisioning push.
const KindPush = store.AgentJobProvisionPush

// CodeTargetRefused: the target answered with a permanent refusal (a bad
// request, an unknown group, an authorisation failure). It is not retried.
const CodeTargetRefused = "target_refused"

// Bounds of a push on the agent.
const (
	// PushTimeout bounds one push on the agent (apply and re-reads).
	PushTimeout = 2 * time.Minute
	// pushCallTimeout bounds one call to the target.
	pushCallTimeout = 30 * time.Second
	// PushVerifyTries is how many times the agent re-reads the target before it
	// reports that the change is not visible; PushVerifyWait is the pause between.
	PushVerifyTries = 3
	PushVerifyWait  = 2 * time.Second
)

// PushJob is what a claim returns for a provision_push job. TenantID and
// AgentID are the binding the credential was sealed under (the server computes
// them; the agent cannot check them, but a blob moved to another row, agent or
// tenant does not open).
type PushJob struct {
	TenantID         string          `json:"tenant_id"`
	AgentID          string          `json:"agent_id"`
	Spec             target.PushSpec `json:"spec"`
	SealedCredential []byte          `json:"sealed_credential,omitempty"`
	SealKeyID        string          `json:"seal_key_id,omitempty"`
}

// PushResult is the agent's report of a push whose apply succeeded: whether
// the re-read showed the change, and what it expected and saw.
type PushResult struct {
	Applied  bool   `json:"applied"`
	Verified bool   `json:"verified"`
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`
}

// SealKeyRequest is the body of PathSealKey.
type SealKeyRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	PublicKey       []byte `json:"public_key"`
}

// PushHooks is what the server wiring (internal/worker) supplies so that this
// package stays free of the provisioning engine.
type PushHooks interface {
	// Credential returns the credential of the job's connection's target,
	// opened under the KEK, or "" when the target has none.
	Credential(tx *store.TenantTx, j *store.AgentJob) (string, error)
	// Done finishes the job's operation with the agent's outcome, in tx, and
	// returns the counts-only summary kept on the job. An operation that
	// cannot be finished because Tessera could not apply its side of the
	// change returns a *PushApplyError.
	Done(tx *store.TenantTx, now time.Time, a *store.DirectoryAgent, j *store.AgentJob, res *PushResult) (ojson.Object, error)
	// Failed records that the job failed. final: it will not be tried again,
	// so the operation fails too; otherwise the operation keeps waiting.
	Failed(tx *store.TenantTx, now time.Time, a *store.DirectoryAgent, j *store.AgentJob, msg string, final bool) error
}

// PushApplyError is returned by PushHooks.Done when the target shows the change
// but Tessera's own side of it could not be applied. The transaction is
// unusable; Report records the failure in a second one.
type PushApplyError struct{ Err error }

func (e *PushApplyError) Error() string { return e.Err.Error() }
func (e *PushApplyError) Unwrap() error { return e.Err }

// ---------------------------------------------------------------- server side

// pushJob builds the claim of a push job: the validated spec and the
// credential sealed to the agent. An error means the job can never run as it is
// (the caller fails it for good, with the message).
func (s *Service) pushJob(c *store.TenantTx, a *store.DirectoryAgent, j *store.AgentJob) (*PushJob, error) {
	if s.Push == nil {
		return nil, errors.New("this server cannot hand out provisioning pushes")
	}
	var spec target.PushSpec
	if err := json.Unmarshal([]byte(j.Payload), &spec); err != nil || spec.Validate() != nil || j.OpID == nil || spec.OpID != *j.OpID {
		return nil, errors.New("the job payload is not valid")
	}
	k, err := c.AgentSealKey(a.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("this agent has not registered a sealing key: upgrade it to a build that supports provisioning pushes and restart it")
	}
	if err != nil {
		return nil, err
	}
	pj := &PushJob{TenantID: c.Tenant().String(), AgentID: a.ID, Spec: spec}
	token, err := s.Push.Credential(c, j)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return pj, nil
	}
	pub, err := seal.ParseAgentPublicKey(k.PublicKey)
	if err != nil {
		return nil, errors.New("the agent's registered sealing key is not valid: restart the agent to register a new one")
	}
	aad, ok := seal.AgentAAD(c.Tenant(), a.ID, j.ConnectionID, j.ID)
	if !ok {
		return nil, errors.New("the job cannot be bound to the agent")
	}
	if pj.SealedCredential, err = seal.SealToAgent(pub, []byte(token), aad); err != nil {
		return nil, errors.New("the credential could not be sealed to the agent")
	}
	pj.SealKeyID = k.KeyID
	return pj, nil
}

// RegisterSealKey records the agent's public sealing key (a repeat of the same
// key changes nothing; another key replaces it, audited).
func (s *Service) RegisterSealKey(ctx context.Context, p *Principal, req SealKeyRequest) (keyID string, err error) {
	if req.ProtocolVersion != ProtocolVersion {
		return "", ErrProtocol
	}
	if _, err := seal.ParseAgentPublicKey(req.PublicKey); err != nil {
		return "", fmt.Errorf("%w: the public key is not valid", ErrBadInput)
	}
	keyID = seal.AgentKeyID(req.PublicKey)
	now := s.Clock()
	err = s.DB.InTenant(ctx, p.Tenant, func(c *store.TenantTx) error {
		a, err := c.DirectoryAgent(p.AgentID)
		if err != nil {
			return err
		}
		if a.Status != store.AgentActive {
			return ErrUnauthorized
		}
		old, err := c.AgentSealKey(a.ID)
		switch {
		case err == nil && old.KeyID == keyID:
			return nil
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return err
		}
		if err := c.PutAgentSealKey(&store.AgentSealKey{AgentID: a.ID, PublicKey: req.PublicKey, KeyID: keyID}, now); err != nil {
			return err
		}
		d := ojson.Object{{Key: "agent_id", Value: a.ID}, {Key: "key_id", Value: keyID}, {Key: "replaced", Value: old != nil}}
		_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "agent.seal_key_registered", LegacyActor: "agent:" + a.Name,
			TargetType: "directory_agent", TargetID: a.ID, Detail: d})
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrUnauthorized
	}
	return keyID, err
}

// failPush ends a push job whose operation could not be finished (Tessera
// could not apply its side of a verified change) in a second transaction.
func (s *Service) failPush(ctx context.Context, p *Principal, jobID, msg string) error {
	now := s.Clock()
	err := s.DB.InTenant(ctx, p.Tenant, func(c *store.TenantTx) error {
		a, err := c.DirectoryAgent(p.AgentID)
		if err != nil {
			return err
		}
		j, err := c.AgentJob(jobID)
		if err != nil || j.AgentID != p.AgentID || j.Status != store.AgentJobLeased {
			return ErrUnknownJob
		}
		if err := c.FailAgentJob(j, msg, false, now); err != nil {
			return err
		}
		if err := s.Push.Failed(c, now, a, j, msg, true); err != nil {
			return err
		}
		return s.auditJob(c, now, a, "agent.job_failed", j, ojson.Object{{Key: "error", Value: msg}, {Key: "will_retry", Value: false}})
	})
	if errors.Is(err, store.ErrNotFound) {
		return ErrUnknownJob
	}
	return err
}

// ---------------------------------------------------------------- agent side

// ExecutePush runs one pulled provision_push job and returns the report to
// send. Like ExecuteSync it checks the typed spec, then the local allowlist,
// before anything is resolved or dialed; the credential reaches it sealed to
// its own key (or is read from its local store by name); it applies the change
// with the SCIM or Okta connector over a policy-checked HTTPS client, re-reads
// the target, and never puts the credential in the report.
func (e *Executor) ExecutePush(ctx context.Context, j PulledJob) (res PullResult) {
	res.JobID = j.ID
	fail := func(code, msg string) PullResult {
		res.Error = &ResultError{Code: code, Message: msg}
		return res
	}
	if j.Kind != KindPush || j.Push == nil {
		return fail(CodeUnknownOp, "not a Directory Agent job kind")
	}
	if j.ID == "" || len(j.ID) > 64 {
		return fail(CodeBadRequest, "job id is required")
	}
	spec := j.Push.Spec
	if err := spec.Validate(); err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	host, port, err := spec.HostPort()
	if err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	if !safedial.Listed(e.AllowPush, host, port) {
		return fail(CodeTargetNotAllowed, "target is not on this agent's local allowed_push_targets")
	}
	token, code, msg := e.pushCredential(j)
	if code != "" {
		return fail(code, msg)
	}
	d, err := e.pushDialer()
	if err != nil {
		return fail(CodeFailed, "dialer: "+err.Error())
	}
	conn, err := pushConnector(spec, token, d.HTTPClient(pushCallTimeout))
	if err != nil {
		return fail(CodeBadRequest, err.Error())
	}
	limit := PushTimeout
	if t := time.Duration(j.TimeoutSecs) * time.Second; t > 0 && t < limit {
		limit = t
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	req := spec.Request()
	if err := conn.Apply(ctx, req); err != nil {
		return fail(pushCode(err), safeMessage(err, token))
	}
	tries, wait := PushVerifyTries, e.PushVerifyWait
	if wait <= 0 {
		wait = PushVerifyWait
	}
	var v target.Verdict
	for i := 1; ; i++ {
		var verr error
		if v, verr = conn.Verify(ctx, req); verr != nil {
			return fail(pushCode(verr), "applied, but the re-read failed: "+safeMessage(verr, token))
		}
		if v.OK || i >= tries {
			break
		}
		select {
		case <-ctx.Done():
			return fail(CodeFailed, "applied, but the push ran out of time before the re-read showed it")
		case <-time.After(wait):
		}
	}
	res.Push = &PushResult{Applied: true, Verified: v.OK, Expected: clip(v.Expected), Observed: clip(v.Observed)}
	return res
}

// pushCredential returns the job's credential: opened from the blob sealed to
// this agent's key, or read from the local store by name. code is "" on success.
func (e *Executor) pushCredential(j PulledJob) (token, code, msg string) {
	spec := j.Push.Spec
	switch {
	case spec.CredName != "":
		if e.Creds == nil {
			return "", CodeNoCredential, "no credential store on this agent"
		}
		tok, err := e.Creds.Get(spec.CredName)
		if errors.Is(err, ErrNoCredential) {
			return "", CodeNoCredential, "no credential of that name on this agent"
		}
		if err != nil {
			return "", CodeFailed, "the local credential store could not be read"
		}
		return tok, "", ""
	case len(j.Push.SealedCredential) > 0:
		if e.SealKey == nil {
			return "", CodeNoCredential, "this agent has no sealing key"
		}
		tenant, err := tenancy.Parse(j.Push.TenantID)
		if err != nil {
			return "", CodeBadRequest, "the job's tenant is not valid"
		}
		aad, ok := seal.AgentAAD(tenant, j.Push.AgentID, j.ConnectionID, j.ID)
		if !ok {
			return "", CodeBadRequest, "the job cannot be bound to this agent"
		}
		tok, err := seal.OpenFromAgent(e.SealKey, j.Push.SealedCredential, aad)
		if err != nil {
			return "", CodeNoCredential, "the sealed credential could not be opened with this agent's key"
		}
		return string(tok), "", ""
	}
	return "", "", "" // a target with no credential
}

func pushConnector(spec target.PushSpec, token string, hc *http.Client) (target.Connector, error) {
	switch spec.Target {
	case "scim":
		return &scim.Client{HTTP: hc, BaseURL: spec.BaseURL, Token: token, Dialect: spec.Dialect}, nil
	case "okta":
		return &okta.Client{HTTP: hc, BaseURL: spec.BaseURL, Token: token}, nil
	}
	return nil, fmt.Errorf("unknown target kind %q", spec.Target)
}

// pushCode maps a target error to a result code: a permanent refusal is not
// retried, anything a later attempt may fix is.
func pushCode(err error) string {
	switch {
	case errors.Is(err, safedial.ErrBlockedAddress), errors.Is(err, safedial.ErrPort):
		return CodeTargetNotAllowed
	case target.Retryable(err):
		return CodeFailed
	}
	return CodeTargetRefused
}

func clip(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// LoadPushRoots builds the pool of CAs push targets' certificates are verified
// against from the agent's push_ca_file (without one, the system roots).
func LoadPushRoots(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("agent: push_ca_file holds no certificate")
	}
	return pool, nil
}
