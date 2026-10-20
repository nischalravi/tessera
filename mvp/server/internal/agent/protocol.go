// Package agent is the Tessera Directory Agent protocol (DR-11, design
// docs/design/deployment-readiness.md §5.3).
//
// A private directory (an Active Directory or LDAP server inside a customer
// network) is never dialed from Tessera. A small agent, run by the customer
// inside that network, connects outbound to Tessera over mutual TLS and
// answers a closed set of typed, read-only operations. This package holds both
// ends:
//
//   - the server side (Service, Hub, Handler, RemoteProber): enrolment, the
//     mTLS channel, the job queue and a connectors.Prober that sends each
//     probe operation to the agent;
//   - the agent side (Executor, Client, the credential stores): the local
//     allowlist, typed-operation dispatch and the HTTP client.
//
// What keeps it narrow:
//
//   - The only operations are the nine of connectors.ProberOps, each with
//     typed arguments (Job). There is no operation that sends arbitrary bytes,
//     arbitrary LDAP operations or a command, and no generic proxy: the agent
//     opens its own connection to the directory and runs the read-only Prober
//     itself. Jobs are decoded with unknown fields refused and every argument
//     is bounded.
//   - The agent refuses any target that is not on its own local allowlist (a
//     file only a local administrator can edit) before it dials anything. A
//     tenant administrator, or a compromised Tessera, cannot point it at
//     another host or port.
//   - The directory credential lives on the agent (a file store with 0600
//     permissions, or DPAPI on Windows). A job carries only the credential's
//     name; Tessera keeps the reference agent:<id>/<name> and never sees the
//     secret.
//   - Enrolment uses a single-use code (random, 15 minutes, stored only as a
//     hash). The agent then presents a client key that Tessera pins (SHA-256
//     of its public key) and the agent pins Tessera's CA, so neither end
//     trusts a public CA or a name alone.
//
// This package imports no LDAP library, no os/exec and no SQL;
// TestAgent_OnlyTypedOps scans it for them.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// ProtocolVersion is the wire protocol. An agent speaking another version is
// refused at enrolment and heartbeat.
const ProtocolVersion = 1

// Version is this build's agent version. MinVersion is the oldest agent the
// server treats as up to date (Admin shows an older one as out of date).
const (
	Version    = "0.1.0"
	MinVersion = "0.1.0"
)

// Paths of the agent API (served on the mTLS listener only).
const (
	PathEnrol     = "/agent/v1/enrol"
	PathHeartbeat = "/agent/v1/heartbeat"
	PathPoll      = "/agent/v1/poll"
	PathResult    = "/agent/v1/result"
)

// Bounds. Requests from the agent are small; a result is capped because a
// sample result is counts, never values.
const (
	MaxRequestBytes = 64 << 10
	MaxResultBytes  = 1 << 20
	// EnrolmentTTL is the lifetime of an enrolment code.
	EnrolmentTTL = 15 * time.Minute
	// PollWait is how long a poll is held open waiting for a job.
	PollWait = 25 * time.Second
	// JobTimeout bounds one operation end to end (queue, agent, result).
	JobTimeout = 30 * time.Second

	maxFilter = 2048
	maxList   = 64
	maxItem   = 512
	maxCA     = 64 << 10
)

// Op is one of the typed operations. The set is closed: it is exactly
// connectors.ProberOps (TestAgent_OnlyTypedOps).
type Op string

// The operations, one per connectors.Prober method.
const (
	OpConnect         Op = "connect"
	OpAuthenticate    Op = "authenticate"
	OpRootInfo        Op = "root_info"
	OpObjectExists    Op = "object_exists"
	OpSample          Op = "sample"
	OpEffectiveRights Op = "effective_rights"
	OpChangeFeed      Op = "change_feed"
	OpRateLimits      Op = "rate_limits"
	OpTime            Op = "time"
)

// Ops lists every operation.
var Ops = []Op{OpConnect, OpAuthenticate, OpRootInfo, OpObjectExists, OpSample, OpEffectiveRights, OpChangeFeed,
	OpRateLimits, OpTime}

// Valid reports whether op is one of the typed operations.
func (o Op) Valid() bool {
	for _, k := range Ops {
		if k == o {
			return true
		}
	}
	return false
}

// Target is the directory a job addresses. The agent checks it against its
// local allowlist; the server has already restricted the port to 389 and 636.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ProbeConfig is the non-secret connection settings a job carries. CredName
// names a credential in the agent's own store; the secret is never sent.
type ProbeConfig struct {
	BindDN     string   `json:"bind_dn"`
	CredName   string   `json:"cred_name"`
	BaseDNs    []string `json:"base_dns,omitempty"`
	UserFilter string   `json:"user_filter,omitempty"`
	// CABundle is the connection's PEM CA bundle (public certificates).
	CABundle string `json:"ca_bundle,omitempty"`
}

// Job is one typed operation for one agent. Arg is the object reference of
// object_exists and effective_rights; Sample is the bounded query of sample.
type Job struct {
	ID       string                  `json:"id"`
	Op       Op                      `json:"op"`
	Target   Target                  `json:"target"`
	Config   ProbeConfig             `json:"config"`
	Arg      string                  `json:"arg,omitempty"`
	Sample   *connectors.SampleQuery `json:"sample,omitempty"`
	Deadline time.Time               `json:"deadline"`
}

// Result error codes. They map to the errors of package connectors.
const (
	CodeTargetNotAllowed = "target_not_allowed"
	CodeUnsupported      = "unsupported"
	CodeRateLimited      = "rate_limited"
	CodeUnknownOp        = "unknown_op"
	CodeBadRequest       = "bad_request"
	CodeNoCredential     = "no_credential" // #nosec G101 -- an error code, not a credential
	CodeFailed           = "failed"
)

// ResultError is a failed operation. Message never contains the credential.
type ResultError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Result is the agent's answer to one job: Payload is the JSON of the
// connectors type the operation returns (ConnInfo, AuthInfo, ...).
type Result struct {
	JobID   string          `json:"job_id"`
	Error   *ResultError    `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Err converts a failed result to an error that wraps the matching error of
// package connectors, so readiness reports "unsupported" and "rate limited"
// as before.
func (r Result) Err() error {
	if r.Error == nil {
		return nil
	}
	msg := r.Error.Message
	switch r.Error.Code {
	case CodeTargetNotAllowed:
		return fmt.Errorf("%w (not on its local allowlist)", connectors.ErrAgentRefused)
	case CodeUnsupported:
		return connectors.ErrUnsupported
	case CodeRateLimited:
		return connectors.ErrRateLimited
	}
	if msg == "" {
		msg = r.Error.Code
	}
	return fmt.Errorf("directory agent: %s", msg)
}

// ---------------------------------------------------------------- wire messages

// EnrolRequest is the body of PathEnrol. The agent's client certificate is
// taken from the TLS handshake, not from the body.
type EnrolRequest struct {
	Code            string `json:"code"`
	ProtocolVersion int    `json:"protocol_version"`
	Telemetry
}

// EnrolResponse answers PathEnrol.
type EnrolResponse struct {
	AgentID         string `json:"agent_id"`
	ProtocolVersion int    `json:"protocol_version"`
	HeartbeatSecs   int    `json:"heartbeat_seconds"`
}

// Telemetry is what an agent reports about itself.
type Telemetry struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Version       string `json:"version"`
	AllowlistHash string `json:"allowlist_hash"`
}

// HeartbeatRequest is the body of PathHeartbeat.
type HeartbeatRequest struct {
	ProtocolVersion int `json:"protocol_version"`
	Telemetry
}

// Validate bounds the free-text fields an agent reports.
func (t Telemetry) Validate() error {
	for name, v := range map[string]string{"hostname": t.Hostname, "os": t.OS, "version": t.Version} {
		if len(v) > 128 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: %s", ErrBadInput, name)
		}
	}
	if len(t.AllowlistHash) > 64 {
		return fmt.Errorf("%w: allowlist_hash", ErrBadInput)
	}
	return nil
}

// ErrBadInput marks a request field the server refuses.
var ErrBadInput = errors.New("agent: invalid input")

// ValidateJob checks the typed arguments of a job. The agent calls it before
// anything is dialed; the RemoteProber builds only jobs that pass it.
func ValidateJob(j Job) error {
	if !j.Op.Valid() {
		return fmt.Errorf("unknown operation %q", j.Op)
	}
	if j.ID == "" || len(j.ID) > 64 {
		return errors.New("job id is required")
	}
	if j.Target.Host == "" || len(j.Target.Host) > 253 || strings.ContainsAny(j.Target.Host, "/@ \t\r\n\x00") {
		return errors.New("target host is not valid")
	}
	if j.Target.Port != safedial.PortLDAPS && j.Target.Port != safedial.PortStartTLS {
		return fmt.Errorf("target port must be %d or %d", safedial.PortStartTLS, safedial.PortLDAPS)
	}
	c := j.Config
	if len(c.BindDN) > maxItem || !validCredName(c.CredName) || len(c.UserFilter) > maxFilter || len(c.CABundle) > maxCA ||
		len(c.BaseDNs) > maxList {
		return errors.New("config is not valid")
	}
	for _, d := range c.BaseDNs {
		if len(d) > maxItem {
			return errors.New("config is not valid")
		}
	}
	if len(j.Arg) > maxItem {
		return errors.New("arg is too long")
	}
	switch j.Op {
	case OpSample:
		q := j.Sample
		if q == nil {
			return errors.New("sample needs a query")
		}
		if q.Limit < 0 || q.Limit > connectors.MaxSample || len(q.Filter) > maxFilter || len(q.Classes) > maxList ||
			len(q.Attrs) > maxList || len(q.Op) > 32 {
			return errors.New("sample query is not valid")
		}
		for _, s := range append(append([]string{}, q.Classes...), q.Attrs...) {
			if len(s) > maxItem {
				return errors.New("sample query is not valid")
			}
		}
	default:
		if j.Sample != nil {
			return fmt.Errorf("%s takes no sample query", j.Op)
		}
	}
	if (j.Op != OpObjectExists && j.Op != OpEffectiveRights) && j.Arg != "" {
		return fmt.Errorf("%s takes no argument", j.Op)
	}
	return nil
}

// validCredName: a credential name is a short file-safe token.
func validCredName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return s != "." && s != ".."
}

// ValidCredName is validCredName for the credential stores and the server.
func ValidCredName(s string) bool { return validCredName(s) }

// ParseRef parses a credential reference agent:<id>/<name>.
func ParseRef(ref string) (agentID, name string, ok bool) {
	rest, found := strings.CutPrefix(ref, "agent:")
	if !found {
		return "", "", false
	}
	agentID, name, found = strings.Cut(rest, "/")
	if !found || agentID == "" || !validCredName(name) || strings.ContainsAny(agentID, "/:") {
		return "", "", false
	}
	return agentID, name, true
}
