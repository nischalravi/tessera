package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Errors of enrolment and authentication. They are deliberately coarse: a
// caller learns nothing about why a code or key was refused.
var (
	ErrInvalidCode  = errors.New("agent: the enrolment code is not valid")
	ErrUnauthorized = errors.New("agent: not an enrolled agent")
	ErrProtocol     = errors.New("agent: unsupported protocol version")
	ErrName         = errors.New("agent: the name must be 1 to 64 characters: letters, digits, space, dot, dash or underscore")
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// codePrefix marks an enrolment code (so a leaked one is recognisable by a
// secret scanner). The rest is 32 random bytes, base64url.
const codePrefix = "tdae_"

// Service holds the agent state machine: issuing an enrolment code, enrolling
// an agent, authenticating the agent's key, heartbeats and revocation. The
// admin methods run inside the caller's tenant transaction, so the domain
// event is written in the same transaction as the change.
type Service struct {
	DB    *store.DB
	Hub   *Hub
	Clock timeutil.Clock
	// Recorder ingests a pulled sync (see pull.go); without it a report is refused.
	Recorder SyncRecorder
	// PullPoll is how often a long-poll looks for work (2 s).
	PullPoll time.Duration
}

// HashCode is the SHA-256 (hex) under which a code is stored and looked up.
func HashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// PinOf is the SHA-256 (hex) of a certificate's public key (its SPKI), the
// pin Tessera holds for an agent. It does not depend on the certificate's
// validity period or issuer, so the agent may use a self-signed certificate.
func PinOf(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

func newCode() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return codePrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// View is an agent as the admin API shows it. It carries no secret and no pin.
type View struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Status        string     `json:"status"`
	Online        bool       `json:"online"`
	Outdated      bool       `json:"outdated"`
	Hostname      string     `json:"hostname,omitempty"`
	OS            string     `json:"os,omitempty"`
	Version       string     `json:"version,omitempty"`
	AllowlistHash string     `json:"allowlist_hash,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	EnrolledAt    *time.Time `json:"enrolled_at,omitempty"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedBy     string     `json:"revoked_by,omitempty"`
	// CredentialRef is the prefix of the reference to use for a credential
	// stored on this agent: agent:<id>/<name>.
	CredentialRef string `json:"credential_ref_prefix"`
}

// Enrolment is the response of issuing a code: the only time the code is
// visible.
type Enrolment struct {
	Agent     View      `json:"agent"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) view(t tenancy.ID, a *store.DirectoryAgent) View {
	v := View{ID: a.ID, Name: a.Name, Status: a.Status, Hostname: a.Hostname, OS: a.OS, Version: a.Version,
		AllowlistHash: a.AllowlistHash, LastSeenAt: a.LastSeenAt, EnrolledAt: a.EnrolledAt, CreatedBy: a.CreatedBy,
		CreatedAt: a.CreatedAt, RevokedAt: a.RevokedAt, RevokedBy: a.RevokedBy, CredentialRef: "agent:" + a.ID + "/"}
	if a.Status == store.AgentActive {
		v.Online = s.Hub != nil && s.Hub.Online(t, a.ID)
		v.Outdated = olderThan(a.Version, MinVersion)
	}
	return v
}

// olderThan compares dotted numeric versions; an unparsable version is old.
func olderThan(v, min string) bool {
	parse := func(s string) ([]int, bool) {
		var out []int
		for _, p := range strings.Split(strings.TrimPrefix(s, "v"), ".") {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return nil, false
			}
			out = append(out, n)
		}
		return out, true
	}
	a, ok1 := parse(v)
	b, ok2 := parse(min)
	if !ok1 || !ok2 {
		return true
	}
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// List returns the tenant's agents, oldest first.
func (s *Service) List(c *store.TenantTx) ([]View, error) {
	as, err := c.DirectoryAgents()
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(as))
	for _, a := range as {
		out = append(out, s.view(c.Tenant(), a))
	}
	return out, nil
}

// Get returns one agent of the tenant (store.ErrNotFound otherwise).
func (s *Service) Get(c *store.TenantTx, id string) (*View, error) {
	a, err := c.DirectoryAgent(id)
	if err != nil {
		return nil, err
	}
	v := s.view(c.Tenant(), a)
	return &v, nil
}

// Active returns the agent if it exists in the tenant and is active
// (store.ErrNotFound otherwise, including another tenant's agent).
func (s *Service) Active(c *store.TenantTx, id string) (*View, error) {
	a, err := c.DirectoryAgent(id)
	if err != nil {
		return nil, err
	}
	if a.Status != store.AgentActive {
		return nil, store.ErrNotFound
	}
	v := s.view(c.Tenant(), a)
	return &v, nil
}

// Do sends a typed job to the agent (Dispatcher), so a Service can be handed to
// readiness as its single link to the agents.
func (s *Service) Do(ctx context.Context, t tenancy.ID, agentID string, j Job) (Result, error) {
	return s.Hub.Do(ctx, t, agentID, j)
}

// Create adds a pending agent and issues its single-use enrolment code, which
// is returned once and stored only as a hash. The event never carries it.
func (s *Service) Create(c *store.TenantTx, name, actor string, now time.Time) (*Enrolment, error) {
	name = strings.TrimSpace(name)
	if !nameRE.MatchString(name) {
		return nil, ErrName
	}
	code, err := newCode()
	if err != nil {
		return nil, err
	}
	a := &store.DirectoryAgent{ID: store.NewID(), Name: name, Status: store.AgentPending, CreatedBy: actor, CreatedAt: now}
	if err := c.InsertDirectoryAgent(a); err != nil {
		return nil, err
	}
	exp := now.Add(EnrolmentTTL)
	if err := c.InsertAgentEnrolment(&store.AgentEnrolment{ID: store.NewID(), AgentID: a.ID, TokenHash: HashCode(code),
		ExpiresAt: exp, CreatedBy: actor, CreatedAt: now}); err != nil {
		return nil, err
	}
	if _, err := c.RecordAudit(store.AuditRecord{At: now, Action: "agent.enrolment_issued", LegacyActor: actor,
		TargetType: "directory_agent", TargetID: a.ID,
		Detail: ojson.Object{{Key: "agent_id", Value: a.ID}, {Key: "name", Value: name},
			{Key: "expires_at", Value: store.RT(exp)}}}); err != nil {
		return nil, err
	}
	return &Enrolment{Agent: s.view(c.Tenant(), a), Code: code, ExpiresAt: exp}, nil
}

// Revoke revokes an agent: it can no longer authenticate, its unused code is
// void, and its pending operations fail. Connections that used it then fail
// their live checks (they do not fall back to a direct dial).
func (s *Service) Revoke(c *store.TenantTx, id, actor string, now time.Time) error {
	if err := c.RevokeDirectoryAgent(id, actor, now); err != nil {
		return err
	}
	if _, err := c.RecordAudit(store.AuditRecord{At: now, Action: "agent.revoked", LegacyActor: actor,
		TargetType: "directory_agent", TargetID: id,
		Detail: ojson.Object{{Key: "agent_id", Value: id}}}); err != nil {
		return err
	}
	// pulled jobs are cancelled in the same transaction, so a revoked agent's
	// work is never handed to anything else
	if _, err := c.CancelAgentJobs(id, now); err != nil {
		return err
	}
	if s.Hub != nil {
		s.Hub.Revoke(c.Tenant(), id)
	}
	return nil
}

// Enrol consumes a single-use code and pins the presented client key: the
// agent becomes active. Every failure (unknown, expired, used, revoked, key
// already pinned) is ErrInvalidCode. pin is PinOf the TLS client certificate.
func (s *Service) Enrol(ctx context.Context, req EnrolRequest, pin string) (*EnrolResponse, error) {
	if req.ProtocolVersion != ProtocolVersion {
		return nil, ErrProtocol
	}
	if err := req.Telemetry.Validate(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(req.Code, codePrefix) || len(req.Code) > 128 || len(pin) != 64 {
		return nil, ErrInvalidCode
	}
	hash := HashCode(req.Code)
	var tenant tenancy.ID
	var enrolID string
	err := s.DB.ReadSystem(ctx, "agent enrolment lookup", func(sx *store.SystemTx) error {
		t, id, err := sx.LookupAgentEnrolmentByTokenHash(hash)
		tenant, enrolID = t, id.String()
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	now := s.Clock()
	var agentID string
	err = s.DB.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		e, err := c.AgentEnrolment(enrolID)
		if err != nil {
			return err
		}
		a, err := c.DirectoryAgent(e.AgentID)
		if err != nil {
			return err
		}
		// Consume first: exactly one concurrent enrolment wins, and only
		// before expiry. A failure below rolls the consumption back.
		if err := c.ConsumeAgentEnrolment(e.ID, now); err != nil {
			return err
		}
		t := store.AgentTelemetry{Hostname: req.Hostname, OS: req.OS, Version: req.Version, AllowlistHash: req.AllowlistHash}
		if err := c.ActivateDirectoryAgent(a.ID, pin, t, now); err != nil {
			return err
		}
		agentID = a.ID
		_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "agent.enrolled", LegacyActor: "agent:" + a.Name,
			TargetType: "directory_agent", TargetID: a.ID,
			Detail: ojson.Object{{Key: "agent_id", Value: a.ID}, {Key: "name", Value: a.Name}, {Key: "key_pin", Value: pin},
				{Key: "hostname", Value: req.Hostname}, {Key: "os", Value: req.OS}, {Key: "version", Value: req.Version},
				{Key: "allowlist_hash", Value: req.AllowlistHash}}})
		return err
	})
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrDuplicate) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	return &EnrolResponse{AgentID: agentID, ProtocolVersion: ProtocolVersion, HeartbeatSecs: 30}, nil
}

// Principal is an authenticated agent: its tenant and id come from the pinned
// key, never from anything the agent sends.
type Principal struct {
	Tenant  tenancy.ID
	AgentID string
}

// Authenticate resolves the pin of the TLS client certificate to an active
// agent. A key that is not pinned, or whose agent is pending or revoked, is
// ErrUnauthorized.
func (s *Service) Authenticate(ctx context.Context, pin string) (*Principal, error) {
	var tenant tenancy.ID
	var id string
	err := s.DB.ReadSystem(ctx, "agent key lookup", func(sx *store.SystemTx) error {
		t, aid, err := sx.LookupDirectoryAgentByCertPin(pin)
		tenant, id = t, aid.String()
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	err = s.DB.ReadTenant(ctx, tenant, func(c *store.TenantTx) error {
		a, err := c.DirectoryAgent(id)
		if err != nil {
			return err
		}
		if a.Status != store.AgentActive || a.CertPin != pin {
			return ErrUnauthorized
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	return &Principal{Tenant: tenant, AgentID: id}, nil
}

// Heartbeat records liveness and what the agent reports. A change of version,
// host or allowlist is audited; a bare last-seen update is not (it would fill
// the ledger).
func (s *Service) Heartbeat(ctx context.Context, p *Principal, req HeartbeatRequest) error {
	if req.ProtocolVersion != ProtocolVersion {
		return ErrProtocol
	}
	if err := req.Telemetry.Validate(); err != nil {
		return err
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
		t := store.AgentTelemetry{Hostname: req.Hostname, OS: req.OS, Version: req.Version, AllowlistHash: req.AllowlistHash}
		if err := c.TouchDirectoryAgent(a.ID, t, now); err != nil {
			return err
		}
		if a.Version == t.Version && a.AllowlistHash == t.AllowlistHash && a.Hostname == t.Hostname && a.OS == t.OS {
			return nil
		}
		_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "agent.updated", LegacyActor: "agent:" + a.Name,
			TargetType: "directory_agent", TargetID: a.ID,
			Detail: ojson.Object{{Key: "agent_id", Value: a.ID}, {Key: "version", Value: t.Version},
				{Key: "previous_version", Value: a.Version}, {Key: "allowlist_hash", Value: t.AllowlistHash},
				{Key: "previous_allowlist_hash", Value: a.AllowlistHash}, {Key: "hostname", Value: t.Hostname}, {Key: "os", Value: t.OS}}})
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return ErrUnauthorized
	}
	return err
}
