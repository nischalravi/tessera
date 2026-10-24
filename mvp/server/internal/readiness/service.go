// Package readiness gates customer connections on a deployment-readiness
// checklist (design docs/design/deployment-readiness.md).
//
// A connection revision moves draft → ready_to_validate → validated →
// dry_run_reconciled → active, and every forward step has a server-side gate
// evaluated from stored evidence: attestations, live check results, dry-run
// data check results and reconciliation findings. This package is the only
// code that changes a revision's state (store.SetRevisionState); a source
// scan test enforces it.
package readiness

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Service holds the readiness configuration. Its methods take a *store.TenantTx;
// mutating ones expect a write transaction.
type Service struct {
	Templates *template.Registry
	// Env is TESSERA_ENV. DR-10 lifted the rule that non-demo connector types
	// can be activated only when it is "dev"; nothing reads it now.
	Env     string
	LiveTTL time.Duration
	Runner  RunnerOptions

	// extraEvidence lets in-package tests add evidence to a revision.
	extraEvidence func(c *store.TenantTx, b *store.ConnectionRevision, ev *Evidence)
}

// NewService returns a service over a template registry.
func NewService(reg *template.Registry, env string) *Service {
	s := &Service{Templates: reg, Env: env, LiveTTL: DefaultLiveTTL}
	s.Runner.Live.Env = env
	return s
}

// Bundle is a revision with everything needed to evaluate it.
type Bundle struct {
	Conn       *store.Connection
	Rev        *store.ConnectionRevision
	Template   *template.Resolved
	Config     ConnConfig
	Hash       HashInput
	ConfigHash string
	Evidence   *Evidence
	Eval       *Evaluation
	LiveTTL    time.Duration

	// cred is the opened credential of a real revision, loaded by Validate
	// for one run. It never leaves the bundle and prints as [redacted].
	cred ldap.Secret
	// agentID and agentCred are the Directory Agent and the credential name
	// on it, for an agent:<id>/<name> reference (bindAgent).
	agentID, agentCred string
}

// Simulated reports whether the connection uses a demo (simulated) connector.
func (b *Bundle) Simulated() bool { return IsDemoType(b.Conn.ConnectorType) }

// templateFor resolves a revision's pinned template plus its pinned overlay.
func (s *Service) templateFor(c *store.TenantTx, templateID, version string, overlayVersion int) (*template.Resolved, error) {
	t, err := s.Templates.Resolve(templateID + "@" + version)
	if err != nil {
		return nil, err
	}
	if overlayVersion == 0 {
		return t, nil
	}
	row, err := c.OverlayVersion(templateID, overlayVersion)
	if err != nil {
		return nil, fmt.Errorf("readiness: overlay %s v%d: %w", templateID, overlayVersion, err)
	}
	o, err := decodeOverlay([]byte(row.Body))
	if err != nil {
		return nil, err
	}
	o.Version = overlayVersion
	return template.Apply(t, o)
}

func hashInput(conn *store.Connection, rev *store.ConnectionRevision, cfg ConnConfig) HashInput {
	in := HashInput{Config: cfg, Role: conn.Role, TemplatePin: rev.TemplateID + "@" + rev.TemplateVersion,
		OverlayVersion: rev.OverlayVersion}
	if rev.SecretRef != nil {
		in.SecretRef = *rev.SecretRef
	}
	if rev.SecretVersion != nil {
		in.SecretVersion = *rev.SecretVersion
	}
	return in
}

// Load evaluates a revision.
func (s *Service) Load(c *store.TenantTx, rev *store.ConnectionRevision, now time.Time) (*Bundle, error) {
	conn, err := c.Connection(rev.ConnectionID)
	if err != nil {
		return nil, err
	}
	tmpl, err := s.templateFor(c, rev.TemplateID, rev.TemplateVersion, rev.OverlayVersion)
	if err != nil {
		return nil, err
	}
	cfg, err := DecodeConfig([]byte(rev.Config))
	if err != nil {
		return nil, err
	}
	b := &Bundle{Conn: conn, Rev: rev, Template: tmpl, Config: cfg, Hash: hashInput(conn, rev, cfg), LiveTTL: s.LiveTTL}
	if err := b.Hash.Normalize(); err != nil {
		return nil, err
	}
	if b.ConfigHash, err = b.Hash.ConfigHash(); err != nil {
		return nil, err
	}
	if b.Evidence, err = s.loadEvidence(c, conn, rev); err != nil {
		return nil, err
	}
	b.Eval, err = b.Evaluate(now, s.LiveTTL)
	return b, err
}

func (s *Service) loadEvidence(c *store.TenantTx, conn *store.Connection, rev *store.ConnectionRevision) (*Evidence, error) {
	ev := &Evidence{TenantTypes: map[string]bool{}, Live: map[resultKey]*ResultInfo{}, Data: map[resultKey]*ResultInfo{}}
	var err error
	if ev.Attestations, err = c.Attestations(rev.ID); err != nil {
		return nil, err
	}
	if ev.LiveAttestations, err = c.LiveAttestations(rev.ID); err != nil {
		return nil, err
	}
	if ev.Skips, err = c.Skips(rev.ID); err != nil {
		return nil, err
	}
	if req, err := c.LatestActivationRequest(conn.ID); err == nil {
		if req.Status == store.ActivationApplied && req.RevisionID == rev.ID {
			ev.Approval = req
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	conns, err := c.Connections()
	if err != nil {
		return nil, err
	}
	for _, o := range conns {
		if o.ID == conn.ID || o.RetiredAt != nil {
			continue
		}
		if id, ok := s.Templates.TemplateID(o.ConnectorType); ok {
			ev.TenantTypes[id] = true
		}
	}
	if err := loadRunEvidence(c, rev, ev); err != nil {
		return nil, err
	}
	if s.extraEvidence != nil {
		s.extraEvidence(c, rev, ev)
	}
	return ev, nil
}

// Revisions returns a connection with its live and in-progress revisions.
func Revisions(c *store.TenantTx, connID string) (conn *store.Connection, live, pending *store.ConnectionRevision, err error) {
	conn, err = c.Connection(connID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil, notFound("no connection %s", connID)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	revs, err := c.Revisions(connID)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, r := range revs {
		switch {
		case IsLive(r.State) && live == nil:
			live = r
		case IsPending(r.State) && pending == nil:
			pending = r
		}
	}
	return conn, live, pending, nil
}

// Current returns the revision the checklist shows: the in-progress one if
// there is one, otherwise the live one, otherwise the newest.
func (s *Service) Current(c *store.TenantTx, connID string, now time.Time) (*Bundle, error) {
	conn, live, pending, err := Revisions(c, connID)
	if err != nil {
		return nil, err
	}
	rev := pending
	if rev == nil {
		rev = live
	}
	if rev == nil {
		revs, err := c.Revisions(conn.ID)
		if err != nil {
			return nil, err
		}
		if len(revs) == 0 {
			return nil, notFound("connection %s has no revision", connID)
		}
		rev = revs[0]
	}
	return s.Load(c, rev, now)
}

// pendingBundle returns the in-progress revision, creating a new draft
// revision from the live one when the connection is active (design K6).
func (s *Service) pendingBundle(c *store.TenantTx, connID, actor string, now time.Time) (*Bundle, bool, error) {
	conn, live, pending, err := Revisions(c, connID)
	if err != nil {
		return nil, false, err
	}
	if conn.RetiredAt != nil {
		return nil, false, conflict("connection_retired", "connection %s is retired", conn.Name)
	}
	if pending != nil {
		b, err := s.Load(c, pending, now)
		return b, false, err
	}
	if live == nil {
		return nil, false, conflict("no_revision", "connection %s has no editable revision", conn.Name)
	}
	t, ok := s.Templates.Get(live.TemplateID)
	if !ok {
		return nil, false, fmt.Errorf("readiness: template %s missing", live.TemplateID)
	}
	ov, err := c.LatestOverlay(t.ID)
	if err != nil {
		return nil, false, err
	}
	rev := &store.ConnectionRevision{ID: store.NewID(), ConnectionID: conn.ID, Rev: live.Rev + 1,
		TemplateID: t.ID, TemplateVersion: strings.TrimPrefix(t.Pin(), t.ID+"@"), Config: live.Config,
		SecretRef: live.SecretRef, SecretVersion: live.SecretVersion, WriteMode: live.WriteMode,
		ExpectedCounts: live.ExpectedCounts, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	if ov != nil {
		rev.OverlayVersion = ov.Version
	}
	cfg, err := DecodeConfig([]byte(rev.Config))
	if err != nil {
		return nil, false, err
	}
	if rev.ConfigHash, err = hashInput(conn, rev, cfg).ConfigHash(); err != nil {
		return nil, false, err
	}
	if err := c.InsertRevision(rev); err != nil {
		return nil, false, err
	}
	if err := c.Audit(now, actor, "connection.revision_created", ojson.Object{{Key: "connection_id", Value: conn.ID},
		{Key: "revision_id", Value: rev.ID}, {Key: "rev", Value: rev.Rev}, {Key: "from_revision_id", Value: live.ID}}); err != nil {
		return nil, false, err
	}
	rev.State = store.StateDraft
	b, err := s.Load(c, rev, now)
	return b, true, err
}

// ---------------------------------------------------------------- create

// CreateInput is POST /api/connections.
type CreateInput struct {
	Name          string          `json:"name"`
	ConnectorType string          `json:"connector_type"`
	System        string          `json:"system,omitempty"`
	Role          string          `json:"role,omitempty"`
	Config        json.RawMessage `json:"config,omitempty"`
}

var systemRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// demoSystems are the graph system names of the demo connector types.
var demoSystems = map[string]string{"demo-ad": "ad-corp", "demo-okta": "okta", "demo-workday": "workday"}

func validText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && printable.MatchString(s)
}

// Create adds a connection in draft (design §4.2: the template must exist and
// the config must parse into the typed config).
func (s *Service) Create(c *store.TenantTx, in CreateInput, actor string, now time.Time) (*Bundle, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !validText(in.Name, 100) {
		return nil, unprocessable("invalid_name", "name is required (at most 100 printable characters)")
	}
	t, ok := s.Templates.ForConnectorType(in.ConnectorType)
	if !ok {
		return nil, unprocessable("unknown_connector_type", "no readiness template for connector type %q", in.ConnectorType)
	}
	if in.System == "" {
		in.System = demoSystems[in.ConnectorType]
	}
	if in.System == "" {
		in.System = strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(in.Name), "-"), "-")
	}
	if !systemRE.MatchString(in.System) {
		return nil, unprocessable("invalid_system", "system must be lower-case letters, digits, '-' or '_'")
	}
	if in.Role == "" {
		in.Role = t.Role
	}
	if !slices.Contains(template.Roles, in.Role) {
		return nil, unprocessable("invalid_role", "role must be authoritative or account_source")
	}
	cfg := DefaultConfig(in.ConnectorType, t)
	if len(in.Config) > 0 && string(in.Config) != "null" {
		var err error
		if cfg, err = MergeConfig(cfg, in.Config); err != nil {
			return nil, &Error{Status: http.StatusUnprocessableEntity, Code: "invalid_config", Msg: err.Error()}
		}
	}
	ov, err := c.LatestOverlay(t.ID)
	if err != nil {
		return nil, err
	}
	conn := &store.Connection{ID: store.NewID(), Name: in.Name, ConnectorType: in.ConnectorType, System: in.System,
		Role: in.Role, TechnicalOwner: optText(cfg.TechnicalOwner), BusinessOwner: optText(cfg.BusinessOwner),
		CreatedAt: now, UpdatedAt: now}
	if err := c.InsertConnection(conn); errors.Is(err, store.ErrDuplicate) {
		return nil, conflict("duplicate_connection", "a connection named %q or for system %q already exists", in.Name, in.System)
	} else if err != nil {
		return nil, err
	}
	rev := &store.ConnectionRevision{ID: store.NewID(), ConnectionID: conn.ID, Rev: 1, TemplateID: t.ID,
		TemplateVersion: strings.TrimPrefix(t.Pin(), t.ID+"@"), WriteMode: writeMode(cfg), CreatedBy: actor,
		CreatedAt: now, UpdatedAt: now}
	if ov != nil {
		rev.OverlayVersion = ov.Version
	}
	if err := setRevisionConfig(rev, conn, cfg); err != nil {
		return nil, err
	}
	if err := c.InsertRevision(rev); err != nil {
		return nil, err
	}
	rev.State = store.StateDraft
	if err := c.Audit(now, actor, "connection.created", ojson.Object{{Key: "connection_id", Value: conn.ID},
		{Key: "name", Value: conn.Name}, {Key: "connector_type", Value: conn.ConnectorType}, {Key: "system", Value: conn.System},
		{Key: "template", Value: rev.TemplateID + "@" + rev.TemplateVersion}, {Key: "revision_id", Value: rev.ID}}); err != nil {
		return nil, err
	}
	b, err := s.Load(c, rev, now)
	if err != nil {
		return nil, err
	}
	return b, s.persist(c, b, now)
}

func optText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func writeMode(cfg ConnConfig) string {
	if cfg.WriteMode == "" {
		return "off"
	}
	return cfg.WriteMode
}

// setRevisionConfig stores cfg, write mode, expected counts and the config hash on rev.
func setRevisionConfig(rev *store.ConnectionRevision, conn *store.Connection, cfg ConnConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	rev.Config, rev.WriteMode = string(raw), writeMode(cfg)
	rev.ExpectedCounts = nil
	if cfg.ExpectedCounts != nil {
		ec, err := json.Marshal(cfg.ExpectedCounts)
		if err != nil {
			return err
		}
		s := string(ec)
		rev.ExpectedCounts = &s
	}
	rev.ConfigHash, err = hashInput(conn, rev, cfg).ConfigHash()
	return err
}

// ---------------------------------------------------------------- edits

// ConfigResult is the response to a config edit.
type ConfigResult struct {
	Bundle      *Bundle
	NewRevision bool
	Invalidated []string // items that passed before the edit and no longer do
}

// PatchConfig applies a partial config to the in-progress revision (creating
// one when the connection is active) and moves the revision back through the
// gates whose evidence the change invalidated.
func (s *Service) PatchConfig(c *store.TenantTx, connID string, patch []byte, actor string, now time.Time) (*ConfigResult, error) {
	b, created, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	cfg, err := MergeConfig(b.Config, patch)
	if err != nil {
		return nil, &Error{Status: http.StatusUnprocessableEntity, Code: "invalid_config", Msg: err.Error()}
	}
	if cfg.WriteMode != "" && !slices.Contains(template.WriteModes, cfg.WriteMode) {
		return nil, unprocessable("invalid_config", "write_mode must be one of %v", template.WriteModes)
	}
	before := passing(b.Eval)
	changed := changedFields(b.Config, cfg)
	rev := *b.Rev
	if err := setRevisionConfig(&rev, b.Conn, cfg); err != nil {
		return nil, err
	}
	if err := c.UpdateRevisionConfig(rev.ID, rev.Config, rev.ConfigHash, rev.WriteMode, rev.ExpectedCounts, now); err != nil {
		return nil, err
	}
	if err := c.UpdateConnectionOwners(b.Conn.ID, optText(cfg.TechnicalOwner), optText(cfg.BusinessOwner), now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor, "connection.config_changed", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: rev.ID}, {Key: "fields", Value: changed}, {Key: "config_hash", Value: rev.ConfigHash}}); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, rev.ID, now)
	if err != nil {
		return nil, err
	}
	if err := s.settle(c, nb, actor, now, "configuration changed"); err != nil {
		return nil, err
	}
	res := &ConfigResult{Bundle: nb, NewRevision: created}
	for _, it := range nb.Eval.Items {
		if before[it.ID] && it.Status != StatusPass {
			res.Invalidated = append(res.Invalidated, it.ID)
		}
	}
	return res, nil
}

func passing(e *Evaluation) map[string]bool {
	out := map[string]bool{}
	for _, it := range e.Items {
		if it.Status == StatusPass {
			out[it.ID] = true
		}
	}
	return out
}

func changedFields(a, b ConnConfig) []string {
	am, bm := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	ra, _ := json.Marshal(a) // ConnConfig always marshals
	rb, _ := json.Marshal(b)
	_ = json.Unmarshal(ra, &am)
	_ = json.Unmarshal(rb, &bm)
	var out []string
	for k, v := range bm {
		if string(am[k]) != string(v) {
			out = append(out, k)
		}
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// CredentialInput is PUT /api/connections/{id}/credential. Exactly one of
// Secret or Reference is set. The secret is write-only.
type CredentialInput struct {
	Secret    string `json:"secret,omitempty"`
	Reference string `json:"reference,omitempty"`
}

var refRE = regexp.MustCompile(`^(vault|agent):[A-Za-z0-9._/:@-]{1,200}$`)

// SetCredential records a credential reference on the in-progress revision.
//
// A submitted secret is sealed under the KEK (internal/seal, AAD bound to the
// tenant, connection and reference) and stored in connection_credentials when the service has
// a Sealer (Runner.Live.Sealer); the revision keeps only the sealed:<id>
// reference. Without a Sealer the value is discarded, as before: demo
// connectors need no secret and a real connector then has no credential to
// run with.
// A replaced credential's row is kept: a new revision copies its predecessor's
// reference, so the live revision may still use it.
func (s *Service) SetCredential(c *store.TenantTx, connID string, in CredentialInput, actor string, now time.Time) (*Bundle, error) {
	var ref string
	switch {
	case in.Secret != "" && in.Reference != "":
		return nil, unprocessable("invalid_credential", "send either secret or reference, not both")
	case in.Reference != "":
		if !refRE.MatchString(in.Reference) {
			if strings.Contains(in.Reference, "=") && strings.Contains(in.Reference, ",") {
				return nil, unprocessable("invalid_credential", "that looks like a distinguished name: enter the bind DN in Bind DN, and the password in Or the secret; this field is only a reference such as vault:<path> or agent:<id>/<name>")
			}
			return nil, unprocessable("invalid_credential", "reference must look like vault:<path> or agent:<id>/<name>; the bind DN goes in Bind DN and the password in Or the secret")
		}
		if strings.HasPrefix(in.Reference, "agent:") {
			id, _, ok := agent.ParseRef(in.Reference)
			if !ok {
				return nil, unprocessable("invalid_credential", "an agent reference must look like agent:<agent id>/<credential name>")
			}
			// The agent must be an active one of this tenant (another tenant's
			// agent is indistinguishable from a missing one).
			if s.Runner.Live.Agents != nil {
				if _, err := s.Runner.Live.Agents.Active(c, id); errors.Is(err, store.ErrNotFound) {
					return nil, unprocessable("unknown_agent", "no active Directory Agent with that id")
				} else if err != nil {
					return nil, err
				}
			}
		}
		ref = in.Reference
	case in.Secret != "":
		if len(in.Secret) > 8192 {
			return nil, unprocessable("invalid_credential", "secret is longer than 8 KiB")
		}
		ref = "sealed:" + store.NewID()
	default:
		return nil, unprocessable("invalid_credential", "secret or reference is required")
	}
	b, _, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	rev := *b.Rev
	version := store.NewID()
	rev.SecretRef, rev.SecretVersion = &ref, &version
	hash, err := hashInput(b.Conn, &rev, b.Config).ConfigHash()
	if err != nil {
		return nil, err
	}
	if err := c.UpdateRevisionSecret(rev.ID, ref, version, hash, now); err != nil {
		return nil, err
	}
	if in.Secret != "" && s.Runner.Live.Sealer != nil {
		blob, err := s.Runner.Live.Sealer.Seal([]byte(in.Secret), connectionSecretAAD(c.Tenant(), b.Conn.ID, ref))
		if err != nil {
			return nil, err
		}
		if err := c.PutCredential(&store.Credential{ConnectionID: b.Conn.ID, Purpose: store.PurposeBind, Ref: ref,
			Sealed: blob, UpdatedBy: actor, UpdatedAt: now}); err != nil {
			return nil, err
		}
	}
	kind, _, _ := strings.Cut(ref, ":")
	if err := c.Audit(now, actor, "connection.credential_set", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: rev.ID}, {Key: "kind", Value: kind}, {Key: "secret_version", Value: version}}); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, rev.ID, now)
	if err != nil {
		return nil, err
	}
	return nb, s.settle(c, nb, actor, now, "credential changed")
}

// reload re-reads a revision after a write.
func (s *Service) reload(c *store.TenantTx, revID string, now time.Time) (*Bundle, error) {
	rev, err := c.Revision(revID)
	if err != nil {
		return nil, err
	}
	return s.Load(c, rev, now)
}

// ---------------------------------------------------------------- items

// MinAttestNote and MinSkipReason are the minimum lengths (§3.3, §4.3).
const (
	MinAttestNote = 10
	MinSkipReason = 20
)

func (s *Service) itemFor(b *Bundle, itemID string) (*ItemEval, error) {
	it, ok := b.Eval.Item(itemID)
	if !ok {
		return nil, notFound("no checklist item %q in template %s", itemID, b.Template.ID)
	}
	return it, nil
}

// Attest records an attestation for an item of the in-progress revision.
func (s *Service) Attest(c *store.TenantTx, connID, itemID, note, actor string, now time.Time) (*Bundle, error) {
	return s.AttestAs(c, connID, itemID, note, actor, "", now)
}

// AttestAs is Attest that also records the attester's platform user id (empty for a principal that
// is not a user), which ApproveActivation compares with SameActor (#425).
func (s *Service) AttestAs(c *store.TenantTx, connID, itemID, note, actor, actorUserID string, now time.Time) (*Bundle, error) {
	b, _, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	it, err := s.itemFor(b, itemID)
	if err != nil {
		return nil, err
	}
	note = strings.TrimSpace(note)
	switch {
	case !it.HasKind(template.Attestation):
		return nil, unprocessable("not_attestable", "%s is verified by checks, not attestation", itemID)
	case !it.Applicable:
		return nil, unprocessable("not_applicable", "%s does not apply: %s", itemID, it.Reason)
	case utf8.RuneCountInString(note) < MinAttestNote || len(note) > 2000 || !printableNote(note):
		return nil, unprocessable("note_too_short", "an attestation needs a note of at least %d characters", MinAttestNote)
	case len(it.BlockedBy) > 0:
		g := &GateReport{State: b.Rev.State, To: "attest", ConfigHash: b.ConfigHash, EvaluatedAt: store.RT(now)}
		for _, d := range it.BlockedBy {
			if dep, ok := b.Eval.Item(d); ok {
				g.Blocking = append(g.Blocking, blockerFor(dep, dep.Status, ""))
			}
		}
		return nil, blocked("dependencies_not_passing", g)
	}
	var byUser *string
	if actorUserID != "" {
		byUser = &actorUserID
	}
	if err := c.UpsertAttestation(&store.Attestation{RevisionID: b.Rev.ID, ItemID: itemID, ActorID: actor, ActorUserID: byUser, Note: note,
		ItemHash: it.ItemHash, ConfigHash: b.ConfigHash, AttestedAt: now}); err != nil {
		return nil, err
	}
	if err := c.BumpEvidence(b.Rev.ID, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor, "readiness.item.attested", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "item", Value: itemID}, {Key: "level", Value: string(it.Level)},
		{Key: "note", Value: note}, {Key: "config_hash", Value: b.ConfigHash}}); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, b.Rev.ID, now)
	if err != nil {
		return nil, err
	}
	return nb, s.settle(c, nb, actor, now, "attestation")
}

// Limits of an attestation in place of an unsupported live check (#217).
const (
	MinAttesterName = 2
	MaxAttesterName = 120
	MinLiveReason   = 20
	MinEvidence     = 10
	MaxEvidence     = 4000
)

// LiveAttestInput is what a person gives in place of a live check the system
// cannot answer.
type LiveAttestInput struct {
	Attester string // the named person who verified it
	Reason   string // why the live check cannot be used
	Evidence string // what they looked at
}

// AttestInstead records an attestation for an item whose live check reported
// "unsupported" (the system cannot answer it). It is refused unless the item's
// template declares the alternative (on_unsupported) and the latest live
// result is unsupported and current: a failing result can never be attested
// away. The attestation is bound to the item's config fields and expires like
// live results; its audit event is written in the same transaction.
func (s *Service) AttestInstead(c *store.TenantTx, connID, itemID string, in LiveAttestInput, actor string, now time.Time) (*Bundle, error) {
	b, _, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	it, err := s.itemFor(b, itemID)
	if err != nil {
		return nil, err
	}
	in.Attester, in.Reason, in.Evidence = strings.TrimSpace(in.Attester), strings.TrimSpace(in.Reason), strings.TrimSpace(in.Evidence)
	n := utf8.RuneCountInString(in.Attester)
	switch {
	case !it.HasLiveAlternative():
		return nil, unprocessable("not_attestable_instead", "%s has no attestation alternative to its live check", itemID)
	case !it.Applicable:
		return nil, unprocessable("not_applicable", "%s does not apply: %s", itemID, it.Reason)
	case n < MinAttesterName || n > MaxAttesterName ||
		strings.ContainsAny(in.Attester, "\r\n") || !printableNote(in.Attester):
		return nil, unprocessable("attester_required", "name the person who verified it (%d to %d characters)", MinAttesterName, MaxAttesterName)
	case utf8.RuneCountInString(in.Reason) < MinLiveReason || len(in.Reason) > 2000 || !printableNote(in.Reason):
		return nil, unprocessable("reason_too_short", "an attestation needs a reason of at least %d characters", MinLiveReason)
	case utf8.RuneCountInString(in.Evidence) < MinEvidence || len(in.Evidence) > MaxEvidence || !printableNote(in.Evidence):
		return nil, unprocessable("evidence_required", "an attestation needs evidence text of at least %d characters", MinEvidence)
	case !it.liveUnsupported():
		return nil, unprocessable("live_check_not_unsupported",
			"%s can be attested only when its live check reports it cannot be answered; a failed or missing result cannot be attested", itemID)
	case len(it.BlockedBy) > 0:
		g := &GateReport{State: b.Rev.State, To: "attest", ConfigHash: b.ConfigHash, EvaluatedAt: store.RT(now)}
		for _, d := range it.BlockedBy {
			if dep, ok := b.Eval.Item(d); ok {
				g.Blocking = append(g.Blocking, blockerFor(dep, dep.Status, ""))
			}
		}
		return nil, blocked("dependencies_not_passing", g)
	}
	if err := c.UpsertLiveAttestation(&store.LiveAttestation{RevisionID: b.Rev.ID, ItemID: itemID, ActorID: actor,
		Attester: in.Attester, Reason: in.Reason, Evidence: in.Evidence, ItemHash: it.ItemHash, ConfigHash: b.ConfigHash,
		AttestedAt: now}); err != nil {
		return nil, err
	}
	if err := c.BumpEvidence(b.Rev.ID, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor, "readiness.item.attested_instead", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "item", Value: itemID}, {Key: "level", Value: string(it.Level)},
		{Key: "attester", Value: in.Attester}, {Key: "reason", Value: in.Reason}, {Key: "evidence", Value: in.Evidence},
		{Key: "config_hash", Value: b.ConfigHash}}); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, b.Rev.ID, now)
	if err != nil {
		return nil, err
	}
	return nb, s.settle(c, nb, actor, now, "attestation")
}

func printableNote(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f })
}

// Skip records a reasoned skip of a Recommended item. Required items cannot
// be skipped (422 required_item_not_skippable).
func (s *Service) Skip(c *store.TenantTx, connID, itemID, reason string, reviewBy *time.Time, actor string, now time.Time) (*Bundle, error) {
	b, _, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	it, err := s.itemFor(b, itemID)
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	switch {
	case it.Level == template.Required:
		return nil, unprocessable("required_item_not_skippable", "%s is Required and cannot be skipped", itemID)
	case it.Level == template.Optional:
		return nil, unprocessable("optional_item_not_skippable", "%s is Optional and never blocks activation", itemID)
	case !it.Applicable:
		return nil, unprocessable("not_applicable", "%s does not apply: %s", itemID, it.Reason)
	case utf8.RuneCountInString(reason) < MinSkipReason || len(reason) > 2000 || !printableNote(reason):
		return nil, unprocessable("reason_too_short", "a skip needs a reason of at least %d characters", MinSkipReason)
	}
	review := now.AddDate(0, 0, 90)
	if reviewBy != nil {
		if !reviewBy.After(now) || reviewBy.After(now.AddDate(1, 0, 0)) {
			return nil, unprocessable("invalid_review_by", "review_by must be in the next 12 months")
		}
		review = *reviewBy
	}
	if err := c.UpsertSkip(&store.Skip{RevisionID: b.Rev.ID, ConnectionID: b.Conn.ID, ItemID: itemID, Level: string(it.Level),
		ActorID: actor, Reason: reason, ReviewBy: review, TemplateVersion: b.Template.Version, SkippedAt: now}); err != nil {
		return nil, err
	}
	if err := c.BumpEvidence(b.Rev.ID, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor, "readiness.item.skipped", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "item", Value: itemID}, {Key: "level", Value: string(it.Level)},
		{Key: "reason", Value: reason}, {Key: "review_by", Value: store.RT(review)},
		{Key: "template_version", Value: b.Template.Version}}); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, b.Rev.ID, now)
	if err != nil {
		return nil, err
	}
	return nb, s.settle(c, nb, actor, now, "item skipped")
}

// Unskip removes a skip.
func (s *Service) Unskip(c *store.TenantTx, connID, itemID, actor string, now time.Time) (*Bundle, error) {
	b, _, err := s.pendingBundle(c, connID, actor, now)
	if err != nil {
		return nil, err
	}
	it, err := s.itemFor(b, itemID)
	if err != nil {
		return nil, err
	}
	ok, err := c.DeleteSkip(b.Rev.ID, itemID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, notFound("%s is not skipped", itemID)
	}
	if err := c.BumpEvidence(b.Rev.ID, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor, "readiness.item.unskipped", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "item", Value: itemID}, {Key: "level", Value: string(it.Level)},
		{Key: "template_version", Value: b.Template.Version}}); err != nil {
		return nil, err
	}
	nb, err := s.reload(c, b.Rev.ID, now)
	if err != nil {
		return nil, err
	}
	return nb, s.settle(c, nb, actor, now, "skip removed")
}

// ---------------------------------------------------------------- overlays

func decodeOverlay(raw []byte) (*template.Overlay, error) {
	var o template.Overlay
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return nil, err
	}
	return &o, nil
}

// PutOverlay stores a new tenant overlay version for a template after
// checking it against the no-downgrade rule (422 level_downgrade_forbidden).
// New revisions pin the new version; existing revisions keep theirs.
func (s *Service) PutOverlay(c *store.TenantTx, templateID string, raw []byte, actor string, now time.Time) (*template.Resolved, error) {
	t, ok := s.Templates.Get(templateID)
	if !ok {
		return nil, notFound("no readiness template %q", templateID)
	}
	o, err := decodeOverlay(raw)
	if err != nil {
		return nil, unprocessable(template.CodeInvalidOverlay, "%v", err)
	}
	merged, err := template.Apply(t, o)
	var oe *template.OverlayError
	if errors.As(err, &oe) {
		return nil, unprocessable(oe.Code, "%s", oe.Msg)
	} else if err != nil {
		return nil, err
	}
	cur, err := c.LatestOverlay(templateID)
	if err != nil {
		return nil, err
	}
	o.Version = 1
	if cur != nil {
		o.Version = cur.Version + 1
	}
	body, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	if err := c.InsertOverlay(&store.OverlayRow{ID: store.NewID(), ConnectorType: templateID, Version: o.Version,
		Body: string(body), UpdatedBy: actor, UpdatedAt: now}); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actor, "readiness.overlay.changed", ojson.Object{{Key: "template", Value: templateID},
		{Key: "version", Value: o.Version}, {Key: "added_items", Value: len(o.AddItems)},
		{Key: "raised_levels", Value: len(o.RaiseLevels)}, {Key: "thresholds", Value: len(o.Thresholds)}}); err != nil {
		return nil, err
	}
	merged.OverlayVersion = o.Version
	return merged, nil
}

// TemplateForTenant returns a template with the tenant's latest overlay applied.
func (s *Service) TemplateForTenant(c *store.TenantTx, templateID string) (*template.Resolved, error) {
	t, ok := s.Templates.Get(templateID)
	if !ok {
		return nil, notFound("no readiness template %q", templateID)
	}
	ov, err := c.LatestOverlay(templateID)
	if err != nil || ov == nil {
		return t, err
	}
	return s.templateFor(c, templateID, strings.TrimPrefix(t.Pin(), t.ID+"@"), ov.Version)
}
