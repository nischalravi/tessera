package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Deps are what the built-in targets reach the network and the disk through.
type Deps struct {
	// HTTP is the safehttp client of the SCIM and webhook targets. It must come
	// from safehttp.New; the targets never build a client of their own.
	HTTP *http.Client
	// Dial is the safehttp dialer of the LDAP targets (safehttp.NewDialer).
	Dial safehttp.DialFunc
	// AllowPlainLDAP allows ldap:// without TLS (security "none"). Dev and test only.
	AllowPlainLDAP bool
	// SQLDir is the directory of the SQL target's database files
	// (TESSERA_GROUPS_PROV_SQL_DIR). Empty: the SQL target is unavailable.
	SQLDir string
}

// TargetSpec is what a target is built from.
type TargetSpec struct {
	Tenant        tenancy.ID
	ProvisionerID string
	Type          string
	Common        *Compiled
	// Secret holds the opened credentials (never logged, never returned).
	Secret map[string]string
	Deps   Deps
}

// Target types.
const (
	TypeLDAP    = "ldap"
	TypeAD      = "ad"
	TypeSCIM2   = "scim2"
	TypeSQL     = "sql"
	TypeWebhook = "webhook"
)

// TargetTypes lists the built-in target types.
func TargetTypes() []string { return []string{TypeAD, TypeLDAP, TypeSCIM2, TypeSQL, TypeWebhook} }

// Service runs provisioners. It is safe for concurrent use.
type Service struct {
	DB     *store.DB
	Sealer *seal.Sealer
	Deps   Deps
	Clock  timeutil.Clock
	Log    *slog.Logger

	// Open builds the target of a spec. Nil: the built-in targets (tests inject fakes).
	Open func(ctx context.Context, spec TargetSpec) (Provisioner, error)
	// Sleep waits between verification attempts. Nil: a context-aware sleep.
	Sleep func(ctx context.Context, d time.Duration)
	// Backoff is the wait before attempt 2 and 3 of an op (default 1s, 4s).
	Backoff []time.Duration

	locks sync.Map // tenant|provisioner -> *sync.Mutex
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return timeutil.System()
	}
	return s.Clock()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

func (s *Service) open(ctx context.Context, spec TargetSpec) (Provisioner, error) {
	if s.Open != nil {
		return s.Open(ctx, spec)
	}
	switch spec.Type {
	case TypeLDAP, TypeAD:
		return openLDAP(ctx, spec)
	case TypeSCIM2:
		return openSCIM(spec)
	case TypeSQL:
		return openSQL(ctx, spec)
	case TypeWebhook:
		return openWebhook(spec)
	}
	return nil, cfgErr("unknown target type %q", spec.Type)
}

func (s *Service) lock(t tenancy.ID, id string) *sync.Mutex {
	m, _ := s.locks.LoadOrStore(t.String()+"|"+id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (s *Service) sleep(ctx context.Context, d time.Duration) {
	if s.Sleep != nil {
		s.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (s *Service) backoff(attempt int) time.Duration {
	b := s.Backoff
	if len(b) == 0 {
		b = []time.Duration{time.Second, 4 * time.Second}
	}
	if attempt-1 < len(b) {
		return b[attempt-1]
	}
	return b[len(b)-1]
}

// ---------------------------------------------------------------- secrets

// secretKeys are the credentials each target type takes.
var secretKeys = map[string][]string{
	TypeLDAP:    {"bind_password"},
	TypeAD:      {"bind_password"},
	TypeSCIM2:   {"token"},
	TypeSQL:     {},
	TypeWebhook: {"signing_secret"},
}

// secretRequired are the credentials a type cannot work without.
var secretRequired = map[string][]string{
	TypeLDAP:    {"bind_password"},
	TypeAD:      {"bind_password"},
	TypeSCIM2:   {"token"},
	TypeWebhook: {"signing_secret"},
}

func secretAAD(t tenancy.ID, id string) []byte {
	return seal.AAD(t, "grp_provisioners", "secret_enc", id)
}

func checkSecret(typ string, sec map[string]string) error {
	for k, v := range sec {
		if !slices.Contains(secretKeys[typ], k) {
			return cfgErr("secret.%s is not a credential of a %s target", k, typ)
		}
		if len(v) == 0 || len(v) > 8192 {
			return cfgErr("secret.%s must be 1 to 8192 bytes", k)
		}
	}
	if sec["signing_secret"] != "" && len(sec["signing_secret"]) < 16 {
		return cfgErr("secret.signing_secret must be at least 16 bytes")
	}
	return nil
}

func (s *Service) sealSecret(t tenancy.ID, id string, sec map[string]string) ([]byte, error) {
	if s.Sealer == nil {
		return nil, errors.New("provisioning: no key-encryption key is configured, so credentials cannot be stored")
	}
	b, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}
	return s.Sealer.Seal(b, secretAAD(t, id))
}

func (s *Service) openSecret(t tenancy.ID, p *store.Provisioner) (map[string]string, error) {
	out := map[string]string{}
	if p.SecretEnc == nil {
		return out, nil
	}
	if s.Sealer == nil {
		return nil, errors.New("provisioning: no key-encryption key is configured")
	}
	b, err := s.Sealer.Open(p.SecretEnc, secretAAD(t, p.ID))
	if err != nil {
		return nil, fmt.Errorf("provisioning: open the secret of provisioner %s: %w", p.ID, err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SecretKeysSet says which credentials a provisioner has stored, never their values.
func (s *Service) SecretKeysSet(t tenancy.ID, p *store.Provisioner) []string {
	sec, err := s.openSecret(t, p)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(sec))
	for k := range sec {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// ---------------------------------------------------------------- validation

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,99}$`)

// ValidateConfig checks a target configuration without touching the network.
func (s *Service) ValidateConfig(typ string, config json.RawMessage, sec map[string]string) error {
	if !slices.Contains(TargetTypes(), typ) {
		return cfgErr("target_type must be one of %v", TargetTypes())
	}
	c, err := ParseCommon(config)
	if err != nil {
		return err
	}
	if err := checkSecret(typ, sec); err != nil {
		return err
	}
	return validateTarget(typ, c, s.Deps)
}

func validateTarget(typ string, c *Compiled, deps Deps) error {
	switch typ {
	case TypeLDAP, TypeAD:
		_, err := parseLDAPConfig(typ, c, deps)
		return err
	case TypeSCIM2:
		_, err := parseSCIMConfig(c)
		return err
	case TypeSQL:
		_, err := parseSQLConfig(c, deps)
		return err
	case TypeWebhook:
		_, err := parseWebhookConfig(c)
		return err
	}
	return cfgErr("unknown target type %q", typ)
}

// ---------------------------------------------------------------- provisioner CRUD

// CreateInput is a new provisioner.
type CreateInput struct {
	Name         string
	TargetType   string
	ConnectionID *string
	Config       json.RawMessage
	Secret       map[string]string
	FullSchedule string
	Failsafe     json.RawMessage
}

func (s *Service) check(typ, name, schedule string, failsafe json.RawMessage) error {
	if !nameRE.MatchString(name) {
		return cfgErr("name is required: 1 to 100 letters, digits, spaces and _ . : -")
	}
	if schedule != "" && !ValidSchedule(schedule) {
		return cfgErr(`full_schedule must be "M H * * *" (a daily UTC time)`)
	}
	_, err := ParseFailsafe(failsafe)
	return err
}

// Create stores a provisioner in adopt mode: it changes nothing on the target
// until an admin reviews the first full sync and sets the mode to active.
func (s *Service) Create(tx *store.TenantTx, now time.Time, actor string, in CreateInput) (*store.Provisioner, error) {
	if err := s.check(in.TargetType, in.Name, in.FullSchedule, in.Failsafe); err != nil {
		return nil, err
	}
	if err := s.ValidateConfig(in.TargetType, in.Config, in.Secret); err != nil {
		return nil, err
	}
	for _, k := range secretRequired[in.TargetType] {
		if in.Secret[k] == "" {
			return nil, cfgErr("secret.%s is required for a %s target", k, in.TargetType)
		}
	}
	if _, err := tx.ProvisionerByName(in.Name); err == nil {
		return nil, &DuplicateError{Name: in.Name}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if in.ConnectionID != nil {
		if _, err := tx.Connection(*in.ConnectionID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, cfgErr("connection_id: no such connection")
			}
			return nil, err
		}
	}
	p := &store.Provisioner{ID: uuid.NewString(), Name: in.Name, TargetType: in.TargetType, ConnectionID: in.ConnectionID,
		Config: in.Config, Mode: store.ProvModeAdopt, FullSchedule: in.FullSchedule, Failsafe: in.Failsafe, CreatedBy: actor, CreatedAt: now}
	if p.FullSchedule == "" {
		p.FullSchedule = "0 2 * * *"
	}
	if len(p.Failsafe) == 0 {
		p.Failsafe = json.RawMessage("{}")
	}
	if len(in.Secret) > 0 {
		var err error
		if p.SecretEnc, err = s.sealSecret(tx.Tenant(), p.ID, in.Secret); err != nil {
			return nil, err
		}
	}
	if err := tx.InsertProvisioner(p); err != nil {
		return nil, err
	}
	if _, err := tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.provisioner.created", LegacyActor: actor,
		TargetType: "provisioner", TargetID: p.ID, Detail: ojson.Object{{Key: "name", Value: p.Name}, {Key: "target_type", Value: p.TargetType},
			{Key: "mode", Value: p.Mode}}}); err != nil {
		return nil, err
	}
	return tx.Provisioner(p.ID)
}

// DuplicateError is a provisioner name already in use.
type DuplicateError struct{ Name string }

func (e *DuplicateError) Error() string {
	return fmt.Sprintf("a provisioner named %q already exists", e.Name)
}

// UpdateInput changes a provisioner; nil fields stay. Secret keys replace the
// stored credentials (an empty map leaves them).
type UpdateInput struct {
	Version      int64
	Name         *string
	ConnectionID *string
	Config       json.RawMessage
	Secret       map[string]string
	Mode         *string
	FullSchedule *string
	Failsafe     json.RawMessage
}

// Update changes a provisioner. Any change schedules a full sync; a change of
// mode to active needs the first run to have completed in adopt or dry_run.
func (s *Service) Update(tx *store.TenantTx, now time.Time, actor, id string, in UpdateInput) (*store.Provisioner, error) {
	p, err := tx.Provisioner(id)
	if err != nil {
		return nil, err
	}
	if in.Version != p.Version {
		return nil, store.ErrVersionConflict
	}
	oldMode := p.Mode
	if in.Name != nil {
		p.Name = *in.Name
	}
	if in.ConnectionID != nil {
		if *in.ConnectionID == "" {
			p.ConnectionID = nil
		} else {
			p.ConnectionID = in.ConnectionID
		}
	}
	if len(in.Config) > 0 {
		p.Config = in.Config
	}
	if in.Mode != nil {
		switch *in.Mode {
		case store.ProvModeAdopt, store.ProvModeDryRun, store.ProvModeActive, store.ProvModePaused:
			p.Mode = *in.Mode
		default:
			return nil, cfgErr("mode must be adopt, dry_run, active or paused")
		}
	}
	if in.FullSchedule != nil {
		p.FullSchedule = *in.FullSchedule
	}
	if len(in.Failsafe) > 0 {
		p.Failsafe = in.Failsafe
	}
	if err := s.check(p.TargetType, p.Name, p.FullSchedule, p.Failsafe); err != nil {
		return nil, err
	}
	if p.Mode == store.ProvModeActive && oldMode != store.ProvModeActive {
		// an admin enables a provisioner after reviewing what a full sync would do
		last, err := tx.LastSyncRun(id, store.RunFull)
		if errors.Is(err, store.ErrNotFound) || (err == nil && last.Status != store.RunDone) {
			return nil, ErrReviewRequired
		} else if err != nil {
			return nil, err
		}
	}
	sec, err := s.openSecret(tx.Tenant(), p)
	if err != nil {
		return nil, err
	}
	for k, v := range in.Secret {
		sec[k] = v
	}
	if err := s.ValidateConfig(p.TargetType, p.Config, sec); err != nil {
		return nil, err
	}
	for _, k := range secretRequired[p.TargetType] {
		if sec[k] == "" {
			return nil, cfgErr("secret.%s is required for a %s target", k, p.TargetType)
		}
	}
	if p.Name != "" {
		if other, err := tx.ProvisionerByName(p.Name); err == nil && other.ID != p.ID {
			return nil, &DuplicateError{Name: p.Name}
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if p.ConnectionID != nil {
		if _, err := tx.Connection(*p.ConnectionID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, cfgErr("connection_id: no such connection")
			}
			return nil, err
		}
	}
	p.SecretEnc = nil // keep the stored secret unless new credentials came with the request
	if len(in.Secret) > 0 {
		if p.SecretEnc, err = s.sealSecret(tx.Tenant(), p.ID, sec); err != nil {
			return nil, err
		}
	}
	if err := tx.UpdateProvisioner(p, now); err != nil {
		return nil, err
	}
	detail := ojson.Object{{Key: "name", Value: p.Name}, {Key: "mode_from", Value: oldMode}, {Key: "mode_to", Value: p.Mode},
		{Key: "secret_changed", Value: len(in.Secret) > 0}}
	if _, err := tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.provisioner.updated", LegacyActor: actor,
		TargetType: "provisioner", TargetID: p.ID, Detail: detail}); err != nil {
		return nil, err
	}
	return tx.Provisioner(p.ID)
}

// Delete removes a provisioner and its marks, ownership records, runs and ops.
// It does not touch the target.
func (s *Service) Delete(tx *store.TenantTx, now time.Time, actor, id string) error {
	p, err := tx.Provisioner(id)
	if err != nil {
		return err
	}
	if err := tx.DeleteProvisioner(id); err != nil {
		return err
	}
	_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.provisioner.deleted", LegacyActor: actor,
		TargetType: "provisioner", TargetID: id, Detail: ojson.Object{{Key: "name", Value: p.Name}, {Key: "target_type", Value: p.TargetType}}})
	return err
}

// MarkInput is a mark on a folder or a group.
type MarkInput struct {
	ObjectType string // folder | group
	ObjectID   string
	Scope      string // one | sub for a folder; empty or self for a group
	Include    bool
	Metadata   json.RawMessage
}

// SetMark creates or replaces a mark and schedules a full sync.
func (s *Service) SetMark(tx *store.TenantTx, now time.Time, actor, provisioner string, in MarkInput) (*store.ProvMark, error) {
	if _, err := tx.Provisioner(provisioner); err != nil {
		return nil, err
	}
	switch in.ObjectType {
	case "group":
		if in.Scope != "" && in.Scope != "self" {
			return nil, cfgErr("a group mark has no scope")
		}
		in.Scope = "self"
		g, err := tx.GrpGroup(store.GroupID(in.ObjectID))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, cfgErr("object_id: no such group")
			}
			return nil, err
		}
		if g.Status == store.GroupDeleted {
			return nil, cfgErr("object_id: the group is deleted")
		}
	case "folder":
		if in.Scope != "one" && in.Scope != "sub" {
			return nil, cfgErr("a folder mark's scope is one or sub")
		}
		if _, err := tx.GrpFolder(store.FolderID(in.ObjectID)); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, cfgErr("object_id: no such folder")
			}
			return nil, err
		}
	default:
		return nil, cfgErr("object_type is folder or group")
	}
	if err := ValidateMetadata(in.Metadata); err != nil {
		return nil, err
	}
	m := &store.ProvMark{ProvisionerID: provisioner, ObjectType: in.ObjectType, ObjectID: in.ObjectID, Scope: in.Scope,
		Include: in.Include, Metadata: in.Metadata}
	if len(m.Metadata) == 0 {
		m.Metadata = json.RawMessage("{}")
	}
	if err := tx.PutProvMark(m); err != nil {
		return nil, err
	}
	if err := tx.SetProvisionerNeedsFull(provisioner, true, false); err != nil {
		return nil, err
	}
	_, err := tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.provisioner.mark_set", LegacyActor: actor,
		TargetType: "provisioner", TargetID: provisioner, Detail: ojson.Object{{Key: "object_type", Value: m.ObjectType},
			{Key: "object_id", Value: m.ObjectID}, {Key: "scope", Value: m.Scope}, {Key: "include", Value: m.Include}}})
	return m, err
}

// RemoveMark removes a mark and schedules a full sync.
func (s *Service) RemoveMark(tx *store.TenantTx, now time.Time, actor, provisioner, objectType, objectID string) error {
	if _, err := tx.Provisioner(provisioner); err != nil {
		return err
	}
	if err := tx.DeleteProvMark(provisioner, objectType, objectID); err != nil {
		return err
	}
	if err := tx.SetProvisionerNeedsFull(provisioner, true, false); err != nil {
		return err
	}
	_, err := tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.provisioner.mark_removed", LegacyActor: actor,
		TargetType: "provisioner", TargetID: provisioner, Detail: ojson.Object{{Key: "object_type", Value: objectType},
			{Key: "object_id", Value: objectID}}})
	return err
}

// RequestFull schedules a full sync for the runner to pick up. approve lets
// that run exceed the failsafe limits once (an admin reviewed a held run).
func (s *Service) RequestFull(tx *store.TenantTx, now time.Time, actor, id string, approve bool) error {
	p, err := tx.Provisioner(id)
	if err != nil {
		return err
	}
	if p.Mode == store.ProvModePaused {
		return ErrPaused
	}
	if approve && p.Mode != store.ProvModeActive {
		return cfgErr("the failsafe limits only apply in active mode: there is nothing to approve")
	}
	if err := tx.SetProvisionerNeedsFull(id, true, approve); err != nil {
		return err
	}
	_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.provisioner.sync_requested", LegacyActor: actor,
		TargetType: "provisioner", TargetID: id, Detail: ojson.Object{{Key: "approve_failsafe", Value: approve}}})
	return err
}
