package loaders

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Spec is the whole definition of a loader: what a create sends, what an
// update sends once merged with the loader it changes, and what the admin
// change of a SQL loader carries (so a second person approves exactly what
// will be applied). It holds no secret.
type Spec struct {
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	ConnectionID    string          `json:"connection_id,omitempty"`
	Config          json.RawMessage `json:"config"`
	TargetFolder    string          `json:"target_folder"`
	NameTemplate    string          `json:"name_template,omitempty"`
	OnMissingGroup  string          `json:"on_missing_group,omitempty"`
	AndGroup        string          `json:"and_group,omitempty"`
	Schedule        string          `json:"schedule,omitempty"`
	IncrementalSecs *int64          `json:"incremental_secs,omitempty"`
	Failsafe        *Failsafe       `json:"failsafe,omitempty"`
	// Status is enabled or disabled (default enabled). A held loader stays
	// held until its run is decided.
	Status string `json:"status,omitempty"`
}

// SpecOf is the spec of an existing loader (for an update that changes some
// fields).
func SpecOf(l *store.GrpLoader) (Spec, error) {
	s := Spec{Name: l.Name, Type: l.Type, Config: json.RawMessage(l.Config), TargetFolder: string(l.TargetFolder),
		NameTemplate: l.NameTemplate, OnMissingGroup: l.OnMissingGroup, Schedule: l.Schedule, IncrementalSecs: l.IncrementalSecs,
		Status: l.Status}
	if l.ConnectionID != nil {
		s.ConnectionID = *l.ConnectionID
	}
	if l.AndGroup != nil {
		s.AndGroup = string(*l.AndGroup)
	}
	f, err := ParseFailsafe(l.Failsafe)
	if err != nil {
		return s, err
	}
	s.Failsafe = &f
	if l.Status == store.LoaderHeld {
		s.Status = ""
	}
	return s, nil
}

// Valid names, in the order a person reads them.
const (
	maxNameRunes = MaxNameBytes
	// SecretMaxBytes bounds a loader's credential.
	SecretMaxBytes = 4096
)

// Validate checks spec against the tenant's current state (the folder, group
// and connection exist, the config fits the type) and returns the row it would
// store. existing is the loader being changed, nil for a create.
func Validate(tx *store.TenantTx, spec Spec, existing *store.GrpLoader) (*store.GrpLoader, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" || len(name) > maxNameRunes || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return nil, invalid("invalid_name", "name is 1 to %d characters without control characters", maxNameRunes)
	}
	if _, err := SourceFor(spec.Type); err != nil {
		if errors.Is(err, ErrTypeUnavailable) {
			return nil, invalid("loader_type_unavailable", "loader type %q is designed but not available yet (types: %s)", spec.Type, strings.Join(Types(), ", "))
		}
		return nil, invalid("invalid_type", "type is one of %s", strings.Join(Types(), ", "))
	}
	if existing != nil && existing.Type != spec.Type {
		return nil, conflict("type_immutable", "a loader's type cannot change: make a new loader")
	}
	l := &store.GrpLoader{Name: name, Type: spec.Type, TargetFolder: store.FolderID(spec.TargetFolder), Status: store.LoaderEnabled,
		IncrementalSecs: spec.IncrementalSecs}
	if existing != nil {
		*l = *existing
		l.Name, l.TargetFolder, l.IncrementalSecs = name, store.FolderID(spec.TargetFolder), spec.IncrementalSecs
	}
	l.ConnectionID, l.AndGroup = nil, nil
	if spec.ConnectionID != "" {
		if _, err := tx.Connection(spec.ConnectionID); errors.Is(err, store.ErrNotFound) {
			return nil, invalid("unknown_connection", "no such connection")
		} else if err != nil {
			return nil, err
		}
		c := spec.ConnectionID
		l.ConnectionID = &c
	}
	cfg, err := ValidateConfig(spec.Type, spec.Config, l.ConnectionID != nil)
	if err != nil {
		return nil, err
	}
	l.Config = string(cfg)
	if spec.TargetFolder == "" {
		return nil, invalid("invalid_target_folder", "target_folder is required")
	}
	folder, err := tx.GrpFolder(l.TargetFolder)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid("unknown_folder", "no such target folder")
	}
	if err != nil {
		return nil, err
	}
	if folder.ManagedBy == store.ManagedByGrouperMirror {
		return nil, conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", folder.Name)
	}
	if l.NameTemplate = spec.NameTemplate; l.NameTemplate == "" {
		l.NameTemplate = "{{.Name}}"
	}
	if err := ValidateTemplate(l.NameTemplate); err != nil {
		return nil, err
	}
	if l.OnMissingGroup = spec.OnMissingGroup; l.OnMissingGroup == "" {
		l.OnMissingGroup = "empty"
	}
	switch l.OnMissingGroup {
	case "empty", "disable", "delete", "keep":
	default:
		return nil, invalid("invalid_on_missing_group", "on_missing_group is empty, disable, delete or keep")
	}
	if spec.AndGroup != "" {
		g, err := tx.GrpGroup(store.GroupID(spec.AndGroup))
		if errors.Is(err, store.ErrNotFound) || (err == nil && g.Status == store.GroupDeleted) {
			return nil, invalid("unknown_group", "no such and_group")
		}
		if err != nil {
			return nil, err
		}
		id := g.ID
		l.AndGroup = &id
	}
	if l.Schedule = strings.TrimSpace(spec.Schedule); l.Schedule == "" {
		l.Schedule = "@daily"
	}
	if _, err := ParseSchedule(l.Schedule); err != nil {
		return nil, invalid("invalid_schedule", "schedule: %v", err)
	}
	if l.IncrementalSecs != nil {
		if *l.IncrementalSecs < 30 || *l.IncrementalSecs > 86400 {
			return nil, invalid("invalid_incremental", "incremental_secs is 30 to 86400")
		}
		var sc SQLConfig
		if !IsSQL(spec.Type) || strictDecode(cfg, &sc) != nil || sc.IncrementalQuery == "" {
			return nil, invalid("invalid_incremental", "incremental_secs needs a SQL loader with an incremental_query")
		}
	}
	var fs Failsafe
	if spec.Failsafe != nil {
		fs = *spec.Failsafe
	}
	if fs, err = fs.Normalize(); err != nil {
		return nil, err
	}
	fb, err := json.Marshal(fs)
	if err != nil {
		return nil, err
	}
	l.Failsafe = string(fb)
	switch spec.Status {
	case "":
	case store.LoaderEnabled, store.LoaderDisabled:
		if l.Status != store.LoaderHeld {
			l.Status = spec.Status
		} else if spec.Status == store.LoaderDisabled {
			return nil, conflict("loader_held", "the loader is held: approve or reject its held run first")
		}
	default:
		return nil, invalid("invalid_status", "status is enabled or disabled")
	}
	return l, nil
}

// SaveEnv is the context of a save: the transaction (which carries the audit
// context), the clock reading, the acting user and the sealer for the loader's
// credential.
type SaveEnv struct {
	Tx     *store.TenantTx
	Now    time.Time
	By     *string
	Sealer *seal.Sealer
	// Prod: a Postgres source's connection string must be sslmode=verify-full.
	Prod bool
}

func (e SaveEnv) audit(action string, l *store.GrpLoader, extra ojson.Object) error {
	sum := sha256.Sum256([]byte(l.Config))
	detail := ojson.Object{{Key: "loader_id", Value: l.ID}, {Key: "name", Value: l.Name}, {Key: "type", Value: l.Type},
		{Key: "target_folder_id", Value: string(l.TargetFolder)}, {Key: "status", Value: l.Status},
		{Key: "config_sha256", Value: hex.EncodeToString(sum[:])}}
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups", TargetType: "loader",
		TargetID: l.ID, Detail: append(detail, extra...)})
	return err
}

// sealSecret seals a loader's credential: a bearer token (a CSV URL, a SCIM
// provider), a client secret, an LDAP bind password or a Postgres connection
// string, by the type of the loader.
func (e SaveEnv) sealSecret(l *store.GrpLoader, secret string) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}
	if SecretPolicy(l.Type, json.RawMessage(l.Config)) == SecretNone {
		return nil, invalid("secret_not_used", "a loader of type %s with this config takes no secret", l.Type)
	}
	if err := CheckSecret(l.Type, json.RawMessage(l.Config), secret, e.Prod); err != nil {
		return nil, err
	}
	if e.Sealer == nil {
		return nil, conflict("sealer_unavailable", "no key-encryption key is configured to seal the credential")
	}
	return e.Sealer.Seal([]byte(secret), seal.AAD(e.Tx.Tenant(), "grp_loaders", "secret_enc", l.ID))
}

// requireSecret refuses a loader that needs a credential and has none.
func requireSecret(l *store.GrpLoader) error {
	if SecretPolicy(l.Type, json.RawMessage(l.Config)) == SecretRequired && len(l.SecretEnc) == 0 {
		return invalid("secret_required", "a %s loader needs its credential (secret)", l.Type)
	}
	return nil
}

// Create validates and stores a loader. secret is its credential ("" for none).
func Create(e SaveEnv, spec Spec, secret string) (*store.GrpLoader, error) {
	l, err := Validate(e.Tx, spec, nil)
	if err != nil {
		return nil, err
	}
	l.ID = uuid.NewString()
	l.CreatedBy, l.CreatedAt, l.UpdatedAt = e.By, e.Now, e.Now
	if l.SecretEnc, err = e.sealSecret(l, secret); err != nil {
		return nil, err
	}
	if err := requireSecret(l); err != nil {
		return nil, err
	}
	if err := e.Tx.InsertGrpLoader(l); errors.Is(err, store.ErrDuplicate) {
		return nil, conflict("name_taken", "a loader named %q exists", l.Name)
	} else if err != nil {
		return nil, err
	}
	return l, e.audit("groups.loader.created", l, ojson.Object{{Key: "has_secret", Value: len(l.SecretEnc) > 0}})
}

// Update validates spec (the whole resulting definition) against the loader id
// and stores it if the version still matches (nil: any). secret nil keeps the
// credential, "" clears it, anything else replaces it.
func Update(e SaveEnv, id string, version *int64, spec Spec, secret *string) (*store.GrpLoader, error) {
	old, err := e.Tx.GrpLoader(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such loader")
	}
	if err != nil {
		return nil, err
	}
	if version != nil && *version != old.Version {
		return nil, conflict("version_conflict", "the loader changed since it was read; reload it and retry")
	}
	l, err := Validate(e.Tx, spec, old)
	if err != nil {
		return nil, err
	}
	switch {
	case secret == nil:
		// kept (but a loader that no longer needs a credential, such as a CSV that
		// is a file now, has no use for one)
		if len(l.SecretEnc) > 0 && SecretPolicy(l.Type, json.RawMessage(l.Config)) == SecretNone {
			l.SecretEnc = nil
		}
	case *secret == "":
		l.SecretEnc = nil
	default:
		if l.SecretEnc, err = e.sealSecret(l, *secret); err != nil {
			return nil, err
		}
	}
	if err := requireSecret(l); err != nil {
		return nil, err
	}
	l.UpdatedAt = e.Now
	switch err := e.Tx.UpdateGrpLoader(l); {
	case errors.Is(err, store.ErrDuplicate):
		return nil, conflict("name_taken", "a loader named %q exists", l.Name)
	case errors.Is(err, store.ErrVersionConflict):
		return nil, conflict("version_conflict", "the loader changed since it was read; reload it and retry")
	case errors.Is(err, store.ErrNotFound):
		return nil, notFound("no such loader")
	case err != nil:
		return nil, err
	}
	return l, e.audit("groups.loader.updated", l, ojson.Object{{Key: "old_name", Value: old.Name},
		{Key: "has_secret", Value: len(l.SecretEnc) > 0}})
}
