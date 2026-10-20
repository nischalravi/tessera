package sinks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Audit actions. Details never carry credentials.
const (
	ActionCreated     = "groups.sink.created"
	ActionUpdated     = "groups.sink.updated"
	ActionDeleted     = "groups.sink.deleted"
	ActionDeadLetter  = "groups.sink.dead_lettered"
	ActionRedeliver   = "groups.sink.redelivery_requested"
	ActionDiscarded   = "groups.sink.dead_letter_discarded"
	ActionRedelivered = "groups.sink.redelivered"
)

// MaxSinks is how many sinks a tenant may have.
const MaxSinks = 20

// Service creates, changes and deletes sinks. Every method runs in the
// caller's transaction and writes its audit event there.
type Service struct {
	Sealer *seal.Sealer
	// AllowInsecure permits plain amqp:// and non-TLS Kafka (dev only).
	AllowInsecure bool
}

// Error is a refusal that is the caller's to fix: Kind is "invalid",
// "conflict" or "unavailable".
type Error struct {
	Kind, Code, Msg string
}

func (e *Error) Error() string { return e.Msg }

func invalid(code, format string, a ...any) error {
	return &Error{Kind: "invalid", Code: code, Msg: fmt.Sprintf(format, a...)}
}

// secretAAD binds a sealed credential to its tenant, table, column and sink.
func secretAAD(tx *store.TenantTx, id string) []byte {
	return seal.AAD(tx.Tenant(), "grp_event_sinks", "secret_enc", id)
}

func (s *Service) seal(tx *store.TenantTx, id string, c Credentials) ([]byte, error) {
	if c.IsZero() {
		return nil, nil
	}
	if s.Sealer == nil {
		return nil, &Error{Kind: "unavailable", Code: "sealing_unavailable", Msg: "sealing is not configured, so credentials cannot be stored"}
	}
	raw, err := json.Marshal(c) // #nosec G117 -- the plaintext goes straight into Sealer.Seal below and is never stored or returned
	if err != nil {
		return nil, err
	}
	return s.Sealer.Seal(raw, secretAAD(tx, id))
}

// Credentials opens a sink's sealed credentials.
func (s *Service) Credentials(tx *store.TenantTx, k *store.GrpSink) (Credentials, error) {
	var c Credentials
	if len(k.SecretEnc) == 0 {
		return c, nil
	}
	if s.Sealer == nil {
		return c, errors.New("sinks: sealing is not configured")
	}
	raw, err := s.Sealer.Open(k.SecretEnc, secretAAD(tx, k.ID))
	if err != nil {
		return c, fmt.Errorf("sinks: open credentials of sink %s: %w", k.ID, err)
	}
	err = json.Unmarshal(raw, &c)
	return c, err
}

// Spec decrypts a sink into what Open needs.
func (s *Service) Spec(tx *store.TenantTx, k *store.GrpSink) (Spec, error) {
	var cfg Config
	if err := json.Unmarshal(k.Config, &cfg); err != nil {
		return Spec{}, fmt.Errorf("sinks: sink %s has an unreadable configuration: %w", k.ID, err)
	}
	cr, err := s.Credentials(tx, k)
	return Spec{Kind: k.Kind, Config: cfg, Creds: cr}, err
}

// Consumer is the cursor name of a sink in grp_event_cursors.
func Consumer(id string) string { return "sink:" + id }

func checkName(name string) error {
	if n := len(strings.TrimSpace(name)); n < 1 || len(name) > 80 || strings.ContainsAny(name, "\x00\r\n") {
		return invalid("invalid_name", "name is required: 1 to 80 characters")
	}
	return nil
}

func (s *Service) validate(kind string, c Config, cr Credentials, types []string) error {
	if err := Validate(kind, c, cr, s.AllowInsecure); err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return invalid("invalid_"+ve.Field, "%s", ve.Msg)
		}
		return err
	}
	if err := ValidateTypes(types, func(t string) bool { _, ok := events.ObjectType(t); return ok }); err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return invalid("invalid_event_types", "%s", ve.Msg)
		}
		return err
	}
	return nil
}

func nameTaken(tx *store.TenantTx, name, except string) (bool, int, error) {
	all, err := tx.GrpSinks()
	if err != nil {
		return false, 0, err
	}
	for _, k := range all {
		if k.Name == name && k.ID != except {
			return true, len(all), nil
		}
	}
	return false, len(all), nil
}

// CreateInput is a new sink. From is "now" (the default: only events written
// after this) or "start" (every event still in the outbox).
type CreateInput struct {
	Name       string
	Kind       string
	Config     Config
	Creds      Credentials
	EventTypes []string
	Enabled    bool
	From       string
}

// Create validates and stores a sink, and sets its cursor.
func (s *Service) Create(tx *store.TenantTx, in CreateInput, actor string, now time.Time) (*store.GrpSink, error) {
	if err := checkName(in.Name); err != nil {
		return nil, err
	}
	if in.From != "" && in.From != "now" && in.From != "start" {
		return nil, invalid("invalid_from", "from is now or start")
	}
	if err := s.validate(in.Kind, in.Config, in.Creds, in.EventTypes); err != nil {
		return nil, err
	}
	taken, n, err := nameTaken(tx, in.Name, "")
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, &Error{Kind: "conflict", Code: "name_taken", Msg: "a sink with this name exists"}
	}
	if n >= MaxSinks {
		return nil, invalid("too_many_sinks", "a tenant may have at most %d sinks", MaxSinks)
	}
	id := uuid.NewString()
	enc, err := s.seal(tx, id, in.Creds)
	if err != nil {
		return nil, err
	}
	cfg, err := json.Marshal(in.Config)
	if err != nil {
		return nil, err
	}
	k := &store.GrpSink{ID: id, Name: in.Name, Kind: in.Kind, Enabled: in.Enabled, Config: cfg, EventTypes: in.EventTypes, SecretEnc: enc,
		CreatedBy: actor, CreatedAt: now}
	if err := tx.InsertGrpSink(k); err != nil {
		return nil, err
	}
	if in.From != "start" {
		head, err := tx.GrpEventHead()
		if err != nil {
			return nil, err
		}
		if err := events.Ack(tx, Consumer(id), head.LastSeq, now); err != nil {
			return nil, err
		}
	}
	if err := tx.Audit(now, actor, ActionCreated, ojson.Object{{Key: "sink_id", Value: id}, {Key: "name", Value: in.Name},
		{Key: "kind", Value: in.Kind}, {Key: "enabled", Value: in.Enabled}, {Key: "credentials_set", Value: !in.Creds.IsZero()}}); err != nil {
		return nil, err
	}
	return tx.GrpSink(id)
}

// UpdateInput changes a sink; nil fields stay as they are. Config and Creds
// replace the whole configuration or credential set.
type UpdateInput struct {
	Name       *string
	Enabled    *bool
	Config     *Config
	Creds      *Credentials
	EventTypes *[]string
}

// Update validates and stores the change. A new configuration or credential
// resets the sink's retry state, so a fixed endpoint is tried at once.
func (s *Service) Update(tx *store.TenantTx, id string, in UpdateInput, actor string, now time.Time) (*store.GrpSink, error) {
	k, err := tx.GrpSink(id)
	if err != nil {
		return nil, err
	}
	spec, err := s.Spec(tx, k)
	if err != nil && in.Creds == nil {
		return nil, err
	}
	changed := []any{}
	if in.Name != nil {
		if err := checkName(*in.Name); err != nil {
			return nil, err
		}
		taken, _, err := nameTaken(tx, *in.Name, id)
		if err != nil {
			return nil, err
		}
		if taken {
			return nil, &Error{Kind: "conflict", Code: "name_taken", Msg: "a sink with this name exists"}
		}
		k.Name = *in.Name
		changed = append(changed, "name")
	}
	if in.Enabled != nil {
		k.Enabled = *in.Enabled
		changed = append(changed, "enabled")
	}
	if in.EventTypes != nil {
		k.EventTypes = *in.EventTypes
		changed = append(changed, "event_types")
	}
	if in.Config != nil {
		spec.Config = *in.Config
		changed = append(changed, "config")
	}
	if in.Creds != nil {
		spec.Creds = *in.Creds
		changed = append(changed, "credentials")
	}
	if err := s.validate(k.Kind, spec.Config, spec.Creds, k.EventTypes); err != nil {
		return nil, err
	}
	if in.Config != nil {
		if k.Config, err = json.Marshal(spec.Config); err != nil {
			return nil, err
		}
	}
	if in.Creds != nil {
		if k.SecretEnc, err = s.seal(tx, id, spec.Creds); err != nil {
			return nil, err
		}
	}
	if err := tx.UpdateGrpSink(k, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor, ActionUpdated, ojson.Object{{Key: "sink_id", Value: id}, {Key: "name", Value: k.Name},
		{Key: "changed", Value: changed}}); err != nil {
		return nil, err
	}
	return tx.GrpSink(id)
}

// Delete removes a sink, its dead letters and its cursor.
func (s *Service) Delete(tx *store.TenantTx, id string, actor string, now time.Time) error {
	k, err := tx.GrpSink(id)
	if err != nil {
		return err
	}
	if err := tx.DeleteGrpSink(id); err != nil {
		return err
	}
	return tx.Audit(now, actor, ActionDeleted, ojson.Object{{Key: "sink_id", Value: id}, {Key: "name", Value: k.Name}, {Key: "kind", Value: k.Kind}})
}

// Requeue marks a dead letter for redelivery: the runner sends it on its next
// pass, out of order with respect to the events after it.
func (s *Service) Requeue(tx *store.TenantTx, sinkID string, seq int64, actor string, now time.Time) error {
	d, err := tx.GrpDeadLetter(sinkID, seq)
	if err != nil {
		return err
	}
	if d.Status != store.DeadLetterDead {
		return &Error{Kind: "conflict", Code: "not_dead", Msg: "the event is " + d.Status + ", not dead"}
	}
	if err := tx.SetGrpDeadLetterStatus(sinkID, seq, store.DeadLetterRequeued, d.Attempts, d.LastError, now); err != nil {
		return err
	}
	return tx.Audit(now, actor, ActionRedeliver, ojson.Object{{Key: "sink_id", Value: sinkID}, {Key: "seq", Value: seq}})
}

// Discard gives up on a dead letter.
func (s *Service) Discard(tx *store.TenantTx, sinkID string, seq int64, actor string, now time.Time) error {
	d, err := tx.GrpDeadLetter(sinkID, seq)
	if err != nil {
		return err
	}
	if d.Status != store.DeadLetterDead && d.Status != store.DeadLetterRequeued {
		return &Error{Kind: "conflict", Code: "not_dead", Msg: "the event is " + d.Status + ", not dead"}
	}
	if err := tx.SetGrpDeadLetterStatus(sinkID, seq, store.DeadLetterDiscarded, d.Attempts, d.LastError, now); err != nil {
		return err
	}
	return tx.Audit(now, actor, ActionDiscarded, ojson.Object{{Key: "sink_id", Value: sinkID}, {Key: "seq", Value: seq}})
}
