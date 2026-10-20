package rules

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Env is one save's context: the tenant transaction, the clock reading, the
// platform user who saves (a rule acts with this user's authority from then on)
// and the checker for what that user holds now.
type Env struct {
	Tx      *store.TenantTx
	Now     time.Time
	By      string // platform user id; "" for a machine client, which cannot save rules
	Checker *privs.Checker
	RT      *Runtime
}

// View is a rule as the API shows it. The webhook secret is never shown again
// after it was created or rotated.
type View struct {
	ID         string      `json:"id"`
	OwnerType  string      `json:"owner_type"`
	OwnerID    string      `json:"owner_id"`
	Scope      string      `json:"scope"`
	Name       string      `json:"name"`
	Trigger    string      `json:"trigger"`
	Conditions []Condition `json:"conditions"`
	Action     string      `json:"action"`
	Params     Params      `json:"params"`
	Enabled    bool        `json:"enabled"`
	Veto       bool        `json:"veto"` // the rule can deny a membership add
	HasSecret  bool        `json:"has_secret"`
	CreatedBy  string      `json:"created_by"`
	UpdatedBy  string      `json:"updated_by"` // the rule acts with this user's privileges
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// ViewOf decodes a stored rule for the API.
func ViewOf(r *store.GrpRule) (*View, error) {
	c, err := Compile(r)
	if err != nil {
		return nil, err
	}
	if c.Spec.Conditions == nil {
		c.Spec.Conditions = []Condition{}
	}
	return &View{ID: r.ID, OwnerType: r.OwnerType, OwnerID: r.OwnerID, Scope: r.Scope, Name: r.Name, Trigger: r.Trigger,
		Conditions: c.Spec.Conditions, Action: r.Action, Params: c.Spec.Params, Enabled: r.Enabled, Veto: c.Spec.IsVeto(),
		HasSecret: len(r.SecretEnc) > 0, CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}

// headSeq is the last event of the tenant's outbox: a rule saved now reacts to
// what comes after it.
func (e Env) headSeq() (int64, error) {
	h, err := e.Tx.GrpEventHead()
	return h.LastSeq, err
}

func (e Env) audit(action string, r *store.GrpRule, extra ...ojson.KV) error {
	d := ojson.Object{{Key: "rule_id", Value: r.ID}, {Key: "owner_type", Value: r.OwnerType}, {Key: "owner_id", Value: r.OwnerID},
		{Key: "name", Value: r.Name}, {Key: "trigger", Value: r.Trigger}, {Key: "action", Value: r.Action}, {Key: "enabled", Value: r.Enabled}}
	d = append(d, extra...)
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups", TargetType: "rule", TargetID: r.ID, Detail: d})
	return err
}

// emailAllowed reports whether the tenant lets rules send email (off by default).
func emailAllowed(tx *store.TenantTx) (bool, error) {
	s, err := tx.GrpRuleSettings()
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && s.EmailEnabled, err
}

// checkSave is what creating and updating share: the vocabulary, the author's
// privileges (design §10.3: admin on the owner and on every object the action
// touches), that what the rule names exists, and the tenant's email gate.
func (e Env) checkSave(spec *Spec) error {
	if e.By == "" {
		return forbidden("rule_needs_user", "a rule acts with the authority of the user who saves it, so a machine client cannot save one")
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if err := Authorize(e.Checker, spec); err != nil {
		return err // *privs.DeniedError: 403 privilege_required
	}
	for _, n := range spec.needs() {
		if n.obj.Type != privs.Group || n.obj.ID == spec.OwnerID {
			continue
		}
		g, err := e.Tx.GrpGroup(store.GroupID(n.obj.ID))
		if errors.Is(err, store.ErrNotFound) {
			return invalid("unknown_group", "no such group: %s", n.obj.ID)
		}
		if err != nil {
			return err
		}
		if g.Status == store.GroupDeleted {
			return conflict("group_deleted", "group %q is deleted", g.Name)
		}
	}
	for _, id := range []int64{spec.Params.HolderIdentity, spec.Params.ToIdentity} {
		if id == 0 {
			continue
		}
		if _, err := e.Tx.Identity(id); errors.Is(err, store.ErrNotFound) {
			return invalid("unknown_identity", "no such identity: %d", id)
		} else if err != nil {
			return err
		}
	}
	if spec.Action == ActNotify {
		if ok, err := emailAllowed(e.Tx); err != nil {
			return err
		} else if !ok {
			return conflict("email_rules_disabled", "rule actions that send email are off for this tenant: a tenant admin turns them on in the groups settings")
		}
	}
	if spec.Action == ActWebhook && strings.HasPrefix(spec.Params.URL, "http://") && (e.RT == nil || !e.RT.AllowHTTP) {
		return invalid("invalid_url", "a webhook is called over https")
	}
	return nil
}

// owner loads the rule's owner: it must exist, not be deleted and not be
// mirrored from Grouper (K11).
func (e Env) owner(spec *Spec) error {
	switch spec.OwnerType {
	case store.RuleOwnerFolder:
		f, err := e.Tx.GrpFolder(store.FolderID(spec.OwnerID))
		if errors.Is(err, store.ErrNotFound) {
			return notFound("no such folder")
		}
		if err != nil {
			return err
		}
		if f.ManagedBy == store.ManagedByGrouperMirror {
			return conflict("folder_mirrored", "folder %q is mirrored from Grouper and is read-only here", f.Name)
		}
	case store.RuleOwnerGroup:
		g, err := e.Tx.GrpGroup(store.GroupID(spec.OwnerID))
		if errors.Is(err, store.ErrNotFound) {
			return notFound("no such group")
		}
		if err != nil {
			return err
		}
		if g.Status == store.GroupDeleted {
			return conflict("group_deleted", "group %q is deleted", g.Name)
		}
		if g.ManagedBy == store.ManagedByGrouperMirror {
			return conflict("folder_mirrored", "group %q is mirrored from Grouper and is read-only here", g.Name)
		}
	}
	return nil
}

// Create saves a new rule. The second result is the webhook signing secret of
// a webhook rule, shown here once.
func Create(e Env, spec Spec) (*View, string, error) {
	if err := e.owner(&spec); err != nil {
		return nil, "", err
	}
	if err := e.checkSave(&spec); err != nil {
		return nil, "", err
	}
	have, err := e.Tx.GrpRulesOf(spec.OwnerType, spec.OwnerID)
	if err != nil {
		return nil, "", err
	}
	if len(have) >= MaxRulesPerOwner {
		return nil, "", conflict("too_many_rules", "an owner has at most %d rules", MaxRulesPerOwner)
	}
	r := &store.GrpRule{ID: uuid.NewString(), OwnerType: spec.OwnerType, OwnerID: spec.OwnerID, Scope: spec.Scope, Name: spec.Name,
		Trigger: spec.Trigger, Conditions: spec.conditionsJSON(), Action: spec.Action, Params: spec.paramsJSON(), Enabled: spec.Enabled,
		CreatedBy: e.By, CreatedAt: e.Now, UpdatedBy: e.By, UpdatedAt: e.Now}
	if r.ActiveSeq, err = e.headSeq(); err != nil {
		return nil, "", err
	}
	var secret string
	if spec.Action == ActWebhook {
		if secret, r.SecretEnc, err = e.RT.newSecret(e.Tx.Tenant(), r.ID); err != nil {
			return nil, "", err
		}
	}
	if err := e.Tx.InsertGrpRule(r); err != nil {
		return nil, "", err
	}
	if err := e.audit("groups.rule.created", r); err != nil {
		return nil, "", err
	}
	v, err := ViewOf(r)
	return v, secret, err
}

// Get returns one rule.
func Get(tx *store.TenantTx, id string) (*store.GrpRule, error) {
	r, err := tx.GrpRule(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("no such rule")
	}
	return r, err
}

// Update replaces a rule's trigger, conditions, action, params, name and
// enabled flag (its owner never changes). The updating user becomes the rule's
// author: from now on it acts with their privileges. A rule that is saved
// does not act on events from before the save. rotate makes a new webhook secret.
func Update(e Env, id string, spec Spec, rotate bool) (*View, string, error) {
	r, err := Get(e.Tx, id)
	if err != nil {
		return nil, "", err
	}
	spec.OwnerType, spec.OwnerID = r.OwnerType, r.OwnerID
	if r.OwnerType == store.RuleOwnerFolder && spec.Scope == "" {
		spec.Scope = r.Scope
	}
	if err := e.owner(&spec); err != nil {
		return nil, "", err
	}
	if err := e.checkSave(&spec); err != nil {
		return nil, "", err
	}
	var secret string
	switch {
	case spec.Action != ActWebhook:
		r.SecretEnc = nil
	case len(r.SecretEnc) == 0 || rotate:
		if secret, r.SecretEnc, err = e.RT.newSecret(e.Tx.Tenant(), r.ID); err != nil {
			return nil, "", err
		}
	}
	r.Scope, r.Name, r.Trigger, r.Conditions, r.Action, r.Params = spec.Scope, spec.Name, spec.Trigger, spec.conditionsJSON(),
		spec.Action, spec.paramsJSON()
	r.Enabled, r.UpdatedBy, r.UpdatedAt = spec.Enabled, e.By, e.Now
	if r.ActiveSeq, err = e.headSeq(); err != nil {
		return nil, "", err
	}
	if err := e.Tx.UpdateGrpRule(r); err != nil {
		return nil, "", err
	}
	if err := e.audit("groups.rule.updated", r, ojson.KV{Key: "secret_rotated", Value: secret != ""}); err != nil {
		return nil, "", err
	}
	v, err := ViewOf(r)
	return v, secret, err
}

// Delete removes a rule. Removing needs admin on the owner only: it takes
// authority away, it does not use any.
func Delete(e Env, id string) error {
	r, err := Get(e.Tx, id)
	if err != nil {
		return err
	}
	c, err := Compile(r)
	if err != nil {
		return err
	}
	if err := Authorize(e.Checker, &Spec{OwnerType: c.Spec.OwnerType, OwnerID: c.Spec.OwnerID}); err != nil {
		return err
	}
	if err := e.Tx.DeleteGrpRule(r.ID); err != nil {
		return err
	}
	return e.audit("groups.rule.deleted", r)
}

// List returns an owner's rules, oldest first.
func List(tx *store.TenantTx, ownerType, ownerID string) ([]*View, error) {
	rs, err := tx.GrpRulesOf(ownerType, ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]*View, 0, len(rs))
	for _, r := range rs {
		v, err := ViewOf(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Settings are the tenant's rule settings.
type Settings struct {
	// EmailEnabled lets rule actions send email. Off until a tenant admin turns it on.
	EmailEnabled bool       `json:"email_enabled"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	UpdatedBy    *string    `json:"updated_by,omitempty"`
}

// LoadSettings returns the tenant's settings (the defaults while none are saved).
func LoadSettings(tx *store.TenantTx) (Settings, error) {
	s, err := tx.GrpRuleSettings()
	if errors.Is(err, store.ErrNotFound) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	return Settings{EmailEnabled: s.EmailEnabled, UpdatedAt: &s.UpdatedAt, UpdatedBy: s.UpdatedBy}, nil
}

// SaveSettings stores the settings. Turning email on needs the tenant_admin
// role (the route's groups.admin permission is checked before this).
func SaveSettings(e Env, in Settings) (Settings, error) {
	var by *string
	if e.By != "" {
		by = &e.By
	}
	if err := e.Tx.SetGrpRuleSettings(in.EmailEnabled, e.Now, by); err != nil {
		return Settings{}, err
	}
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: "groups.rule_settings.updated", LegacyActor: "groups",
		TargetType: "tenant", TargetID: e.Tx.Tenant().String(),
		Detail: ojson.Object{{Key: "email_enabled", Value: in.EmailEnabled}}})
	if err != nil {
		return Settings{}, err
	}
	return LoadSettings(e.Tx)
}
