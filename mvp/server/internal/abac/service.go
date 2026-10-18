package abac

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits on a policy's text.
const (
	MaxName        = 120
	MaxDescription = 2000
	MaxNote        = 500
	// MaxListed caps the people a simulation lists per side; the totals are exact.
	MaxListed = 200
)

// Refusal is a refused change; Code is stable for API clients.
type Refusal struct {
	Status int
	Code   string
	Msg    string
}

func (e *Refusal) Error() string { return e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Refusal{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Actor is who made a change.
type Actor struct {
	UserID  uuid.UUID
	Display string
}

func (a Actor) uid() *string {
	if a.UserID == uuid.Nil {
		return nil
	}
	s := a.UserID.String()
	return &s
}

// Spec is a policy's editable content.
type Spec struct {
	Name        string
	Description string
	Condition   *Node
	Note        string // why the change was made (kept in the version)
}

func (s *Spec) validate() (string, error) {
	s.Name, s.Description, s.Note = strings.TrimSpace(s.Name), strings.TrimSpace(s.Description), strings.TrimSpace(s.Note)
	switch {
	case s.Name == "" || len(s.Name) > MaxName:
		return "", refuse(422, "invalid_name", "a name of 1 to %d characters is required", MaxName)
	case len(s.Description) > MaxDescription:
		return "", refuse(422, "invalid_description", "the description is at most %d characters", MaxDescription)
	case len(s.Note) > MaxNote:
		return "", refuse(422, "invalid_note", "the note is at most %d characters", MaxNote)
	case s.Condition == nil:
		return "", refuse(422, "invalid_condition", "a condition is required")
	}
	if err := s.Condition.Validate(); err != nil {
		return "", refuse(422, "invalid_condition", "%s", err.Error())
	}
	return s.Condition.Canonical()
}

// Condition parses a stored policy's condition.
func Condition(p *store.AbacPolicy) (*Node, error) { return Parse([]byte(p.Condition)) }

func snapshot(p *store.AbacPolicy) (string, error) {
	b, err := json.Marshal(map[string]any{"name": p.Name, "description": p.Description,
		"condition": json.RawMessage(p.Condition), "status": p.Status})
	return string(b), err
}

func version(tx *store.TenantTx, p *store.AbacPolicy, note string, by Actor, now time.Time) error {
	snap, err := snapshot(p)
	if err != nil {
		return err
	}
	var n *string
	if note != "" {
		n = &note
	}
	return tx.AddAbacPolicyVersion(&store.AbacPolicyVersion{PolicyID: p.ID, Version: p.Version, Snapshot: snap, Note: n,
		ChangedBy: by.uid(), Actor: by.Display, ChangedAt: now})
}

func detail(p *store.AbacPolicy) ojson.Object {
	return ojson.Object{{Key: "policy_id", Value: p.ID}, {Key: "name", Value: p.Name}, {Key: "version", Value: p.Version},
		{Key: "condition", Value: json.RawMessage(p.Condition)}}
}

func nameFree(tx *store.TenantTx, name, selfID string) error {
	other, err := tx.AbacPolicyByName(name)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if other.ID != selfID {
		return refuse(409, "name_taken", "a policy named %q exists", name)
	}
	return nil
}

// Create saves a new policy (version 1) and audits it.
func Create(tx *store.TenantTx, s Spec, by Actor, now time.Time) (*store.AbacPolicy, error) {
	cond, err := s.validate()
	if err != nil {
		return nil, err
	}
	if err := nameFree(tx, s.Name, ""); err != nil {
		return nil, err
	}
	p := &store.AbacPolicy{ID: uuid.NewString(), Name: s.Name, Description: s.Description, Condition: cond,
		Status: store.AbacActive, Version: 1, CreatedAt: now, UpdatedBy: by.uid(), UpdatedAt: now}
	if err := tx.InsertAbacPolicy(p); err != nil {
		return nil, err
	}
	if err := version(tx, p, s.Note, by, now); err != nil {
		return nil, err
	}
	return p, tx.Audit(now, by.Display, "abac.policy.create", detail(p))
}

// Update saves new content as the next version; ver must be the current one.
func Update(tx *store.TenantTx, id string, ver int, s Spec, by Actor, now time.Time) (*store.AbacPolicy, error) {
	old, err := tx.AbacPolicy(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "policy_not_found", "policy not found")
	} else if err != nil {
		return nil, err
	}
	if old.Status != store.AbacActive {
		return nil, refuse(409, "policy_retired", "%s is retired", old.Name)
	}
	if ver != old.Version {
		return nil, refuse(409, "version_conflict", "the policy changed since version %d (now %d); reload it", ver, old.Version)
	}
	cond, err := s.validate()
	if err != nil {
		return nil, err
	}
	if err := nameFree(tx, s.Name, id); err != nil {
		return nil, err
	}
	p := *old
	p.Name, p.Description, p.Condition = s.Name, s.Description, cond
	p.Version, p.UpdatedBy, p.UpdatedAt = old.Version+1, by.uid(), now
	if err := tx.SaveAbacPolicy(&p, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the policy changed; reload it")
	} else if err != nil {
		return nil, err
	}
	if err := version(tx, &p, s.Note, by, now); err != nil {
		return nil, err
	}
	return &p, tx.Audit(now, by.Display, "abac.policy.update", detail(&p))
}

// Usage is where a policy is referenced.
type Usage struct {
	Roles        []string // birthright rules (role names)
	CatalogItems []string // bound catalog items (item ids)
}

// Empty reports whether nothing references the policy.
func (u Usage) Empty() bool { return len(u.Roles) == 0 && len(u.CatalogItems) == 0 }

// RulePolicy returns the policy id a stored birthright rule names ("" if none).
func RulePolicy(birthright *string) string {
	if birthright == nil || *birthright == "" {
		return ""
	}
	var r struct {
		Policy string `json:"policy"`
	}
	if json.Unmarshal([]byte(*birthright), &r) != nil {
		return ""
	}
	return r.Policy
}

// UsageOf lists what references each policy, by policy id.
func UsageOf(tx *store.TenantTx) (map[string]*Usage, error) {
	out := map[string]*Usage{}
	get := func(id string) *Usage {
		if out[id] == nil {
			out[id] = &Usage{}
		}
		return out[id]
	}
	rs, err := tx.BusinessRoles()
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if id := RulePolicy(r.Birthright); id != "" && r.Status == store.RoleActive {
			get(id).Roles = append(get(id).Roles, r.Name)
		}
	}
	bs, err := tx.AbacBindings()
	if err != nil {
		return nil, err
	}
	for _, b := range bs {
		get(b.PolicyID).CatalogItems = append(get(b.PolicyID).CatalogItems, b.TargetID)
	}
	for _, u := range out {
		sort.Strings(u.Roles)
		sort.Strings(u.CatalogItems)
	}
	return out, nil
}

// Retire retires a policy nothing references.
func Retire(tx *store.TenantTx, id, reason string, by Actor, now time.Time) (*store.AbacPolicy, error) {
	old, err := tx.AbacPolicy(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "policy_not_found", "policy not found")
	} else if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	switch {
	case old.Status != store.AbacActive:
		return nil, refuse(409, "policy_retired", "%s is already retired", old.Name)
	case reason == "" || len(reason) > MaxNote:
		return nil, refuse(422, "invalid_reason", "a reason of 1 to %d characters is required", MaxNote)
	}
	use, err := UsageOf(tx)
	if err != nil {
		return nil, err
	}
	if u := use[id]; u != nil && !u.Empty() {
		return nil, refuse(409, "policy_in_use", "%s is used by %d role rule(s) and %d catalog item(s); detach it first",
			old.Name, len(u.Roles), len(u.CatalogItems))
	}
	p := *old
	p.Status, p.Version, p.UpdatedBy, p.UpdatedAt = store.AbacRetired, old.Version+1, by.uid(), now
	if err := tx.SaveAbacPolicy(&p, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the policy changed; reload it")
	} else if err != nil {
		return nil, err
	}
	if err := version(tx, &p, reason, by, now); err != nil {
		return nil, err
	}
	return &p, tx.Audit(now, by.Display, "abac.policy.retire", append(detail(&p), ojson.KV{Key: "reason", Value: reason}))
}

// Bind attaches an active policy to a catalog item (policyID "": detach).
func Bind(tx *store.TenantTx, kind, targetID, policyID string, by Actor, now time.Time) error {
	if policyID == "" {
		if _, err := tx.AbacBinding(kind, targetID); errors.Is(err, store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if err := tx.DeleteAbacBinding(kind, targetID); err != nil {
			return err
		}
		return tx.Audit(now, by.Display, "abac.binding.remove", ojson.Object{{Key: "kind", Value: kind}, {Key: "target_id", Value: targetID}})
	}
	p, err := tx.AbacPolicy(policyID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "policy_not_found", "policy not found")
	} else if err != nil {
		return err
	}
	if p.Status != store.AbacActive {
		return refuse(409, "policy_retired", "%s is retired", p.Name)
	}
	if err := tx.PutAbacBinding(&store.AbacBinding{Kind: kind, TargetID: targetID, PolicyID: policyID, BoundBy: by.uid(), BoundAt: now}); err != nil {
		return err
	}
	return tx.Audit(now, by.Display, "abac.binding.put", ojson.Object{{Key: "kind", Value: kind}, {Key: "target_id", Value: targetID},
		{Key: "policy_id", Value: policyID}, {Key: "policy_version", Value: p.Version}})
}

// Active returns the conditions of the tenant's active policies, by id.
func Active(tx *store.TenantTx) (map[string]*Node, error) {
	ps, err := tx.AbacPolicies()
	if err != nil {
		return nil, err
	}
	out := map[string]*Node{}
	for _, p := range ps {
		if p.Status != store.AbacActive {
			continue
		}
		n, err := Condition(p)
		if err != nil {
			return nil, fmt.Errorf("abac: stored policy %s: %w", p.ID, err)
		}
		out[p.ID] = n
	}
	return out, nil
}
