package privs

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Default is a grant made to everyone on every new object of ObjectType (G-40:
// for example READ or VIEW for Grouper's EveryEntity).
type Default struct {
	ObjectType ObjectType `json:"object_type"`
	Privilege  Privilege  `json:"privilege"`
}

// Settings are the tenant's privilege settings (Admin > Groups settings).
type Settings struct {
	// EveryoneAllowed is the policy for the everyone holder: the only privileges
	// that may be granted to everyone. Enabling everyone on an object needs
	// tenant_admin whatever this says (the equivalent of restricting
	// EveryEntity in Grouper), and an admin-class privilege is never allowed.
	EveryoneAllowed []Privilege `json:"everyone_allowed"`
	// Defaults are granted to everyone on each new folder or group.
	Defaults []Default `json:"defaults"`
}

// neverEveryone are the privileges no policy can give to everyone.
var neverEveryone = []Privilege{Admin, StemAdmin, AttrAdmin}

// DefaultSettings is what a tenant has until it saves its own: the read-side
// privileges may be given to everyone, and nothing is granted by default.
func DefaultSettings() Settings {
	return Settings{
		EveryoneAllowed: []Privilege{View, Read, Optin, Optout, StemView, AttrView, AttrRead, AttrOptin, AttrOptout},
		Defaults:        []Default{},
	}
}

// Allowed reports whether the policy lets p be granted to everyone.
func (s Settings) Allowed(p Privilege) bool {
	return !slices.Contains(neverEveryone, p) && slices.Contains(s.EveryoneAllowed, p)
}

// normalize validates s and returns it in canonical form (privileges in table
// order, no duplicates, empty lists not null).
func (s Settings) normalize() (Settings, error) {
	out := Settings{EveryoneAllowed: []Privilege{}, Defaults: []Default{}}
	for _, p := range s.EveryoneAllowed {
		switch {
		case !Valid(p):
			return out, invalid("invalid_privilege", "everyone_allowed: %q is not a privilege", p)
		case slices.Contains(neverEveryone, p):
			return out, invalid("everyone_not_allowed", "%s can never be granted to everyone", p)
		}
	}
	for _, p := range All() {
		if slices.Contains(s.EveryoneAllowed, p) {
			out.EveryoneAllowed = append(out.EveryoneAllowed, p)
		}
	}
	seen := map[Default]bool{}
	for _, d := range s.Defaults {
		switch {
		case d.ObjectType != Folder && d.ObjectType != Group && d.ObjectType != AttrDef:
			return out, invalid("invalid_default", "defaults apply to new folders, groups and attribute definitions, not %q", d.ObjectType)
		case !Valid(d.Privilege) || ObjectOf(d.Privilege) != d.ObjectType:
			return out, invalid("invalid_default", "%q is not a %s privilege", d.Privilege, d.ObjectType)
		case !out.Allowed(d.Privilege):
			return out, invalid("everyone_not_allowed", "%s is not in everyone_allowed, so it cannot be a default", d.Privilege)
		}
		if !seen[d] {
			seen[d] = true
			out.Defaults = append(out.Defaults, d)
		}
	}
	slices.SortFunc(out.Defaults, func(a, b Default) int {
		return slices.Index(All(), a.Privilege) - slices.Index(All(), b.Privilege)
	})
	return out, nil
}

// LoadSettings returns the tenant's settings (the defaults before it saves any).
func LoadSettings(tx *store.TenantTx) (Settings, error) {
	row, err := tx.GrpPrivSettings()
	if errors.Is(err, store.ErrNotFound) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal([]byte(row.Body), &s); err != nil {
		return Settings{}, fmt.Errorf("privs: stored settings: %w", err)
	}
	return s.normalize()
}

// SaveSettings validates and stores the settings. Only a tenant_admin may.
func SaveSettings(e Env, s Settings) (Settings, error) {
	if !e.TenantAdmin {
		return Settings{}, forbidden("tenant_admin_required", "only a tenant admin changes the privilege settings")
	}
	s, err := s.normalize()
	if err != nil {
		return s, err
	}
	body, err := store.JSON(s)
	if err != nil {
		return s, err
	}
	if err := e.Tx.SetGrpPrivSettings(body, e.Now, e.By); err != nil {
		return s, err
	}
	return s, e.audit("groups.privilege.settings_changed", "groups_settings", "privileges", ojson.Object{
		{Key: "everyone_allowed", Value: privStrings(s.EveryoneAllowed)}, {Key: "defaults", Value: len(s.Defaults)}})
}

func privStrings(ps []Privilege) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

// Env is one operation's context: the tenant transaction, the clock reading and
// the actor. TenantAdmin says the actor holds an active tenant_admin role;
// ByIdentity is the identity behind the acting platform user, which creator
// privileges go to.
type Env struct {
	Tx          *store.TenantTx
	Now         time.Time
	By          *string
	ByIdentity  *int64
	TenantAdmin bool
	// Cause and CauseRef stamp the operation's events (api when empty).
	Cause, CauseRef string
}

func (e Env) audit(action, targetType, targetID string, detail ojson.Object) error {
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups",
		TargetType: targetType, TargetID: targetID, Detail: detail})
	return err
}
