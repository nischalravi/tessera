package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeProvWriteBackEnable switches write-back on for a provisioning target of any kind (issue #569). Write-back
// is what lets Tessera change accounts in a downstream system, so one admin must not turn it on alone: the
// requester proposes, a different admin approves what the payload hash says (self-approval is refused, as for
// every change). The payload names the target and the fingerprint of the configuration the requester reviewed
// (ProvTargetConfigHash), so a target edited after the request is refused rather than enabled in a form nobody
// approved. Turning write-back off stays one admin, immediate (PUT /api/provisioning/targets/{id}).
const TypeProvWriteBackEnable = "provisioning.write_back.enable"

type provWriteBackPayload struct {
	ConnectionID string `json:"connection_id"`
	ConfigHash   string `json:"config_hash"`
}

func init() {
	t := typed(TypeProvWriteBackEnable, nil, planProvWriteBack, applyProvWriteBack,
		func(e *env, v *provWriteBackPayload) string { return e.provSummary(v.ConnectionID) })
	// one open request per target: a second one while the first waits would only approve the same thing twice
	t.afterSubmit = func(e *env, ch *store.AdminChange, v any) error {
		open, err := e.tx.OpenAdminChanges()
		if err != nil {
			return err
		}
		for _, o := range open {
			if o.ID != ch.ID && o.Type == TypeProvWriteBackEnable && o.TargetID == ch.TargetID {
				return conflict("invalid_state", "a write-back request for this target is already waiting for approval")
			}
		}
		return nil
	}
	changeTypes[TypeProvWriteBackEnable] = t
}

// provSummary tells the approver what they are enabling: the connection, kind, origin, what happens to deprovisioned
// accounts and what the target may write.
func (e *env) provSummary(connectionID string) string {
	name := e.provTargetName(connectionID)
	t, err := e.tx.ProvTarget(connectionID)
	if err != nil {
		return "Enable write-back on provisioning target " + name
	}
	var st provision.Settings
	_ = json.Unmarshal([]byte(t.Settings), &st)
	scope := "the target's standard user and group operations"
	switch {
	case st.LDAP != nil:
		scope = "entries under " + strings.Join(st.LDAP.WriteScope, ", ")
	case st.SQL != nil:
		scope = fmt.Sprintf("database %s on %s (%s mode)", st.SQL.Database, st.SQL.Host, st.SQL.Mode)
	case len(st.REST) > 0:
		var spec struct {
			Writes map[string]json.RawMessage `json:"writes"`
		}
		if json.Unmarshal(st.REST, &spec) == nil {
			ops := make([]string, 0, len(spec.Writes))
			for k := range spec.Writes {
				ops = append(ops, k)
			}
			sort.Strings(ops)
			scope = "REST operations " + strings.Join(ops, ", ")
		}
	}
	onDep := "disable"
	if st.OnDeprovision == "delete" {
		onDep = "delete"
	}
	origin := t.BaseURL
	if u, err := url.Parse(t.BaseURL); err == nil && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	return fmt.Sprintf("Enable write-back on provisioning target %s (kind %s, origin %s, deprovisioned accounts: %s, may write: %s)",
		name, t.Kind, origin, onDep, scope)
}

// ProvTargetConfigHash fingerprints what a write-back approval covers: the target's kind, origin, settings
// (without the informational discovery record) and credential version. It holds no secret.
func ProvTargetConfigHash(t *store.ProvTarget) string {
	var st provision.Settings
	settings := t.Settings // settings that do not parse are hashed as stored, so any change still shows
	if json.Unmarshal([]byte(t.Settings), &st) == nil {
		st.Discovery = nil
		if b, err := json.Marshal(st); err == nil {
			settings = string(b)
		}
	}
	ver := ""
	if t.CredentialVer != nil {
		ver = *t.CredentialVer
	}
	h := sha256.Sum256([]byte(t.Kind + "\x00" + t.BaseURL + "\x00" + settings + "\x00" + ver))
	return hex.EncodeToString(h[:])
}

func (e *env) provTargetName(connectionID string) string {
	if c, err := e.tx.Connection(connectionID); err == nil {
		return c.Name
	}
	return "unknown connection"
}

func planProvWriteBack(e *env, v *provWriteBackPayload) (plan, error) {
	if _, err := uuid.Parse(v.ConnectionID); err != nil || len(v.ConnectionID) != 36 {
		return plan{}, invalid("connection_id must be the id of the connection")
	}
	if raw, err := hex.DecodeString(v.ConfigHash); err != nil || len(raw) != sha256.Size {
		return plan{}, invalid("config_hash is required: the 64 hex characters of the config_hash of the target you reviewed")
	}
	t, err := e.tx.ProvTarget(v.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return plan{}, notFound("provisioning target")
	} else if err != nil {
		return plan{}, err
	}
	switch {
	case t.WriteBack:
		return plan{}, conflict("invalid_state", "write-back is already on for this target")
	case ProvTargetConfigHash(t) != v.ConfigHash:
		return plan{}, conflict("stale_target", "the target was edited since this request was made; reload it and request again")
	}
	return plan{twoPerson: true, target: v.ConnectionID}, nil
}

func applyProvWriteBack(e *env, ch *store.AdminChange, v *provWriteBackPayload) error {
	if _, err := planProvWriteBack(e, v); err != nil {
		return err
	}
	if err := e.tx.SetProvTargetWriteBack(v.ConnectionID, true, e.now); err != nil {
		return err
	}
	t, err := e.tx.ProvTarget(v.ConnectionID)
	if err != nil {
		return err
	}
	detail := ojson.Object{{Key: "connection_id", Value: v.ConnectionID}, {Key: "kind", Value: t.Kind},
		{Key: "write_back", Value: true}, {Key: "change_id", Value: ch.ID.String()},
		{Key: "requested_by", Value: ch.RequestedBy.String()}}
	if ch.ApprovedBy != nil {
		detail = append(detail, ojson.KV{Key: "approved_by", Value: ch.ApprovedBy.String()})
	}
	_, err = audit.Record(e.tx.Context(), e.tx, "provision.write_back_enabled", detail, audit.At(e.now),
		audit.Target("admin_change", ch.ID.String()))
	return err
}
