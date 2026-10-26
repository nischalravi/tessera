package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

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
	changeTypes[TypeProvWriteBackEnable] = typed(TypeProvWriteBackEnable, nil, planProvWriteBack, applyProvWriteBack,
		func(e *env, v *provWriteBackPayload) string {
			return "Enable write-back on provisioning target " + e.provTargetName(v.ConnectionID)
		})
}

// ProvTargetConfigHash fingerprints what a write-back approval covers: the target's kind, origin, settings
// (without the informational discovery record) and credential version. It holds no secret.
func ProvTargetConfigHash(t *store.ProvTarget) string {
	var st provision.Settings
	_ = json.Unmarshal([]byte(t.Settings), &st)
	st.Discovery = nil
	b, _ := json.Marshal(st)
	ver := ""
	if t.CredentialVer != nil {
		ver = *t.CredentialVer
	}
	h := sha256.Sum256([]byte(t.Kind + "\x00" + t.BaseURL + "\x00" + string(b) + "\x00" + ver))
	return hex.EncodeToString(h[:])
}

func (e *env) provTargetName(connectionID string) string {
	if c, err := e.tx.Connection(connectionID); err == nil {
		return c.Name
	}
	return "unknown connection"
}

func planProvWriteBack(e *env, v *provWriteBackPayload) (plan, error) {
	if len(v.ConnectionID) != 36 {
		return plan{}, invalid("connection_id is required")
	}
	if len(v.ConfigHash) != 64 {
		return plan{}, invalid("config_hash is required: the config_hash of the target you reviewed")
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
