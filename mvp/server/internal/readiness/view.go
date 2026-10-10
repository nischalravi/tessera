package readiness

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// API views. Secrets never appear: a credential is shown as present, its
// kind (sealed, vault, agent) and its version only.

// TemplateRef names a revision's pinned template.
type TemplateRef struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	Pin            string `json:"pin"`
	DisplayName    string `json:"display_name"`
	OverlayVersion int    `json:"overlay_version"`
}

// CredentialView describes a credential without revealing it.
type CredentialView struct {
	Present bool    `json:"present"`
	Kind    *string `json:"kind"`
	Version *string `json:"version"`
}

// RevisionView is one revision.
type RevisionView struct {
	ID          string          `json:"id"`
	Rev         int             `json:"rev"`
	State       string          `json:"state"`
	Template    TemplateRef     `json:"template"`
	Config      ConnConfig      `json:"config"`
	Credential  CredentialView  `json:"credential"`
	ConfigHash  string          `json:"config_hash"`
	WriteMode   string          `json:"write_mode"`
	GateReport  json.RawMessage `json:"gate_report"`
	ActivatedAt *string         `json:"activated_at"`
	ActivatedBy *string         `json:"activated_by"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

// NextStep is the next forward transition and what blocks it.
type NextStep struct {
	To       string    `json:"to"`
	Action   string    `json:"action"`
	Blocking []Blocker `json:"blocking"`
}

// ConnectionView is a connection with its revisions and checklist progress.
type ConnectionView struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ConnectorType    string               `json:"connector_type"`
	System           string               `json:"system"`
	Role             string               `json:"role"`
	Template         TemplateRef          `json:"template"`
	Simulated        bool                 `json:"simulated"`
	Legacy           bool                 `json:"legacy"`
	State            string               `json:"state"`
	Health           string               `json:"health"`
	UpdateInProgress bool                 `json:"update_in_progress"`
	TechnicalOwner   *string              `json:"technical_owner"`
	BusinessOwner    *string              `json:"business_owner"`
	ActiveRevision   *RevisionView        `json:"active_revision"`
	PendingRevision  *RevisionView        `json:"pending_revision"`
	Progress         map[string]*Progress `json:"progress"`
	Next             *NextStep            `json:"next"`
	Blocking         int                  `json:"blocking"`
	Score            *ScoreSummary        `json:"score"`
	LatestValidation *string              `json:"latest_validation_id"`
	LatestDryRun     *string              `json:"latest_dry_run_id"`
	CreatedAt        string               `json:"created_at"`
	UpdatedAt        string               `json:"updated_at"`
	RetiredAt        *string              `json:"retired_at"`
}

// ScoreSummary is the connection readiness score shown in lists.
type ScoreSummary struct {
	Score int    `json:"score"`
	Band  string `json:"band"`
}

func templateRef(b *Bundle) TemplateRef {
	return TemplateRef{ID: b.Template.ID, Version: b.Template.Version, Pin: b.Rev.TemplateID + "@" + b.Rev.TemplateVersion,
		DisplayName: b.Template.DisplayName, OverlayVersion: b.Rev.OverlayVersion}
}

// RevisionOf renders a revision.
func RevisionOf(b *Bundle) *RevisionView {
	r := b.Rev
	v := &RevisionView{ID: r.ID, Rev: r.Rev, State: r.State, Template: templateRef(b), Config: b.Config,
		ConfigHash: r.ConfigHash, WriteMode: r.WriteMode, ActivatedBy: r.ActivatedBy, CreatedBy: r.CreatedBy,
		CreatedAt: store.RT(r.CreatedAt), UpdatedAt: store.RT(r.UpdatedAt), GateReport: json.RawMessage("null")}
	if r.SecretRef != nil {
		kind, _, _ := strings.Cut(*r.SecretRef, ":")
		v.Credential = CredentialView{Present: true, Kind: &kind, Version: r.SecretVersion}
	}
	if r.GateReport != nil {
		v.GateReport = json.RawMessage(*r.GateReport)
	}
	if r.ActivatedAt != nil {
		at := store.RT(*r.ActivatedAt)
		v.ActivatedAt = &at
	}
	return v
}

// nextStep returns the next forward transition of an in-progress revision.
func nextStep(state string) (to, action string) {
	switch state {
	case store.StateDraft:
		return store.StateReadyToValidate, "transition"
	case store.StateReadyToValidate:
		return store.StateValidated, "validate"
	case store.StateValidated:
		return store.StateDryRunReconciled, "dry_run"
	case store.StateDryRunReconciled:
		return store.StateActive, "activate"
	}
	return "", ""
}

// View renders a connection. current is the revision the checklist shows
// (in-progress if any, else live); live is the live revision, if different.
func (s *Service) View(c *store.TenantTx, connID string, now time.Time) (*ConnectionView, *Bundle, error) {
	conn, live, pending, err := Revisions(c, connID)
	if err != nil {
		return nil, nil, err
	}
	cur, err := s.Current(c, connID, now)
	if err != nil {
		return nil, nil, err
	}
	v := &ConnectionView{ID: conn.ID, Name: conn.Name, ConnectorType: conn.ConnectorType, System: conn.System,
		Role: conn.Role, Template: templateRef(cur), Simulated: IsDemoType(conn.ConnectorType), Health: conn.Health,
		TechnicalOwner: conn.TechnicalOwner, BusinessOwner: conn.BusinessOwner, Progress: cur.Eval.Progress(),
		CreatedAt: store.RT(conn.CreatedAt), UpdatedAt: store.RT(conn.UpdatedAt)}
	if conn.RetiredAt != nil {
		at := store.RT(*conn.RetiredAt)
		v.RetiredAt = &at
	}
	switch {
	case conn.RetiredAt != nil:
		v.State = store.StateRetired
	case live != nil:
		v.State = live.State
		v.UpdateInProgress = pending != nil
	case pending != nil:
		v.State = pending.State
	default:
		v.State = cur.Rev.State
	}
	if live != nil {
		lb := cur
		if live.ID != cur.Rev.ID {
			if lb, err = s.Load(c, live, now); err != nil {
				return nil, nil, err
			}
		}
		v.ActiveRevision = RevisionOf(lb)
	}
	if cur.Evidence.LiveRun != nil {
		v.LatestValidation = &cur.Evidence.LiveRun.ID
	}
	if cur.Evidence.DataRun != nil {
		v.LatestDryRun = &cur.Evidence.DataRun.ID
	}
	if pending != nil {
		v.PendingRevision = RevisionOf(cur)
		to, action := nextStep(pending.State)
		g := cur.Gate(to, now)
		v.Next = &NextStep{To: to, Action: action, Blocking: g.Blocking}
		v.Blocking = len(g.Blocking)
	}
	return v, cur, nil
}

// ItemView is a checklist row.
type ItemView struct {
	*ItemEval
	Attestation *AttestationView `json:"attestation"`
	Skip        *SkipView        `json:"skip"`
}

// AttestationView is who attested an item.
type AttestationView struct {
	Actor string `json:"actor"`
	Note  string `json:"note"`
	At    string `json:"at"`
	Stale bool   `json:"stale"`
}

// SkipView is a skip and its review date.
type SkipView struct {
	Actor    string `json:"actor"`
	Reason   string `json:"reason"`
	ReviewBy string `json:"review_by"`
	At       string `json:"at"`
	Expired  bool   `json:"expired"`
}

// ChecklistView is GET /api/connections/{id}/checklist.
type ChecklistView struct {
	ConnectionID string               `json:"connection_id"`
	RevisionID   string               `json:"revision_id"`
	Rev          int                  `json:"rev"`
	State        string               `json:"state"`
	Template     TemplateRef          `json:"template"`
	Simulated    bool                 `json:"simulated"`
	ConfigHash   string               `json:"config_hash"`
	Progress     map[string]*Progress `json:"progress"`
	Next         *NextStep            `json:"next"`
	Categories   []string             `json:"categories"`
	Items        []ItemView           `json:"items"`
}

// Checklist renders a bundle's checklist.
func Checklist(b *Bundle, now time.Time) *ChecklistView {
	v := &ChecklistView{ConnectionID: b.Conn.ID, RevisionID: b.Rev.ID, Rev: b.Rev.Rev, State: b.Rev.State,
		Template: templateRef(b), Simulated: b.Simulated(), ConfigHash: b.ConfigHash, Progress: b.Eval.Progress(),
		Categories: template.Categories, Items: make([]ItemView, 0, len(b.Eval.Items))}
	if to, action := nextStep(b.Rev.State); to != "" {
		v.Next = &NextStep{To: to, Action: action, Blocking: b.Gate(to, now).Blocking}
	}
	for _, it := range b.Eval.Items {
		iv := ItemView{ItemEval: it}
		if a := it.Attestation; a != nil {
			iv.Attestation = &AttestationView{Actor: a.ActorID, Note: a.Note, At: store.RT(a.AttestedAt), Stale: a.ItemHash != it.ItemHash}
		}
		if k := it.Skip; k != nil {
			iv.Skip = &SkipView{Actor: k.ActorID, Reason: k.Reason, ReviewBy: store.RT(k.ReviewBy), At: store.RT(k.SkippedAt),
				Expired: !k.ReviewBy.After(now)}
		}
		if iv.Parts == nil {
			iv.Parts = []Part{}
		}
		v.Items = append(v.Items, iv)
	}
	return v
}
