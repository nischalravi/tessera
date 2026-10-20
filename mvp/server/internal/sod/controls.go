package sod

import (
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Control types and frequencies of the mitigating control library.
var (
	ControlTypes       = []string{"preventive", "detective", "corrective"}
	ControlFrequencies = []string{"continuous", "daily", "weekly", "monthly", "quarterly", "annually"}
)

// MaxEvidenceRequirement bounds a control's evidence requirement text.
const MaxEvidenceRequirement = 2000

// ControlInput is a control's editable content.
type ControlInput struct {
	Name                string
	Description         string
	OwnerID             *int64
	Type                string
	Frequency           string
	EvidenceRequirement string
}

func (w *Writer) checkControl(in *ControlInput, selfID string) error {
	in.Name, in.Description, in.EvidenceRequirement = clean(in.Name), clean(in.Description), clean(in.EvidenceRequirement)
	if err := checkText(in.Name, in.Description, ""); err != nil {
		return err
	}
	switch {
	case !contains(ControlTypes, in.Type):
		return refuse(422, "invalid_type", "type is one of %s", strings.Join(ControlTypes, ", "))
	case !contains(ControlFrequencies, in.Frequency):
		return refuse(422, "invalid_frequency", "frequency is one of %s", strings.Join(ControlFrequencies, ", "))
	case len(in.EvidenceRequirement) > MaxEvidenceRequirement:
		return refuse(422, "invalid_evidence_requirement", "the evidence requirement is at most %d characters", MaxEvidenceRequirement)
	case in.OwnerID == nil:
		return refuse(422, "owner_required", "a control needs an owner")
	}
	if err := w.owner(in.OwnerID); err != nil {
		return err
	}
	if other, err := w.Tx.SodControlByName(in.Name); err == nil && other.ID != selfID {
		return refuse(409, "name_taken", "a control named %q exists", in.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func controlDetail(c *store.SodControl) ojson.Object {
	return ojson.Object{{Key: "control_id", Value: c.ID}, {Key: "name", Value: c.Name}, {Key: "type", Value: c.Type},
		{Key: "frequency", Value: c.Frequency}, {Key: "version", Value: c.Version}}
}

// CreateControl adds a control to the library.
func (w *Writer) CreateControl(in ControlInput) (*store.SodControl, error) {
	if err := w.checkControl(&in, ""); err != nil {
		return nil, err
	}
	c := &store.SodControl{ID: uuid.NewString(), Name: in.Name, Description: in.Description, OwnerID: in.OwnerID, Type: in.Type,
		Frequency: in.Frequency, EvidenceRequirement: in.EvidenceRequirement, Status: store.SodActive, Version: 1,
		CreatedAt: w.Now, UpdatedBy: w.By.uid(), UpdatedAt: w.Now}
	if err := w.Tx.InsertSodControl(c); err != nil {
		return nil, err
	}
	return c, w.audit("sod.control.create", controlDetail(c))
}

// UpdateControl saves new content as the next version; ver must be current.
func (w *Writer) UpdateControl(id string, ver int, in ControlInput) (*store.SodControl, error) {
	old, err := w.Tx.SodControl(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "control_not_found", "control not found")
	} else if err != nil {
		return nil, err
	}
	if old.Status != store.SodActive {
		return nil, refuse(409, "control_retired", "%s is retired", old.Name)
	}
	if ver != old.Version {
		return nil, refuse(409, "version_conflict", "the control changed since version %d (now %d); reload it", ver, old.Version)
	}
	if err := w.checkControl(&in, id); err != nil {
		return nil, err
	}
	c := *old
	c.Name, c.Description, c.OwnerID, c.Type, c.Frequency, c.EvidenceRequirement = in.Name, in.Description, in.OwnerID, in.Type, in.Frequency, in.EvidenceRequirement
	c.Version, c.UpdatedBy, c.UpdatedAt = old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodControl(&c, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the control changed; reload it")
	} else if err != nil {
		return nil, err
	}
	return &c, w.audit("sod.control.update", controlDetail(&c))
}

// RetireControl retires a control no pending or active mitigation uses.
func (w *Writer) RetireControl(id, reason string) (*store.SodControl, error) {
	old, err := w.Tx.SodControl(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "control_not_found", "control not found")
	} else if err != nil {
		return nil, err
	}
	reason = clean(reason)
	switch {
	case old.Status != store.SodActive:
		return nil, refuse(409, "control_retired", "%s is already retired", old.Name)
	case reason == "" || len(reason) > MaxNote:
		return nil, refuse(422, "invalid_reason", "a reason of 1 to %d characters is required", MaxNote)
	}
	ms, err := w.Tx.SodMitigations()
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if m.ControlID != nil && *m.ControlID == id && (m.Status == store.MitigationPending || m.Status == store.MitigationActive) {
			return nil, refuse(409, "control_in_use", "%s covers a pending or active mitigation; wait for it to end or revoke it", old.Name)
		}
	}
	c := *old
	c.Status, c.Version, c.UpdatedBy, c.UpdatedAt = store.SodRetired, old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodControl(&c, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the control changed; reload it")
	} else if err != nil {
		return nil, err
	}
	return &c, w.audit("sod.control.retire", append(controlDetail(&c), ojson.KV{Key: "reason", Value: reason}))
}
