package requests

import (
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Tenant-wide request settings (issue #298, "Request settings"). They are
// enforced by Submit, so a client cannot bypass them; the UI only reads them
// to guide people.

// For-others policies and history visibilities.
const (
	ForOthersNobody     = "nobody"     // everyone requests for themselves only
	ForOthersManagers   = "managers"   // only the beneficiary's manager requests for them
	ForOthersPermission = "permission" // anyone holding requests.create_for_others

	HistoryReaders  = "readers"  // also anyone who can read the graph sees others' requests
	HistoryInvolved = "involved" // only the people on a request, its approvers and deciders
)

// Attachment limits. An attachment is a reference (a ticket or document link or
// id), not an uploaded file; Tessera stores no files.
const (
	MaxAttachments   = 5
	MaxAttachmentRef = 300
)

// Settings are the tenant's request settings.
type Settings struct {
	JustificationRequired bool     `json:"justification_required"`
	JustificationMin      int      `json:"justification_min_length"`
	DefaultHours          *float64 `json:"default_hours"` // nil: the item's default, else "until removed"
	MaxHours              *float64 `json:"max_hours"`     // nil: only the item's and MaxHours limits apply
	AttachmentsAllowed    bool     `json:"attachments_allowed"`
	HistoryVisibility     string   `json:"history_visibility"`
	ForOthers             string   `json:"for_others"`
}

// DefaultSettings is what a tenant that never saved settings gets: the
// behaviour before the settings existed.
func DefaultSettings() Settings {
	return Settings{JustificationRequired: true, JustificationMin: 1, HistoryVisibility: HistoryReaders, ForOthers: ForOthersPermission}
}

// Check validates settings from the API.
func (s Settings) Check() error {
	switch {
	case s.JustificationMin < 1 || s.JustificationMin > MaxJustification:
		return refuse(422, "invalid_justification_min", "the minimum justification length is between 1 and %d characters", MaxJustification)
	case s.DefaultHours != nil && !(*s.DefaultHours > 0 && *s.DefaultHours <= MaxHours):
		return refuse(422, "invalid_default_hours", "the default duration is between 0 and %d hours", MaxHours)
	case s.MaxHours != nil && !(*s.MaxHours > 0 && *s.MaxHours <= MaxHours):
		return refuse(422, "invalid_max_hours", "the maximum duration is between 0 and %d hours", MaxHours)
	case s.DefaultHours != nil && s.MaxHours != nil && *s.DefaultHours > *s.MaxHours:
		return refuse(422, "default_above_max", "the default duration cannot exceed the maximum")
	case s.HistoryVisibility != HistoryReaders && s.HistoryVisibility != HistoryInvolved:
		return refuse(422, "invalid_history_visibility", "history visibility is %s or %s", HistoryReaders, HistoryInvolved)
	case s.ForOthers != ForOthersNobody && s.ForOthers != ForOthersManagers && s.ForOthers != ForOthersPermission:
		return refuse(422, "invalid_for_others", "request for others is %s, %s or %s", ForOthersNobody, ForOthersManagers, ForOthersPermission)
	}
	return nil
}

// LoadSettings returns the tenant's settings, and the version they were saved
// at (0 for the defaults).
func LoadSettings(tx *store.TenantTx) (Settings, int, error) {
	row, err := tx.RequestSettings()
	if store.ErrNoRequestSettings(err) {
		return DefaultSettings(), 0, nil
	} else if err != nil {
		return Settings{}, 0, err
	}
	return Settings{JustificationRequired: row.JustificationRequired, JustificationMin: row.JustificationMin, DefaultHours: row.DefaultHours,
		MaxHours: row.MaxHours, AttachmentsAllowed: row.AttachmentsAllowed, HistoryVisibility: row.HistoryVisibility,
		ForOthers: row.ForOthers}, row.Version, nil
}

func settingsDetail(s Settings) ojson.Object {
	d := ojson.Object{{Key: "justification_required", Value: s.JustificationRequired}, {Key: "justification_min_length", Value: s.JustificationMin},
		{Key: "attachments_allowed", Value: s.AttachmentsAllowed}, {Key: "history_visibility", Value: s.HistoryVisibility},
		{Key: "for_others", Value: s.ForOthers}}
	if s.DefaultHours != nil {
		d = append(d, ojson.KV{Key: "default_hours", Value: strconv.FormatFloat(*s.DefaultHours, 'g', -1, 64)})
	}
	if s.MaxHours != nil {
		d = append(d, ojson.KV{Key: "max_hours", Value: strconv.FormatFloat(*s.MaxHours, 'g', -1, 64)})
	}
	return d
}

// SaveSettings replaces the tenant's settings. ver is the version the caller
// read (0 if it read the defaults); a different current version is a conflict.
// The change is audited in the same transaction, with the old values.
func SaveSettings(tx *store.TenantTx, s Settings, ver int, by Actor, now time.Time) (Settings, int, error) {
	if err := s.Check(); err != nil {
		return Settings{}, 0, err
	}
	old, cur, err := LoadSettings(tx)
	if err != nil {
		return Settings{}, 0, err
	}
	if ver != cur {
		return Settings{}, 0, refuse(409, "version_conflict", "the settings changed since version %d (now %d); reload them", ver, cur)
	}
	row := &store.RequestSettingsRow{JustificationRequired: s.JustificationRequired, JustificationMin: s.JustificationMin,
		DefaultHours: s.DefaultHours, MaxHours: s.MaxHours, AttachmentsAllowed: s.AttachmentsAllowed,
		HistoryVisibility: s.HistoryVisibility, ForOthers: s.ForOthers, UpdatedBy: by.Display}
	if err := tx.PutRequestSettings(row, now); err != nil {
		return Settings{}, 0, err
	}
	detail := append(settingsDetail(s), ojson.KV{Key: "previous", Value: settingsDetail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	if err := tx.Audit(now, by.Display, "request.settings.update", detail); err != nil {
		return Settings{}, 0, err
	}
	return s, cur + 1, nil
}

// checkJustification applies the justification settings.
func (s Settings) checkJustification(just string) error {
	switch {
	case len(just) > MaxJustification:
		return refuse(422, "justification_required", "a justification of at most %d characters is allowed", MaxJustification)
	case s.JustificationRequired && len(just) < s.JustificationMin:
		return refuse(422, "justification_required", "a justification of %d to %d characters is required", s.JustificationMin, MaxJustification)
	}
	return nil
}

// checkAttachments applies the attachment settings.
func (s Settings) checkAttachments(refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if !s.AttachmentsAllowed {
		return nil, refuse(422, "attachments_not_allowed", "attachments are turned off for requests")
	}
	if len(refs) > MaxAttachments {
		return nil, refuse(422, "too_many_attachments", "at most %d attachments", MaxAttachments)
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		r = strings.TrimSpace(r)
		if r == "" || len(r) > MaxAttachmentRef {
			return nil, refuse(422, "invalid_attachment", "an attachment is a reference of 1 to %d characters", MaxAttachmentRef)
		}
		out = append(out, r)
	}
	return out, nil
}

// checkDuration applies the duration settings to the hours an item resolved to
// (nil: until removed).
func (s Settings) checkDuration(hours *float64, name string) error {
	if s.MaxHours == nil {
		return nil
	}
	switch {
	case hours == nil:
		return refuse(422, "duration_required", "%s needs a duration of at most %g hours", name, *s.MaxHours)
	case *hours > *s.MaxHours:
		return refuse(422, "duration_too_long", "requests last at most %g hours", *s.MaxHours)
	}
	return nil
}

// checkForOthers applies the request-for-others policy to one beneficiary.
// hasPerm is whether the actor holds requests.create_for_others.
func (s Settings) checkForOthers(ben *store.Identity, by Actor, hasPerm bool) error {
	if by.IdentityID != nil && *by.IdentityID == ben.ID {
		return nil // for yourself is always allowed
	}
	switch s.ForOthers {
	case ForOthersNobody:
		return refuse(403, "for_others_not_allowed", "requests for other people are turned off; you can request access only for yourself")
	case ForOthersManagers:
		if by.IdentityID == nil || ben.ManagerID == nil || *ben.ManagerID != *by.IdentityID {
			return refuse(403, "for_others_not_allowed", "you can request access only for yourself or the people who report to you")
		}
		return nil
	}
	if !hasPerm {
		return refuse(403, "for_others_not_allowed", "you can request access only for yourself")
	}
	return nil
}
