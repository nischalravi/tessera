package branding

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/prefs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Settings are a tenant's language, renamed terms and email-logo switch (schema/0765_tenant_label_settings.sql).
type Settings struct {
	DefaultLanguage string            `json:"default_language"`
	EmailLogo       bool              `json:"email_logo"`
	Labels          map[string]string `json:"labels"`
}

// Languages are the languages a tenant can default to: the locales a person can choose (internal/prefs).
func Languages() []string { return prefs.Locales }

// LoadSettings returns the tenant's settings and their version (0 for the defaults).
func LoadSettings(tx *store.TenantTx) (Settings, int, error) {
	row, err := tx.LabelSettings()
	if errors.Is(err, store.ErrNotFound) {
		return Settings{Labels: map[string]string{}}, 0, nil
	} else if err != nil {
		return Settings{}, 0, err
	}
	s := Settings{DefaultLanguage: row.DefaultLanguage, EmailLogo: row.EmailLogo}
	if err := json.Unmarshal([]byte(row.Labels), &s.Labels); err != nil {
		return Settings{}, 0, err
	}
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	return s, row.Version, nil
}

func settingsDetail(s Settings) ojson.Object {
	labels := ojson.Object{}
	for _, t := range Terms {
		if v, ok := s.Labels[t.Key]; ok {
			labels = append(labels, ojson.KV{Key: t.Key, Value: v})
		}
	}
	return ojson.Object{{Key: "default_language", Value: s.DefaultLanguage}, {Key: "email_logo", Value: s.EmailLogo}, {Key: "labels", Value: labels}}
}

// SaveSettings validates and replaces the tenant's settings. ver is the version the caller read (0 for the defaults); a
// different current version is a conflict. It is audited in the same transaction, with the old values.
func SaveSettings(tx *store.TenantTx, s Settings, ver int, by string, now time.Time) (Settings, int, error) {
	if s.DefaultLanguage != "" && !slices.Contains(Languages(), s.DefaultLanguage) {
		return Settings{}, 0, cfgerr.Refuse(422, "invalid_language", "the language is empty or one of %v", Languages())
	}
	labels, err := Labels(s.Labels)
	if err != nil {
		return Settings{}, 0, err
	}
	s.Labels = labels
	old, cur, err := LoadSettings(tx)
	if err != nil {
		return Settings{}, 0, err
	}
	if ver != cur {
		return Settings{}, 0, cfgerr.Conflict(ver, cur)
	}
	raw, _ := json.Marshal(s.Labels)
	row := &store.LabelSettingsRow{DefaultLanguage: s.DefaultLanguage, EmailLogo: s.EmailLogo, Labels: string(raw), UpdatedBy: by}
	if err := tx.PutLabelSettings(row, now); err != nil {
		return Settings{}, 0, err
	}
	d := append(settingsDetail(s), ojson.KV{Key: "previous", Value: settingsDetail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	if err := tx.Audit(now, by, "branding.labels.update", d); err != nil {
		return Settings{}, 0, err
	}
	return s, cur + 1, nil
}
