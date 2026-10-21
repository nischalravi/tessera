package sod

import (
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SoD page configuration (issue #298): which columns and filters SoD reviewers
// see on the conflicts page. It is tenant-wide; the conflicts page reads it and
// shows exactly those. The page's own essentials (the person, the priority, the
// status and the system) are always shown; these are the optional ones.

// View keys, in the order the page lays them out.
const (
	ViewRisk              = "risk"
	ViewFunction          = "function"
	ViewEntitlement       = "entitlement"
	ViewRuleset           = "ruleset"
	ViewMitigatingControl = "mitigating_control"
	ViewBusinessProcess   = "business_process"
)

// ViewKeys are the columns and filters a tenant can show or hide.
var ViewKeys = []string{ViewRisk, ViewFunction, ViewEntitlement, ViewRuleset, ViewMitigatingControl, ViewBusinessProcess}

// ViewSettings is the page configuration.
type ViewSettings struct {
	Columns []string `json:"columns"`
	Filters []string `json:"filters"`
}

// DefaultView shows everything, as before the page was configurable.
func DefaultView() ViewSettings {
	return ViewSettings{Columns: slices.Clone(ViewKeys), Filters: slices.Clone(ViewKeys)}
}

// canonical checks the keys, drops repeats and puts them in page order.
func canonical(keys []string, what string) ([]string, error) {
	for _, k := range keys {
		if !slices.Contains(ViewKeys, k) {
			return nil, cfgerr.Refuse(422, "invalid_"+what, "%q is not one of %v", k, ViewKeys)
		}
	}
	out := []string{}
	for _, k := range ViewKeys {
		if slices.Contains(keys, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// Check validates settings from the API and returns them in canonical form.
// A page needs at least one optional column to be worth configuring: the API
// refuses an empty column list so a reviewer is never left with a bare page.
func (v ViewSettings) Check() (ViewSettings, error) {
	cols, err := canonical(v.Columns, "column")
	if err != nil {
		return ViewSettings{}, err
	}
	filters, err := canonical(v.Filters, "filter")
	if err != nil {
		return ViewSettings{}, err
	}
	if len(cols) == 0 {
		return ViewSettings{}, cfgerr.Refuse(422, "columns_required", "show at least one column")
	}
	return ViewSettings{Columns: cols, Filters: filters}, nil
}

// LoadView returns the tenant's configuration and the version it was saved at
// (0 for the default of showing everything).
func LoadView(tx *store.TenantTx) (ViewSettings, int, error) {
	row, err := tx.SodViewSettings()
	if store.ErrNoSettings(err) {
		return DefaultView(), 0, nil
	} else if err != nil {
		return ViewSettings{}, 0, err
	}
	return ViewSettings{Columns: nonNil(row.Columns), Filters: nonNil(row.Filters)}, row.Version, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func viewDetail(v ViewSettings) ojson.Object {
	return ojson.Object{{Key: "columns", Value: v.Columns}, {Key: "filters", Value: v.Filters}}
}

// SaveView replaces the tenant's configuration. ver is the version the caller
// read (0 if it read the default); a different current version is a conflict.
// The change is audited in the same transaction, with the old values.
func SaveView(tx *store.TenantTx, v ViewSettings, ver int, by string, now time.Time) (ViewSettings, int, error) {
	v, err := v.Check()
	if err != nil {
		return ViewSettings{}, 0, err
	}
	old, cur, err := LoadView(tx)
	if err != nil {
		return ViewSettings{}, 0, err
	}
	if ver != cur {
		return ViewSettings{}, 0, cfgerr.Conflict(ver, cur)
	}
	if err := tx.PutSodViewSettings(&store.SodViewSettingsRow{Columns: v.Columns, Filters: v.Filters, UpdatedBy: by}, now); err != nil {
		return ViewSettings{}, 0, err
	}
	d := append(viewDetail(v), ojson.KV{Key: "previous", Value: viewDetail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	if err := tx.Audit(now, by, "sod.view.update", d); err != nil {
		return ViewSettings{}, 0, err
	}
	return v, cur + 1, nil
}
