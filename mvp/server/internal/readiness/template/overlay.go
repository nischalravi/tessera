package template

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Overlay is a tenant's additions to a template (§3.5). Customers may add
// items, raise levels and tighten thresholds. They may never lower a level,
// remove or disable an item, or loosen a threshold.
//
// RemoveItems and DisableItems exist only so that a request asking for them
// is rejected explicitly (level_downgrade_forbidden) rather than ignored.
type Overlay struct {
	Version      int                `json:"version,omitempty"`
	AddItems     []Item             `json:"add_items,omitempty"`
	RaiseLevels  map[string]Level   `json:"raise_levels,omitempty"`
	Thresholds   map[string]float64 `json:"thresholds,omitempty"`
	RemoveItems  []string           `json:"remove_items,omitempty"`
	DisableItems []string           `json:"disable_items,omitempty"`
}

// Overlay error codes returned to the API as 422 bodies.
const (
	CodeDowngrade      = "level_downgrade_forbidden"
	CodeInvalidOverlay = "invalid_overlay"
)

// OverlayError is a rejected overlay.
type OverlayError struct {
	Code string
	Msg  string
}

func (e *OverlayError) Error() string { return e.Code + ": " + e.Msg }

func downgrade(format string, args ...any) error {
	return &OverlayError{CodeDowngrade, fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) error {
	return &OverlayError{CodeInvalidOverlay, fmt.Sprintf(format, args...)}
}

// CustomPrefix starts the id of every overlay item.
const CustomPrefix = "custom."

// Apply returns a copy of r with the overlay merged in, or an *OverlayError.
// The input is never modified.
func Apply(r *Resolved, o *Overlay) (*Resolved, error) {
	if o == nil {
		return r.Clone(), nil
	}
	if len(o.RemoveItems) > 0 {
		return nil, downgrade("template items cannot be removed: %s", strings.Join(o.RemoveItems, ", "))
	}
	if len(o.DisableItems) > 0 {
		return nil, downgrade("template items cannot be disabled: %s", strings.Join(o.DisableItems, ", "))
	}
	out := r.Clone()
	out.OverlayVersion = o.Version
	for _, id := range slices.Sorted(maps.Keys(o.RaiseLevels)) {
		lvl := o.RaiseLevels[id]
		it, ok := out.Item(id)
		if !ok {
			return nil, invalid("raise_levels: no item %q in template %s", id, r.ID)
		}
		if !lvl.Valid() {
			return nil, invalid("raise_levels: %q is not a level", lvl)
		}
		if lvl.Rank() < it.Level.Rank() {
			return nil, downgrade("%s is %s in the template and cannot be lowered to %s", id, it.Level, lvl)
		}
		it.Level = lvl
	}
	for _, k := range slices.Sorted(maps.Keys(o.Thresholds)) {
		v := o.Thresholds[k]
		dir, ok := Thresholds[k]
		if !ok {
			return nil, invalid("unknown threshold %q", k)
		}
		if cur, ok := out.Thresholds[k]; ok && float64(dir)*(v-cur) < 0 {
			return nil, downgrade("threshold %s is %v in the template; %v would loosen it", k, cur, v)
		}
		out.Thresholds[k] = v
	}
	all := map[string]*Item{}
	for i := range out.Items {
		all[out.Items[i].ID] = &out.Items[i]
	}
	for _, add := range o.AddItems {
		it := cloneItem(add)
		if _, exists := all[it.ID]; exists {
			return nil, downgrade("add_items: %q already exists; template items cannot be redefined", it.ID)
		}
		if !strings.HasPrefix(it.ID, CustomPrefix) || len(it.ID) == len(CustomPrefix) {
			return nil, invalid("add_items: id %q must start with %q", it.ID, CustomPrefix)
		}
		if err := checkCustomItem(r.ID, &it, all); err != nil {
			return nil, err
		}
		it.TemplateLevel = it.Level
		it.Source = "overlay"
		out.Items = append(out.Items, it)
		all[it.ID] = &out.Items[len(out.Items)-1]
	}
	return out, nil
}

// checkCustomItem lints a tenant item. Custom items may be attested or use a
// registered data check; live checks need code review, so they are template-only.
func checkCustomItem(tid string, it *Item, all map[string]*Item) error {
	var probs []string
	add := func(_, _ string, format string, args ...any) { probs = append(probs, fmt.Sprintf(format, args...)) }
	lintItem(tid, it, all, add)
	for _, v := range it.Verify {
		if v.Kind == Live {
			probs = append(probs, "custom items may use attestation or a registered data check, not a live check")
		}
	}
	if len(probs) > 0 {
		return invalid("add_items: %s: %s", it.ID, strings.Join(probs, "; "))
	}
	return nil
}
