package catalog

import (
	"fmt"
	"sort"
	"strings"
)

// LevelChange is an action whose access level changed.
type LevelChange struct {
	Action string      `json:"action"`
	From   AccessLevel `json:"from"`
	To     AccessLevel `json:"to"`
}

// DiffReport is the human-readable difference between two catalog versions,
// for the nightly refresh PR (design §10.3). All lists are sorted.
type DiffReport struct {
	From            string        `json:"from"` // "" when there is no earlier catalog
	To              string        `json:"to"`
	Snapshot        string        `json:"snapshot"`
	ServicesAdded   []string      `json:"services_added"`
	ServicesRemoved []string      `json:"services_removed"`
	ActionsAdded    []string      `json:"actions_added"`
	ActionsRemoved  []string      `json:"actions_removed"`
	LevelChanges    []LevelChange `json:"level_changes"`
	KeysAdded       []string      `json:"keys_added"`
	KeysRemoved     []string      `json:"keys_removed"`
	RCPAdded        []string      `json:"rcp_added"`   // overlay change between the two versions
	RCPRemoved      []string      `json:"rcp_removed"` // overlay change between the two versions
	RCPDrift        RCPDrift      `json:"rcp_drift"`   // live page versus the new overlay
	Warnings        []string      `json:"warnings"`
}

// Diff compares an earlier compiled catalog (nil for none) with a new
// compilation result. Without an earlier catalog everything is "added".
func Diff(old *Compiled, res *Result) *DiffReport {
	nw := res.Compiled
	r := &DiffReport{
		To: nw.Version, Snapshot: nw.Snapshot, RCPDrift: res.RCPDrift, Warnings: res.Warnings,
		ServicesAdded: []string{}, ServicesRemoved: []string{}, ActionsAdded: []string{}, ActionsRemoved: []string{},
		LevelChanges: []LevelChange{}, KeysAdded: []string{}, KeysRemoved: []string{}, RCPAdded: []string{}, RCPRemoved: []string{},
	}
	if r.RCPDrift.PageOnly == nil {
		r.RCPDrift = RCPDrift{PageOnly: []string{}, OverlayOnly: []string{}}
	}
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	oldSvc := map[string]bool{}
	oldAct := map[string]AccessLevel{}
	oldKeys := map[string]bool{}
	var oldRCP []string
	if old != nil {
		r.From = old.Version
		for _, s := range old.Services {
			oldSvc[s.Prefix] = true
			for _, a := range s.Actions {
				oldAct[a.Name] = a.Level
			}
		}
		for _, k := range old.Keys {
			oldKeys[normKey(k.Name)] = true
		}
		oldRCP = old.Overlays.RCP.Services
	}
	newSvc := map[string]bool{}
	newAct := map[string]bool{}
	for _, s := range nw.Services {
		newSvc[s.Prefix] = true
		if !oldSvc[s.Prefix] {
			r.ServicesAdded = append(r.ServicesAdded, s.Prefix)
		}
		for _, a := range s.Actions {
			newAct[a.Name] = true
			lvl, had := oldAct[a.Name]
			switch {
			case !had:
				r.ActionsAdded = append(r.ActionsAdded, a.Name)
			case lvl != a.Level:
				r.LevelChanges = append(r.LevelChanges, LevelChange{Action: a.Name, From: lvl, To: a.Level})
			}
		}
	}
	for s := range oldSvc {
		if !newSvc[s] {
			r.ServicesRemoved = append(r.ServicesRemoved, s)
		}
	}
	for a := range oldAct {
		if !newAct[a] {
			r.ActionsRemoved = append(r.ActionsRemoved, a)
		}
	}
	newKeys := map[string]bool{}
	for _, k := range nw.Keys {
		n := normKey(k.Name)
		newKeys[n] = true
		if !oldKeys[n] {
			r.KeysAdded = append(r.KeysAdded, k.Name)
		}
	}
	for _, k := range old.keyNames() {
		if !newKeys[normKey(k)] {
			r.KeysRemoved = append(r.KeysRemoved, k)
		}
	}
	d := compareRCP(nw.Overlays.RCP.Services, oldRCP)
	r.RCPAdded, r.RCPRemoved = d.PageOnly, d.OverlayOnly
	for _, l := range [][]string{r.ServicesAdded, r.ServicesRemoved, r.ActionsAdded, r.ActionsRemoved, r.KeysAdded, r.KeysRemoved} {
		sort.Strings(l)
	}
	sort.Slice(r.LevelChanges, func(i, j int) bool { return r.LevelChanges[i].Action < r.LevelChanges[j].Action })
	return r
}

func (c *Compiled) keyNames() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Keys))
	for _, k := range c.Keys {
		out = append(out, k.Name)
	}
	return out
}

// Changed reports whether the new catalog differs from the old in anything a
// reviewer should see.
func (r *DiffReport) Changed() bool {
	return len(r.ServicesAdded)+len(r.ServicesRemoved)+len(r.ActionsAdded)+len(r.ActionsRemoved)+
		len(r.LevelChanges)+len(r.KeysAdded)+len(r.KeysRemoved)+len(r.RCPAdded)+len(r.RCPRemoved)+
		len(r.RCPDrift.PageOnly)+len(r.RCPDrift.OverlayOnly) > 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Title is the refresh PR title, for example
// "catalog: 2026-10-09 (+12 actions, +1 RCP service)".
func (r *DiffReport) Title() string {
	var parts []string
	if n := len(r.ActionsAdded); n > 0 {
		parts = append(parts, fmt.Sprintf("+%d %s", n, plural(n, "action", "actions")))
	}
	if n := len(r.ActionsRemoved); n > 0 {
		parts = append(parts, fmt.Sprintf("-%d %s", n, plural(n, "action", "actions")))
	}
	if n := len(r.RCPAdded) + len(r.RCPDrift.PageOnly); n > 0 {
		parts = append(parts, fmt.Sprintf("+%d RCP %s", n, plural(n, "service", "services")))
	}
	if n := len(r.RCPRemoved) + len(r.RCPDrift.OverlayOnly); n > 0 {
		parts = append(parts, fmt.Sprintf("-%d RCP %s", n, plural(n, "service", "services")))
	}
	switch {
	case len(parts) > 0:
	case r.Changed():
		parts = append(parts, "other changes")
	default:
		parts = append(parts, "no changes")
	}
	return fmt.Sprintf("catalog: %s (%s)", r.Snapshot, strings.Join(parts, ", "))
}

const maxListed = 200

func writeList(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s (%d)\n\n", title, len(items))
	for i, it := range items {
		if i == maxListed {
			fmt.Fprintf(b, "- ... and %d more\n", len(items)-maxListed)
			break
		}
		fmt.Fprintf(b, "- `%s`\n", it)
	}
	b.WriteString("\n")
}

// Markdown renders the report for a PR description. Entry names are
// upstream text, so they are shown in code spans with backticks removed.
func (r *DiffReport) Markdown() string {
	clean := func(in []string) []string {
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s)
		}
		return out
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", r.Title())
	from := r.From
	if from == "" {
		from = "(none)"
	}
	fmt.Fprintf(&b, "Catalog version `%s` (from `%s`)\n\n", r.To, from)
	if !r.Changed() {
		b.WriteString("No changes.\n")
	}
	writeList(&b, "Services added", clean(r.ServicesAdded))
	writeList(&b, "Services removed", clean(r.ServicesRemoved))
	writeList(&b, "Actions added", clean(r.ActionsAdded))
	writeList(&b, "Actions removed", clean(r.ActionsRemoved))
	if len(r.LevelChanges) > 0 {
		lc := make([]string, len(r.LevelChanges))
		for i, c := range r.LevelChanges {
			lc[i] = fmt.Sprintf("%s: %s -> %s", c.Action, c.From, c.To)
		}
		writeList(&b, "Access level changes", clean(lc))
	}
	writeList(&b, "Condition keys added", clean(r.KeysAdded))
	writeList(&b, "Condition keys removed", clean(r.KeysRemoved))
	writeList(&b, "RCP services added to the overlay", clean(r.RCPAdded))
	writeList(&b, "RCP services removed from the overlay", clean(r.RCPRemoved))
	writeList(&b, "RCP page lists these services, the overlay does not (needs iam-authz-expert review)", clean(r.RCPDrift.PageOnly))
	writeList(&b, "Overlay lists these services, the RCP page does not (needs iam-authz-expert review)", clean(r.RCPDrift.OverlayOnly))
	writeList(&b, "Warnings", clean(r.Warnings))
	return b.String()
}
