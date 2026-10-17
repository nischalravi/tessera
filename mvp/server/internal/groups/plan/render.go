package plan

import (
	"fmt"
	"io"
	"strings"
)

// Render writes the diff and, if there is one, the simulated impact. The
// format is stable (golden-tested): a summary line, one line per action in
// apply order, then the impact.
func Render(w io.Writer, p *Plan, imp *Impact) error {
	var b strings.Builder
	if p.Empty() {
		fmt.Fprintf(&b, "No changes: the server already matches the plan (%d items checked).\n", p.Unchanged)
		_, err := io.WriteString(w, b.String())
		return err
	}
	c := p.Counts()
	var parts []string
	add := func(n int, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(c[FolderCreate], plural(c[FolderCreate], "folder", "folders")+" to create")
	add(c[GroupCreate], plural(c[GroupCreate], "group", "groups")+" to create")
	add(c[PrivGrant], plural(c[PrivGrant], "privilege", "privileges")+" to grant")
	add(c[MemberAdd], plural(c[MemberAdd], "member", "members")+" to add")
	add(c[MemberRemove], plural(c[MemberRemove], "member", "members")+" to remove")
	fmt.Fprintf(&b, "Plan: %s; %d unchanged.\n\n", strings.Join(parts, ", "), p.Unchanged)
	for _, a := range p.Actions {
		switch a.Kind {
		case FolderCreate:
			fmt.Fprintf(&b, "  + folder  %s%s\n", a.Name, suffix(a.Detail))
		case GroupCreate:
			fmt.Fprintf(&b, "  + group   %s%s\n", a.Name, suffix(a.Detail))
		case PrivGrant:
			fmt.Fprintf(&b, "  + grant   %s  %s\n", a.Name, a.Detail)
		case MemberAdd:
			fmt.Fprintf(&b, "  + member  %s <- %s\n", a.Name, a.Detail)
		case MemberRemove:
			fmt.Fprintf(&b, "  - member  %s <- %s\n", a.Name, a.Detail)
		}
	}
	if imp != nil {
		b.WriteString("\n")
		renderImpact(&b, imp)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func suffix(detail string) string {
	if detail == "" {
		return ""
	}
	return "  (" + detail + ")"
}

func renderImpact(b *strings.Builder, imp *Impact) {
	if imp.Simulated == 0 {
		b.WriteString("Impact: no membership change on an existing group to simulate.\n")
	} else {
		fmt.Fprintf(b, "Impact (simulated by the server; nothing was changed): +%d / -%d identities in %d %s.\n",
			imp.Added, imp.Removed, len(imp.Groups), plural(len(imp.Groups), "group", "groups"))
		for _, g := range imp.Groups {
			kind := "via nesting"
			if g.Targeted {
				kind = "changed"
			}
			fmt.Fprintf(b, "  %s  %d -> %d (+%d, -%d)  %s\n", printable(g.Name), g.Before, g.After, g.Added, g.Removed, kind)
		}
		if imp.Chunks > 1 {
			fmt.Fprintf(b, "  The changes were simulated in %d chunks of up to %d: an identity added by two chunks is counted twice.\n", imp.Chunks, simChunk)
		}
		if imp.Truncated {
			b.WriteString("  The simulation was truncated: the lists above are incomplete.\n")
		}
	}
	if imp.Skipped > 0 {
		fmt.Fprintf(b, "  %d membership %s on groups or members that the plan creates %s not simulated.\n",
			imp.Skipped, plural(imp.Skipped, "change", "changes"), plural(imp.Skipped, "was", "were"))
	}
}
