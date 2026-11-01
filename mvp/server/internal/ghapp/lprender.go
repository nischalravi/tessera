package ghapp

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The pull request Tessera opens for a right-sizing recommendation (issue #665, LP-9). The text is a function of the
// recommendation and its preview alone, so a golden test can pin it; every value that came from the estate (names,
// permissions, files) goes through code(), the renderer of the policy check, so markdown, HTML and @mentions in it do
// nothing.

// LPMarker opens every right-sizing pull request body, with the recommendation's id, so the pull request is recognizably
// Tessera's and the same recommendation is found again.
const LPMarker = "<!-- tessera:lp-rightsize:v1 "

// RightSize is one recommendation as the pull request states it.
type RightSize struct {
	RecID        string
	Kind         string
	IdentityName string
	IdentityType string
	Grant        string
	Group        string // the entitlement removed, system:name
	RoleKey      string
	RoleFile     string
	RoleMembers  int // members of the role who lose a permission when the entitlement goes (all members, not one identity)
	// MembersUsing: how many of those used a permission the entitlement gives within the window
	MembersUsing int
	// Permissions are examples of what the identity loses, all unused; PermissionsLost counts all of them.
	Permissions     []string
	PermissionsLost int
	UnusedLost      int
	UsedLost        int
	UnusedDays      int
	LastUsed        string // "" when never seen
	Fidelity        string // exact: the evaluator found the grant unconditional
	// RepoDiffers: the role file in the repository is not the one Tessera exports, so the simulation below is of Tessera's
	// export with the same edit, and the check run is neutral.
	RepoDiffers bool
	// FileRewritten: the role file in the repository is not what Tessera's renderer writes (comments or formatting), so
	// the commit rewrites it in full
	FileRewritten bool
	ExplanationID string
	Preview       Preview
}

// plain cuts text from the estate to one line for a title or a commit message, where markdown is not rendered but a
// mention can still notify: control characters go, and "@" is written "(at)".
func plain(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) || r == 0x200d {
			return ' '
		}
		return r
	}, s)
	s = strings.ReplaceAll(strings.TrimSpace(s), "@", "(at)")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n]) + "..."
	}
	return s
}

// cell is code() for a table cell: a "|" would end the cell even inside a code span, so it is written "¦".
func cell(s string, n int) string { return code(strings.ReplaceAll(s, "|", "¦"), n) }

// RightSizeTitle is the pull request's title and the commit's subject.
func RightSizeTitle(rs RightSize) string {
	return "Tessera: remove " + plain(rs.Group, 60) + " from role " + plain(rs.RoleKey, 60) + " (right-sizing " + plain(rs.RecID, 24) + ")"
}

// RightSizeCommitMessage is the commit message.
func RightSizeCommitMessage(rs RightSize) string {
	return RightSizeTitle(rs) + "\n\nUnused for " + fmt.Sprint(rs.UnusedDays) + " days by the identity the recommendation names. Opened by Tessera for review; not merged by it."
}

// RightSizeBody is the pull request's description.
func RightSizeBody(rs RightSize) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s -->\n", LPMarker, plain(rs.RecID, 64))
	b.WriteString("## Tessera right-sizing recommendation\n\n")
	b.WriteString("Removes an entitlement from a business role, which takes it from every member of the role. Tessera opened this pull request and never merges it: a person reviews it, and the policy check run on this pull request shows what the change does.\n\n")
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Recommendation | %s (%s) |\n", cell(rs.RecID, 64), cell(rs.Kind, 20))
	fmt.Fprintf(&b, "| Identity | %s (%s) |\n", cell(rs.IdentityName, maxTextLen), cell(rs.IdentityType, 20))
	fmt.Fprintf(&b, "| Grant | %s |\n", cell(rs.Grant, maxTextLen))
	fmt.Fprintf(&b, "| Entitlement removed | %s from role %s in %s |\n", cell(rs.Group, maxTextLen), cell(rs.RoleKey, 64), cell(rs.RoleFile, maxTextLen))
	fmt.Fprintf(&b, "| Role members who lose it | %d (%d used it in the window) |\n", rs.RoleMembers, rs.MembersUsing)
	fmt.Fprintf(&b, "| Permissions lost by this identity | %d (%d unused, %d used) |\n", rs.PermissionsLost, rs.UnusedLost, rs.UsedLost)
	last := "never seen in the usage data"
	if rs.LastUsed != "" {
		last = "last used " + cell(rs.LastUsed, 40)
	}
	fmt.Fprintf(&b, "| Usage window | %d days; %s |\n", rs.UnusedDays, last)
	fmt.Fprintf(&b, "| Confidence | grant evaluated %s (never approximate or conditional) |\n", cell(rs.Fidelity, 20))
	if rs.ExplanationID != "" {
		fmt.Fprintf(&b, "| Evidence | %s |\n", cell("GET /api/aws/explanations/"+rs.ExplanationID, maxTextLen))
	} else {
		b.WriteString("| Evidence | the recommendation's usage record |\n")
	}
	if len(rs.Permissions) > 0 {
		b.WriteString("\n**Unused permissions it removes**\n\n")
		for i, p := range rs.Permissions {
			if i == maxListed {
				fmt.Fprintf(&b, "- ... and %d more\n", len(rs.Permissions)-maxListed)
				break
			}
			fmt.Fprintf(&b, "- %s\n", code(p, maxTextLen))
		}
	}
	if r := rs.Preview.Report; r != nil {
		b.WriteString("\n### Simulation of this change\n")
		writeBlastTable(&b, r)
	}
	if rs.RepoDiffers {
		b.WriteString("\n**The role file in the repository differs from the one Tessera exports.** The simulation above is of Tessera's export with the same edit, not of this file: review the file's own diff.\n")
	}
	if rs.UsedLost > 0 || rs.MembersUsing > 0 {
		if rs.MembersUsing > 0 {
			fmt.Fprintf(&b, "\n**%d role member(s) used what this removes.** The recommendation is about one identity that did not; the other members lose it too. Check the usage before approving.\n", rs.MembersUsing)
		} else {
			b.WriteString("\n**Some of what this removes was used.** Check the usage before approving.\n")
		}
	}
	if rs.FileRewritten {
		b.WriteString("\n**Tessera rewrites the role file in full.** Comments and formatting in the repository's file are not preserved in this change: review the file's own diff.\n")
	}
	short := func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	}
	fmt.Fprintf(&b, "\n<sub>Bundle %s, preview %s.</sub>\n", code(short(rs.Preview.BundleSHA256), 12), code(short(rs.Preview.DiffSHA256), 12))
	return b.String()
}
