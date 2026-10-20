// Package render turns an access diff (query.Diff) into the text of a pull
// request comment (design §11.3): who gains or loses which permission, how
// sure the engine is, and why, in a form a reviewer reads in a diff view. It is
// pure: no I/O, no clock, no HTTP. Posting the comment is the API layer's job.
package render

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
)

// Marker opens every comment Markdown produces, so a later run can find and
// replace the comment it posted.
const Marker = "<!-- tessera-access-diff -->"

// DefaultMaxBytes keeps a comment well under GitHub's 65,536 character limit.
const DefaultMaxBytes = 60000

// Meta identifies what was compared.
type Meta struct {
	BaseSnapshot   string // snapshot id
	Head           string // what the base is compared with, for example "PR head"
	CatalogVersion string
	EngineVersion  string
}

// Options tunes the rendering. The zero value is usable.
type Options struct {
	// Why returns the trace lines under a change (nil: none).
	Why func(c *query.Change) []string
	// UsedDays says how many days ago the principal last used the action; nil
	// is unknown (design §11.3 step 5).
	UsedDays func(principal, action string) *int
	// MaxPrincipals bounds the principals named under a change (default 5).
	MaxPrincipals int
	// MaxBytes bounds the comment (default DefaultMaxBytes).
	MaxBytes int
}

// Text renders the diff as the plain text of the design's example comment.
func Text(res *query.DiffResult, m Meta, o Options) string {
	return build(res, m, o)
}

// Markdown renders the diff for a GitHub comment: the text in a fenced block
// (so nothing a name contains is interpreted as Markdown or as a mention),
// after the marker.
func Markdown(res *query.DiffResult, m Meta, o Options) string {
	return Marker + "\n```text\n" + build(res, m, o) + "```\n"
}

var kindOrder = map[query.ChangeKind]int{query.Gained: 0, query.Lost: 1, query.ConditionalChanged: 2, query.FidelityChanged: 3}

func build(res *query.DiffResult, m Meta, o Options) string {
	if o.MaxPrincipals <= 0 {
		o.MaxPrincipals = 5
	}
	max := o.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	var b strings.Builder
	head := m.Head
	if head == "" {
		head = "head"
	}
	fmt.Fprintf(&b, "Tessera access diff — snapshot %s → %s (catalog %s, engine %s)\n", short(m.BaseSnapshot), clean(head),
		clean(orDash(m.CatalogVersion)), clean(orDash(m.EngineVersion)))
	if res == nil || len(res.Changes) == 0 {
		b.WriteString(" no change in who can do what\n")
		return b.String()
	}
	changes := append([]query.Change(nil), res.Changes...)
	sort.SliceStable(changes, func(i, j int) bool {
		a, c := changes[i], changes[j]
		if kindOrder[a.Kind] != kindOrder[c.Kind] {
			return kindOrder[a.Kind] < kindOrder[c.Kind]
		}
		if a.Principals[0] != c.Principals[0] {
			return a.Principals[0] < c.Principals[0]
		}
		return strings.Join(a.Actions, ",") < strings.Join(c.Actions, ",")
	})
	shown := 0
	for _, c := range changes {
		block := changeBlock(&c, o)
		if b.Len()+len(block) > max-200 {
			break
		}
		b.WriteString(block)
		shown++
	}
	if shown < len(changes) {
		fmt.Fprintf(&b, " … %d more change(s) not shown (the comment is limited to %d bytes)\n", len(changes)-shown, max)
	}
	return b.String()
}

func changeBlock(c *query.Change, o Options) string {
	var b strings.Builder
	n := len(c.Principals)
	who := plural(n, "principal")
	what := namesText(c.Actions, c.ActionCount) + " on " + namesText(c.Resources, c.ResourceCount)
	fid := fidelityTag(c)
	switch c.Kind {
	case query.Gained:
		fmt.Fprintf(&b, " + %s GAIN %s   [%s]\n", who, what, fid)
	case query.Lost:
		used := ""
		if d := minUsed(c, o); d != nil {
			used = fmt.Sprintf(" (used %s)", daysText(*d))
		}
		fmt.Fprintf(&b, " − %s %s %s%s   [%s]\n", who, loseVerb(n), what, used, fid)
	case query.ConditionalChanged:
		fmt.Fprintf(&b, " ~ %s %s on %s   [%s]\n", who, conditionalText(c), what, fid)
	default:
		fmt.Fprintf(&b, " ! %s: result is %s%s on %s\n", who, strings.ToUpper(after(c).Fidelity.String()), reasonsText(after(c).Reasons), what)
	}
	for i, p := range c.Principals {
		if i == o.MaxPrincipals {
			fmt.Fprintf(&b, "     … and %d more\n", n-i)
			break
		}
		fmt.Fprintf(&b, "     %s\n", principalText(p))
	}
	if o.Why != nil {
		for _, l := range o.Why(c) {
			fmt.Fprintf(&b, "       %s\n", clean(l))
		}
	}
	if c.Kind != query.FidelityChanged {
		if a := after(c); a.Fidelity != authz.Exact && a.Reasons != "" {
			fmt.Fprintf(&b, " ! %s%s\n", strings.ToUpper(a.Fidelity.String()), reasonsText(a.Reasons))
		}
	}
	return b.String()
}

// after is the cell a change ends in; a lost permission ends in a deny, which
// has its before cell's fidelity reasons.
func after(c *query.Change) cellView {
	cell := c.After
	if c.Kind == query.Lost || cell == nil {
		cell = c.Before
	}
	if cell == nil {
		return cellView{Fidelity: authz.Exact}
	}
	return cellView{Fidelity: cell.Fidelity, Reasons: cell.Reasons, Outcome: cell.Outcome, Residual: cell.ResidualText}
}

type cellView struct {
	Fidelity authz.Fidelity
	Reasons  string
	Outcome  authz.Outcome
	Residual string
}

func fidelityTag(c *query.Change) string {
	return strings.ToUpper(after(c).Fidelity.String())
}

func conditionalText(c *query.Change) string {
	a, bf := c.After, c.Before
	switch {
	case a != nil && a.Outcome == authz.Conditional:
		return "become CONDITIONAL (" + clean(a.ResidualText) + ")"
	case bf != nil && bf.Outcome == authz.Conditional && a != nil:
		return "stop being CONDITIONAL (now " + strings.ToUpper(a.Outcome.String()) + ")"
	case bf != nil && bf.Outcome == authz.Conditional:
		return "stop being CONDITIONAL (now DENY)"
	case bf != nil && a != nil:
		return "change from " + strings.ToUpper(bf.Outcome.String()) + " to " + strings.ToUpper(a.Outcome.String())
	}
	return "change"
}

func reasonsText(reasons string) string {
	if reasons == "" {
		return ""
	}
	parts := strings.Split(reasons, ",")
	for i, p := range parts {
		parts[i] = clean(strings.TrimSuffix(p, "!"))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func minUsed(c *query.Change, o Options) *int {
	if o.UsedDays == nil {
		return nil
	}
	var best *int
	for _, p := range c.Principals {
		for _, a := range c.Actions {
			if d := o.UsedDays(p, a); d != nil && (best == nil || *d < *best) {
				v := *d
				best = &v
			}
		}
	}
	return best
}

func daysText(d int) string {
	switch d {
	case 0:
		return "today"
	case 1:
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", d)
}

func loseVerb(n int) string {
	if n == 1 {
		return "LOSES"
	}
	return "LOSE"
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// namesText lists up to three names, then the number left.
func namesText(names []string, total int) string {
	const show = 3
	if len(names) == 0 {
		return "*"
	}
	n := names
	if len(n) > show {
		n = n[:show]
	}
	out := make([]string, len(n))
	for i, s := range n {
		out[i] = clean(s)
	}
	text := strings.Join(out, ", ")
	if total > len(out) {
		text += fmt.Sprintf(" (+%d more)", total-len(out))
	}
	return text
}

// principalText shortens an IAM ARN to "role/Name (account)"; any other
// requester is shown as it is.
func principalText(arn string) string {
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[4] != "" {
		return clean(parts[5]) + " (" + clean(parts[4]) + ")"
	}
	return clean(arn)
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return orDash(id)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// clean makes a string safe to print in a comment: no control characters, no
// backtick (it would end the fenced block), and a bounded length.
func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '`':
			b.WriteRune('\'')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029:
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
		if n++; n >= 300 {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}

// Explainer returns an Options.Why that adds the engine's one-line verdict for
// the first principal, action and resource of a change: on the head for what a
// change gives, on the base for what it takes away. Both queriers must use the
// options the diff was made with.
func Explainer(ctx context.Context, base, head *query.Querier) func(c *query.Change) []string {
	return func(c *query.Change) []string {
		if len(c.Principals) == 0 || len(c.Actions) == 0 {
			return nil
		}
		q, label := head, "after: "
		if c.Kind == query.Lost {
			q, label = base, "before: "
		}
		res := "*"
		if len(c.Resources) > 0 {
			res = c.Resources[0]
		}
		d, err := q.Can(ctx, c.Principals[0], c.Actions[0], res)
		if err != nil {
			return nil
		}
		return []string{label + eval.Summary(d)}
	}
}
