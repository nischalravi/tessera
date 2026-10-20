package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/cliauth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/plan"
)

// tessera-cli groups: the native groups API from the command line, and
// declarative plans (issue #49, GR-6; design §10.12). Every request goes
// through the signed-in session of `tessera-cli login` (DPoP-bound OAuth
// tokens, internal/cliauth), so the server's route permission and the object
// privilege of each step apply to the CLI exactly as they do to the UI.

const groupsUsage = `usage:
  tessera-cli groups ls [FOLDER]                       folders and groups, below FOLDER if given
  tessera-cli groups show NAME                         a folder or group
  tessera-cli groups members ls GROUP [--filter direct|indirect|effective|composite]
  tessera-cli groups members add GROUP MEMBER... [--reason TEXT]
  tessera-cli groups members rm  GROUP MEMBER...       MEMBER is identity:<id> (or the id) or group:<name>
  tessera-cli groups plan   -f PLAN.yaml               show what the plan would change and its membership impact
  tessera-cli groups apply  -f PLAN.yaml [--run-id ID] apply the plan (a -f of - reads standard input)
  tessera-cli groups export FOLDER [-o FILE]           write a folder and everything below it as a plan
  tessera-cli groups templates                         the plan templates
`

// apiClient adapts the signed-in CLI session to the plan package's Client.
type apiClient struct{ c *cliauth.Client }

func (a apiClient) Call(ctx context.Context, method, path string, body any, header http.Header) (int, []byte, error) {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	res, err := a.c.DoWith(ctx, method, path, b, header)
	if err != nil {
		return 0, nil, err
	}
	return res.Status, res.Body, nil
}

func groupsCmd(ctx context.Context, c *cliauth.Client, args []string, e runEnv) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	api := apiClient{c}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "ls":
		return groupsLs(ctx, api, rest, e)
	case "show":
		return groupsShow(ctx, api, rest, e)
	case "members":
		return groupsMembers(ctx, api, rest, e)
	case "plan":
		return groupsPlan(ctx, api, rest, e, false)
	case "apply":
		return groupsPlan(ctx, api, rest, e, true)
	case "export":
		return groupsExport(ctx, api, rest, e)
	case "templates":
		return groupsTemplates(rest, e)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitOK
	}
	_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups: unknown command %q\n%s", cmd, groupsUsage)
	return exitUsage
}

// groupsFail reports an error of a groups command; a step-up demand is
// explained like the api command does.
func groupsFail(e runEnv, err error) int { return failResponse(e, nil, err) }

func groupsLs(ctx context.Context, api apiClient, args []string, e runEnv) int {
	fs := flags("groups ls", e)
	if err := fs.Parse(args); err != nil || fs.NArg() > 1 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	prefix := fs.Arg(0)
	if _, err := naming.Parse(prefix); err != nil {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups ls: %v\n", err)
		return exitUsage
	}
	live, err := plan.LoadCatalog(ctx, api)
	if err != nil {
		return groupsFail(e, err)
	}
	type row struct{ kind, name, detail string }
	var rows []row
	for _, f := range live.Folders {
		if f.Name != "" && naming.IsWithin(f.Name, prefix) {
			rows = append(rows, row{"folder", f.Name, ""})
		}
	}
	for _, g := range live.Groups {
		if naming.IsWithin(g.Name, prefix) {
			d := g.Type
			if g.Definition != "" && g.Definition != "basic" {
				d += ", " + g.Definition
			}
			rows = append(rows, row{"group", g.Name, d})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return naming.Fold(rows[i].name) < naming.Fold(rows[j].name) })
	for _, r := range rows {
		_, _ = fmt.Fprintf(e.stdout, "%-7s %s", r.kind, clean(r.name))
		if r.detail != "" {
			_, _ = fmt.Fprintf(e.stdout, "  (%s)", clean(r.detail))
		}
		_, _ = fmt.Fprintln(e.stdout)
	}
	return exitOK
}

func groupsShow(ctx context.Context, api apiClient, args []string, e runEnv) int {
	if len(args) != 1 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	live, err := plan.LoadCatalog(ctx, api)
	if err != nil {
		return groupsFail(e, err)
	}
	path := ""
	switch name := args[0]; {
	case live.FindGroup(name) != nil:
		path = "/api/groups/" + url.PathEscape(live.FindGroup(name).ID)
	case live.FindFolder(name) != nil && name != "":
		path = "/api/groups/folders/" + url.PathEscape(live.FindFolder(name).ID)
	default:
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups show: %q is not a folder or group you can see\n", clean(name))
		return exitError
	}
	status, body, err := api.Call(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return groupsFail(e, err)
	}
	if status != http.StatusOK {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli: the server answered %d\n", status)
		return exitError
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fail(e, fmt.Errorf("the server's answer is not JSON: %w", err))
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if doc[k] == nil {
			continue
		}
		var v string
		switch x := doc[k].(type) {
		case string:
			v = x
		default:
			b, _ := json.Marshal(x)
			v = string(b)
		}
		_, _ = fmt.Fprintf(e.stdout, "%-20s %s\n", k+":", clean(v))
	}
	return exitOK
}

func groupsMembers(ctx context.Context, api apiClient, args []string, e runEnv) int {
	if len(args) < 2 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	fs := flags("groups members "+sub, e)
	filter := fs.String("filter", "direct", "ls: direct, indirect, effective or composite")
	reason := fs.String("reason", "", "add: why (kept with the membership)")
	// flags may follow the positional arguments
	var pos []string
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return exitUsage
		}
		pos = append(pos, fs.Args()[:min(1, fs.NArg())]...)
		rest = fs.Args()[min(1, fs.NArg()):]
	}
	if len(pos) < 1 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	group, members := pos[0], pos[1:]
	switch sub {
	case "ls":
		return membersLs(ctx, api, e, group, *filter, members)
	case "add", "rm":
		if len(members) == 0 {
			_, _ = fmt.Fprint(e.stderr, groupsUsage)
			return exitUsage
		}
		spec := &plan.Spec{Groups: []plan.GroupSpec{{Name: group}}}
		if sub == "add" {
			spec.Groups[0].Members.Add = members
		} else {
			spec.Groups[0].Members.Remove = members
		}
		if err := spec.Validate(); err != nil {
			_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups members: %v\n", err)
			return exitUsage
		}
		live, err := plan.Load(ctx, api, spec)
		if err != nil {
			return groupsFail(e, err)
		}
		if live.FindGroup(group) == nil {
			_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups members: %q is not a group you can see\n", clean(group))
			return exitError
		}
		p, err := plan.Compute(spec, live)
		if err != nil {
			_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups members: %v\n", err)
			return exitError
		}
		if p.Empty() {
			_, _ = fmt.Fprintln(e.stdout, "Nothing to do: the group already matches.")
			return exitOK
		}
		return runApply(ctx, api, e, p, live, plan.Options{Reason: *reason})
	}
	_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups members: unknown command %q\n%s", sub, groupsUsage)
	return exitUsage
}

func membersLs(ctx context.Context, api apiClient, e runEnv, group, filter string, extra []string) int {
	if len(extra) != 0 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	live, err := plan.LoadCatalog(ctx, api)
	if err != nil {
		return groupsFail(e, err)
	}
	g := live.FindGroup(group)
	if g == nil {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups members: %q is not a group you can see\n", clean(group))
		return exitError
	}
	q := url.Values{"filter": {filter}, "limit": {"500"}}
	for offset := 0; ; offset += 500 {
		q.Set("offset", fmt.Sprint(offset))
		status, body, err := api.Call(ctx, http.MethodGet, "/api/groups/"+url.PathEscape(g.ID)+"/members?"+q.Encode(), nil, nil)
		if err != nil {
			return groupsFail(e, err)
		}
		if status != http.StatusOK {
			_, _ = fmt.Fprintf(e.stderr, "tessera-cli: the server answered %d: %s\n", status, clean(string(body)))
			return exitError
		}
		var out struct {
			Items []struct {
				Type       string  `json:"type"`
				IdentityID *int64  `json:"identity_id"`
				GroupID    *string `json:"group_id"`
				Name       string  `json:"name"`
				Active     *bool   `json:"active"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return fail(e, fmt.Errorf("the server's answer is not JSON: %w", err))
		}
		for _, m := range out.Items {
			ref := m.Type
			switch {
			case m.IdentityID != nil:
				ref = fmt.Sprintf("identity:%d", *m.IdentityID)
			case m.GroupID != nil:
				ref = "group:" + clean(m.Name)
			}
			note := ""
			if m.Active != nil && !*m.Active {
				note = "  (not active)"
			}
			_, _ = fmt.Fprintf(e.stdout, "%s  %s%s\n", clean(ref), clean(m.Name), note)
		}
		if len(out.Items) < 500 {
			return exitOK
		}
	}
}

// readPlan reads and expands a plan file ("-" is standard input).
func readPlan(e runEnv, file string) (*plan.Spec, error) {
	var r io.Reader
	if file == "-" {
		r = e.stdin
	} else {
		f, err := os.Open(file) // #nosec G304 G703 -- a path the operator passes to their own CLI
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	spec, err := plan.Parse(r)
	if err != nil {
		return nil, err
	}
	if spec, err = plan.Expand(spec); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return spec, nil
}

func groupsPlan(ctx context.Context, api apiClient, args []string, e runEnv, apply bool) int {
	name := "plan"
	if apply {
		name = "apply"
	}
	fs := flags("groups "+name, e)
	file := fs.String("f", "", "the plan file (- for standard input)")
	runID := fs.String("run-id", "", "apply: mixed into the idempotency keys; change it to send a repeated plan afresh")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *file == "" || (!apply && *runID != "") {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	spec, err := readPlan(e, *file)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups %s: %v\n", name, err)
		return exitUsage
	}
	live, err := plan.Load(ctx, api, spec)
	if err != nil {
		return groupsFail(e, err)
	}
	p, err := plan.Compute(spec, live)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli groups %s: %v\n", name, err)
		return exitError
	}
	if apply {
		return runApply(ctx, api, e, p, live, plan.Options{RunID: *runID})
	}
	var imp *plan.Impact
	if !p.Empty() {
		if imp, err = plan.Simulate(ctx, api, p, live); err != nil {
			return groupsFail(e, err)
		}
	}
	if err := plan.Render(e.stdout, p, imp); err != nil {
		return fail(e, err)
	}
	return exitOK
}

// runApply shows the plan, applies it and reports what was done.
func runApply(ctx context.Context, api apiClient, e runEnv, p *plan.Plan, live *plan.Live, o plan.Options) int {
	if err := plan.Render(e.stdout, p, nil); err != nil {
		return fail(e, err)
	}
	if p.Empty() {
		return exitOK
	}
	res, err := plan.Apply(ctx, api, p, live, o)
	if res != nil {
		_, _ = fmt.Fprintf(e.stdout, "\nApplied: %d folders, %d groups, %d privileges granted, %d members added, %d removed.\n",
			res.Folders, res.Groups, res.Grants, res.Added, res.Removed)
		if len(res.Ops) > 0 {
			_, _ = fmt.Fprintf(e.stdout, "Large changes are finishing in the background (engine operations %v).\n", res.Ops)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(e.stderr, "The plan stopped part way. Fix the cause and run it again: it only does what is still missing.")
		return groupsFail(e, err)
	}
	return exitOK
}

func groupsExport(ctx context.Context, api apiClient, args []string, e runEnv) int {
	fs := flags("groups export", e)
	out := fs.String("o", "", "write the plan to this file instead of standard output")
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return exitUsage
		}
		pos = append(pos, fs.Args()[:min(1, fs.NArg())]...)
		args = fs.Args()[min(1, fs.NArg()):]
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	spec, warnings, err := plan.Export(ctx, api, pos[0])
	if err != nil {
		return groupsFail(e, err)
	}
	b, err := plan.Marshal(spec)
	if err != nil {
		return fail(e, err)
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(e.stderr, "tessera-cli: warning: %s\n", clean(w))
	}
	if *out == "" {
		_, _ = e.stdout.Write(b)
		return exitOK
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil { // #nosec G304 G703 -- a path the operator passes to their own CLI
		return fail(e, err)
	}
	_, _ = fmt.Fprintf(e.stderr, "Wrote %s.\n", *out)
	return exitOK
}

func groupsTemplates(args []string, e runEnv) int {
	if len(args) != 0 {
		_, _ = fmt.Fprint(e.stderr, groupsUsage)
		return exitUsage
	}
	for _, t := range plan.Templates() {
		_, _ = fmt.Fprintf(e.stdout, "%s (version %d)\n  %s\n", t.ID, t.Version, t.Description)
		for _, p := range t.Params {
			req := ""
			if p.Required {
				req = ", required"
			}
			_, _ = fmt.Fprintf(e.stdout, "  param %s (%s%s): %s\n", p.Name, p.Type, req, strings.TrimSpace(p.Description))
		}
	}
	return exitOK
}
