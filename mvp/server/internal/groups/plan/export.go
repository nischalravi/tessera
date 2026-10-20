package plan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// Export reads a folder and everything below it into a plan (replacing
// "export to GSH", G-99): the folders, the groups with their composite
// definitions and direct members, and the privilege rows on them. Dates and
// reasons of memberships are not part of a plan. Privilege rows are listed only
// where the caller may see them (admin on the object); the others are reported
// as warnings. Applying the result to the same server changes nothing.
func Export(ctx context.Context, c Client, folder string) (*Spec, []string, error) {
	if _, err := naming.Parse(folder); err != nil || folder == "" {
		return nil, nil, fmt.Errorf("%q is not a folder name", folder)
	}
	live, err := LoadCatalog(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	if live.FindFolder(folder) == nil {
		return nil, nil, fmt.Errorf("folder %q was not found", folder)
	}
	spec := &Spec{}
	var warnings []string
	var folders []*LiveFolder
	for _, f := range live.Folders {
		if naming.IsWithin(f.Name, folder) {
			folders = append(folders, f)
		}
	}
	sort.Slice(folders, func(i, j int) bool { return naming.Fold(folders[i].Name) < naming.Fold(folders[j].Name) })
	var groups []*LiveGroup
	for _, g := range live.Groups {
		if naming.IsWithin(g.Name, folder) {
			groups = append(groups, g)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return naming.Fold(groups[i].Name) < naming.Fold(groups[j].Name) })

	for _, f := range folders {
		var full struct {
			DisplayExtension string  `json:"display_extension"`
			Description      string  `json:"description"`
			DataOwner        *string `json:"data_owner"`
		}
		if _, err := call(ctx, c, http.MethodGet, "/api/groups/folders/"+url.PathEscape(f.ID), nil, &full, nil); err != nil {
			return nil, nil, fmt.Errorf("folder %s: %w", f.Name, err)
		}
		fs := FolderSpec{Name: f.Name, DisplayName: full.DisplayExtension, Description: full.Description}
		if full.DataOwner != nil {
			fs.DataOwner = *full.DataOwner
		}
		spec.Folders = append(spec.Folders, fs)
	}
	for _, g := range groups {
		var full struct {
			DisplayExtension  string   `json:"display_extension"`
			Description       string   `json:"description"`
			Type              string   `json:"type"`
			CompositeOp       *string  `json:"composite_op"`
			Factors           []string `json:"factors"`
			DataOwner         *string  `json:"data_owner"`
			MemberDescription *string  `json:"member_description"`
		}
		if _, err := call(ctx, c, http.MethodGet, "/api/groups/"+url.PathEscape(g.ID), nil, &full, nil); err != nil {
			return nil, nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		gs := GroupSpec{Name: g.Name, DisplayName: full.DisplayExtension, Description: full.Description}
		if full.Type == "role" {
			gs.Type = "role"
		}
		if full.DataOwner != nil {
			gs.DataOwner = *full.DataOwner
		}
		if full.MemberDescription != nil {
			gs.MemberDescription = *full.MemberDescription
		}
		if g.Definition == "composite" && full.CompositeOp != nil {
			cs := &CompositeSpec{Op: *full.CompositeOp}
			for _, id := range full.Factors {
				f := live.GroupByID(id)
				if f == nil {
					return nil, nil, fmt.Errorf("group %s: its factor %s is not visible to you", g.Name, id)
				}
				cs.Factors = append(cs.Factors, f.Name)
			}
			gs.Composite = cs
		} else if err := live.loadMembers(ctx, c, g.ID); err != nil {
			return nil, nil, fmt.Errorf("group %s: %w", g.Name, err)
		} else {
			for key := range live.Members[g.ID] {
				gs.Members.Add = append(gs.Members.Add, memberText(live, key))
			}
			slices.Sort(gs.Members.Add)
		}
		spec.Groups = append(spec.Groups, gs)
	}
	objects := make([]ObjectRef, 0, len(folders)+len(groups))
	for _, f := range folders {
		objects = append(objects, ObjectRef{Type: "folder", Name: f.Name})
	}
	for _, g := range groups {
		objects = append(objects, ObjectRef{Type: "group", Name: g.Name})
	}
	for _, o := range objects {
		id := live.objectID(o)
		if err := live.loadPrivs(ctx, c, o.Type, id); err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == http.StatusForbidden {
				warnings = append(warnings, fmt.Sprintf("the privileges on %s were not exported: you are not allowed to list them", o))
				continue
			}
			return nil, nil, fmt.Errorf("privileges on %s: %w", o, err)
		}
		ps, w := privSpecs(live, o, live.Privs[id])
		warnings = append(warnings, w...)
		spec.Privileges = append(spec.Privileges, ps...)
	}
	return spec, warnings, nil
}

// memberText turns a member key of the live state back into plan syntax, with
// the group's real-cased name.
func memberText(live *Live, key string) string {
	if rest, ok := strings.CutPrefix(key, "group:"); ok {
		if g := live.FindGroup(rest); g != nil {
			return "group:" + g.Name
		}
	}
	return key
}

// privSpecs turns the rows of one object into plan entries, merging the self
// row and the inherited row a plan creates for a folder's own privilege back
// into one entry with scope one or sub.
func privSpecs(live *Live, o ObjectRef, rows []LivePriv) ([]PrivSpec, []string) {
	var warnings []string
	holder := func(r LivePriv) (string, bool) {
		switch r.HolderType {
		case "identity":
			return "identity:" + r.HolderID, true
		case "group":
			if g := live.GroupByID(r.HolderID); g != nil {
				return "group:" + g.Name, true
			}
			return "", false
		}
		return "everyone", true
	}
	type key struct{ priv, holder string }
	selfRows := map[key]bool{}
	for _, r := range rows {
		if h, ok := holder(r); ok && r.AppliesTo == "self" {
			selfRows[key{r.Privilege, h}] = true
		}
	}
	byScope := map[string]map[string][]string{}
	put := func(scope, priv, h string) {
		if byScope[scope] == nil {
			byScope[scope] = map[string][]string{}
		}
		if !slices.Contains(byScope[scope][priv], h) {
			byScope[scope][priv] = append(byScope[scope][priv], h)
		}
	}
	merged := map[key]bool{}
	for _, r := range rows {
		h, ok := holder(r)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("a %s privilege on %s held by a group you cannot see was not exported", r.Privilege, o))
			continue
		}
		if r.AppliesTo == "self" {
			continue
		}
		put(r.Scope, r.Privilege, h)
		if privObject(r.Privilege) == o.Type && selfRows[key{r.Privilege, h}] {
			merged[key{r.Privilege, h}] = true
		}
	}
	for _, r := range rows {
		if h, ok := holder(r); ok && r.AppliesTo == "self" && !merged[key{r.Privilege, h}] {
			put("self", r.Privilege, h)
		}
	}
	scopes := make([]string, 0, len(byScope))
	for s := range byScope {
		scopes = append(scopes, s)
	}
	slices.Sort(scopes)
	var out []PrivSpec
	for _, s := range scopes {
		for _, hs := range byScope[s] {
			slices.Sort(hs)
		}
		g := GrantSpec{Privileges: byScope[s]}
		if s != "self" {
			g.Scope = s
		}
		out = append(out, PrivSpec{Object: o.String(), Grant: g})
	}
	return out, warnings
}
