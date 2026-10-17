package loaders

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The sources that read Tessera's own data. They name people by Tessera's
// identity id ("tessera_id"), so the subjects always resolve (a connected
// account that belongs to no identity is the exception: it is listed by its
// system and external id, and is unresolved).

// sanitizeExt turns free text into a group name segment: characters the naming
// rules refuse become "_".
func sanitizeExt(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 200 {
		out = out[:200]
	}
	if out == "" || out == "." || out == ".." {
		out = "_" + out
	}
	return out
}

func tesseraRef(id int64) SubjectRef {
	return SubjectRef{Source: "tessera_id", Identifier: strconv.FormatInt(id, 10)}
}

// ---------------------------------------------------------------- connector_groups

// connectorSource loads the groups of a connection (Okta, Entra, Google, AWS,
// ...) as native groups: the connection's `system` picks the groups, and the
// accounts that are members of each are mapped to their identities.
type connectorSource struct{ noChanges }

func (connectorSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg ConnectorGroupsConfig
	if err := decodeConfig(job, &cfg); err != nil {
		return nil, err
	}
	if job.Loader.ConnectionID == nil {
		return nil, conflict("connection_missing", "the loader has no connection")
	}
	var out []LoadedGroup
	err := job.Env.DB.ReadTenant(ctx, job.Env.Tenant, func(tx *store.TenantTx) error {
		conn, err := tx.Connection(*job.Loader.ConnectionID)
		if errors.Is(err, store.ErrNotFound) {
			return conflict("connection_missing", "the loader's connection no longer exists")
		}
		if err != nil {
			return err
		}
		groups, err := tx.Groups()
		if err != nil {
			return err
		}
		accts, err := tx.Accounts()
		if err != nil {
			return err
		}
		acct := make(map[int64]*store.Account, len(accts))
		for _, a := range accts {
			acct[a.ID] = a
		}
		used := map[string]bool{}
		for _, g := range groups {
			if g.System != conn.System {
				continue
			}
			ext := cfg.NamePrefix + sanitizeExt(g.Name)
			if used[strings.ToLower(ext)] {
				ext += "_" + sanitizeExt(g.ExternalID)
			}
			used[strings.ToLower(ext)] = true
			lg := LoadedGroup{Name: ext, DisplayName: g.Name}
			if g.Description != nil {
				lg.Description = *g.Description
			}
			edges, err := tx.EdgesTo(fmt.Sprintf("group:%d", g.ID))
			if err != nil {
				return err
			}
			for _, e := range edges {
				if e.Relation != "member_of" || !strings.HasPrefix(e.Src, "account:") {
					continue
				}
				if e.ExpiresAt != nil && !e.ExpiresAt.After(job.Env.Now) {
					continue
				}
				id, err := strconv.ParseInt(strings.TrimPrefix(e.Src, "account:"), 10, 64)
				if err != nil || acct[id] == nil {
					continue
				}
				a := acct[id]
				if a.IdentityID != nil {
					lg.Members = append(lg.Members, tesseraRef(*a.IdentityID))
				} else {
					lg.Members = append(lg.Members, SubjectRef{Source: a.System, Identifier: a.ExternalID})
				}
				job.Stats.Rows++
			}
			out = append(out, lg)
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------- attribute

// attributeSource makes one group per distinct value of an identity attribute
// (an organization hierarchy: one group per department under ref:dept:).
type attributeSource struct{ noChanges }

func (attributeSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg AttributeConfig
	if err := decodeConfig(job, &cfg); err != nil {
		return nil, err
	}
	onlyActive := cfg.OnlyActive == nil || *cfg.OnlyActive
	var out []LoadedGroup
	err := job.Env.DB.ReadTenant(ctx, job.Env.Tenant, func(tx *store.TenantTx) error {
		idents, err := tx.Identities()
		if err != nil {
			return err
		}
		byValue := map[string]*LoadedGroup{}
		var order []string
		for _, i := range idents {
			if onlyActive && i.Status != "active" {
				continue
			}
			var v string
			switch cfg.Attribute {
			case "department":
				v = deref(i.Department)
			case "title":
				v = deref(i.Title)
			case "type":
				v = i.Type
			case "status":
				v = i.Status
			case "source":
				v = deref(i.Source)
			}
			if strings.TrimSpace(v) == "" {
				continue
			}
			g := byValue[v]
			if g == nil {
				g = &LoadedGroup{Name: cfg.Prefix + sanitizeExt(v), DisplayName: v}
				byValue[v] = g
				order = append(order, v)
			}
			g.Members = append(g.Members, tesseraRef(i.ID))
			job.Stats.Rows++
		}
		sort.Strings(order)
		seen := map[string]string{}
		for _, v := range order {
			g := byValue[v]
			if other, dup := seen[strings.ToLower(g.Name)]; dup {
				return conflict("duplicate_group", "the attribute values %q and %q make the same group name %q", other, v, g.Name)
			}
			seen[strings.ToLower(g.Name)] = v
			out = append(out, *g)
		}
		return nil
	})
	return out, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---------------------------------------------------------------- recent_memberships

// recentSource holds the people who were effective members of a group at some
// time in the last N days and are not any longer (a grace list: "left within 30
// days"), and with include_current the current members too. It is fed by the
// point-in-time history, so it is exact: the effective-membership intervals
// that overlap the window (§10.2).
type recentSource struct{ noChanges }

func (recentSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg RecentConfig
	if err := decodeConfig(job, &cfg); err != nil {
		return nil, err
	}
	var out []LoadedGroup
	err := job.Env.DB.ReadTenant(ctx, job.Env.Tenant, func(tx *store.TenantTx) error {
		src, err := tx.GrpGroupByName(cfg.SourceGroup)
		if errors.Is(err, store.ErrNotFound) {
			a, aerr := tx.GrpAliasByName(cfg.SourceGroup)
			if aerr != nil || a.ObjectType != "group" {
				return conflict("source_group_missing", "the group %q does not exist", cfg.SourceGroup)
			}
			src, err = tx.GrpGroup(store.GroupID(a.ObjectID))
		}
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return conflict("source_group_missing", "the group %q does not exist", cfg.SourceGroup)
			}
			return err
		}
		list := store.MembersListID(tx.Tenant())
		from := job.Env.Now.Add(-time.Duration(cfg.Days) * 24 * time.Hour)
		// who is a member now (a deleted group is an empty set)
		current := map[int64]bool{}
		for after := int64(0); src.Status != store.GroupDeleted; {
			ids, err := tx.GrpEffectiveIdentitiesAfter(src.ID, list, after, 1000)
			if err != nil {
				return err
			}
			for _, id := range ids {
				current[id] = true
			}
			if len(ids) < 1000 {
				break
			}
			after = ids[len(ids)-1]
		}
		// who was a member at any time in the window, from the history
		inWindow := map[int64]bool{}
		for offset := 0; ; {
			rows, _, err := pit.MembersBetween(tx, src.ID, list, from, job.Env.Now, 1000, offset)
			if err != nil {
				return err
			}
			for _, r := range rows {
				inWindow[r.Identity] = true
			}
			offset += len(rows)
			if len(rows) < 1000 {
				break
			}
		}
		lg := LoadedGroup{Name: cfg.Group, DisplayName: cfg.Group,
			Description: fmt.Sprintf("People who were members of %s in the last %d days", src.Name, cfg.Days)}
		var ids []int64
		for id := range inWindow {
			if cfg.IncludeCurrent || !current[id] {
				ids = append(ids, id)
			}
		}
		if cfg.IncludeCurrent {
			for id := range current {
				if !inWindow[id] {
					ids = append(ids, id)
				}
			}
		}
		slices.Sort(ids)
		for _, id := range ids {
			lg.Members = append(lg.Members, tesseraRef(id))
		}
		job.Stats.Rows = len(lg.Members)
		out = []LoadedGroup{lg}
		return nil
	})
	return out, err
}
