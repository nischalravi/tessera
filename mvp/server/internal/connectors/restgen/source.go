package restgen

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// mapper holds a Resource's compiled field paths.
type mapper struct {
	r      *Resource
	fields map[string]*Path
}

func newMapper(r *Resource) (*mapper, error) {
	m := &mapper{r: r, fields: make(map[string]*Path, len(r.Fields))}
	for k, src := range r.Fields {
		p, err := CompilePath(src)
		if err != nil {
			return nil, fmt.Errorf("fields.%s: %w", k, err)
		}
		m.fields[k] = p
	}
	return m, nil
}

// get returns the first scalar the field's path reaches in rec, or "".
func (m *mapper) get(field string, rec any) string {
	p := m.fields[field]
	if p == nil {
		return ""
	}
	for _, n := range p.Select(rec) {
		if s, ok := Scalar(n); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// user is one mapped user record.
type user struct {
	id, username, email, name, dept, title string
	active                                 bool
	created, lastLogin                     *time.Time
	attrs                                  map[string]string
}

var defaultActive = []string{"active", "enabled", "true", "1", "yes"}

// mapUser applies the users mapping to one record. ok is false when the
// record has no id (it cannot be tracked) or no sign-in name.
func (m *mapper) mapUser(rec any) (u user, ok bool) {
	u.id = m.get("id", rec)
	u.email = m.get("email", rec)
	u.username = m.get("username", rec)
	if u.username == "" {
		u.username = u.email
	}
	if u.id == "" || u.username == "" {
		return u, false
	}
	u.name = m.get("display_name", rec)
	if u.name == "" {
		u.name = u.username
	}
	u.dept, u.title = m.get("department", rec), m.get("title", rec)
	u.created, u.lastLogin = parseTime(m.get("created_at", rec)), parseTime(m.get("last_login_at", rec))
	u.active = true
	if m.fields["status"] != nil {
		st := strings.ToLower(m.get("status", rec))
		vals := m.r.ActiveValues
		if len(vals) == 0 {
			vals = defaultActive
		}
		u.active = slices.ContainsFunc(vals, func(v string) bool { return strings.EqualFold(v, st) })
	}
	u.attrs = map[string]string{}
	for k := range m.fields {
		if strings.HasPrefix(k, "attr.") {
			if v := m.get(k, rec); v != "" {
				u.attrs[k[5:]] = v
			}
		}
	}
	for k, v := range map[string]string{"email": u.email, "department": u.dept, "title": u.title} {
		if v != "" {
			u.attrs[k] = v
		}
	}
	return u, true
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 1e8 {
		var t time.Time
		if n > 1e11 { // milliseconds
			t = time.UnixMilli(n).UTC()
		} else {
			t = time.Unix(n, 0).UTC()
		}
		return &t
	}
	return nil
}

// Source is the REST system as an identity source. It is read-only: Discover
// sends GET requests only.
type Source struct {
	spec *Spec
	c    *Client
	sys  string
}

// New returns the source connector for a Spec. hc must come from internal/safehttp.
func New(spec *Spec, sec Secrets, rt connsync.Runtime, hc *http.Client) (*Source, error) {
	if errs := spec.Validate(rt); len(errs) > 0 {
		return nil, errs
	}
	c, err := NewClient(spec, sec, rt, hc)
	if err != nil {
		return nil, err
	}
	sys := spec.System
	if sys == "" {
		sys = DefaultSystem
	}
	return &Source{spec: spec, c: c, sys: sys}, nil
}

// System implements connectors.Connector.
func (s *Source) System() string { return s.sys }

// DisplayName implements connectors.Connector.
func (s *Source) DisplayName() string { return "REST (" + s.sys + ")" }

// TypeName implements connectors.Connector.
func (s *Source) TypeName() string { return "rest" }

// StreamEvents implements connectors.Connector: a generic REST system has no event feed.
func (s *Source) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// Stats are the requests, throttling and rate-limit headers seen so far.
func (s *Source) Stats() Stats { return s.c.Stats() }

// Discover reads users, groups and entitlements as the Spec maps them. A
// listing that stopped at a configured limit gives a result marked Partial,
// so the deletion guard holds every removal it would cause; any other failure
// is an error.
func (s *Source) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	res := &connectors.DiscoveryResult{System: s.sys}
	users := map[string]bool{}
	var partial []string
	note := func(what string, err error) error {
		if errors.Is(err, ErrTruncated) {
			partial = append(partial, what+": "+err.Error())
			return nil
		}
		return fmt.Errorf("%s: %w", what, err)
	}
	if u := s.spec.Users; u != nil {
		m, err := newMapper(u)
		if err != nil {
			return nil, err
		}
		_, err = s.c.walk(ctx, u.list(), nil, func(rec any) error {
			x, ok := m.mapUser(rec)
			if !ok || users[x.id] {
				return nil
			}
			users[x.id] = true
			xid := s.sys + ":" + x.id
			ref := &connectors.IdentityRef{ExternalID: xid, Email: x.email}
			status := "active"
			if !x.active {
				status = "disabled"
			}
			if !s.spec.NoIdentities {
				res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: x.name, Type: "human",
					Email: strp(x.email), Department: strp(x.dept), Title: strp(x.title), Status: "active"})
			}
			res.Accounts = append(res.Accounts, connectors.AccountRecord{System: s.sys, ExternalID: x.id, Username: x.username,
				Identity: ref, Kind: "user", Status: status, CreatedAt: x.created, LastLoginAt: x.lastLogin, Attributes: x.attrs})
			return nil
		})
		if err != nil {
			if err := note("users", err); err != nil {
				return nil, err
			}
		}
	}
	for _, g := range []struct {
		name, prefix string
		r            *Resource
	}{{"groups", "group:", s.spec.Groups}, {"entitlements", "entitlement:", s.spec.Entitlements}} {
		if g.r == nil {
			continue
		}
		if err := s.groups(ctx, res, g.name, g.prefix, g.r, users, note); err != nil {
			return nil, err
		}
	}
	res.Partial = strings.Join(partial, "; ")
	return res, nil
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *Source) groups(ctx context.Context, res *connectors.DiscoveryResult, what, prefix string, r *Resource,
	users map[string]bool, note func(string, error) error) error {
	m, err := newMapper(r)
	if err != nil {
		return err
	}
	priv := r.PrivilegedValues
	if len(priv) == 0 {
		priv = []string{"true", "yes", "1"}
	}
	kind := "group"
	if what == "entitlements" {
		kind = "role"
	}
	var idsPath, idPath *Path
	if r.Members != nil {
		if idsPath, err = optionalOrNil(r.Members.IDsPath); err != nil {
			return err
		}
		ip := r.Members.IDPath
		if ip == "" {
			ip = "$.id"
		}
		if idPath, err = CompilePath(ip); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	var failed error
	_, err = s.c.walk(ctx, r.list(), nil, func(rec any) error {
		id := m.get("id", rec)
		name := m.get("name", rec)
		if id == "" || name == "" || seen[id] {
			return nil
		}
		seen[id] = true
		gid := prefix + id
		g := connectors.GroupRecord{System: s.sys, ExternalID: gid, Name: name, Kind: kind,
			Privileged: slices.ContainsFunc(priv, func(v string) bool {
				return m.fields["privileged"] != nil && strings.EqualFold(v, m.get("privileged", rec))
			})}
		if d := m.get("description", rec); d != "" {
			g.Description = &d
		}
		res.Groups = append(res.Groups, g)
		if r.Members == nil {
			return nil
		}
		var memberIDs []string
		if idsPath != nil {
			memberIDs = idsPath.Strings(rec)
		} else if _, err := s.c.walk(ctx, r.Members.list(), Vars{"id": id}, func(mr any) error {
			memberIDs = append(memberIDs, idPath.Strings(mr)...)
			return nil
		}); err != nil {
			if failed == nil {
				failed = fmt.Errorf("members of %s %s: %w", what, id, err)
			}
			return nil // keep the group, remember that its members are incomplete
		}
		for _, uid := range memberIDs {
			if users[uid] {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Relation: "member_of",
					Src: connectors.Ref{Kind: "account", System: s.sys, ExternalID: uid},
					Dst: connectors.Ref{Kind: "group", System: s.sys, ExternalID: gid}})
			}
		}
		return nil
	})
	if err != nil {
		return note(what, err)
	}
	if failed != nil {
		return note(what, failed)
	}
	return nil
}

func optionalOrNil(s string) (*Path, error) {
	if s == "" {
		return nil, nil
	}
	return CompilePath(s)
}

// firstValue returns the first scalar a path reaches in a JSON document.
func firstValue(p *Path, doc any) string {
	if n, ok := p.First(doc); ok {
		s, _ := Scalar(n)
		return s
	}
	return ""
}
