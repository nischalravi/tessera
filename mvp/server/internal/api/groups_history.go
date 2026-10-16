package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Group change events and point-in-time history (issue #46, GR-3; design
// docs/design/groups-grouper-parity.md §10.1, §10.2). The three pit routes are
// tenant-wide history maintenance and need groups.admin (tenant_admin); a
// point-in-time members read goes through the members route and needs the
// group's read privilege (groups_members.go).
//
//	GET  /api/groups/{id}/members?as_of=T[&filter=effective|direct]       members at an instant
//	GET  /api/groups/{id}/members?between=T1,T2[&filter=effective|direct]  members at any time in the window
//	GET  /api/groups/pit/digests?limit=                                    the daily Merkle digests, newest first
//	GET  /api/groups/pit/verify?day=YYYY-MM-DD                             recompute a day's root (no day: the newest 100)
//	POST /api/groups/pit/rebuild                                           {group_id?} rebuild the PIT rows from the events
//
// Times are RFC 3339 and must not be in the future. A PIT read answers for
// deleted groups too (their history is kept); without filter it lists
// effective members. "group" is the group's snapshot at the instant (name,
// status, definition), null if it did not exist then.
func (s *Server) registerGroupsHistoryRoutes() {
	G, P := http.MethodGet, http.MethodPost
	perm := need(auth.PermGroupsAdmin)
	s.handle(G, "/api/groups/pit/digests", read, perm, s.rd(s.listPitDigests))
	s.handle(G, "/api/groups/pit/verify", read, perm, s.rd(s.verifyPit))
	s.handle(P, "/api/groups/pit/rebuild", write, perm, s.rd(s.rebuildPit))
}

// pitWindow reads as_of or between from a members request. ok is false when
// neither is present (an ordinary members read).
func pitWindow(p *params, now time.Time) (from, to time.Time, asOf, ok bool, err error) {
	asRaw, hasAs := p.query("as_of")
	btRaw, hasBt := p.query("between")
	switch {
	case !hasAs && !hasBt:
		return from, to, false, false, nil
	case hasAs && hasBt:
		return from, to, false, false, badRequest("invalid_window", "use as_of or between, not both")
	}
	parse := func(field, v string) (time.Time, error) {
		t, perr := time.Parse(time.RFC3339, strings.TrimSpace(v))
		if perr != nil {
			return t, badRequest("invalid_"+field, field+" must be an RFC 3339 time")
		}
		t = t.UTC()
		if t.After(now) {
			return t, badRequest("invalid_"+field, field+" must not be in the future")
		}
		return t, nil
	}
	if hasAs {
		t, err := parse("as_of", asRaw)
		return t, t, true, true, err
	}
	a, b, found := strings.Cut(btRaw, ",")
	if !found {
		return from, to, false, false, badRequest("invalid_between", "between is two RFC 3339 times separated by a comma")
	}
	if from, err = parse("between", a); err != nil {
		return from, to, false, false, err
	}
	if to, err = parse("between", b); err != nil {
		return from, to, false, false, err
	}
	if err := pit.CheckWindow(from, to); err != nil {
		return from, to, false, false, badRequest("invalid_between", strings.TrimPrefix(err.Error(), "pit: invalid time window: "))
	}
	return from, to, false, true, nil
}

type pitMemberView struct {
	IdentityID *int64  `json:"identity_id,omitempty"`
	GroupID    *string `json:"group_id,omitempty"`
	Name       string  `json:"name"`
	Type       string  `json:"type,omitempty"`
	Source     string  `json:"source,omitempty"`
	// EnabledFrom and DisabledAt are the direct row's own dates in that interval.
	EnabledFrom *string `json:"enabled_from,omitempty"`
	DisabledAt  *string `json:"disabled_at,omitempty"`
	// StartAt and EndAt bound the interval (EndAt is null while it is open).
	StartAt string  `json:"start_at"`
	EndAt   *string `json:"end_at"`
}

type pitMemberList struct {
	GroupID string          `json:"group_id"`
	AsOf    *string         `json:"as_of,omitempty"`
	From    *string         `json:"from,omitempty"`
	To      *string         `json:"to,omitempty"`
	Filter  string          `json:"filter"`
	Group   json.RawMessage `json:"group"`
	Items   []pitMemberView `json:"items"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
	// Total counts distinct effective members, or direct intervals.
	Total int `json:"total"`
}

func rtPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := store.RT(*t)
	return &s
}

// pitMembers answers a members read with as_of or between.
func (s *Server) pitMembers(r *http.Request, p *params, id string, from, to time.Time, asOf bool) (int, any, error) {
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	filter, _ := p.query("filter")
	if filter == "" {
		filter = "effective"
	}
	if filter != "direct" && filter != "effective" {
		return 0, nil, badRequest("invalid_filter", "filter is direct or effective")
	}
	tx := store.TxFrom(r.Context())
	g := store.GroupID(id)
	// a group of another tenant looks nonexistent; a deleted one is still history
	if _, err := tx.GrpGroup(g); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, nil, grpNotFound("group")
		}
		return 0, nil, err
	}
	out := pitMemberList{GroupID: id, Filter: filter, Limit: limit, Offset: offset, Items: []pitMemberView{}, Group: json.RawMessage("null")}
	if asOf {
		out.AsOf = rtPtr(&from)
	} else {
		out.From, out.To = rtPtr(&from), rtPtr(&to)
	}
	if o, err := pit.ObjectAt(tx, store.EventObjGroup, id, to); err == nil {
		out.Group = o.Snapshot
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, nil, err
	}
	list := store.MembersListID(tx.Tenant())
	if filter == "effective" {
		rows, total, err := pit.MembersBetween(tx, g, list, from, to, limit, offset)
		if err != nil {
			return 0, nil, err
		}
		out.Total = total
		for _, m := range rows {
			v := pitMemberView{IdentityID: &m.Identity, StartAt: store.RT(m.StartAt), EndAt: rtPtr(m.EndAt)}
			if ident, err := tx.Identity(m.Identity); err == nil {
				v.Name = ident.Name
			}
			out.Items = append(out.Items, v)
		}
		return http.StatusOK, out, nil
	}
	rows, total, err := pit.DirectBetween(tx, g, list, from, to, limit, offset)
	if err != nil {
		return 0, nil, err
	}
	out.Total = total
	for _, m := range rows {
		v := pitMemberView{Type: string(m.MemberType), Source: m.Source, EnabledFrom: rtPtr(m.EnabledFrom), DisabledAt: rtPtr(m.DisabledAt),
			StartAt: store.RT(m.StartAt), EndAt: rtPtr(m.EndAt)}
		if m.Identity != nil {
			v.IdentityID = m.Identity
			if ident, err := tx.Identity(*m.Identity); err == nil {
				v.Name = ident.Name
			}
		} else {
			gid := m.MemberGroup
			v.GroupID = &gid
			if cg, err := tx.GrpGroup(store.GroupID(gid)); err == nil {
				v.Name = cg.Name
			}
		}
		out.Items = append(out.Items, v)
	}
	return http.StatusOK, out, nil
}

type digestView struct {
	Day              string `json:"day"`
	FirstSeq         int64  `json:"first_seq"`
	LastSeq          int64  `json:"last_seq"`
	EventCount       int64  `json:"event_count"`
	MerkleRoot       string `json:"merkle_root"`
	AuditSeq         int64  `json:"audit_seq"`
	CreatedAt        string `json:"created_at"`
	Algorithm        string `json:"algorithm"`
	Canonicalization string `json:"canonicalization"`
}

func (s *Server) listPitDigests(r *http.Request, p *params) (int, any, error) {
	limit, _, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	ds, err := store.TxFrom(r.Context()).GrpDigests(limit)
	if err != nil {
		return 0, nil, err
	}
	items := make([]digestView, len(ds))
	for i, d := range ds {
		items[i] = digestView{Day: d.Day, FirstSeq: d.FirstSeq, LastSeq: d.LastSeq, EventCount: d.EventCount, MerkleRoot: d.MerkleRoot,
			AuditSeq: d.AuditSeq, CreatedAt: store.RT(d.CreatedAt), Algorithm: "rfc6962-sha256", Canonicalization: "rfc8785"}
	}
	return http.StatusOK, map[string]any{"items": items, "limit": limit}, nil
}

// verifyPit recomputes the Merkle root of one day (or of the newest digests)
// and compares it with the stored digest and the audit ledger's copy.
func (s *Server) verifyPit(r *http.Request, p *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	var vs []pit.Verdict
	if day, ok := p.query("day"); ok && day != "" {
		v, err := pit.VerifyDay(tx, day)
		if errors.Is(err, pit.ErrBadDay) {
			return 0, nil, badRequest("invalid_day", "day must be YYYY-MM-DD")
		}
		if err != nil {
			return 0, nil, err
		}
		vs = []pit.Verdict{v}
	} else {
		limit := 100
		if _, set := p.query("limit"); set {
			var err error
			if limit, _, err = pageParams(p); err != nil {
				return 0, nil, err
			}
		}
		var err error
		if vs, err = pit.VerifyAll(tx, limit); err != nil {
			return 0, nil, err
		}
	}
	ok := true
	for _, v := range vs {
		if v.Status == pit.VerdictMismatch || v.Status == pit.VerdictLedgerMismatch {
			ok = false
		}
	}
	if vs == nil {
		vs = []pit.Verdict{}
	}
	return http.StatusOK, map[string]any{"ok": ok, "days": vs}, nil
}

// rebuildPit recreates the derived PIT rows from the event outbox, for one
// group or the whole tenant. The rows are derived data, so this is safe; it is
// audited like any other write.
func (s *Server) rebuildPit(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		GroupID string `json:"group_id"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return 0, nil, err
	}
	if err := grpBodyID("group_id", in.GroupID); err != nil {
		return 0, nil, err
	}
	var n int64
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		if in.GroupID != "" {
			if _, err := c.GrpGroup(store.GroupID(in.GroupID)); err != nil {
				return err
			}
		}
		var err error
		if n, err = pit.Rebuild(c, in.GroupID); err != nil {
			return err
		}
		return pit.RecordRebuild(c, now, in.GroupID, n)
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return 0, nil, grpNotFound("group")
	case errors.Is(err, pit.ErrHistoryPruned):
		return 0, nil, &readiness.Error{Status: http.StatusConflict, Code: "history_pruned",
			Msg: "retention removed events this history was built from, so it cannot be rebuilt from them"}
	case err != nil:
		return 0, nil, grpErr(err)
	}
	return http.StatusOK, map[string]any{"group_id": nilIfEmptyStr(in.GroupID), "events_replayed": n}, nil
}

func nilIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
