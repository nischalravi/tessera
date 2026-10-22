package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	grpapi "github.com/nischalravi/tessera/mvp/server/internal/groups/api"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The groups REST API beyond the CRUD routes (issue #48, GR-5; design
// docs/design/groups-grouper-parity.md §10.11). Like every group route, each
// needs its route permission (groups.read or groups.write) and then the
// privilege of the group it names; the SCIM server is in scim.go.
//
//	POST /api/groups/{id}/members:batch   {add:[{identity|group, enabled_from, disabled_at, reason}], remove:[member], enabled_from,
//	                                       disabled_at, reason, atomic}  up to 1000 operations; update on the group (optin / optout for oneself)
//	GET  /api/identities/{identity_id}/groups?filter=effective|direct|indirect&list=&as_of=&limit=&offset=
//	                                       the groups the identity is in that the caller may read (read, because it tells who is a member)
//	POST /api/groups:simulate             {changes:[{kind, group, ...}]}  the same privileges as the changes themselves
//	GET  /api/openapi/groups.json         the OpenAPI document of the groups routes, built from the route table
//
// Idempotency: POST /members, DELETE /members/{member} and the batch accept an
// Idempotency-Key header. The first answer (2xx) is stored with the change, in its
// transaction, for 24 hours, scoped to the tenant and the caller; the same key
// with the same request replays it (with Idempotent-Replayed: true) and writes
// nothing, the same key with another request is 422 idempotency_key_reused.
func (s *Server) registerGroupsAPIRoutes() {
	G, P := http.MethodGet, http.MethodPost
	canRead, canWrite := need(auth.PermGroupsRead), need(auth.PermGroupsWrite)
	s.handle(P, "/api/groups/{id}/members:batch", write, canWrite, s.idem(s.batchGrpMembers))
	// a simulation computes an answer: it fails closed like a read if its audit event cannot be written
	s.handle(P, "/api/groups:simulate", write, canWrite, s.rd(s.simulateGrp)).answersRead = true
	s.handle(G, "/api/identities/{identity_id}/groups", read, canRead, s.rd(s.identityGroups))
	s.handle(G, "/api/openapi/groups.json", noTenant, need(auth.PermAuthenticated), s.groupsOpenAPI)
}

// ---------------------------------------------------------------- parameters

// listParam accepts only the built-in members list (by name or id).
func listParam(p *params, members store.ListID) error {
	if v, ok := p.query("list"); ok && v != "" && v != "members" && v != string(members) {
		return badRequest("invalid_list", "list is members (the built-in list)")
	}
	return nil
}

// boolParam reads an optional true or false query parameter.
func boolParam(p *params, name string) (bool, error) {
	switch v, _ := p.query(name); v {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, badRequest("invalid_"+name, name+" is true or false")
}

// pagePair applies page (1-based, with limit) instead of offset.
func pagePair(p *params, limit, offset int) (int, int, error) {
	v, ok := p.query("page")
	if !ok {
		return limit, offset, nil
	}
	if _, has := p.query("offset"); has {
		return 0, 0, badRequest("invalid_page", "use page or offset, not both")
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 1_000_000 {
		return 0, 0, badRequest("invalid_page", "page is a number from 1")
	}
	return limit, (n - 1) * limit, nil
}

// searchParams reads q, sort and enabled of a members listing.
func searchParams(p *params, filter string) (model.MemberQuery, error) {
	var q model.MemberQuery
	var err error
	if q.Q, err = queryStr(p, "q", 255); err != nil {
		return q, err
	}
	q.Sort, _ = p.query("sort")
	if !slices.Contains([]string{"", "name", "-name", "since", "-since"}, q.Sort) {
		return q, badRequest("invalid_sort", "sort is name, -name, since or -since")
	}
	q.Enabled, _ = p.query("enabled")
	switch {
	case q.Enabled != "" && q.Enabled != "true" && q.Enabled != "false":
		return q, badRequest("invalid_enabled", "enabled is true or false")
	case q.Enabled != "" && filter != "direct":
		return q, badRequest("invalid_enabled", "enabled applies to the direct filter")
	}
	q.Indirect = filter == "indirect"
	return q, nil
}

type traceStepView struct {
	GroupID string `json:"group_id"`
	Name    string `json:"name"`
	Via     string `json:"via"`
	Op      string `json:"op,omitempty"`
	Role    string `json:"role,omitempty"`
}

func viewTrace(t *model.Trace) []map[string]any {
	out := make([]map[string]any, len(t.Paths))
	for i, path := range t.Paths {
		steps := make([]traceStepView, len(path.Steps))
		for j, st := range path.Steps {
			steps[j] = traceStepView{GroupID: string(st.Group), Name: st.Name, Via: st.Via, Op: string(st.Op), Role: st.Role}
		}
		out[i] = map[string]any{"steps": steps}
	}
	return out
}

// ---------------------------------------------------------------- idempotency

const idemHeader = "Idempotency-Key"

// idemPrincipal names the caller a key belongs to.
func idemPrincipal(pr *auth.Principal) string {
	if pr.UserID != nil {
		return "user:" + pr.UserID.String()
	}
	return "client:" + pr.ClientID
}

// peekBody reads the request body and puts it back for the handler.
func peekBody(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw, nil
}

// idem adapts a write handler that accepts an Idempotency-Key. Without the
// header it is s.rd. With it, a stored answer to the same request is replayed;
// otherwise the handler runs and its (successful) answer is stored in the same
// transaction, so a retry after a lost response, or a duplicate sent at the same
// time, never repeats the change. A refused request stores nothing: the retry
// is evaluated again.
func (s *Server) idem(fn rdFunc) handlerFunc {
	plain := s.rd(fn)
	return func(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
		vals := r.Header.Values(idemHeader)
		if len(vals) == 0 {
			return plain(w, r, p)
		}
		if len(vals) > 1 || !grpapi.ValidKey(vals[0]) {
			return nil, badRequest("invalid_idempotency_key", "Idempotency-Key is 1 to 255 characters of letters, digits and . _ ~ : + = -")
		}
		raw, err := peekBody(r)
		if err != nil {
			return nil, err
		}
		tx, now := store.TxFrom(r.Context()), s.clock()
		k := grpapi.Key{Principal: idemPrincipal(principal(r)), Key: vals[0], Hash: grpapi.RequestHash(r.Method, r.URL.RequestURI(), raw)}
		replay, err := grpapi.Lookup(tx, now, k)
		switch {
		case errors.Is(err, grpapi.ErrKeyReused):
			return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "idempotency_key_reused",
				Msg: "this Idempotency-Key was used with a different request"}
		case err != nil:
			return nil, err
		case replay != nil:
			w.Header().Set("Idempotent-Replayed", "true")
			return statusBody{replay.Status, rawJSON(replay.Body)}, nil
		}
		status, body, err := fn(r, p)
		if err != nil {
			return nil, err
		}
		b, err := ojson.Marshal(body)
		if err != nil {
			return nil, err
		}
		if err := grpapi.Save(tx, now, k, status, b); err != nil {
			return nil, err
		}
		return statusBody{status, rawJSON(b)}, nil
	}
}

// ---------------------------------------------------------------- authorization of one member change

// memberChangeAuth is the privilege a member change needs, as the single
// routes ask it: update on the group, or optin / optout when the caller is the
// member. The errors are the privilege model's (a *privs.DeniedError) and the
// model's (404), not yet HTTP, so a batch can report them per operation.
func memberChangeAuth(e model.Env, ck *privs.Checker, group store.GroupID, opt privs.Privilege, self bool) error {
	g, err := e.Group(group)
	if err != nil {
		return err
	}
	want := []privs.Privilege{privs.Update}
	if self {
		want = []privs.Privilege{opt, privs.Update}
	}
	return ck.RequireAny(privs.GroupObject(g.ID), want...)
}

// readOnAuth requires read on a group that exists (an unknown one is the model's answer to give).
func readOnAuth(e model.Env, ck *privs.Checker, ids ...store.GroupID) error {
	for _, id := range ids {
		if _, err := e.Tx.GrpGroup(id); errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		if err := ck.Require(privs.GroupObject(id), privs.Read); err != nil {
			return err
		}
	}
	return nil
}

// removeSelf reports whether a member string of a remove names the caller.
func removeSelf(ck *privs.Checker, member string) bool {
	if typ, key, ok := model.ParseMember(member); ok && typ == store.MemberIdentity {
		if n, err := strconv.ParseInt(key, 10, 64); err == nil {
			return isSelf(ck, n)
		}
	}
	return false
}

// opFailure is the HTTP error of a refused operation: the refusal itself with
// the index of the operation.
func opFailure(oe *model.OpError) error {
	err := grpErr(oe.Err)
	var re *readiness.Error
	if errors.As(err, &re) {
		x := *re
		x.Extra = map[string]any{"index": oe.Index}
		for k, v := range re.Extra {
			x.Extra[k] = v
		}
		return &x
	}
	return err
}

// ---------------------------------------------------------------- batch

type batchAdd struct {
	Identity    *int64  `json:"identity"`
	Group       string  `json:"group"`
	EnabledFrom *string `json:"enabled_from"`
	DisabledAt  *string `json:"disabled_at"`
	Reason      *string `json:"reason"`
}

type batchIn struct {
	Add         []batchAdd `json:"add"`
	Remove      []string   `json:"remove"`
	EnabledFrom *string    `json:"enabled_from"`
	DisabledAt  *string    `json:"disabled_at"`
	Reason      string     `json:"reason"`
	Atomic      *bool      `json:"atomic"`
}

type batchItemView struct {
	Index      int     `json:"index"`
	Op         string  `json:"op"`
	MemberType string  `json:"member_type"`
	Member     string  `json:"member"`
	Status     string  `json:"status"`
	Effective  *string `json:"effective"`
	OpID       *int64  `json:"op_id"`
	Error      any     `json:"error"`
}

// batchOps validates the request and turns it into the model's operations:
// the adds, then the removes, in the order given.
func batchOps(in *batchIn) ([]model.BatchOp, error) {
	if n := len(in.Add) + len(in.Remove); n == 0 {
		return nil, badRequest("empty_batch", "add or remove at least one member")
	} else if n > model.MaxBatchOps {
		return nil, badRequest("batch_too_large", fmt.Sprintf("a batch has at most %d operations", model.MaxBatchOps))
	}
	if checkTextField("reason", in.Reason, model.MaxReason) != nil {
		return nil, badRequest("invalid_reason", "reason is too long")
	}
	defFrom, err := grpTimeBody("enabled_from", in.EnabledFrom)
	if err != nil {
		return nil, err
	}
	defTo, err := grpTimeBody("disabled_at", in.DisabledAt)
	if err != nil {
		return nil, err
	}
	ops := make([]model.BatchOp, 0, len(in.Add)+len(in.Remove))
	named := map[string]bool{}
	for i, a := range in.Add {
		if (a.Identity == nil) == (a.Group == "") {
			return nil, indexed(i, "add", badRequest("invalid_member", "name exactly one of identity or group"))
		}
		op := model.BatchOp{Kind: model.BatchAdd, Identity: a.Identity, EnabledFrom: defFrom, DisabledAt: defTo, Reason: in.Reason}
		switch {
		case a.Identity != nil && *a.Identity < 1:
			return nil, indexed(i, "add", badRequest("invalid_identity", "identity must be an identity id"))
		case a.Group != "":
			if err := grpBodyID("group", a.Group); err != nil {
				return nil, indexed(i, "add", err)
			}
			op.Group = store.GroupID(a.Group)
			named["group:"+a.Group] = true
		default:
			named["identity:"+strconv.FormatInt(*a.Identity, 10)] = true
		}
		if a.EnabledFrom != nil {
			if op.EnabledFrom, err = grpTimeBody("enabled_from", a.EnabledFrom); err != nil {
				return nil, indexed(i, "add", err)
			}
		}
		if a.DisabledAt != nil {
			if op.DisabledAt, err = grpTimeBody("disabled_at", a.DisabledAt); err != nil {
				return nil, indexed(i, "add", err)
			}
		}
		if a.Reason != nil {
			if checkTextField("reason", *a.Reason, model.MaxReason) != nil {
				return nil, indexed(i, "add", badRequest("invalid_reason", "reason is too long"))
			}
			op.Reason = *a.Reason
		}
		ops = append(ops, op)
	}
	for i, m := range in.Remove {
		typ, key, ok := model.ParseMember(m)
		if !ok {
			return nil, indexed(len(in.Add)+i, "remove", badRequest("invalid_member", "member is an identity id or a group id"))
		}
		if named[string(typ)+":"+key] {
			return nil, indexed(len(in.Add)+i, "remove", badRequest("conflicting_operations", "a member is both added and removed"))
		}
		ops = append(ops, model.BatchOp{Kind: model.BatchRemove, Member: m})
	}
	return ops, nil
}

// checkTextField bounds a free-text field.
func checkTextField(field, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%s is longer than %d bytes", field, max)
	}
	return nil
}

// indexed adds the index and kind of the offending operation to a refusal.
func indexed(i int, kind string, err error) error {
	var re *readiness.Error
	if errors.As(err, &re) {
		x := *re
		x.Extra = map[string]any{"index": i, "op": kind}
		return &x
	}
	return err
}

func (s *Server) batchGrpMembers(r *http.Request, p *params) (int, any, error) {
	id, err := grpPathID(p, "group")
	if err != nil {
		return 0, nil, err
	}
	var in batchIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	ops, err := batchOps(&in)
	if err != nil {
		return 0, nil, err
	}
	atomic := in.Atomic == nil || *in.Atomic
	ck := s.grpChecker(r)
	var res *model.BatchResult
	col := &deleteguard.Collector{}
	err = s.grpWrite(r, func(e model.Env) error {
		authorize := func(_ int, op model.BatchOp) error {
			if op.Kind == model.BatchRemove {
				return memberChangeAuth(e, ck, store.GroupID(id), privs.Optout, removeSelf(ck, op.Member))
			}
			if err := memberChangeAuth(e, ck, store.GroupID(id), privs.Optin, op.Identity != nil && isSelf(ck, *op.Identity)); err != nil {
				return err
			}
			if op.Group != "" { // a nested group's members become this group's: the caller must be able to read it
				return readOnAuth(e, ck, op.Group)
			}
			return nil
		}
		var err error
		e.Held = col
		res, err = e.ApplyBatch(store.GroupID(id), ops, atomic, authorize)
		var oe *model.OpError
		if errors.As(err, &oe) {
			return opFailure(oe)
		}
		if err == nil && res.Failed == len(res.Items) {
			// nothing was permitted: the caller has no business with this group at all
			var d *privs.DeniedError
			if errors.As(res.Items[0].Err, &d) && allDenied(res) {
				return d
			}
		}
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	items := make([]batchItemView, len(res.Items))
	for i, it := range res.Items {
		v := batchItemView{Index: it.Index, Op: it.Kind, MemberType: string(it.MemberType), Member: it.Member, Status: it.Status, OpID: it.Op}
		if it.Err != nil {
			var re *readiness.Error
			if errors.As(grpErr(it.Err), &re) {
				v.Error = readinessErrorBody(re)
			}
		} else {
			eff := it.Effective
			v.Effective = &eff
		}
		items[i] = v
	}
	effective, status := "applied", http.StatusOK
	ops64 := []int64{}
	if len(res.Ops) > 0 {
		effective, status, ops64 = "pending", http.StatusAccepted, res.Ops
	}
	body := map[string]any{"group_id": id, "atomic": atomic, "created": res.Created, "updated": res.Updated,
		"removed": res.Removed, "failed": res.Failed, "effective": effective, "ops": ops64, "results": items}
	if held := col.Result(); held != nil {
		// the deletion guard held some removals: 202 with what was applied and what waits for approval
		return http.StatusAccepted, heldBody(held, body), nil
	}
	return status, body, nil
}

// allDenied reports whether every operation of a batch failed for want of a privilege.
func allDenied(res *model.BatchResult) bool {
	for _, it := range res.Items {
		var d *privs.DeniedError
		if !errors.As(it.Err, &d) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- simulate

type simChangeIn struct {
	Kind           string   `json:"kind"`
	Group          string   `json:"group"`
	Identity       *int64   `json:"identity"`
	MemberGroup    string   `json:"member_group"`
	Member         string   `json:"member"`
	EnabledFrom    *string  `json:"enabled_from"`
	DisabledAt     *string  `json:"disabled_at"`
	Reason         string   `json:"reason"`
	Op             string   `json:"op"`
	Factors        []string `json:"factors"`
	DiscardMembers bool     `json:"discard_members"`
}

type simulateIn struct {
	Changes []simChangeIn `json:"changes"`
}

func simChanges(in *simulateIn) ([]model.Change, error) {
	if len(in.Changes) == 0 {
		return nil, badRequest("empty_simulation", "name at least one change")
	}
	if len(in.Changes) > model.MaxSimChanges {
		return nil, badRequest("too_many_changes", fmt.Sprintf("a simulation has at most %d changes", model.MaxSimChanges))
	}
	out := make([]model.Change, len(in.Changes))
	for i, c := range in.Changes {
		fail := func(err error) ([]model.Change, error) { return nil, indexed(i, c.Kind, err) }
		if !slices.Contains([]string{model.ChangeAddMember, model.ChangeRemoveMember, model.ChangeSetComposite,
			model.ChangeConvertToComposite}, c.Kind) {
			return fail(badRequest("invalid_change", "kind is add_member, remove_member, set_composite or convert_to_composite"))
		}
		if !idRE.MatchString(c.Group) {
			return fail(badRequest("invalid_group", "group must be a group id (a UUID)"))
		}
		ch := model.Change{Kind: c.Kind, Group: store.GroupID(c.Group), Identity: c.Identity, Member: store.GroupID(c.MemberGroup),
			Reason: c.Reason, Remove: c.Member, Op: store.CompositeOp(c.Op), DiscardMembers: c.DiscardMembers}
		var err error
		switch c.Kind {
		case model.ChangeAddMember:
			if (c.Identity == nil) == (c.MemberGroup == "") || (c.Identity != nil && *c.Identity < 1) {
				return fail(badRequest("invalid_member", "name exactly one of identity (an identity id) or member_group"))
			}
			if err = grpBodyID("member_group", c.MemberGroup); err != nil {
				return fail(err)
			}
			if ch.EnabledFrom, err = grpTimeBody("enabled_from", c.EnabledFrom); err != nil {
				return fail(err)
			}
			if ch.DisabledAt, err = grpTimeBody("disabled_at", c.DisabledAt); err != nil {
				return fail(err)
			}
			if checkTextField("reason", c.Reason, model.MaxReason) != nil {
				return fail(badRequest("invalid_reason", "reason is too long"))
			}
		case model.ChangeRemoveMember:
			if _, _, ok := model.ParseMember(c.Member); !ok {
				return fail(badRequest("invalid_member", "member is an identity id or a group id"))
			}
		default:
			if ch.Factors, err = grpFactorIDs(c.Factors); err != nil {
				return fail(err)
			}
		}
		out[i] = ch
	}
	return out, nil
}

type simMemberView struct {
	IdentityID int64  `json:"identity_id"`
	Name       string `json:"name"`
}

func simMembers(in []model.SimMember) []simMemberView {
	out := make([]simMemberView, len(in))
	for i, m := range in {
		out[i] = simMemberView{IdentityID: m.Identity, Name: m.Name}
	}
	return out
}

func (s *Server) simulateGrp(r *http.Request, _ *params) (int, any, error) {
	var in simulateIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	changes, err := simChanges(&in)
	if err != nil {
		return 0, nil, err
	}
	ck := s.grpChecker(r)
	var res *model.SimResult
	err = s.grpWrite(r, func(e model.Env) error {
		authorize := func(_ int, c model.Change) error {
			switch c.Kind {
			case model.ChangeAddMember:
				if err := memberChangeAuth(e, ck, c.Group, privs.Optin, c.Identity != nil && isSelf(ck, *c.Identity)); err != nil {
					return err
				}
				if c.Member != "" {
					return readOnAuth(e, ck, c.Member)
				}
			case model.ChangeRemoveMember:
				return memberChangeAuth(e, ck, c.Group, privs.Optout, removeSelf(ck, c.Remove))
			default:
				g, err := e.Group(c.Group)
				if err != nil {
					return err
				}
				if err := ck.Require(privs.GroupObject(g.ID), privs.Admin); err != nil {
					return err
				}
				return readOnAuth(e, ck, c.Factors...)
			}
			return nil
		}
		var err error
		res, err = e.Simulate(changes, authorize)
		var oe *model.OpError
		if errors.As(err, &oe) {
			return opFailure(oe)
		}
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	chs := make([]map[string]any, len(res.Changes))
	for i, c := range res.Changes {
		chs[i] = map[string]any{"index": c.Index, "kind": c.Kind, "group_id": string(c.Group), "name": c.Name, "status": c.Status}
	}
	groups := make([]map[string]any, len(res.Groups))
	for i, g := range res.Groups {
		groups[i] = map[string]any{"group_id": string(g.Group), "name": g.Name, "targeted": g.Targeted, "before": g.Before, "after": g.After,
			"added": g.Added, "removed": g.Removed, "added_sample": simMembers(g.AddedSample), "removed_sample": simMembers(g.RemovedSample)}
	}
	return http.StatusOK, map[string]any{"simulated": true, "changes": chs, "groups": groups, "added": res.Added, "removed": res.Removed,
		"truncated": res.Truncated}, nil
}

// ---------------------------------------------------------------- the groups of an identity

type identityGroupView struct {
	GroupID     string  `json:"group_id"`
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Type        string  `json:"type"`
	Definition  string  `json:"definition"`
	Status      string  `json:"status"`
	Since       *string `json:"since"`
}

type identityGroupList struct {
	IdentityID int64               `json:"identity_id"`
	Filter     string              `json:"filter"`
	AsOf       *string             `json:"as_of,omitempty"`
	Items      []identityGroupView `json:"items"`
	Limit      int                 `json:"limit"`
	Offset     int                 `json:"offset"`
}

func (s *Server) identityGroups(r *http.Request, p *params) (int, any, error) {
	ident, perr := strconv.ParseInt(p.path["identity_id"], 10, 64)
	tx := store.TxFrom(r.Context())
	if perr != nil || ident < 1 {
		return 0, nil, grpNotFound("identity")
	}
	if _, err := tx.Identity(ident); errors.Is(err, store.ErrNotFound) {
		return 0, nil, grpNotFound("identity")
	} else if err != nil {
		return 0, nil, err
	}
	limit, offset, err := pageParams(p)
	if err != nil {
		return 0, nil, err
	}
	list := store.MembersListID(tx.Tenant())
	if err := listParam(p, list); err != nil {
		return 0, nil, err
	}
	filter, _ := p.query("filter")
	if filter == "" {
		filter = "effective"
	}
	if !slices.Contains([]string{"effective", "direct", "indirect"}, filter) {
		return 0, nil, badRequest("invalid_filter", "filter is effective, direct or indirect")
	}
	_, at, asOf, ok, err := pitWindow(p, s.clock())
	if err != nil {
		return 0, nil, err
	}
	if ok && !asOf {
		return 0, nil, badRequest("invalid_between", "between does not apply here; use as_of")
	}
	if ok && filter != "effective" {
		return 0, nil, badRequest("invalid_filter", "filter does not apply to as_of")
	}
	// only the groups the caller may read: who is a member is what a read says
	ck := s.grpChecker(r)
	out := identityGroupList{IdentityID: ident, Filter: filter, Items: []identityGroupView{}, Limit: limit, Offset: offset}
	if ok {
		out.AsOf = rtPtr(&at)
		rows, err := visible(ck, privs.Group, limit, offset, func(l, o int) ([]*store.PitEffective, error) {
			rows, _, err := tx.GrpPitGroupsOfIdentity(ident, list, at, l, o)
			return rows, err
		}, func(row *store.PitEffective) privs.Object { return privs.GroupObject(store.GroupID(row.Group)) }, privs.Read)
		if err != nil {
			return 0, nil, err
		}
		for _, row := range rows {
			v := identityGroupView{GroupID: row.Group, Since: rtPtr(&row.StartAt)}
			if obj, err := pit.ObjectAt(tx, store.EventObjGroup, row.Group, at); err == nil {
				var snap struct {
					Name        string `json:"name"`
					DisplayName string `json:"display_name"`
					Kind        string `json:"kind"`
					Definition  string `json:"definition"`
					Status      string `json:"status"`
				}
				if json.Unmarshal(obj.Snapshot, &snap) == nil {
					v.Name, v.DisplayName, v.Type, v.Definition, v.Status = snap.Name, snap.DisplayName, snap.Kind, snap.Definition, snap.Status
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				return 0, nil, err
			}
			out.Items = append(out.Items, v)
		}
		return http.StatusOK, out, nil
	}
	now := s.clock()
	groups, err := visible(ck, privs.Group, limit, offset, func(l, o int) ([]*store.NativeGroup, error) {
		return tx.GrpGroupsOfIdentity(ident, list, filter, now, l, o)
	}, func(g *store.NativeGroup) privs.Object { return privs.GroupObject(g.ID) }, privs.Read)
	if err != nil {
		return 0, nil, err
	}
	for _, g := range groups {
		out.Items = append(out.Items, identityGroupView{GroupID: string(g.ID), Name: g.Name, DisplayName: g.DisplayName,
			Type: string(g.Kind), Definition: string(g.Definition), Status: g.Status})
	}
	return http.StatusOK, out, nil
}

// ---------------------------------------------------------------- OpenAPI

func (s *Server) groupsOpenAPI(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	routes := make([]grpapi.RouteInfo, 0, len(s.routes))
	for _, rt := range s.routes {
		if grpapi.Covers(rt.method, rt.pattern) {
			routes = append(routes, grpapi.RouteInfo{Method: rt.method, Pattern: rt.pattern, Perm: string(rt.spec.Perm), StepUp: rt.spec.Authn != nil})
		}
	}
	b, err := grpapi.OpenAPI(routes, s.authn.Cookies.Name())
	if err != nil {
		return nil, err
	}
	return rawJSON(b), nil
}
