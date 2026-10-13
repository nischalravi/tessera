package api

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/condaccess"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Conditional access administration (issue #163): named network ranges,
// access policies, the device-compliance signal, and a what-if evaluation.
// New API surface: plain JSON errors ({"error": code, "detail": msg}).
// Changes need a fresh phishing-resistant sign-in (StepUpPolicy) but are
// exempt from the privileged-scope policies themselves, so a policy can
// never lock an admin out of fixing it.

// Limits that keep a tenant's policy set (and every audit event naming it)
// small.
const (
	maxAccessPolicies   = 100
	maxNetworkRanges    = 100
	maxCIDRsPerRange    = 64
	maxSignalExpiryHour = 24 * 90
)

func (s *Server) registerAccessRoutes() {
	G, P, U, D := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	rd, wr := auth.PermConditionalAccessRead, auth.PermConditionalAccessManage
	s.handle(G, "/api/access/policies", read, need(rd), s.rd(s.listAccessPolicies))
	s.handle(P, "/api/access/policies", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.createAccessPolicy))
	s.handle(U, "/api/access/policies/{id}", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.updateAccessPolicy))
	s.handle(D, "/api/access/policies/{id}", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.deleteAccessPolicy))
	s.handle(G, "/api/access/networks", read, need(rd), s.rd(s.listNetworkRanges))
	s.handle(P, "/api/access/networks", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.createNetworkRange))
	s.handle(U, "/api/access/networks/{id}", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.updateNetworkRange))
	s.handle(D, "/api/access/networks/{id}", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.deleteNetworkRange))
	s.handle(G, "/api/access/users", read, need(rd), s.rd(s.listAccessUsers))
	s.handle(G, "/api/access/device-signals", read, need(rd), s.rd(s.listDeviceSignals))
	s.handle(U, "/api/access/device-signals/{user_id}", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.setDeviceSignal))
	s.handle(D, "/api/access/device-signals/{user_id}", write, needStepUpExempt(wr, auth.StepUpPolicy), s.rd(s.clearDeviceSignal))
	// what-if: the answer is data, recorded by nothing but its http.request
	// event, so it fails closed like a read
	s.handle(P, "/api/access/evaluate", write, need(rd), s.rd(s.evaluateAccess)).answersRead = true
}

func accessError(status int, code, msg string) error {
	return &readiness.Error{Status: status, Code: code, Msg: msg}
}

func accessNotFound(what string) error {
	return accessError(http.StatusNotFound, "not_found", "no such "+what)
}

// pathUUID reads a UUID path segment; anything else is "not found", the same
// answer as another tenant's id.
func pathUUID(p *params, name, what string) (uuid.UUID, error) {
	v := p.path[name]
	if !idRE.MatchString(v) {
		return uuid.Nil, accessNotFound(what)
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return uuid.Nil, accessNotFound(what)
	}
	return id, nil
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// ---------------------------------------------------------------- validation

func validName(v string) (string, error) {
	v = strings.TrimSpace(v)
	if n := utf8.RuneCountInString(v); n < 1 || n > 80 {
		return "", accessError(http.StatusUnprocessableEntity, "invalid_name", "name must be 1 to 80 characters")
	}
	if strings.ContainsFunc(v, unicode.IsControl) {
		return "", accessError(http.StatusUnprocessableEntity, "invalid_name", "name must not contain control characters")
	}
	return v, nil
}

func validDescription(v string) (string, error) {
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) > 500 || strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) {
		return "", accessError(http.StatusUnprocessableEntity, "invalid_description", "description must be at most 500 characters, without control characters")
	}
	return v, nil
}

// canonicalCIDRs parses CIDRs (a bare address is a single-host range) into
// their masked form, without duplicates.
func canonicalCIDRs(in []string) ([]string, error) {
	if len(in) == 0 || len(in) > maxCIDRsPerRange {
		return nil, accessError(http.StatusUnprocessableEntity, "invalid_cidrs",
			"a range needs between 1 and 64 CIDRs")
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		var p netip.Prefix
		if a, err := netip.ParseAddr(c); err == nil {
			if a.Zone() != "" {
				return nil, accessError(http.StatusUnprocessableEntity, "invalid_cidrs", "zoned addresses are not accepted")
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		} else if p, err = netip.ParsePrefix(c); err != nil {
			return nil, accessError(http.StatusUnprocessableEntity, "invalid_cidrs", "not a CIDR or address: "+truncate(c, 64))
		}
		if p.Addr().Zone() != "" {
			return nil, accessError(http.StatusUnprocessableEntity, "invalid_cidrs", "zoned addresses are not accepted")
		}
		if p.Addr().Is4In6() {
			// an IPv4-mapped prefix would never match the unmapped client address
			return nil, accessError(http.StatusUnprocessableEntity, "invalid_cidrs", "write IPv4 ranges as IPv4: "+truncate(c, 64))
		}
		m := p.Masked().String()
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- network ranges

type networkBody struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CIDRs       []string `json:"cidrs"`
}

type networkView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CIDRs       []string `json:"cidrs"`
	UsedBy      []string `json:"used_by"` // names of the policies that name the range
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func networkViewOf(n *store.NetworkRange, pols []*store.AccessPolicy) networkView {
	used := []string{}
	for _, p := range pols {
		if slices.Contains(p.NetworkRangeIDs, n.ID) {
			used = append(used, p.Name)
		}
	}
	return networkView{ID: n.ID.String(), Name: n.Name, Description: n.Description, CIDRs: n.CIDRs, UsedBy: used,
		CreatedAt: rt3339(n.CreatedAt), UpdatedAt: rt3339(n.UpdatedAt)}
}

func (s *Server) listNetworkRanges(r *http.Request, _ *params) (int, any, error) {
	c := store.TxFrom(r.Context())
	ranges, err := c.NetworkRanges()
	if err != nil {
		return 0, nil, err
	}
	pols, err := c.AccessPolicies()
	if err != nil {
		return 0, nil, err
	}
	out := make([]networkView, len(ranges))
	for i, n := range ranges {
		out[i] = networkViewOf(n, pols)
	}
	return http.StatusOK, out, nil
}

func parseNetworkBody(r *http.Request) (name, desc string, cidrs []string, err error) {
	var b networkBody
	if err = decodeBody(r, &b, false); err != nil {
		return
	}
	if name, err = validName(b.Name); err != nil {
		return
	}
	if desc, err = validDescription(b.Description); err != nil {
		return
	}
	cidrs, err = canonicalCIDRs(b.CIDRs)
	return
}

func (s *Server) createNetworkRange(r *http.Request, _ *params) (int, any, error) {
	name, desc, cidrs, err := parseNetworkBody(r)
	if err != nil {
		return 0, nil, err
	}
	c, pr, now := store.TxFrom(r.Context()), principal(r), s.clock().UTC()
	existing, err := c.NetworkRanges()
	if err != nil {
		return 0, nil, err
	}
	if len(existing) >= maxNetworkRanges {
		return 0, nil, accessError(http.StatusConflict, "limit_reached", "a tenant can have at most 100 network ranges")
	}
	n := &store.NetworkRange{Name: name, Description: desc, CIDRs: cidrs, CreatedBy: pr.UserID, CreatedAt: now, UpdatedAt: now}
	if err := c.InsertNetworkRange(n); errors.Is(err, store.ErrDuplicate) {
		return 0, nil, accessError(http.StatusConflict, "duplicate_name", "a network range with this name exists")
	} else if err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.network.create", ojson.Object{{Key: "id", Value: n.ID.String()},
		{Key: "name", Value: n.Name}, {Key: "cidrs", Value: n.CIDRs}}, audit.At(now), audit.Target("network_range", n.ID.String())); err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, networkViewOf(n, nil), nil
}

func (s *Server) updateNetworkRange(r *http.Request, p *params) (int, any, error) {
	id, err := pathUUID(p, "id", "network range")
	if err != nil {
		return 0, nil, err
	}
	name, desc, cidrs, err := parseNetworkBody(r)
	if err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	n, err := c.NetworkRange(id)
	if isNotFound(err) {
		return 0, nil, accessNotFound("network range")
	} else if err != nil {
		return 0, nil, err
	}
	before := n.CIDRs
	n.Name, n.Description, n.CIDRs, n.UpdatedAt = name, desc, cidrs, now
	if err := c.UpdateNetworkRange(n); errors.Is(err, store.ErrDuplicate) {
		return 0, nil, accessError(http.StatusConflict, "duplicate_name", "a network range with this name exists")
	} else if err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.network.update", ojson.Object{{Key: "id", Value: n.ID.String()},
		{Key: "name", Value: n.Name}, {Key: "cidrs", Value: n.CIDRs}, {Key: "previous_cidrs", Value: before}},
		audit.At(now), audit.Target("network_range", n.ID.String())); err != nil {
		return 0, nil, err
	}
	pols, err := c.AccessPolicies()
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, networkViewOf(n, pols), nil
}

func (s *Server) deleteNetworkRange(r *http.Request, p *params) (int, any, error) {
	id, err := pathUUID(p, "id", "network range")
	if err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	n, err := c.NetworkRange(id)
	if isNotFound(err) {
		return 0, nil, accessNotFound("network range")
	} else if err != nil {
		return 0, nil, err
	}
	pols, err := c.AccessPolicies()
	if err != nil {
		return 0, nil, err
	}
	if used := networkViewOf(n, pols).UsedBy; len(used) > 0 {
		return 0, nil, &readiness.Error{Status: http.StatusConflict, Code: "range_in_use",
			Msg: "the range is named by policies: " + strings.Join(used, ", "), Extra: map[string]any{"used_by": used}}
	}
	if err := c.DeleteNetworkRange(id); err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.network.delete", ojson.Object{{Key: "id", Value: id.String()},
		{Key: "name", Value: n.Name}}, audit.At(now), audit.Target("network_range", id.String())); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"deleted": id.String()}, nil
}

// ---------------------------------------------------------------- policies

type policyBody struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Scope           string   `json:"scope"`
	Mode            string   `json:"mode"`
	Outcome         string   `json:"outcome"`
	StepUpACR       *string  `json:"step_up_acr"`
	StepUpMaxAge    int      `json:"step_up_max_age"`
	NetworkOp       string   `json:"network_op"`
	NetworkRangeIDs []string `json:"network_range_ids"`
	Device          string   `json:"device"`
	Priority        *int     `json:"priority"`
}

type policyView struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Scope           string   `json:"scope"`
	Mode            string   `json:"mode"`
	Outcome         string   `json:"outcome"`
	StepUpACR       *string  `json:"step_up_acr"`
	StepUpMaxAge    int      `json:"step_up_max_age"`
	NetworkOp       string   `json:"network_op"`
	NetworkRangeIDs []string `json:"network_range_ids"`
	Device          string   `json:"device"`
	Priority        int      `json:"priority"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

func policyViewOf(p *store.AccessPolicy) policyView {
	ids := make([]string, len(p.NetworkRangeIDs))
	for i, id := range p.NetworkRangeIDs {
		ids[i] = id.String()
	}
	return policyView{ID: p.ID.String(), Name: p.Name, Description: p.Description, Scope: p.Scope, Mode: p.Mode,
		Outcome: p.Outcome, StepUpACR: p.StepUpACR, StepUpMaxAge: p.StepUpMaxAge, NetworkOp: p.NetworkOp,
		NetworkRangeIDs: ids, Device: p.Device, Priority: p.Priority, CreatedAt: rt3339(p.CreatedAt), UpdatedAt: rt3339(p.UpdatedAt)}
}

func (s *Server) listAccessPolicies(r *http.Request, _ *params) (int, any, error) {
	pols, err := store.TxFrom(r.Context()).AccessPolicies()
	if err != nil {
		return 0, nil, err
	}
	out := make([]policyView, len(pols))
	for i, p := range pols {
		out[i] = policyViewOf(p)
	}
	return http.StatusOK, out, nil
}

func oneOf(field, v string, allowed ...string) error {
	if !slices.Contains(allowed, v) {
		return accessError(http.StatusUnprocessableEntity, "invalid_"+field, field+" must be one of "+strings.Join(allowed, ", "))
	}
	return nil
}

// policyFrom validates a body into a policy (without id and timestamps). The
// tenant's ranges are those a policy may name.
func policyFrom(b policyBody, ranges []*store.NetworkRange) (*store.AccessPolicy, error) {
	name, err := validName(b.Name)
	if err != nil {
		return nil, err
	}
	desc, err := validDescription(b.Description)
	if err != nil {
		return nil, err
	}
	if b.NetworkOp == "" {
		b.NetworkOp = store.NetworkAny
	}
	if b.Device == "" {
		b.Device = store.DeviceAny
	}
	for _, c := range []struct {
		field, v string
		allowed  []string
	}{
		{"scope", b.Scope, []string{store.AccessScopeSignin, store.AccessScopePrivileged}},
		{"mode", b.Mode, []string{store.AccessModeDisabled, store.AccessModeReportOnly, store.AccessModeEnforce}},
		{"outcome", b.Outcome, []string{store.AccessAllow, store.AccessStepUp, store.AccessDeny}},
		{"network_op", b.NetworkOp, []string{store.NetworkAny, store.NetworkIn, store.NetworkNotIn}},
		{"device", b.Device, []string{store.DeviceAny, store.DeviceUnmanaged, store.DeviceNotCompliant}},
	} {
		if err := oneOf(c.field, c.v, c.allowed...); err != nil {
			return nil, err
		}
	}
	p := &store.AccessPolicy{Name: name, Description: desc, Scope: b.Scope, Mode: b.Mode, Outcome: b.Outcome,
		NetworkOp: b.NetworkOp, Device: b.Device, Priority: 100}
	if b.Priority != nil {
		if *b.Priority < 0 || *b.Priority > 10000 {
			return nil, accessError(http.StatusUnprocessableEntity, "invalid_priority", "priority must be from 0 to 10000")
		}
		p.Priority = *b.Priority
	}
	if b.StepUpMaxAge < 0 || b.StepUpMaxAge > MaxStepUpAge {
		return nil, accessError(http.StatusUnprocessableEntity, "invalid_step_up_max_age", "step_up_max_age must be from 0 to 900")
	}
	if b.Outcome == store.AccessStepUp {
		acr := authnorm.ACRPhr
		if b.StepUpACR != nil {
			acr = *b.StepUpACR
		}
		if err := oneOf("step_up_acr", acr, authnorm.ACRAAL2, authnorm.ACRPhr, authnorm.ACRPhrh); err != nil {
			return nil, err
		}
		p.StepUpACR, p.StepUpMaxAge = &acr, b.StepUpMaxAge
	} else if b.StepUpACR != nil || b.StepUpMaxAge != 0 {
		return nil, accessError(http.StatusUnprocessableEntity, "invalid_step_up_acr", "step_up_acr and step_up_max_age apply to the step_up outcome only")
	}
	known := map[uuid.UUID]bool{}
	for _, n := range ranges {
		known[n.ID] = true
	}
	for _, v := range b.NetworkRangeIDs {
		id, err := uuid.Parse(v)
		if err != nil || !idRE.MatchString(v) || !known[id] {
			// another tenant's range is "unknown" too
			return nil, accessError(http.StatusUnprocessableEntity, "unknown_network_range", "unknown network range "+truncate(v, 40))
		}
		if !slices.Contains(p.NetworkRangeIDs, id) {
			p.NetworkRangeIDs = append(p.NetworkRangeIDs, id)
		}
	}
	if (p.NetworkOp == store.NetworkAny) != (len(p.NetworkRangeIDs) == 0) {
		return nil, accessError(http.StatusUnprocessableEntity, "invalid_network_range_ids",
			"network_range_ids are required with network_op in or not_in, and must be empty with any")
	}
	return p, nil
}

func policyAudit(p *store.AccessPolicy) ojson.Object {
	ids := make([]string, len(p.NetworkRangeIDs))
	for i, id := range p.NetworkRangeIDs {
		ids[i] = id.String()
	}
	o := ojson.Object{{Key: "id", Value: p.ID.String()}, {Key: "name", Value: p.Name}, {Key: "scope", Value: p.Scope},
		{Key: "mode", Value: p.Mode}, {Key: "outcome", Value: p.Outcome}, {Key: "network_op", Value: p.NetworkOp},
		{Key: "network_range_ids", Value: ids}, {Key: "device", Value: p.Device}, {Key: "priority", Value: p.Priority}}
	if p.StepUpACR != nil {
		o = append(o, ojson.KV{Key: "step_up_acr", Value: *p.StepUpACR}, ojson.KV{Key: "step_up_max_age", Value: p.StepUpMaxAge})
	}
	return o
}

func (s *Server) createAccessPolicy(r *http.Request, _ *params) (int, any, error) {
	var b policyBody
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	c, pr, now := store.TxFrom(r.Context()), principal(r), s.clock().UTC()
	ranges, err := c.NetworkRanges()
	if err != nil {
		return 0, nil, err
	}
	p, err := policyFrom(b, ranges)
	if err != nil {
		return 0, nil, err
	}
	if n, err := c.CountAccessPolicies(); err != nil {
		return 0, nil, err
	} else if n >= maxAccessPolicies {
		return 0, nil, accessError(http.StatusConflict, "limit_reached", "a tenant can have at most 100 access policies")
	}
	p.CreatedBy, p.CreatedAt, p.UpdatedAt = pr.UserID, now, now
	if err := c.InsertAccessPolicy(p); errors.Is(err, store.ErrDuplicate) {
		return 0, nil, accessError(http.StatusConflict, "duplicate_name", "a policy with this name exists")
	} else if err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.policy.create", policyAudit(p), audit.At(now),
		audit.Target("access_policy", p.ID.String())); err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, policyViewOf(p), nil
}

func (s *Server) updateAccessPolicy(r *http.Request, p *params) (int, any, error) {
	id, err := pathUUID(p, "id", "policy")
	if err != nil {
		return 0, nil, err
	}
	var b policyBody
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	old, err := c.AccessPolicy(id)
	if isNotFound(err) {
		return 0, nil, accessNotFound("policy")
	} else if err != nil {
		return 0, nil, err
	}
	ranges, err := c.NetworkRanges()
	if err != nil {
		return 0, nil, err
	}
	np, err := policyFrom(b, ranges)
	if err != nil {
		return 0, nil, err
	}
	np.ID, np.CreatedBy, np.CreatedAt, np.UpdatedAt = old.ID, old.CreatedBy, old.CreatedAt, now
	if err := c.UpdateAccessPolicy(np); errors.Is(err, store.ErrDuplicate) {
		return 0, nil, accessError(http.StatusConflict, "duplicate_name", "a policy with this name exists")
	} else if err != nil {
		return 0, nil, err
	}
	detail := append(policyAudit(np), ojson.KV{Key: "previous", Value: policyAudit(old)})
	if _, err := audit.Record(r.Context(), c, "access.policy.update", detail, audit.At(now),
		audit.Target("access_policy", id.String())); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, policyViewOf(np), nil
}

func (s *Server) deleteAccessPolicy(r *http.Request, p *params) (int, any, error) {
	id, err := pathUUID(p, "id", "policy")
	if err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	old, err := c.AccessPolicy(id)
	if isNotFound(err) {
		return 0, nil, accessNotFound("policy")
	} else if err != nil {
		return 0, nil, err
	}
	if err := c.DeleteAccessPolicy(id); err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.policy.delete", policyAudit(old), audit.At(now),
		audit.Target("access_policy", id.String())); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"deleted": id.String()}, nil
}

// ---------------------------------------------------------------- device signals

type signalBody struct {
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	ExpiresInHours int    `json:"expires_in_hours"`
}

type signalView struct {
	UserID    string  `json:"user_id"`
	User      string  `json:"user"`
	Status    string  `json:"status"`
	Source    string  `json:"source"`
	Reason    string  `json:"reason"`
	SetAt     string  `json:"set_at"`
	ExpiresAt *string `json:"expires_at"`
	Active    bool    `json:"active"`
}

type accessUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// listAccessUsers lists the tenant's active platform users, to pick the user
// a device signal is about.
func (s *Server) listAccessUsers(r *http.Request, _ *params) (int, any, error) {
	users, err := store.TxFrom(r.Context()).PlatformUsers()
	if err != nil {
		return 0, nil, err
	}
	out := []accessUser{}
	for _, u := range users {
		if u.Status != "active" {
			continue
		}
		v := accessUser{ID: u.ID.String(), Name: u.DisplayName}
		if u.Email != nil {
			v.Email = *u.Email
		}
		out = append(out, v)
	}
	return http.StatusOK, out, nil
}

func (s *Server) listDeviceSignals(r *http.Request, _ *params) (int, any, error) {
	c, now := store.TxFrom(r.Context()), s.clock()
	sigs, err := c.DeviceSignals()
	if err != nil {
		return 0, nil, err
	}
	users, err := c.PlatformUsers()
	if err != nil {
		return 0, nil, err
	}
	names := map[uuid.UUID]string{}
	for _, u := range users {
		names[u.ID] = u.DisplayName
		if u.Email != nil && *u.Email != "" {
			names[u.ID] = *u.Email
		}
	}
	out := make([]signalView, len(sigs))
	for i, d := range sigs {
		v := signalView{UserID: d.UserID.String(), User: names[d.UserID], Status: d.Status, Source: d.Source,
			Reason: d.Reason, SetAt: rt3339(d.SetAt), Active: d.ExpiresAt == nil || now.Before(*d.ExpiresAt)}
		if d.ExpiresAt != nil {
			e := rt3339(*d.ExpiresAt)
			v.ExpiresAt = &e
		}
		out[i] = v
	}
	return http.StatusOK, out, nil
}

func (s *Server) setDeviceSignal(r *http.Request, p *params) (int, any, error) {
	uid, err := pathUUID(p, "user_id", "user")
	if err != nil {
		return 0, nil, err
	}
	var b signalBody
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	if err := oneOf("status", b.Status, store.DeviceCompliant, store.DeviceNonCompliant); err != nil {
		return 0, nil, err
	}
	reason, err := validDescription(b.Reason)
	if err != nil || utf8.RuneCountInString(reason) > 200 {
		return 0, nil, accessError(http.StatusUnprocessableEntity, "invalid_reason", "reason must be at most 200 characters")
	}
	if b.ExpiresInHours < 0 || b.ExpiresInHours > maxSignalExpiryHour {
		return 0, nil, accessError(http.StatusUnprocessableEntity, "invalid_expires_in_hours", "expires_in_hours must be from 0 to 2160")
	}
	c, pr, now := store.TxFrom(r.Context()), principal(r), s.clock().UTC()
	u, err := c.PlatformUser(uid)
	if isNotFound(err) {
		return 0, nil, accessNotFound("user")
	} else if err != nil {
		return 0, nil, err
	}
	d := &store.DeviceSignal{UserID: uid, Status: b.Status, Source: store.DeviceSourceManual, Reason: reason, SetBy: pr.UserID, SetAt: now}
	detail := ojson.Object{{Key: "user_id", Value: uid.String()}, {Key: "status", Value: b.Status},
		{Key: "source", Value: d.Source}, {Key: "reason", Value: reason}}
	if b.ExpiresInHours > 0 {
		e := now.Add(time.Duration(b.ExpiresInHours) * time.Hour)
		d.ExpiresAt = &e
		detail = append(detail, ojson.KV{Key: "expires_at", Value: rt3339(e)})
	}
	if err := c.SetDeviceSignal(d); err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.device_signal.set", detail, audit.At(now),
		audit.Target("platform_user", uid.String())); err != nil {
		return 0, nil, err
	}
	v := signalView{UserID: uid.String(), User: u.DisplayName, Status: d.Status, Source: d.Source, Reason: reason,
		SetAt: rt3339(now), Active: true}
	if d.ExpiresAt != nil {
		e := rt3339(*d.ExpiresAt)
		v.ExpiresAt = &e
	}
	return http.StatusOK, v, nil
}

func (s *Server) clearDeviceSignal(r *http.Request, p *params) (int, any, error) {
	uid, err := pathUUID(p, "user_id", "user")
	if err != nil {
		return 0, nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock().UTC()
	if err := c.ClearDeviceSignal(uid); isNotFound(err) {
		return 0, nil, accessNotFound("signal")
	} else if err != nil {
		return 0, nil, err
	}
	if _, err := audit.Record(r.Context(), c, "access.device_signal.clear", ojson.Object{{Key: "user_id", Value: uid.String()}},
		audit.At(now), audit.Target("platform_user", uid.String())); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"cleared": uid.String()}, nil
}

// ---------------------------------------------------------------- what-if

type evaluateBody struct {
	Scope            string `json:"scope"`
	ClientIP         string `json:"client_ip"`
	DeviceManaged    *bool  `json:"device_managed"`
	DeviceCompliance string `json:"device_compliance"`
}

// evaluateAccess answers what the tenant's current policies would decide for
// a described request. It changes nothing and is not an access.decision.
func (s *Server) evaluateAccess(r *http.Request, _ *params) (int, any, error) {
	var b evaluateBody
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	if err := oneOf("scope", b.Scope, store.AccessScopeSignin, store.AccessScopePrivileged); err != nil {
		return 0, nil, err
	}
	if b.DeviceCompliance == "" {
		b.DeviceCompliance = condaccess.Unknown
	}
	if err := oneOf("device_compliance", b.DeviceCompliance, condaccess.Compliant, condaccess.NotCompliant, condaccess.Unknown); err != nil {
		return 0, nil, err
	}
	in := condaccess.Input{Scope: b.Scope, IPVia: "what_if", Device: condaccess.DeviceState{Managed: b.DeviceManaged,
		Compliance: b.DeviceCompliance, ComplianceSource: "what_if"}}
	if b.ClientIP != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(b.ClientIP))
		if err != nil || a.Zone() != "" {
			return 0, nil, accessError(http.StatusUnprocessableEntity, "invalid_client_ip", "client_ip must be an IP address")
		}
		in.ClientIP = a.Unmap()
	}
	c := store.TxFrom(r.Context())
	pols, err := c.AccessPolicies()
	if err != nil {
		return 0, nil, err
	}
	ranges, err := c.NetworkRanges()
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, condaccess.Evaluate(pols, ranges, in).Audit(), nil
}
