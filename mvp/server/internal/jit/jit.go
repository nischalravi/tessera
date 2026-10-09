// Package jit implements just-in-time access: time-bound group/role
// membership with auto-expiry.
package jit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// MaxHours is the longest grant that can be requested.
const MaxHours = 72

// Error is a request the caller can fix (mapped to HTTP 400).
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func jitErr(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Hours is a requested duration. Whole marks a value supplied as an integer
// (the API's default of 4, or the seed's literals): the creation response and
// the audit log render it as 4 rather than 4.0, as the original backend did.
type Hours struct {
	N     float64
	Whole bool
}

// JSON returns the value as the API renders it.
func (h Hours) JSON() any {
	if h.Whole && h.N == float64(int64(h.N)) {
		return int64(h.N)
	}
	return ojson.Float(h.N)
}

// AccountFor picks the account that receives the grant: same system as the
// group, else the IdP (Okta) account.
func AccountFor(c *store.Conn, identityID int64, g *store.Group) (*store.Account, error) {
	accts, err := c.Accounts("WHERE identity_id = ? AND status = 'active'", identityID)
	if err != nil {
		return nil, err
	}
	for _, system := range []string{g.System, "okta"} {
		for _, a := range accts {
			if a.System == system {
				return a, nil
			}
		}
	}
	return nil, jitErr("identity has no active account that can receive this grant")
}

func getOrNil[T any](v *T, err error) (*T, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return v, err
}

// CreateRequest files a pending request.
func CreateRequest(c *store.Conn, now time.Time, identityID, groupID int64, hours Hours, justification string) (*store.AccessRequest, error) {
	ident, err := getOrNil(c.Identity(identityID))
	if err != nil {
		return nil, err
	}
	g, err := getOrNil(c.Group(groupID))
	if err != nil {
		return nil, err
	}
	if ident == nil || g == nil {
		return nil, jitErr("unknown identity or group")
	}
	if ident.Status != "active" {
		return nil, jitErr("identity is not active")
	}
	if !g.Requestable {
		return nil, jitErr("%s is not eligible for just-in-time access", g.Name)
	}
	if !(hours.N > 0 && hours.N <= MaxHours) {
		return nil, jitErr("duration must be between 0 and %d hours", MaxHours)
	}
	justification = strings.TrimSpace(justification)
	if justification == "" {
		return nil, jitErr("justification is required")
	}
	acct, err := AccountFor(c, identityID, g)
	if err != nil {
		return nil, err
	}
	n, err := c.Count("SELECT count(*) FROM grant_edges WHERE src = ? AND dst = ? AND source != 'jit'",
		graph.Key("account", acct.ID), graph.Key("group", g.ID))
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, jitErr("%s already holds %s as a standing grant", ident.Name, g.Name)
	}
	id, err := c.Insert(`INSERT INTO access_requests (identity_id, account_id, group_id, justification, duration_hours, status,
		requested_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)`, identityID, acct.ID, g.ID, justification, hours.N, store.T(now))
	if err != nil {
		return nil, err
	}
	if err := c.Audit(now, ident.Name, "jit.request", ojson.Object{{Key: "request_id", Value: id},
		{Key: "group", Value: g.Name}, {Key: "hours", Value: hours.JSON()}}); err != nil {
		return nil, err
	}
	return c.Request(id)
}

func pending(c *store.Conn, id int64) (*store.AccessRequest, error) {
	r, err := getOrNil(c.Request(id))
	if err != nil {
		return nil, err
	}
	if r == nil || r.Status != "pending" {
		return nil, jitErr("request is not pending")
	}
	return r, nil
}

// Approve grants the access until now + duration. createdAt stamps a newly
// created edge (the wall clock, which differs from now when back-dating).
func Approve(c *store.Conn, requestID int64, approver string, now, createdAt time.Time) (*store.AccessRequest, error) {
	req, err := pending(c, requestID)
	if err != nil {
		return nil, err
	}
	src, dst := graph.Key("account", req.AccountID), graph.Key("group", req.GroupID)
	existing, err := getOrNil(c.EdgeBetween(src, dst))
	if err != nil {
		return nil, err
	}
	expires := now.Add(timeutil.Delta(req.DurationHours, timeutil.MicrosPerHour))
	if existing != nil && existing.Source != "jit" {
		return nil, jitErr("identity already holds this access as a standing grant")
	}
	var edgeID int64
	if existing == nil {
		edgeID, err = c.Insert(`INSERT INTO grant_edges (src, dst, relation, source, expires_at, created_at)
			VALUES (?, ?, 'member_of', 'jit', ?, ?)`, src, dst, store.T(expires), store.T(createdAt))
	} else {
		edgeID = existing.ID
		_, err = c.Exec("UPDATE grant_edges SET expires_at = ? WHERE id = ?", store.T(expires), edgeID)
	}
	if err != nil {
		return nil, err
	}
	req.Status, req.DecidedAt, req.DecidedBy, req.ExpiresAt, req.EdgeID = "approved", &now, &approver, &expires, &edgeID
	if err := c.SaveRequest(req); err != nil {
		return nil, err
	}
	if err := c.Audit(createdAt, approver, "jit.approve", ojson.Object{{Key: "request_id", Value: req.ID},
		{Key: "expires_at", Value: timeutil.ISO(expires)}}); err != nil {
		return nil, err
	}
	return req, nil
}

// Deny rejects a pending request.
func Deny(c *store.Conn, requestID int64, approver string, now time.Time) (*store.AccessRequest, error) {
	req, err := pending(c, requestID)
	if err != nil {
		return nil, err
	}
	req.Status, req.DecidedAt, req.DecidedBy = "denied", &now, &approver
	if err := c.SaveRequest(req); err != nil {
		return nil, err
	}
	return req, c.Audit(now, approver, "jit.deny", ojson.Object{{Key: "request_id", Value: req.ID}})
}

// Revoke ends an active grant early.
func Revoke(c *store.Conn, requestID int64, actor string, now time.Time) (*store.AccessRequest, error) {
	req, err := getOrNil(c.Request(requestID))
	if err != nil {
		return nil, err
	}
	if req == nil || req.Status != "approved" {
		return nil, jitErr("request is not active")
	}
	if err := dropEdge(c, req); err != nil {
		return nil, err
	}
	req.Status, req.ExpiresAt = "revoked", &now
	if err := c.SaveRequest(req); err != nil {
		return nil, err
	}
	return req, c.Audit(now, actor, "jit.revoke", ojson.Object{{Key: "request_id", Value: req.ID}})
}

func dropEdge(c *store.Conn, req *store.AccessRequest) error {
	if req.EdgeID == nil || *req.EdgeID == 0 {
		return nil
	}
	_, err := c.Exec("DELETE FROM grant_edges WHERE id = ? AND source = 'jit'", *req.EdgeID)
	return err
}

// NeedsSweep reports whether Sweep would change anything at now.
func NeedsSweep(c *store.Conn, now time.Time) (bool, error) {
	n, err := c.Count(`SELECT (SELECT count(*) FROM access_requests WHERE status = 'approved' AND expires_at <= ?)
		+ (SELECT count(*) FROM grant_edges WHERE source = 'jit' AND expires_at <= ?)`, store.T(now), store.T(now))
	return n > 0, err
}

// Sweep expires approved requests past their deadline, removes their grant
// edges and any orphaned expired JIT edges. It returns the number of
// requests expired.
func Sweep(c *store.Conn, now time.Time) (int, error) {
	reqs, err := c.Requests("WHERE status = 'approved' AND expires_at <= ? ORDER BY id", store.T(now))
	if err != nil {
		return 0, err
	}
	for _, r := range reqs {
		if err := dropEdge(c, r); err != nil {
			return 0, err
		}
		r.Status = "expired"
		if err := c.SaveRequest(r); err != nil {
			return 0, err
		}
		if err := c.Audit(now, "system", "jit.expire", ojson.Object{{Key: "request_id", Value: r.ID}}); err != nil {
			return 0, err
		}
	}
	// orphan JIT edges (e.g. created directly) also expire
	if _, err := c.Exec("DELETE FROM grant_edges WHERE source = 'jit' AND expires_at <= ?", store.T(now)); err != nil {
		return 0, err
	}
	return len(reqs), nil
}
