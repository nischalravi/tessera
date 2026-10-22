package pam

import (
	"context"
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Target is the provisioning target of a vault: it adds and removes safe
// members at a profile. Account operations are not supported: a vault's own
// users come from its directory, not from Tessera.
//
// The entitlement is Group.ExternalID "<safe id>/<profile>" (what Discover
// emits); Account.Username is the member; Account.Attrs["member_type"] may be
// user (default), group or role.
type Target struct{ V Vault }

func (t *Target) request(ctx context.Context, r target.Request) (Safe, string, string, error) {
	safeID, profile, ok := SplitGroupID(r.Group.ExternalID)
	if !ok {
		return Safe{}, "", "", target.Permanent("the entitlement %q is not a safe and a profile (<safe>/<%s>)", r.Group.ExternalID, "list|use|read|manage")
	}
	safes, err := t.V.Safes(ctx)
	if err != nil {
		return Safe{}, "", "", wrap("find safe", err)
	}
	for _, s := range safes {
		if s.ID == safeID {
			typ := r.Account.Attrs["member_type"]
			if typ != MemberGroup && typ != MemberRole {
				typ = MemberUser
			}
			return s, profile, typ, nil
		}
	}
	return Safe{}, "", "", target.Permanent("find safe: the vault has no safe %q", safeID)
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var ue *UnsupportedError
	var nf *NotFoundError
	var se *connsync.StatusError
	switch {
	case errors.As(err, &ue), errors.As(err, &nf):
		return target.Permanent("%s: %v", op, err)
	case errors.As(err, &se):
		return target.Fail(op, se.Status, se.Code)
	}
	return target.Transport(op, err)
}

func find(ms []Member, name string) *Member {
	for i := range ms {
		if ms[i].Name == name {
			return &ms[i]
		}
	}
	return nil
}

// Apply sends the change. It is idempotent: it reads first and does nothing
// when the safe is already as asked.
func (t *Target) Apply(ctx context.Context, r target.Request) error {
	if r.Kind != target.AddEntitlement && r.Kind != target.RemoveEntitlement {
		return target.Permanent("%s is not supported by a vault target: only safe membership is", r.Kind)
	}
	s, profile, typ, err := t.request(ctx, r)
	if err != nil {
		return err
	}
	ms, err := t.V.Members(ctx, s)
	if err != nil {
		return wrap("read members", err)
	}
	m := find(ms, r.Account.Username)
	top := ""
	if m != nil {
		top = TopProfile(m.Perms)
	}
	if r.Kind == target.AddEntitlement {
		if ProfileRank(top) >= ProfileRank(profile) && top != "" {
			return nil // already holds this or more
		}
		return wrap("add member", t.V.SetMember(ctx, s, r.Account.Username, typ, profile))
	}
	switch {
	case m == nil || ProfileRank(top) < ProfileRank(profile):
		return nil // not a member at this profile
	case ProfileRank(top) > ProfileRank(profile):
		return target.Permanent("remove member: %s holds the profile %s on this safe; remove that one", r.Account.Username, top)
	}
	return wrap("remove member", t.V.RemoveMember(ctx, s, r.Account.Username))
}

// Verify re-reads the safe.
func (t *Target) Verify(ctx context.Context, r target.Request) (target.Verdict, error) {
	if r.Kind != target.AddEntitlement && r.Kind != target.RemoveEntitlement {
		return target.Verdict{}, target.Permanent("%s is not supported by a vault target", r.Kind)
	}
	s, profile, _, err := t.request(ctx, r)
	if err != nil {
		return target.Verdict{}, err
	}
	ms, err := t.V.Members(ctx, s)
	if err != nil {
		return target.Verdict{}, wrap("read members", err)
	}
	have := "not a member"
	if m := find(ms, r.Account.Username); m != nil {
		have = "member at " + orNone(TopProfile(m.Perms))
	}
	m := find(ms, r.Account.Username)
	if r.Kind == target.AddEntitlement {
		ok := m != nil && ProfileRank(TopProfile(m.Perms)) >= ProfileRank(profile)
		return target.Verdict{OK: ok, Expected: "member at " + profile + " or above", Observed: have}, nil
	}
	ok := m == nil || ProfileRank(TopProfile(m.Perms)) < ProfileRank(profile)
	return target.Verdict{OK: ok, Expected: "not a member at " + profile, Observed: have}, nil
}

func orNone(p string) string {
	if p == "" {
		return "no profile"
	}
	return p
}
