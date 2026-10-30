package jit_test

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// JIT eligibility enforcement (issue #651, AC-5) in the tiny world: alice and carol are in okta:eng, bob is in
// okta:payments-approvers, aws:ProdAdmin is requestable, aws:DevAdmin is not.

func jitCode(err error) string {
	var je *jit.Error
	if errors.As(err, &je) {
		return je.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func TestEligibilityDenyByDefault(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	user := func(identity string) store.UserRef {
		var ref store.UserRef
		testkit.Write(t, st, func(c *store.TenantTx) error {
			iid := ids[identity]
			u := &store.PlatformUser{DisplayName: identity, IdentityID: &iid, CreatedAt: now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			ref = store.UserRef{ID: u.ID, Display: identity}
			return nil
		})
		return ref
	}
	request := func(who, group string, hours float64) (*store.AccessRequest, error) {
		var r *store.AccessRequest
		var err error
		testkit.Write(t, st, func(c *store.TenantTx) error {
			r, err = jit.CreateRequest(c, now, ids[who], ids["group:"+group], jit.Hours{N: hours}, "incident", store.UserRef{})
			return nil
		})
		return r, err
	}
	approve := func(id int64, by store.UserRef) error {
		var err error
		testkit.Write(t, st, func(c *store.TenantTx) error { _, err = jit.Approve(c, id, by, now, now); return nil })
		return err
	}

	// until a tenant applies rules, groups.requestable decides
	if _, err := request("alice", "okta:eng", 2); err == nil {
		t.Error("a group that is not requestable was requested before eligibility is on")
	}
	if r, err := request("alice", "aws:ProdAdmin", 2); err != nil {
		t.Fatalf("requestable group before eligibility is on: %v", err)
	} else if err := approve(r.ID, store.UserRef{Display: "approver"}); err != nil {
		t.Fatal(err)
	}

	// one rule: people in okta:eng may ask for aws:DevAdmin for 4 hours, okta:payments-approvers decide
	var ruleID string
	testkit.Write(t, st, func(c *store.TenantTx) error {
		e := &store.JITEligibility{Key: "dev-admin", Status: store.JITEligibilityActive, MaxHours: 4, Version: 1, CreatedAt: now, UpdatedAt: now}
		if err := c.InsertJITEligibility(e); err != nil {
			return err
		}
		ruleID = e.ID
		for role, g := range map[string]string{store.JITPrincipal: "okta:eng", store.JITEntitlement: "aws:DevAdmin", store.JITApprover: "okta:payments-approvers"} {
			if err := c.SetJITEligibilityGroups(e.ID, role, []int64{ids["group:"+g]}); err != nil {
				return err
			}
		}
		return c.PutJITSettings(true, "test", now)
	})

	for _, tc := range []struct {
		name, who, group string
		hours            float64
		want             string
	}{
		{"covered", "carol", "aws:DevAdmin", 4, ""},
		{"a requestable group no rule names is denied", "carol", "aws:ProdAdmin", 1, jit.CodeNotEligible},
		{"a person outside the principal groups", "bob", "aws:DevAdmin", 1, jit.CodeNotEligible},
		{"longer than the rule allows", "alice", "aws:DevAdmin", 4.5, jit.CodeNotEligible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := request(tc.who, tc.group, tc.hours); jitCode(err) != tc.want {
				t.Errorf("err = %v; want code %q", err, tc.want)
			}
		})
	}

	// approval: only a person in an approver group of the rule
	r, err := request("alice", "aws:DevAdmin", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := approve(r.ID, user("carol")); jitCode(err) != jit.CodeNotApprover {
		t.Errorf("an approval by someone outside the approver groups: %v; want %s", err, jit.CodeNotApprover)
	}
	// a retired rule no longer allows the request, so it cannot be approved either
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.SaveJITEligibility(&store.JITEligibility{ID: ruleID, Status: store.JITEligibilityRetired, MaxHours: 4, Version: 2, UpdatedAt: now}, 1)
	})
	if err := approve(r.ID, user("bob")); jitCode(err) != jit.CodeNotEligible {
		t.Errorf("an approval after the rule was retired: %v; want %s", err, jit.CodeNotEligible)
	}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return c.SaveJITEligibility(&store.JITEligibility{ID: ruleID, Status: store.JITEligibilityActive, MaxHours: 4, Version: 3, UpdatedAt: now}, 2)
	})
	if err := approve(r.ID, user("bob")); err != nil {
		t.Errorf("an approval by an approver: %v", err)
	}

	// turning enforcement off hands the decision back to groups.requestable
	testkit.Write(t, st, func(c *store.TenantTx) error { return c.PutJITSettings(false, "test", now) })
	if _, err := request("carol", "aws:DevAdmin", 1); err == nil {
		t.Error("a group that is not requestable was requested once eligibility was off")
	}
}
