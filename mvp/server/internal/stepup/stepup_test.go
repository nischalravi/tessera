package stepup

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
)

func catalog() Catalog {
	return BuildCatalog([]RouteDecl{
		{Method: http.MethodPut, Perm: "catalog.manage", Authn: &auth.StepUpPolicy},
		{Method: http.MethodPost, Perm: "catalog.manage", Authn: &auth.StepUpAdmin}, // a stricter route of the same action
		{Method: http.MethodGet, Perm: "catalog.manage"},                            // reads are not covered
		{Method: http.MethodPost, Perm: "requests.create"},                          // no step-up in code
		{Method: http.MethodPost, Perm: "mixed.action", Authn: &auth.StepUpPolicy},
		{Method: http.MethodPost, Perm: "mixed.action"},         // an unguarded route of an action that has a guarded one
		{Method: http.MethodPost, Perm: auth.PermAuthenticated}, // sessions are not covered
		{Method: http.MethodPut, Perm: "admin.change.request", Authn: &auth.StepUpAdmin, Exempt: true},
	})
}

func TestCatalogFloors(t *testing.T) {
	c := catalog()
	if got := c.Actions(); len(got) != 3 || got[0] != "catalog.manage" || got[1] != "mixed.action" || got[2] != "requests.create" {
		t.Fatalf("actions = %v", got)
	}
	f := c["catalog.manage"]
	if f.Req == nil || f.Req.ACR != auth.ACRPhr || f.Req.MaxAge != auth.StepUpPolicy.MaxAge || f.Unguarded || f.Routes != 2 {
		t.Errorf("catalog.manage floor = %+v (want the weakest, the 15 minute one)", f)
	}
	if g := c["requests.create"]; g.Req != nil || !g.Unguarded {
		t.Errorf("requests.create = %+v", g)
	}
}

func TestValidate_NeverBelowTheFloor(t *testing.T) {
	c := catalog()
	e := func(acr auth.ACR, s int) Entry { return Entry{ACR: acr, MaxAge: time.Duration(s) * time.Second} }
	for _, tc := range []struct {
		name string
		p    Policy
		weak bool
		want string // error code, "" for accepted
	}{
		{"stricter age", Policy{"catalog.manage": e(auth.ACRPhr, 120)}, false, ""},
		{"stronger acr", Policy{"catalog.manage": e(auth.ACRPhrh, 900)}, false, ""},
		{"equal to the floor", Policy{"catalog.manage": e(auth.ACRPhr, 900)}, false, ""},
		{"adds step-up where there is none", Policy{"requests.create": e(auth.ACRAAL2, 600)}, false, ""},
		{"mixed action: below the guarded floor adds to the unguarded route", Policy{"mixed.action": e(auth.ACRAAL2, 1800)}, false, ""},
		{"weaker acr", Policy{"catalog.manage": e(auth.ACRAAL2, 300)}, false, "weaker_than_required"},
		{"older sign-in allowed", Policy{"catalog.manage": e(auth.ACRPhr, 1800)}, false, "weaker_than_required"},
		{"weaker, with the dev switch", Policy{"catalog.manage": e(auth.ACRAAL2, 1800)}, true, ""},
		{"unknown action", Policy{"nope.nothing": e(auth.ACRPhr, 300)}, false, "unknown_action"},
		{"a read-only permission is no action", Policy{"graph.read": e(auth.ACRPhr, 300)}, false, "unknown_action"},
		{"the policy's own permission is exempt", Policy{"admin.change.request": e(auth.ACRPhrh, 60)}, false, "unknown_action"},
		{"plain sign-in is no step-up", Policy{"requests.create": e(auth.ACRAAL1, 300)}, false, "invalid_acr"},
		{"age too short", Policy{"requests.create": e(auth.ACRPhr, 30)}, false, "invalid_max_age"},
		{"age too long", Policy{"requests.create": e(auth.ACRPhr, 7200)}, false, "invalid_max_age"},
	} {
		err := c.Validate(tc.p, tc.weak)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		ce, ok := err.(*cfgerr.Error)
		if !ok || ce.Code != tc.want || ce.Status != 422 {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.want)
		}
	}
}

func TestEffective(t *testing.T) {
	floor := &auth.StepUpPolicy // phr within 15 minutes
	pol := Policy{
		"a": {ACR: auth.ACRPhrh, MaxAge: 600 * time.Second},
		"b": {ACR: auth.ACRAAL2, MaxAge: 3600 * time.Second}, // weaker than the floor on both counts
		"c": {ACR: auth.ACRAAL2, MaxAge: 300 * time.Second},
	}
	for _, tc := range []struct {
		name  string
		perm  auth.Permission
		floor *auth.AuthnRequirement
		weak  bool
		want  *auth.AuthnRequirement
	}{
		{"no entry keeps the code's", "z", floor, false, floor},
		{"no entry, no floor: none", "z", nil, false, nil},
		{"stricter on both", "a", floor, false, &auth.AuthnRequirement{ACR: auth.ACRPhrh, MaxAge: 600 * time.Second}},
		{"a weaker entry never lowers the floor", "b", floor, false, floor},
		{"mixed: stronger age, floor acr", "c", floor, false, &auth.AuthnRequirement{ACR: auth.ACRPhr, MaxAge: 300 * time.Second}},
		{"an entry adds step-up where there is none", "c", nil, false, &auth.AuthnRequirement{ACR: auth.ACRAAL2, MaxAge: 300 * time.Second}},
		{"dev switch replaces the floor", "b", floor, true, &auth.AuthnRequirement{ACR: auth.ACRAAL2, MaxAge: 3600 * time.Second}},
	} {
		got := pol.Effective(tc.perm, tc.floor, tc.weak)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// the floor value is never modified through the result
	_ = pol.Effective("a", floor, false)
	if *floor != auth.StepUpPolicy {
		t.Errorf("the shared floor was changed: %+v", *floor)
	}
}

func TestApplies(t *testing.T) {
	for _, tc := range []struct {
		method string
		perm   auth.Permission
		exempt bool
		want   bool
	}{
		{http.MethodPost, "catalog.manage", false, true},
		{http.MethodDelete, "catalog.manage", false, true},
		{http.MethodGet, "catalog.manage", false, false},
		{http.MethodPost, auth.PermAuthenticated, false, false},
		{http.MethodPost, "catalog.manage", true, false},
		{http.MethodPost, "", false, false},
	} {
		if got := Applies(tc.method, tc.perm, tc.exempt); got != tc.want {
			t.Errorf("Applies(%s, %q, %v) = %v", tc.method, tc.perm, tc.exempt, got)
		}
	}
	if !strings.Contains(string(ACRs[0]), "aal2") {
		t.Errorf("ACRs = %v", ACRs)
	}
}
