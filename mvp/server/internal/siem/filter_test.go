package siem

import "testing"

// A sink's filter never hides changes to log streaming, the ledger, admin changes or privileged sign-in (issue #511).
func TestEventMatchesAlwaysDelivers(t *testing.T) {
	narrow := []string{"grant.revoke"}
	for action, want := range map[string]bool{
		"grant.revoke": true, "grant.create": false, "auth.login.success": false,
		"siem.sink.updated": true, "siem.sink.filter_changed": true, "audit.checkpoint.created": true, "audit.verify": true,
		"admin.change.applied": true, "admin.change.submitted": true, "auth.break_glass.used": true, "breakglass.action": true,
		"auth.step_up.failure": true, "auth.role.granted": true, "stepup.policy.update": true, "deletion_guard.policy_changed": true,
		"administrator.thing": false,
	} {
		if got := EventMatches(narrow, action); got != want {
			t.Errorf("EventMatches(%v, %q) = %v, want %v", narrow, action, got, want)
		}
	}
}

func TestNarrows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cur, next []string
		want      bool
	}{
		{"every event to one action", nil, []string{"grant.revoke"}, true},
		{"star to a prefix", []string{"*"}, []string{"auth.*"}, true},
		{"clearing", []string{"grant.revoke"}, nil, false},
		{"to star", []string{"grant.revoke"}, []string{"*"}, false},
		{"empty to empty", nil, nil, false},
		{"same", []string{"a.b", "c.*"}, []string{"c.*", "a.b"}, false},
		{"a subset", []string{"a.b", "c.d"}, []string{"a.b"}, true},
		{"a superset", []string{"a.b"}, []string{"a.b", "c.d"}, false},
		{"an action to its prefix", []string{"auth.login.success"}, []string{"auth.*"}, false},
		{"a prefix to one of its actions", []string{"auth.*"}, []string{"auth.login.success"}, true},
		{"a prefix to a narrower prefix", []string{"auth.*"}, []string{"auth.login.*"}, true},
		{"a prefix to a wider prefix", []string{"auth.login.*"}, []string{"auth.*"}, false},
		{"swapping an entry", []string{"a.b"}, []string{"c.d"}, true},
	} {
		if got := Narrows(tc.cur, tc.next); got != tc.want {
			t.Errorf("%s: Narrows(%v, %v) = %v, want %v", tc.name, tc.cur, tc.next, got, tc.want)
		}
	}
}
