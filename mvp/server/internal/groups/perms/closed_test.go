package perms_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/perms"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestLimits_DenyWithMissingContextFailsClosed: a disallow limited by ipOnNetwork
// holds when the ip is missing or malformed, and is set aside only by an ip that
// was evaluated and is outside the network; an allow limited the same way still
// grants nothing without the value. The Cedar forbid is guarded with `has`.
func TestLimits_DenyWithMissingContextFailsClosed(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.staff)), w.ledger, w.read, false) // broader allow
		deny := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.entry, w.read, true)
		w.limit(t, e, deny, w.ip, "10.0.0.0/8")
		allow := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.staff)), w.entry, w.write, false)
		w.limit(t, e, allow, w.ip, "10.0.0.0/8")

		for _, tc := range []struct {
			name        string
			ctx         perms.Context
			want        bool
			wantMissing []string
		}{
			{"ip in the network", perms.Context{"ip": "10.1.2.3"}, false, nil},
			{"ip outside the network", perms.Context{"ip": "192.168.0.1"}, true, nil},
			{"ip missing", perms.Context{"hour": int64(9)}, false, []string{"ip"}},
			{"ip malformed", perms.Context{"ip": "ten"}, false, []string{"ip"}},
			{"ip of the wrong type", perms.Context{"ip": int64(5)}, false, []string{"ip"}},
		} {
			d := decide(t, c, w.alice, "app:perms:entry", "read", tc.ctx, now)
			if d.Allowed != tc.want {
				t.Errorf("%s: allowed = %v (%s), want %v", tc.name, d.Allowed, d.Reason, tc.want)
			}
			if strings.Join(d.ContextMissing, ",") != strings.Join(tc.wantMissing, ",") {
				t.Errorf("%s: context missing = %v, want %v", tc.name, d.ContextMissing, tc.wantMissing)
			}
		}
		// an allow whose limit cannot be evaluated does not grant
		if d := decide(t, c, w.pat, "app:perms:entry", "write", perms.Context{}, now); d.Allowed {
			t.Errorf("allow with a missing ctx value granted: %+v", d)
		}
		if d := decide(t, c, w.pat, "app:perms:entry", "write", perms.Context{"ip": "10.0.0.9"}, now); !d.Allowed {
			t.Errorf("allow with a matching ip: %+v, want allowed", d)
		}

		s, err := perms.Load(c)
		must(t, err)
		text := s.Policy(now)
		stanza := func(id string) string {
			i := strings.Index(text, "// assignment "+id+"\n")
			if i < 0 {
				t.Fatalf("policy lacks assignment %s:\n%s", id, text)
			}
			st := text[i:]
			if j := strings.Index(st, ";\n"); j >= 0 {
				st = st[:j]
			}
			return st
		}
		if st := stanza(deny); !strings.Contains(st, "forbid (") || !strings.Contains(st, "!(context has ip) || (context has ip && ip(context.ip).isInRange") {
			t.Errorf("forbid lacks the has guard:\n%s", st)
		}
		if st := stanza(allow); strings.Contains(st, "!(context has") {
			t.Errorf("permit must not carry the guard:\n%s", st)
		}
	})
}

// TestEffective_LimitedDisallowIsConditional: the effective view reports a
// disallow with a limit as conditional, consistently with Decide, which sets it
// aside when the limit is evaluated and fails and holds it when a value is missing.
func TestEffective_LimitedDisallowIsConditional(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.entry, w.read, false)
		deny := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.entry, w.read, true)
		w.limit(t, e, deny, w.amt, "100")
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.ledger, w.write, true) // unlimited deny

		s, err := perms.Load(c)
		must(t, err)
		sub, err := perms.SubjectOf(c, w.alice, now)
		must(t, err)
		eff, _, err := s.Effective(sub, now)
		must(t, err)
		got := map[string]perms.Effect{}
		for _, x := range eff {
			got[x.Resource+"/"+x.Action] = x
		}
		if x := got["app:perms:entry/read"]; x.Allowed || !x.Conditional {
			t.Errorf("limited disallow: %+v, want a conditional deny", x)
		}
		if x := got["app:perms:ledger/write"]; x.Allowed || x.Conditional {
			t.Errorf("unlimited disallow: %+v, want an unconditional deny", x)
		}
		for name, tc := range map[string]struct {
			ctx  perms.Context
			want bool
		}{
			"limit fails":   {perms.Context{"amount": int64(500)}, true},
			"limit holds":   {perms.Context{"amount": int64(50)}, false},
			"value missing": {perms.Context{}, false},
		} {
			if d := decide(t, c, w.alice, "app:perms:entry", "read", tc.ctx, now); d.Allowed != tc.want {
				t.Errorf("%s: allowed = %v, want %v", name, d.Allowed, tc.want)
			}
		}
	})
}
