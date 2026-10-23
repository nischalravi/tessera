package perms

import (
	"strings"
	"testing"
)

func TestCompileLimit_Table(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		cedar  string // "" for an invalid limit
		ctx    Context
		holds  bool
	}{
		{"amountLessThan", []string{"100"}, `context has amount && context.amount < 100`, Context{"amount": int64(5)}, true},
		{"x:y:AMOUNTLESSTHAN", []string{"100"}, `context.amount < 100`, Context{"amount": int64(100)}, false},
		{"amountLessThan", []string{"100", "50"}, `(context has amount && context.amount < 100) && (context has amount && context.amount < 50)`, Context{"amount": int64(70)}, false},
		{"amountLessThan", []string{"1.5"}, "", nil, false},
		{"amountLessThan", nil, "", nil, false},
		{"ipOnNetwork", []string{"10.1.2.3/8"}, `ip(context.ip).isInRange(ip("10.0.0.0/8"))`, Context{"ip": "10.200.0.1"}, true},
		{"ipOnNetwork", []string{"2001:db8::/32"}, `ip("2001:db8::/32")`, Context{"ip": "2001:db8::1"}, true},
		{"ipOnNetwork", []string{"10.0.0.0/8"}, `isInRange`, Context{"ip": "::ffff:10.0.0.1"}, true},
		{"ipOnNetwork", []string{"10.0.0.0"}, "", nil, false},
		{"timeWindow", []string{"0-24"}, `context.hour >= 0 && context.hour < 24`, Context{"hour": int64(23)}, true},
		{"timeWindow", []string{"9-17", "20-22"}, `||`, Context{"hour": int64(21)}, true},
		{"timeWindow", []string{"17-9"}, "", nil, false},
		{"timeWindow", []string{"9-25"}, "", nil, false},
		{"expression", []string{`tier >= 3`}, `context has tier && context.tier >= 3`, Context{"tier": int64(3)}, true},
		{"expression", []string{`region != "apac"`}, `context.region != "apac"`, Context{"region": "emea"}, true},
		{"expression", []string{`region < "m"`}, "", nil, false},
		{"expression", []string{`region == "a" || true`}, "", nil, false},
		{"expression", []string{`1 == 1`}, "", nil, false},
		{"expression", []string{`a == "x\"y"`}, "", nil, false},
		{"weekdays", []string{"mon"}, "", nil, false},
	} {
		c, err := CompileLimit(tc.name, tc.values)
		if tc.cedar == "" {
			if err == nil {
				t.Errorf("%s %v: compiled, want an error", tc.name, tc.values)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %v: %v", tc.name, tc.values, err)
			continue
		}
		if !strings.Contains(c.Cedar(), tc.cedar) {
			t.Errorf("%s %v: cedar = %s, want it to contain %s", tc.name, tc.values, c.Cedar(), tc.cedar)
		}
		if got := c.Holds(tc.ctx); got != tc.holds {
			t.Errorf("%s %v with %v: holds = %v, want %v", tc.name, tc.values, tc.ctx, got, tc.holds)
		}
	}
}

// TestCompileLimits_AllMustHold: several limits on one assignment are a conjunction.
func TestCompileLimits_AllMustHold(t *testing.T) {
	c, err := CompileLimits([]Limit{{"a:b:amountLessThan", []string{"10"}}, {"a:b:timeWindow", []string{"9-17"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Holds(Context{"amount": int64(1), "hour": int64(10)}) || c.Holds(Context{"amount": int64(1), "hour": int64(18)}) ||
		c.Holds(Context{"amount": int64(11), "hour": int64(10)}) {
		t.Error("conjunction wrong")
	}
	if c, err := CompileLimits(nil); c != nil || err != nil {
		t.Errorf("no limits = %v, %v", c, err)
	}
	if _, err := CompileLimits([]Limit{{"a:b:bogus", []string{"1"}}}); err == nil {
		t.Error("unknown limit compiled")
	}
}
