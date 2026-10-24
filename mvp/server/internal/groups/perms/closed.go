package perms

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Fail-closed evaluation, used for a disallow: a limit that cannot be evaluated
// because a context value is missing or malformed must not switch the deny off.
// An allow keeps Holds, where such a limit does not grant.

// unknown reports the context attribute a leaf condition needs when the context
// does not carry it in a usable form (absent, the wrong type, or an ip that does
// not parse).
func unknown(c Cond, ctx Context) (string, bool) {
	switch x := c.(type) {
	case cmp:
		v, ok := ctx[x.Attr]
		if ok {
			if x.Int != nil {
				_, ok = v.(int64)
			} else {
				_, ok = v.(string)
			}
		}
		return x.Attr, !ok
	case ipIn:
		s, ok := ctx["ip"].(string)
		if ok {
			_, err := netip.ParseAddr(s)
			ok = err == nil
		}
		return "ip", !ok
	case hourIn:
		_, ok := ctx["hour"].(int64)
		return "hour", !ok
	}
	return "", false
}

// HoldsClosed evaluates a condition for a disallow: a leaf whose context value is
// missing or malformed counts as holding, so a deny is set aside only when its
// limit was evaluated and failed. It also returns the context keys that were
// missing or malformed, sorted.
func HoldsClosed(c Cond, ctx Context) (bool, []string) {
	seen := map[string]bool{}
	ok := holdsClosed(c, ctx, seen)
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return ok, keys
}

func holdsClosed(c Cond, ctx Context, seen map[string]bool) bool {
	switch x := c.(type) {
	case allOf:
		ok := true
		for _, p := range x {
			if !holdsClosed(p, ctx, seen) {
				ok = false
			}
		}
		return ok
	case anyOf:
		ok := false
		for _, p := range x {
			if holdsClosed(p, ctx, seen) {
				ok = true
			}
		}
		return ok
	}
	if k, u := unknown(c, ctx); u {
		seen[k] = true
		return true
	}
	return c.Holds(ctx)
}

// CedarClosed renders a condition for a forbid: each leaf is guarded so it also
// holds when its context attribute is absent (`!(context has ip) || ...`), the
// Cedar form of failing closed. A present but malformed value still errors in
// Cedar, which skips the policy; Decide is the authority there.
func CedarClosed(c Cond) string {
	switch x := c.(type) {
	case allOf:
		return joinClosed(x, " && ", "true")
	case anyOf:
		return joinClosed(x, " || ", "false")
	}
	k, _ := unknown(c, Context{})
	return fmt.Sprintf("!(context has %s) || (%s)", k, c.Cedar())
}

func joinClosed(cs []Cond, sep, empty string) string {
	switch len(cs) {
	case 0:
		return empty
	case 1:
		return CedarClosed(cs[0])
	}
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = "(" + CedarClosed(c) + ")"
	}
	return strings.Join(parts, sep)
}
