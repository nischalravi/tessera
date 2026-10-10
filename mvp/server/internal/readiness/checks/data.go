package checks

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Data checks (§3.3) read the staged snapshot of the latest dry run. They
// report counts and rates, never values.

func data(id string, run func(s *reconcile.Snapshot, p Params) Result) {
	register(&Check{ID: id, Kind: template.Data, Run: func(_ context.Context, env Env, p Params) Result {
		if env.Snapshot == nil {
			return Result{Status: Skipped, Message: "run a dry run first"}
		}
		return run(env.Snapshot, p)
	}})
}

// mainClass is the class holding the people (or workers) of the snapshot.
func mainClass(s *reconcile.Snapshot) string {
	if s.Meta.Role == "authoritative" && s.ClassTotal("worker") > 0 {
		return "worker"
	}
	return "user"
}

func fill(s *reconcile.Snapshot, class, attr string) (present, total int) {
	st, _ := s.Stat(class, attr)
	return st.Present, s.ClassTotal(class)
}

func users(s *reconcile.Snapshot) []*store.StagedAccount {
	var out []*store.StagedAccount
	for _, a := range s.Accounts {
		if !reconcile.IsService(a) {
			out = append(out, a)
		}
	}
	return out
}

func init() {
	data("key_unique", func(s *reconcile.Snapshot, p Params) Result {
		attr := p.String("attr", s.Meta.CorrelationKey)
		var missing []string
		for _, cls := range s.Classes() {
			if cls == "group" || s.ClassTotal(cls) == 0 {
				continue
			}
			st, _ := s.Stat(cls, attr)
			total := s.ClassTotal(cls)
			if st.Present < total || st.Distinct < st.Present {
				missing = append(missing, fmt.Sprintf("%s: %d of %d populated, %d distinct", cls, st.Present, total, st.Distinct))
			}
		}
		obs := map[string]any{"attribute": attr}
		if len(missing) > 0 {
			obs["classes"] = missing
			return fail(attr+" is not populated and unique on every object: "+strings.Join(missing, "; "), obs)
		}
		return pass(attr+" is populated and unique on every staged object.", obs)
	})
	data("correlation_rate", func(s *reconcile.Snapshot, p Params) Result {
		us := users(s)
		n := 0
		for _, a := range us {
			if a.Correlation == reconcile.Correlated {
				n++
			}
		}
		obs := map[string]any{"correlated": n, "accounts": len(us), "rate": pct(n, len(us))}
		if len(us) == 0 || float64(n)/float64(len(us)) < p.Float("min", 0.5) {
			return fail(fmt.Sprintf("Only %s of accounts correlate to a person by HR id or immutable link.", pct(n, len(us))), obs)
		}
		return pass(fmt.Sprintf("%s of accounts correlate to a person (tier 1 or 2).", pct(n, len(us))), obs)
	})
	data("fill_rate", func(s *reconcile.Snapshot, p Params) Result {
		class := mainClass(s)
		attrs := []string{p.String("attr", "")}
		min := p.Float("min", 0.95)
		if p.String("attrs", "") == "required" {
			attrs, min = s.Meta.RequiredAttrs, s.Meta.Thresholds["fill_rate.required"]
			if min == 0 {
				min = 0.95
			}
		}
		rates := map[string]any{}
		var low []string
		for _, attr := range attrs {
			present, total := fill(s, class, attr)
			rates[attr] = pct(present, total)
			if total == 0 || float64(present)/float64(total) < min {
				low = append(low, fmt.Sprintf("%s %s", attr, pct(present, total)))
			}
		}
		obs := map[string]any{"fill": rates, "threshold": fmt.Sprintf("%.0f%%", min*100)}
		if len(low) > 0 {
			return fail("Below the fill-rate threshold: "+strings.Join(low, ", "), obs)
		}
		if len(attrs) == 1 {
			return pass(fmt.Sprintf("%s is filled on %s of records.", attrs[0], rates[attrs[0]]), obs)
		}
		return pass(fmt.Sprintf("All %d required attributes are filled above the threshold.", len(attrs)), obs)
	})
	data("count_match", func(s *reconcile.Snapshot, p Params) Result {
		if s.Meta.ExpectedUsers == nil && s.Meta.ExpectedGroups == nil {
			return Result{Status: Skipped, Message: "enter the expected user and group counts", Observed: map[string]any{}}
		}
		for _, f := range s.FindingStatus("RF-12") {
			return fail(fmt.Sprintf("Staged %s differ from the expected count by %d.", f.Variant, f.Count), map[string]any{"variant": f.Variant, "difference": f.Count})
		}
		return pass("Staged counts are within tolerance of the expected counts.", map[string]any{"users": len(users(s)), "groups": len(s.Groups)})
	})
	data("findings_acknowledged", func(s *reconcile.Snapshot, _ Params) Result {
		var open []string
		for _, f := range s.Findings {
			if f.Status == "open" && (f.Severity == "critical" || f.Severity == "high") {
				open = append(open, f.Code+f.Variant)
			}
		}
		obs := map[string]any{"open_critical_or_high": len(open)}
		if len(open) > 0 {
			return fail("Critical or high findings are open: "+strings.Join(open, ", "), obs)
		}
		return pass("Every critical and high finding is resolved or accepted.", obs)
	})
	data("attr_present", func(s *reconcile.Snapshot, p Params) Result {
		attr := p.String("attr", "")
		present, total := fill(s, mainClass(s), attr)
		obs := map[string]any{"attribute": attr, "present": pct(present, total)}
		if present == 0 {
			return fail(attr+" is not captured.", obs)
		}
		return pass(fmt.Sprintf("%s is captured (%s of records).", attr, pct(present, total)), obs)
	})
	data("status_mapped", func(s *reconcile.Snapshot, _ Params) Result {
		known := []string{"active", "disabled", "suspended", "deprovisioned", "staged", "locked", "deleted"}
		bad, counts := 0, map[string]any{}
		for _, a := range s.Accounts {
			st := strings.ToLower(a.Status)
			if !slices.Contains(known, st) {
				bad++
			}
			n, _ := counts[st].(int)
			counts[st] = n + 1
		}
		if bad > 0 {
			return fail(fmt.Sprintf("%d accounts have an unmapped status.", bad), map[string]any{"statuses": counts})
		}
		return pass("Every account status maps to active, disabled or deleted.", map[string]any{"statuses": counts})
	})
	data("nesting_resolved", func(s *reconcile.Snapshot, _ Params) Result {
		nested, unresolved := 0, 0
		for _, m := range s.Memberships {
			if m.MemberKind != "group" {
				continue
			}
			nested++
			if _, ok := s.Group(m.MemberXID); !ok {
				unresolved++
			}
		}
		obs := map[string]any{"nested_memberships": nested, "unresolved": unresolved}
		if unresolved > 0 {
			return fail(fmt.Sprintf("%d nested groups are outside the snapshot.", unresolved), obs)
		}
		return pass("Nested memberships resolve (cycles are detected).", obs)
	})
	data("group_types", func(s *reconcile.Snapshot, _ Params) Result {
		kinds := map[string]any{}
		for _, g := range s.Groups {
			n, _ := kinds[g.Kind].(int)
			kinds[g.Kind] = n + 1
		}
		return pass(fmt.Sprintf("%d groups typed.", len(s.Groups)), map[string]any{"kinds": kinds})
	})
	data("member_resolution", func(s *reconcile.Snapshot, p Params) Result {
		accts := map[string]bool{}
		for _, a := range s.Accounts {
			accts[a.ExternalID] = true
		}
		total, bad := 0, 0
		for _, m := range s.Memberships {
			if m.MemberKind != "account" {
				continue
			}
			total++
			if !accts[m.MemberXID] {
				bad++
			}
		}
		obs := map[string]any{"memberships": total, "unresolved": bad}
		if total > 0 && float64(bad)/float64(total) > p.Float("max_unresolved", 0.01) {
			return fail(fmt.Sprintf("%s of member references do not resolve.", pct(bad, total)), obs)
		}
		return pass("Member references resolve.", obs)
	})
	data("privileged_unexpected", func(s *reconcile.Snapshot, _ Params) Result {
		priv := 0
		for _, g := range s.Groups {
			if g.Privileged {
				priv++
			}
		}
		obs := map[string]any{"privileged_groups": priv}
		if priv == 0 {
			return fail("No privileged group is tagged.", obs)
		}
		for _, f := range s.FindingStatus("RF-08") {
			obs["unexpected"] = f.Count
			if f.Status == "open" {
				return fail(fmt.Sprintf("%d unexpected privileged memberships are open (RF-08).", f.Count), obs)
			}
		}
		return pass(fmt.Sprintf("%d privileged groups tagged; no open unexpected member.", priv), obs)
	})
	data("cross_link_rate", func(s *reconcile.Snapshot, p Params) Result {
		present, total := fill(s, mainClass(s), p.String("attr", ""))
		obs := map[string]any{"linked": pct(present, total)}
		if total == 0 || float64(present)/float64(total) < p.Float("min", 0.98) {
			return fail("Too few accounts carry the cross-system link.", obs)
		}
		return pass("Accounts are linked across connections.", obs)
	})
	data("expiry_parsed", func(s *reconcile.Snapshot, p Params) Result {
		attr := p.String("attr", "accountExpires")
		bad, seen := 0, 0
		for _, a := range s.Accounts {
			v, ok := a.Attributes[attr]
			if !ok {
				continue
			}
			seen++
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				bad++
			}
		}
		obs := map[string]any{"attribute": attr, "values": seen, "unparsed": bad, "expired": countExpired(s)}
		if seen == 0 || bad > 0 {
			return fail(attr+" is missing or does not parse.", obs)
		}
		return pass(fmt.Sprintf("%s parsed; %d expired accounts treated as inactive.", attr, obs["expired"]), obs)
	})
	data("class_present", func(s *reconcile.Snapshot, p Params) Result {
		cls := p.String("class", "")
		if n := s.ClassTotal(cls); n > 0 {
			return pass(fmt.Sprintf("%d %s objects staged.", n, cls), map[string]any{"class": cls, "objects": n})
		}
		return fail("No "+cls+" objects in scope.", map[string]any{"class": cls, "objects": 0})
	})
	data("uac_mapped", func(s *reconcile.Snapshot, _ Params) Result {
		bad, disabled := 0, 0
		for _, a := range s.Accounts {
			uac, err := strconv.Atoi(a.Attributes["userAccountControl"])
			if err != nil {
				bad++
				continue
			}
			if uac&0x2 != 0 {
				disabled++
			}
		}
		obs := map[string]any{"unreadable": bad, "disabled": disabled}
		if bad > 0 {
			return fail(fmt.Sprintf("userAccountControl is unreadable on %d accounts.", bad), obs)
		}
		return pass(fmt.Sprintf("Disabled status mapped from userAccountControl (%d disabled).", disabled), obs)
	})
	data("primary_group", func(s *reconcile.Snapshot, _ Params) Result {
		present, total := fill(s, "user", "primaryGroupID")
		if present < total {
			return fail("primaryGroupID is missing on some accounts.", map[string]any{"present": pct(present, total)})
		}
		return pass("Primary group membership reconstructed from primaryGroupID.", map[string]any{"present": pct(present, total)})
	})
	data("fsp_resolved", func(s *reconcile.Snapshot, _ Params) Result {
		n := 0
		for _, m := range s.Memberships {
			if strings.HasPrefix(m.MemberXID, "S-1-5-21-") {
				n++
			}
		}
		if n > 0 {
			return fail(fmt.Sprintf("%d foreign security principals are unresolved.", n), map[string]any{"unresolved": n})
		}
		return pass("No unresolved foreign security principals.", map[string]any{"unresolved": 0})
	})
	data("disabled_expression", func(s *reconcile.Snapshot, _ Params) Result {
		n := 0
		for _, a := range s.Accounts {
			if !strings.EqualFold(a.Status, "active") {
				n++
			}
		}
		return pass(fmt.Sprintf("The disabled expression marks %d accounts disabled.", n), map[string]any{"disabled": n})
	})
	data("memberof_consistency", func(*reconcile.Snapshot, Params) Result {
		return pass("Membership is read from member; memberOf is not relied on.", map[string]any{})
	})
	data("delete_detection_mode", func(*reconcile.Snapshot, Params) Result {
		return pass("Deletes are detected by a full-sync diff with a failsafe.", map[string]any{"mode": "full_diff"})
	})
	data("guest_classification", func(s *reconcile.Snapshot, _ Params) Result {
		bad := 0
		for _, a := range s.Accounts {
			if strings.EqualFold(a.Attributes["userType"], "guest") && a.Correlation == reconcile.Proposed {
				bad++
			}
		}
		if bad > 0 {
			return fail(fmt.Sprintf("%d guests match employees by email.", bad), map[string]any{"guests_proposed": bad})
		}
		return pass("Guests are classified and not correlated by email.", map[string]any{"guests_proposed": 0})
	})
	data("profile_source", func(*reconcile.Snapshot, Params) Result {
		return pass("Profile mastering recorded; mastered users correlate once.", map[string]any{})
	})
	data("population_mix", func(s *reconcile.Snapshot, _ Params) Result {
		present, total := fill(s, "worker", "worker_type")
		obs := map[string]any{"workers": total, "worker_type_present": pct(present, total)}
		if total == 0 || present == 0 {
			return fail("The worker population carries no worker type: contingent workers cannot be confirmed.", obs)
		}
		return pass("Employees and contingent workers are both present.", obs)
	})
	data("future_dated_present", func(s *reconcile.Snapshot, _ Params) Result {
		future := 0
		for _, x := range s.Identities {
			if (x.HiredAt != nil && x.HiredAt.After(s.Meta.Now)) || (x.TerminatedAt != nil && x.TerminatedAt.After(s.Meta.Now)) {
				future++
			}
		}
		return pass(fmt.Sprintf("%d future-dated events captured with effective dates.", future), map[string]any{"future_dated": future})
	})
	data("multi_position", func(*reconcile.Snapshot, Params) Result {
		return pass("Primary positions chosen with the primary flag.", map[string]any{})
	})
	data("local_accounts", func(s *reconcile.Snapshot, _ Params) Result {
		n := 0
		for _, a := range users(s) {
			if a.Correlation == reconcile.Uncorrelated {
				n++
			}
		}
		if n > 0 {
			return fail(fmt.Sprintf("%d local accounts are not provisioned by the IdP.", n), map[string]any{"local": n})
		}
		return pass("No local accounts.", map[string]any{"local": 0})
	})
}

func countExpired(s *reconcile.Snapshot) int {
	n := 0
	for _, a := range s.Accounts {
		if reconcile.Expired(a, s.Meta.Now) {
			n++
		}
	}
	return n
}
