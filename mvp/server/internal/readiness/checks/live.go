package checks

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// Live checks (§5.4). Each one calls the single read-only Prober operation
// its catalogue entry declares and judges the answer.

func live(id, op string, run func(ctx context.Context, env Env, p Params) Result) {
	register(&Check{ID: id, Kind: template.Live, Op: op, Run: run})
}

// secretShaped finds credential-looking text in config fields: API tokens,
// PEM blocks, password assignments and long high-entropy strings.
var secretShaped = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bSSWS\s+[0-9A-Za-z_-]{20,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|client_secret|api[_-]?key|token)\s*[=:]\s*\S{4,}`),
	regexp.MustCompile(`\b[A-Za-z0-9+/_-]{40,}={0,2}\b`),
}

var (
	filterItem      = regexp.MustCompile(`\(([^()&|!]+)\)`)
	filterAssertion = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.-]*(:[A-Za-z0-9.:]*)?[~<>]?=.*$`)
)

func versionAtLeast(have, want string) bool {
	var hm, hn, wm, wn int
	_, _ = fmt.Sscanf(have, "%d.%d", &hm, &hn)
	_, _ = fmt.Sscanf(want, "%d.%d", &wm, &wn)
	return hm > wm || (hm == wm && hn >= wn)
}

// filterOK checks LDAP filter syntax: balanced parentheses, a known operator
// after every "(", and an attribute=value inside every item.
func filterOK(f string) bool {
	f = strings.TrimSpace(f)
	if !strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")") {
		return false
	}
	depth := 0
	for i, r := range f {
		switch r {
		case '(':
			depth++
			if i+1 >= len(f) {
				return false
			}
		case ')':
			depth--
			if depth < 0 {
				return false
			}
			if depth == 0 && i != len(f)-1 {
				return false
			}
		}
	}
	if depth != 0 {
		return false
	}
	items := filterItem.FindAllStringSubmatch(f, -1)
	if len(items) == 0 {
		return false
	}
	for _, m := range items {
		if !filterAssertion.MatchString(m[1]) {
			return false
		}
	}
	return true
}

func init() {
	// ---- Tessera's own records
	live("cred_storage", template.OpTessera, func(_ context.Context, env Env, _ Params) Result {
		var fields []string
		for f, v := range env.ConfigStrings {
			for _, re := range secretShaped {
				if re.MatchString(v) {
					fields = append(fields, f)
					break
				}
			}
		}
		sort.Strings(fields)
		if len(fields) > 0 { // never echo the value, only the field name
			return fail("A configuration field holds a secret-shaped value; move it to the credential field.",
				map[string]any{"fields": fields})
		}
		kind, _, _ := strings.Cut(env.SecretRef, ":")
		switch kind {
		case "sealed", "vault", "agent":
			return pass("The credential is held as a "+kind+" reference.", map[string]any{"kind": kind})
		case "":
			return fail("No credential or vault reference is set.", nil)
		}
		return fail("The credential reference is not sealed, vault or agent.", nil)
	})
	live("filter_parse", template.OpTessera, func(_ context.Context, env Env, _ Params) Result {
		if len(env.Filters) == 0 {
			return fail("No search filter is configured.", nil)
		}
		var bad []string
		for name, f := range env.Filters {
			if !filterOK(f) {
				bad = append(bad, name)
			}
		}
		sort.Strings(bad)
		if len(bad) > 0 {
			return fail("These filters do not parse: "+strings.Join(bad, ", "), map[string]any{"invalid": bad})
		}
		if uf, ok := env.Filters["user_filter"]; ok && env.TemplateID == "ad" && !strings.Contains(strings.ToLower(uf), "objectcategory=person") {
			return fail("The user filter does not restrict to objectCategory=person, so computer accounts match.", nil)
		}
		return pass("Every filter parses.", map[string]any{"filters": len(env.Filters)})
	})

	// ---- transport
	live("tls_handshake", template.OpConnect, func(ctx context.Context, env Env, p Params) Result {
		ci, err := env.Probe.Connect(ctx)
		if err != nil {
			return probeErr(err)
		}
		min := p.String("min_version", "1.2")
		obs := map[string]any{"tls_version": ci.TLSVersion}
		switch {
		case !ci.Reachable || ci.TLSVersion == "":
			return fail("No TLS handshake: the server offers no LDAPS or StartTLS.", obs)
		case !versionAtLeast(ci.TLSVersion, min):
			return fail(fmt.Sprintf("TLS %s negotiated; at least %s is required.", ci.TLSVersion, min), obs)
		}
		return pass(fmt.Sprintf("TLS %s negotiated.", ci.TLSVersion), obs)
	})
	live("tls_chain", template.OpConnect, func(ctx context.Context, env Env, p Params) Result {
		ci, err := env.Probe.Connect(ctx)
		if err != nil {
			return probeErr(err)
		}
		days := int(math.Floor(ci.NotAfter.Sub(env.Now).Hours() / 24))
		obs := map[string]any{"issuer": ci.Issuer, "expires_in_days": days}
		switch {
		case !ci.ChainValid:
			return fail("The certificate does not chain to a configured CA.", obs)
		case !ci.HostnameMatch:
			return fail("The certificate does not match the host name.", obs)
		case days < p.Int("min_days_valid", 30):
			return fail(fmt.Sprintf("The certificate expires in %d days.", days), obs)
		}
		return pass(fmt.Sprintf("Chain valid; the certificate expires in %d days.", days), obs)
	})
	live("endpoint_reachable", template.OpConnect, func(ctx context.Context, env Env, _ Params) Result {
		ci, err := env.Probe.Connect(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"tls_version": ci.TLSVersion}
		if !ci.Reachable || !versionAtLeast(ci.TLSVersion, "1.2") || !ci.ChainValid {
			return fail("The endpoint is not reachable over verified TLS 1.2 or later.", obs)
		}
		return pass("Endpoint reachable over TLS "+ci.TLSVersion+".", obs)
	})

	// ---- authentication
	authOK := func(what string) func(ctx context.Context, env Env, _ Params) Result {
		return func(ctx context.Context, env Env, _ Params) Result {
			a, err := env.Probe.Authenticate(ctx)
			if err != nil {
				return probeErr(err)
			}
			obs := map[string]any{"mode": a.Mode}
			if !a.OK {
				return fail(what+" failed.", obs)
			}
			return pass(what+" succeeded.", obs)
		}
	}
	live("bind", template.OpAuthenticate, authOK("Bind"))
	live("token_acquire", template.OpAuthenticate, authOK("Token acquisition"))
	live("auth_ok", template.OpAuthenticate, authOK("Authentication"))
	live("cred_expiry", template.OpAuthenticate, func(ctx context.Context, env Env, p Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		if a.ExpiresAt == nil {
			return fail("The credential's expiry is not known.", nil)
		}
		days := int(math.Floor(a.ExpiresAt.Sub(env.Now).Hours() / 24))
		obs := map[string]any{"expires_in_days": days}
		if days <= p.Int("min_days", 30) {
			return fail(fmt.Sprintf("The credential expires in %d days.", days), obs)
		}
		return pass(fmt.Sprintf("The credential expires in %d days.", days), obs)
	})
	live("bind_identity", template.OpAuthenticate, func(ctx context.Context, env Env, _ Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		if a.RootIdentity || strings.EqualFold(a.Identity, "cn=Directory Manager") {
			return fail("The bind DN is the root DN, which bypasses all access control.", nil)
		}
		return pass("Bound as a dedicated service entry.", map[string]any{"identity": a.Identity})
	})
	live("token_roles", template.OpAuthenticate, func(ctx context.Context, env Env, p Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"roles": a.Roles}
		if len(a.Roles) == 0 {
			return fail("The access token has no roles claim: admin consent is missing.", obs)
		}
		if allowed := p.Strings("allowed"); len(allowed) > 0 {
			if extra := subset(a.Roles, allowed); len(extra) > 0 {
				return fail("The app holds permissions beyond the read-only set: "+strings.Join(extra, ", "), obs)
			}
		}
		return pass(fmt.Sprintf("%d read-only application permissions granted.", len(a.Roles)), obs)
	})
	live("token_scopes", template.OpAuthenticate, func(ctx context.Context, env Env, p Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"scopes": a.Scopes}
		var manage []string
		for _, s := range a.Scopes {
			if strings.HasSuffix(s, ".manage") {
				manage = append(manage, s)
			}
		}
		manage = append(manage, subset(a.Scopes, p.Strings("allowed"))...)
		slices.Sort(manage)
		manage = slices.Compact(manage)
		if len(manage) > 0 && len(p.Strings("allowed")) > 0 {
			return fail("Granted scopes beyond read-only: "+strings.Join(manage, ", "), obs)
		}
		return pass("Only read scopes are granted.", obs)
	})
	live("credential_type", template.OpAuthenticate, func(ctx context.Context, env Env, _ Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"mode": a.Mode}
		switch a.Mode {
		case "certificate", "federation", "oauth_private_key_jwt":
			return pass("Credential is a "+a.Mode+".", obs)
		}
		return fail("Credential is a "+a.Mode+"; use a certificate or workload identity federation.", obs)
	})
	live("auth_mode", template.OpAuthenticate, func(ctx context.Context, env Env, _ Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"mode": a.Mode}
		if a.Mode == "api_token" {
			return fail("The connection uses an SSWS API token.", obs)
		}
		return pass("OAuth 2.0 service app with "+a.Mode+".", obs)
	})
	live("dwd_scopes", template.OpAuthenticate, func(ctx context.Context, env Env, p Params) Result {
		a, err := env.Probe.Authenticate(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"scopes": a.Scopes, "write_scope_refused": len(a.RefusedScopes) > 0}
		if extra := subset(a.Scopes, p.Strings("allowed")); len(extra) > 0 {
			return fail("Delegation grants scopes beyond read-only: "+strings.Join(extra, ", "), obs)
		}
		if len(a.RefusedScopes) == 0 {
			return fail("A token for a write scope was issued: delegation is not read-only.", obs)
		}
		return pass("Only read scopes are delegated; a write scope was refused.", obs)
	})

	// ---- metadata
	live("dc_count", template.OpRootInfo, func(ctx context.Context, env Env, p Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"servers": ri.Servers}
		if ri.Servers < p.Int("min", 2) {
			return fail(fmt.Sprintf("%d domain controller configured.", ri.Servers), obs)
		}
		return pass(fmt.Sprintf("%d domain controllers reachable.", ri.Servers), obs)
	})
	live("forest_domains", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		missing := subset(ri.Domains, ri.ConfiguredDomains)
		obs := map[string]any{"domains": len(ri.Domains), "configured": len(ri.ConfiguredDomains), "missing": missing}
		if len(missing) > 0 {
			return fail("Domains with users are not configured: "+strings.Join(missing, ", "), obs)
		}
		return pass("Every user-bearing domain is configured.", obs)
	})
	live("trusts", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"trusts": len(ri.Trusts), "unconnected": len(ri.UnconnectedTrusts)}
		if len(ri.UnconnectedTrusts) > 0 {
			return fail("Trusted forests without a connection: "+strings.Join(ri.UnconnectedTrusts, ", "), obs)
		}
		return pass("Trusts inventoried.", obs)
	})
	live("recycle_bin_state", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		return pass(fmt.Sprintf("AD Recycle Bin enabled: %v.", ri.RecycleBin), map[string]any{"enabled": ri.RecycleBin})
	})
	live("schema_read", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		return pass(fmt.Sprintf("%d custom schema attributes discovered.", ri.CustomAttributes), map[string]any{"custom_attributes": ri.CustomAttributes})
	})
	live("domains_list", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		missing := subset(ri.Domains, ri.ConfiguredDomains)
		if len(missing) > 0 {
			return fail("Secondary domains not covered: "+strings.Join(missing, ", "), map[string]any{"missing": missing})
		}
		return pass(fmt.Sprintf("%d domains covered.", len(ri.Domains)), map[string]any{"domains": len(ri.Domains)})
	})
	live("ou_list", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		if ri.OrgUnits == 0 {
			return fail("No org units could be listed.", nil)
		}
		return pass(fmt.Sprintf("%d org units listed.", ri.OrgUnits), map[string]any{"org_units": ri.OrgUnits})
	})
	live("scim_discovery", template.OpRootInfo, func(ctx context.Context, env Env, _ Params) Result {
		ri, err := env.Probe.RootInfo(ctx)
		if err != nil {
			return probeErr(err)
		}
		if len(ri.Capabilities) == 0 {
			return fail("ServiceProviderConfig declared no capabilities.", nil)
		}
		return pass("Capabilities recorded: "+strings.Join(ri.Capabilities, ", "), map[string]any{"capabilities": ri.Capabilities})
	})

	// ---- object reads
	live("dn_exists", template.OpObjectExists, func(ctx context.Context, env Env, _ Params) Result {
		if len(env.BaseDNs) == 0 {
			return fail("No base DN is configured.", nil)
		}
		var missing []string
		for _, dn := range env.BaseDNs {
			ok, err := env.Probe.ObjectExists(ctx, dn)
			if err != nil {
				return probeErr(err)
			}
			if !ok {
				missing = append(missing, dn)
			}
		}
		obs := map[string]any{"base_dns": len(env.BaseDNs), "missing": len(missing)}
		if len(missing) > 0 {
			return fail("Base DNs not found: "+strings.Join(missing, "; "), obs)
		}
		return pass(fmt.Sprintf("All %d base DNs exist and are readable.", len(env.BaseDNs)), obs)
	})
	live("deleted_objects_readable", template.OpObjectExists, func(ctx context.Context, env Env, _ Params) Result {
		ok, err := env.Probe.ObjectExists(ctx, "CN=Deleted Objects")
		if err != nil {
			return probeErr(err)
		}
		if !ok {
			return fail("CN=Deleted Objects is not readable with the show-deleted control.", nil)
		}
		return pass("Deleted Objects readable (show-deleted control).", map[string]any{"readable": true})
	})

	// ---- samples
	sample := func(q connectors.SampleQuery, judge func(env Env, p Params, s connectors.SampleStats) Result) func(ctx context.Context, env Env, p Params) Result {
		return func(ctx context.Context, env Env, p Params) Result {
			q := q
			if q.Op == "search" {
				q.Filter = env.Filters["user_filter"]
			}
			if q.Op == "classes" {
				q.Classes, q.Attrs = p.Strings("classes"), env.RequiredAttrs
			}
			if q.Op == "attr" {
				q.Attrs = []string{p.String("attr", "")}
			}
			if q.Op == "page" {
				q.Limit = p.Int("page_limit", 500)
			}
			s, err := env.Probe.Sample(ctx, q)
			if err != nil {
				return probeErr(err)
			}
			return judge(env, p, s)
		}
	}
	live("sample_search", template.OpSample, sample(connectors.SampleQuery{Op: "search", Limit: 50}, func(env Env, _ Params, s connectors.SampleStats) Result {
		obs := map[string]any{"objects": s.Objects, "computers": s.PerClass["computer"]}
		switch {
		case s.Objects == 0:
			return fail("The search returned no objects.", obs)
		case s.PerClass["computer"] > 0:
			return fail("The people filter also returned computer accounts.", obs)
		}
		return pass(fmt.Sprintf("The sample search returned %d people.", s.Objects), obs)
	}))
	live("read_per_class", template.OpSample, sample(connectors.SampleQuery{Op: "classes"}, func(env Env, _ Params, s connectors.SampleStats) Result {
		obs := map[string]any{"sampled": s.Objects, "classes": len(s.PerClass), "missing_attributes": len(s.Missing)}
		if len(s.Missing) > 0 {
			return fail("Required attributes were not returned: "+strings.Join(s.Missing, ", "), obs)
		}
		return pass("Every required attribute was returned for each object class.", obs)
	}))
	live("attr_returned", template.OpSample, sample(connectors.SampleQuery{Op: "attr"}, func(env Env, p Params, s connectors.SampleStats) Result {
		attr := p.String("attr", "")
		obs := map[string]any{"attribute": attr, "present": pct(s.AttrFill[attr], s.Objects)}
		if s.AttrFill[attr] == 0 {
			return fail(attr+" was not returned (operational attributes must be requested explicitly).", obs)
		}
		return pass(attr+" returned.", obs)
	}))
	live("paging", template.OpSample, sample(connectors.SampleQuery{Op: "page"}, func(env Env, p Params, s connectors.SampleStats) Result {
		obs := map[string]any{"page_limit": p.Int("page_limit", 500), "size_limit_hit": s.SizeLimitHit}
		if s.SizeLimitHit || !s.PagedBeyond {
			return fail("Results stop at the server's page limit.", obs)
		}
		return pass("Paged results continue past the server limit.", obs)
	}))
	live("range_retrieval", template.OpSample, sample(connectors.SampleQuery{Op: "range"}, func(env Env, p Params, s connectors.SampleStats) Result {
		obs := map[string]any{"largest_group": s.LargestGroup, "ranged_count": s.RangedCount, "full_count": s.FullCount}
		if s.RangedCount != s.FullCount {
			return fail(fmt.Sprintf("Group %s returned %d of %d members.", s.LargestGroup, s.RangedCount, s.FullCount), obs)
		}
		return pass(fmt.Sprintf("Ranged retrieval returned all %d members of %s.", s.FullCount, s.LargestGroup), obs)
	}))
	available := func(what string) func(env Env, _ Params, s connectors.SampleStats) Result {
		return func(env Env, _ Params, s connectors.SampleStats) Result {
			if !s.Available {
				return fail(what+" could not be read.", map[string]any{"available": false})
			}
			return pass(what+" readable.", map[string]any{"available": true})
		}
	}
	live("roles_readable", template.OpSample, sample(connectors.SampleQuery{Op: "roles", Limit: 20}, available("Admin role assignments")))
	live("group_rules_readable", template.OpSample, sample(connectors.SampleQuery{Op: "rules", Limit: 20}, available("Group rules")))
	live("signin_activity_available", template.OpSample, sample(connectors.SampleQuery{Op: "signin", Limit: 1}, available("signInActivity")))
	live("deprovisioned_visible", template.OpSample, sample(connectors.SampleQuery{Op: "deprovisioned", Limit: 1}, available("DEPROVISIONED users")))
	live("members_complete", template.OpSample, sample(connectors.SampleQuery{Op: "members", Limit: 1}, func(env Env, _ Params, s connectors.SampleStats) Result {
		obs := map[string]any{"list_count": s.RangedCount, "get_count": s.FullCount}
		if s.RangedCount != s.FullCount {
			return fail(fmt.Sprintf("Member lists are truncated: %d on list calls, %d on get.", s.RangedCount, s.FullCount), obs)
		}
		return pass("Group membership is complete on list calls.", obs)
	}))
	live("field_inventory", template.OpSample, sample(connectors.SampleQuery{Op: "fields", Limit: 1}, func(env Env, p Params, s connectors.SampleStats) Result {
		var found []string
		for _, f := range s.Fields {
			for _, bad := range p.Strings("forbidden") {
				if strings.Contains(strings.ToLower(f), bad) {
					found = append(found, f)
				}
			}
		}
		obs := map[string]any{"fields": len(s.Fields), "forbidden": len(found)}
		if len(found) > 0 { // field names only; values are never read
			obs["forbidden_fields"] = found
			return fail("Forbidden fields are returned: "+strings.Join(found, ", "), obs)
		}
		return pass("No forbidden field in the sampled worker.", obs)
	}))

	// ---- effective rights
	rights := func(judge func(env Env, r connectors.Rights) Result) func(ctx context.Context, env Env, _ Params) Result {
		return func(ctx context.Context, env Env, _ Params) Result {
			r, err := env.Probe.EffectiveRights(ctx, "self")
			if err != nil {
				return probeErr(err)
			}
			return judge(env, r)
		}
	}
	live("ad_svc_groups", template.OpEffectiveRight, rights(func(_ Env, r connectors.Rights) Result {
		obs := map[string]any{"privileged_groups": len(r.PrivilegedSIDs), "admin_count": r.AdminCount}
		if len(r.PrivilegedSIDs) > 0 || r.AdminCount {
			return fail("The service account is in a privileged group or has adminCount=1.", obs)
		}
		return pass("The service account is in no privileged group.", obs)
	}))
	noWrite := func(_ Env, r connectors.Rights) Result {
		obs := map[string]any{"writable": len(r.Writable)}
		if len(r.Writable) > 0 {
			return fail(fmt.Sprintf("The account can write %d sampled objects or attributes.", len(r.Writable)), obs)
		}
		return pass("No effective write rights on sampled objects.", obs)
	}
	live("ad_effective_rights", template.OpEffectiveRight, rights(noWrite))
	live("effective_rights", template.OpEffectiveRight, rights(noWrite))
	live("ad_replication_rights", template.OpEffectiveRight, rights(func(_ Env, r connectors.Rights) Result {
		if r.Replication {
			return fail("The account holds Replicating Directory Changes All (DCSync).", map[string]any{"replication": true})
		}
		return pass("No replication (DCSync) right on the domain head.", map[string]any{"replication": false})
	}))
	live("app_admin_roles", template.OpEffectiveRight, rights(func(_ Env, r connectors.Rights) Result {
		obs := map[string]any{"roles": r.AdminRoles}
		for _, x := range r.AdminRoles {
			if x == "SUPER_ADMIN" || x == "ORG_ADMIN" {
				return fail("The service app holds "+x+".", obs)
			}
		}
		return pass("The service app holds a read-only admin role.", obs)
	}))
	live("subject_roles", template.OpEffectiveRight, rights(func(_ Env, r connectors.Rights) Result {
		obs := map[string]any{"roles": r.AdminRoles}
		if slices.Contains(r.AdminRoles, "SUPER_ADMIN") || slices.Contains(r.AdminRoles, "Super Admin") {
			return fail("The impersonated subject is a super admin.", obs)
		}
		return pass("The impersonated subject has a read-only role.", obs)
	}))
	live("write_scope", template.OpEffectiveRight, rights(func(env Env, r connectors.Rights) Result {
		extra := subset(r.Writable, env.WriteScope)
		obs := map[string]any{"writable": len(r.Writable), "outside_scope": len(extra)}
		if len(env.WriteScope) == 0 {
			return fail("Write-back is enabled but no write scope is configured.", obs)
		}
		if len(extra) > 0 {
			return fail("Write rights reach beyond the write scope.", obs)
		}
		return pass("Write rights are limited to the write scope.", obs)
	}))

	// ---- change tracking
	feed := func(what string) func(ctx context.Context, env Env, _ Params) Result {
		return func(ctx context.Context, env Env, _ Params) Result {
			f, err := env.Probe.ChangeFeed(ctx)
			if err != nil {
				return probeErr(err)
			}
			obs := map[string]any{"mechanism": f.Mechanism}
			if !f.Supported {
				return fail(what+" is not available.", obs)
			}
			return pass(what+" available ("+f.Mechanism+").", obs)
		}
	}
	live("incremental_capable", template.OpChangeFeed, feed("Incremental change tracking"))
	live("delta_capable", template.OpChangeFeed, feed("Delta queries"))
	live("syslog_readable", template.OpChangeFeed, feed("The System Log"))
	live("reports_readable", template.OpChangeFeed, feed("The Reports API"))
	live("dirsync_allowed", template.OpChangeFeed, func(ctx context.Context, env Env, _ Params) Result {
		f, err := env.Probe.ChangeFeed(ctx)
		if err != nil {
			return probeErr(err)
		}
		if !f.DirSyncAllowed {
			return fail("DirSync is not permitted for this account.", map[string]any{"mechanism": f.Mechanism})
		}
		return pass("DirSync permitted.", map[string]any{"mechanism": "dirsync"})
	})

	// ---- rate limits and clock
	live("rate_headroom", template.OpRateLimits, func(ctx context.Context, env Env, p Params) Result {
		r, err := env.Probe.RateLimits(ctx)
		if err != nil {
			return probeErr(err)
		}
		obs := map[string]any{"limit": r.Limit, "remaining": r.Remaining, "throttled": r.Throttled}
		if r.Throttled > 0 {
			return fail(fmt.Sprintf("%d throttled responses during validation.", r.Throttled), obs)
		}
		if r.Limit > 0 && float64(r.Remaining)/float64(r.Limit) < p.Float("min_remaining", 0.5) {
			return fail(fmt.Sprintf("Only %s of the rate limit remained.", pct(r.Remaining, r.Limit)), obs)
		}
		return pass(fmt.Sprintf("%s of the rate limit remained; no throttling.", pct(r.Remaining, r.Limit)), obs)
	})
	live("clock_skew", template.OpTime, func(ctx context.Context, env Env, p Params) Result {
		t, err := env.Probe.Time(ctx)
		if err != nil {
			return probeErr(err)
		}
		skew := math.Abs(t.Sub(env.Now).Seconds())
		obs := map[string]any{"skew_seconds": math.Round(skew)}
		switch {
		case skew >= p.Float("fail_seconds", 300):
			return fail(fmt.Sprintf("Clock skew is %.0f s.", skew), obs)
		case skew >= p.Float("warn_seconds", 120):
			return Result{Status: Warn, Message: fmt.Sprintf("Clock skew is %.0f s (warning above 120 s).", skew), Observed: obs}
		}
		return pass(fmt.Sprintf("Clock skew is %.0f s.", skew), obs)
	})
}
