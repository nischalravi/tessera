package readiness

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/nischalravi/tessera/mvp/server/internal/urlshape"
)

// URL-valued settings of a connection (issue #908). A URL carrying userinfo, or a query string or fragment on
// base_url / org_url, is refused on save (urlCredentialError). One that is already stored is shown masked
// (MaskURL), and a masked value sent back unchanged keeps the stored one (keepMaskedURLs), so a client that loads a
// connection and saves it whole cannot overwrite a stored value with its mask.

// URLMask is the fixed text that replaces a credential or a query value in a masked URL.
const URLMask = "masked"

// CodeURLCredentialsRefused is the error code of a URL setting that carries credentials or a query string.
const CodeURLCredentialsRefused = "url_credentials_refused"

// CodeURLNonASCIIAuthority is the error code of a base_url, org_url or URL setting whose scheme or authority is not ASCII.
const CodeURLNonASCIIAuthority = "url_non_ascii_authority"

// urlSetting reports whether a settings entry holds a URL (urlshape.URLSetting: its key names one, or its value reads
// as a URL that names a host).
func urlSetting(k, v string) bool { return urlshape.URLSetting(k, v) }

// urlRisk reports whether v carries userinfo, or (strict) a query string or fragment. v is read as a lenient URL
// parser reads it (urlshape.Classify), so "https:u:p@h" and backslash or whitespace separators count as "https://".
// strict also refuses an "@" in a value with any other scheme prefix ("u:p@host", "ldap:u:p@h"): whether such a
// value names credentials depends on the reader. v is also read folded (urlshape.Fold), so zero-width or fullwidth
// separators ("https\u200b://", "https\uff1a//", "u:p\uff20h") do not hide a credential (issue #932).
func urlRisk(v string, strict bool) bool {
	if f := urlshape.Fold(v); f != v && rawURLRisk(f, strict) {
		return true
	}
	return rawURLRisk(v, strict)
}

func rawURLRisk(v string, strict bool) bool {
	canon, sh := urlshape.Classify(v)
	if urlshape.Embedded(v) {
		// a URL inside a longer value: refused as an unparseable value was before urlshape
		return strings.Contains(canon, "@") || (strict && strings.ContainsAny(canon, "?#"))
	}
	switch sh {
	case urlshape.NotURL:
		return false
	case urlshape.Opaque:
		return strict && strings.Contains(canon, "@")
	}
	u, err := url.Parse(canon)
	if err != nil {
		return strings.ContainsAny(canon, "@?#")
	}
	// strict: an "@" anywhere is refused, so a password holding "/", "?" or "#" (which net/url reads as the end of the
	// authority) cannot slip through as a path, query or fragment
	return u.User != nil || (strict && (u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(canon, "#@")))
}

// MaskURL returns v with its userinfo, query values and fragment replaced by URLMask. A value with
// none is returned unchanged. A value that cannot be parsed but may hold a credential is masked whole, and so is a
// value with a scheme prefix, no authority and an "@" (urlRisk refuses it in base_url and org_url). v is read as
// urlshape.Classify reads it; a masked value is shown in its "scheme://" form.
func MaskURL(v string) string {
	if f := urlshape.Fold(v); f != v && rawURLRisk(f, false) {
		// a credential behind a zero-width or fullwidth separator (issue #932): nothing of it is shown
		return URLMask
	}
	canon, sh := urlshape.Classify(v)
	switch {
	case sh == urlshape.Opaque && strings.Contains(canon, "@"),
		urlshape.Embedded(v) && strings.ContainsAny(canon, "@?#"):
		return URLMask
	case sh != urlshape.Authority || !strings.ContainsAny(canon, "@?#"):
		return v
	}
	u, err := url.Parse(canon)
	if err != nil {
		return URLMask
	}
	if u.User == nil && strings.Contains(canon, "@") {
		// an "@" net/url did not read as userinfo ("https://u:p/w@h", "https://u:1?w@h"): the value may still
		// hold a password whose "/", "?" or "#" ended the authority early, so nothing of it is shown
		return URLMask
	}
	if u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(canon, "#") {
		return v
	}
	if u.User != nil {
		u.User = url.User(URLMask)
	}
	if u.RawQuery != "" {
		pairs := strings.Split(u.RawQuery, "&")
		for i, kv := range pairs {
			if k, _, ok := strings.Cut(kv, "="); ok {
				pairs[i] = k + "=" + URLMask
			} else {
				pairs[i] = URLMask // a bare "?token" is all value
			}
		}
		slices.Sort(pairs)
		u.RawQuery = strings.Join(pairs, "&")
	}
	u.ForceQuery, u.RawFragment = false, ""
	if u.Fragment != "" || strings.Contains(canon, "#") {
		// masked, not dropped: the URL without its fragment is a value a client may send to clear it
		u.Fragment = URLMask
	}
	return u.String()
}

// urlFieldPtrs returns the URL-valued fields of a config by name.
func urlFieldPtrs(cfg *ConnConfig) map[string]*string {
	return map[string]*string{"org_url": &cfg.OrgURL, "base_url": &cfg.BaseURL}
}

// textFieldPtrs returns the typed free-text fields of a config by their JSON name: values an admin types in, none of
// them a URL by design (owners, a correlation key, a tenant host, a schedule). A URL with credentials pasted into one
// is kept in clear all the same, so it is refused and masked like a URL under settings (issue #926). ca_bundle (a PEM)
// and the structured rest and sql blocks have their own checks.
func textFieldPtrs(cfg *ConnConfig) map[string]*string {
	return map[string]*string{
		"host": &cfg.Host, "bind_dn": &cfg.BindDN, "user_filter": &cfg.UserFilter, "group_filter": &cfg.GroupFilter,
		"tenant_id": &cfg.TenantID, "cloud": &cfg.Cloud, "customer": &cfg.Customer, "domain": &cfg.Domain,
		"admin_email": &cfg.AdminEmail, "preset": &cfg.Preset, "tenant_host": &cfg.TenantHost, "api_version": &cfg.APIVersion,
		"interface": &cfg.Interface, "time_zone": &cfg.TimeZone, "correlation_key": &cfg.CorrelationKey,
		"hr_id_attribute": &cfg.HRIDAttribute, "technical_owner": &cfg.TechnicalOwner, "business_owner": &cfg.BusinessOwner,
		"sync_schedule": &cfg.SyncSchedule,
	}
}

// textListPtrs returns the typed free-text list fields of a config by their JSON name (DNs, OUs, a write scope, check
// ids): the same rule as textFieldPtrs, applied to each entry.
func textListPtrs(cfg *ConnConfig) map[string]*[]string {
	return map[string]*[]string{"base_dns": &cfg.BaseDNs, "service_account_ous": &cfg.ServiceAccountOUs,
		"write_scope": &cfg.WriteScope, "demo_fixed_checks": &cfg.DemoFixedChecks}
}

// textURLStartRe finds where a URL may start inside free text: a "scheme://" (either slash direction) or an http(s),
// ws(s) or ftp scheme in any separator form ("https:u:p@h"), the forms urlshape.Classify reads as naming a host.
var textURLStartRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*:[/\\]{2}|\b(?:https?|wss?|ftp):`)

// textTokenEnd ends a URL found inside free text: a space (tabs and line breaks are not, a lenient parser drops them)
// or a quote or bracket a URL is commonly pasted between.
func textTokenEnd(r rune) bool {
	return (unicode.IsSpace(r) && r != '\t' && r != '\n' && r != '\r') || strings.ContainsRune("\"'<>`", r)
}

// textRisk reports whether a free-text value holds a URL with userinfo: the whole value read as a URL that names a
// host, or any URL in it ("Ops team <https://u:p@h>", "see https:u:p@h"). A typed text field is never a URL by
// design, so a URL anywhere in it is checked, not only one that starts the value.
func textRisk(v string) bool {
	v = urlshape.Fold(v) // zero-width and fullwidth separators (issue #932)
	if urlshape.HasAuthority(v) {
		return urlRisk(v, false)
	}
	for _, loc := range textURLStartRe.FindAllStringIndex(v, -1) {
		tok := v[loc[0]:]
		if i := strings.IndexFunc(tok, textTokenEnd); i >= 0 {
			tok = tok[:i]
		}
		if urlRisk(tok, false) {
			return true
		}
	}
	return false
}

// maskText is MaskURL for a free-text value: a value that reads as a URL naming a host is masked as such, and a
// value holding a credentialed URL in longer text is masked whole. Anything else is returned unchanged.
func maskText(v string) string {
	if urlshape.HasAuthority(v) {
		if strings.Count(urlshape.Fold(v), "@") > 1 && textRisk(v) {
			// a second credentialed URL after the first ("https://a:b@h/ https://u:p@h2"): MaskURL masks only the
			// userinfo net/url reads, so the value is masked whole
			return URLMask
		}
		return MaskURL(v)
	}
	if textRisk(v) {
		return URLMask
	}
	return v
}

// MaskText is maskText for values copied out of the config elsewhere (the connection's owners, issue #926).
func MaskText(v string) string { return maskText(v) }

// maskTextPtr returns p masked, and whether it was.
func maskTextPtr(p *string) (*string, bool) {
	if p == nil {
		return nil, false
	}
	if m := maskText(*p); m != *p {
		return &m, true
	}
	return p, false
}

// MaskOwner is MaskText for an optional value (a connection's technical or business owner).
func MaskOwner(p *string) *string {
	m, _ := maskTextPtr(p)
	return m
}

// MaskedConfig returns cfg for a view: URL-valued fields that still carry credentials or query values are masked,
// and the names of the fields that were are returned. cfg is not modified.
func MaskedConfig(cfg ConnConfig) (ConnConfig, []string) {
	var masked []string
	for name, p := range urlFieldPtrs(&cfg) {
		if m := MaskURL(*p); m != *p {
			*p = m
			masked = append(masked, name)
		}
	}
	for name, p := range textFieldPtrs(&cfg) {
		if m := maskText(*p); m != *p {
			*p = m
			masked = append(masked, name)
		}
	}
	for name, p := range textListPtrs(&cfg) {
		var cp []string
		for i, v := range *p {
			if m := maskText(v); m != v {
				if cp == nil {
					cp = slices.Clone(*p)
				}
				cp[i] = m
			}
		}
		if cp != nil {
			*p = cp
			masked = append(masked, name)
		}
	}
	if len(cfg.Settings) > 0 {
		cp := make(map[string]string, len(cfg.Settings))
		for k, v := range cfg.Settings {
			if urlSetting(k, v) {
				if m := MaskURL(v); m != v {
					v = m
					masked = append(masked, "settings."+k)
				}
			}
			cp[k] = v
		}
		cfg.Settings = cp
	}
	slices.Sort(masked)
	return cfg, masked
}

// MaskConfigMap is MaskedConfig for a decoded JSON config object (a change request's payload). It masks in place.
func MaskConfigMap(m map[string]any) []string {
	var masked []string
	for _, name := range []string{"org_url", "base_url"} {
		if v, ok := m[name].(string); ok {
			if mv := MaskURL(v); mv != v {
				m[name], masked = mv, append(masked, name)
			}
		}
	}
	for name := range textFieldPtrs(&ConnConfig{}) {
		if v, ok := m[name].(string); ok {
			if mv := maskText(v); mv != v {
				m[name], masked = mv, append(masked, name)
			}
		}
	}
	for name := range textListPtrs(&ConnConfig{}) {
		if list, ok := m[name].([]any); ok {
			hit := false
			for i, x := range list {
				if v, ok := x.(string); ok {
					if mv := maskText(v); mv != v {
						list[i], hit = mv, true
					}
				}
			}
			if hit {
				masked = append(masked, name)
			}
		}
	}
	if st, ok := m["settings"].(map[string]any); ok {
		for k, x := range st {
			if v, ok := x.(string); ok && urlSetting(k, v) {
				if mv := MaskURL(v); mv != v {
					st[k], masked = mv, append(masked, "settings."+k)
				}
			}
		}
	}
	slices.Sort(masked)
	return masked
}

// keepMaskedURLs restores, in a config about to be saved over cur, every URL field whose new value is exactly the
// mask of cur's value: the client sent back what the view showed.
func keepMaskedURLs(cur, next *ConnConfig) {
	old := urlFieldPtrs(cur)
	for name, p := range urlFieldPtrs(next) {
		if o := *old[name]; *p != o && *p == MaskURL(o) {
			*p = o
		}
	}
	// free text: the mask of a stored value restores that value only, in the same field (and list position), so the
	// round trip can keep a stored value but never move it or bring back one that was replaced
	oldText := textFieldPtrs(cur)
	for name, p := range textFieldPtrs(next) {
		if o := *oldText[name]; *p != o && *p == maskText(o) {
			*p = o
		}
	}
	oldLists := textListPtrs(cur)
	for name, p := range textListPtrs(next) {
		olds := *oldLists[name]
		for i, v := range *p {
			if i < len(olds) && v != olds[i] && v == maskText(olds[i]) {
				(*p)[i] = olds[i]
			}
		}
	}
	for k, v := range next.Settings {
		if o, ok := cur.Settings[k]; ok && v != o && urlSetting(k, o) && v == MaskURL(o) {
			next.Settings[k] = o
		}
	}
}

// urlCredentialError refuses a config whose URL-valued fields carry userinfo, or whose base_url or org_url carries a
// query string or fragment. The value is never echoed. A field left as it is in cur (the stored config; zero for a
// create) is not refused: a value stored before this rule is only masked in views until someone changes it.
func urlCredentialError(cur, cfg ConnConfig) error {
	var bad []FieldError
	if cfg.OrgURL != cur.OrgURL && urlRisk(cfg.OrgURL, true) {
		bad = append(bad, FieldError{"org_url", "must not carry credentials, a query string or a fragment"})
	}
	if cfg.BaseURL != cur.BaseURL && urlRisk(cfg.BaseURL, true) {
		bad = append(bad, FieldError{"base_url", "must not carry credentials, a query string or a fragment"})
	}
	curText := textFieldPtrs(&cur)
	textNames := make([]string, 0, len(curText))
	for name := range curText {
		textNames = append(textNames, name)
	}
	slices.Sort(textNames)
	nextText := textFieldPtrs(&cfg)
	for _, name := range textNames {
		if v := *nextText[name]; v != *curText[name] && textRisk(v) {
			bad = append(bad, FieldError{name, "must not carry credentials"})
		}
	}
	// list fields, attr_map and privileged_expected: an entry not stored as it is in the same field of cur is checked
	curLists, nextLists := textListPtrs(&cur), textListPtrs(&cfg)
	for _, name := range []string{"base_dns", "demo_fixed_checks", "service_account_ous", "write_scope"} {
		old := *curLists[name]
		if slices.ContainsFunc(*nextLists[name], func(v string) bool { return !slices.Contains(old, v) && textRisk(v) }) {
			bad = append(bad, FieldError{name, "must not carry credentials"})
		}
	}
	if attrMapRisk(cur, cfg) {
		bad = append(bad, FieldError{"attr_map", "must not carry credentials"})
	}
	if privilegedRisk(cur, cfg) {
		bad = append(bad, FieldError{"privileged_expected", "must not carry credentials"})
	}
	keys := make([]string, 0, len(cfg.Settings))
	for k := range cfg.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if v := cfg.Settings[k]; v != cur.Settings[k] && urlSetting(k, v) && urlRisk(v, false) {
			bad = append(bad, FieldError{"settings." + k, "must not carry credentials"})
		}
	}
	if len(bad) == 0 {
		return urlASCIIError(cur, cfg) // after the credential checks: a credentialed look-alike URL is reported as that
	}
	return &Error{Status: http.StatusBadRequest, Code: CodeURLCredentialsRefused,
		Msg: "a URL must not carry credentials (user:pass@) or, for base_url and org_url, a query string or fragment; the secret belongs in the credential", Fields: bad}
}

// attrMapRisk reports whether cfg's attr_map has an entry, not stored in cur, with a credentialed URL in a field.
func attrMapRisk(cur, cfg ConnConfig) bool {
	return slices.ContainsFunc(cfg.AttrMap, func(m AttrMapping) bool {
		return !slices.Contains(cur.AttrMap, m) && (textRisk(m.LDAP) || textRisk(m.Target) || textRisk(m.Scope))
	})
}

// privilegedRisk reports whether cfg's privileged_expected names, as a group or a member not stored in cur, a
// credentialed URL.
func privilegedRisk(cur, cfg ConnConfig) bool {
	for g, members := range cfg.PrivilegedExpected {
		old, had := cur.PrivilegedExpected[g]
		if !had && textRisk(g) {
			return true
		}
		if slices.ContainsFunc(members, func(m string) bool { return !slices.Contains(old, m) && textRisk(m) }) {
			return true
		}
	}
	return false
}

// urlASCIIError refuses a base_url, org_url or URL-valued setting, changed from cur, whose scheme or authority holds a non-ASCII
// character (urlshape.NonASCIIHead). The value is never echoed.
func urlASCIIError(cur, cfg ConnConfig) error {
	var bad []FieldError
	if cfg.OrgURL != cur.OrgURL && urlshape.NonASCIIHead(cfg.OrgURL) {
		bad = append(bad, FieldError{"org_url", "scheme and host must be ASCII; give an international host name as punycode (xn--)"})
	}
	if cfg.BaseURL != cur.BaseURL && urlshape.NonASCIIHead(cfg.BaseURL) {
		bad = append(bad, FieldError{"base_url", "scheme and host must be ASCII; give an international host name as punycode (xn--)"})
	}
	keys := make([]string, 0, len(cfg.Settings))
	for k := range cfg.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		// a URL-valued setting (a token or SCIM endpoint, say) is fetched like base_url: the same rule, for a value
		// that names a host as written or folded
		v := cfg.Settings[k]
		if v != cur.Settings[k] && urlSetting(k, v) && urlshape.NonASCIIHead(v) &&
			(urlshape.HasAuthority(v) || urlshape.HasAuthority(urlshape.Fold(v))) {
			bad = append(bad, FieldError{"settings." + k, "scheme and host must be ASCII; give an international host name as punycode (xn--)"})
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return &Error{Status: http.StatusBadRequest, Code: CodeURLNonASCIIAuthority,
		Msg: "a URL's scheme and host must be ASCII; give an international host name as punycode (xn--)", Fields: bad}
}
