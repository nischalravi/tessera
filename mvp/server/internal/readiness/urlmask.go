package readiness

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

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

// urlSetting reports whether a settings entry holds a URL (urlshape.URLSetting: its key names one, or its value reads
// as a URL that names a host).
func urlSetting(k, v string) bool { return urlshape.URLSetting(k, v) }

// urlRisk reports whether v carries userinfo, or (strict) a query string or fragment. v is read as a lenient URL
// parser reads it (urlshape.Classify), so "https:u:p@h" and backslash or whitespace separators count as "https://".
// strict also refuses an "@" in a value with any other scheme prefix ("u:p@host", "ldap:u:p@h"): whether such a
// value names credentials depends on the reader.
func urlRisk(v string, strict bool) bool {
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
		if urlshape.HasAuthority(*p) {
			if m := MaskURL(*p); m != *p {
				*p = m
				masked = append(masked, name)
			}
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
		if v, ok := m[name].(string); ok && urlshape.HasAuthority(v) {
			if mv := MaskURL(v); mv != v {
				m[name], masked = mv, append(masked, name)
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
	oldText := textFieldPtrs(cur)
	for name, p := range textFieldPtrs(next) {
		if o := *oldText[name]; *p != o && urlshape.HasAuthority(o) && *p == MaskURL(o) {
			*p = o
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
		if v := *nextText[name]; v != *curText[name] && urlshape.HasAuthority(v) && urlRisk(v, false) {
			bad = append(bad, FieldError{name, "must not carry credentials"})
		}
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
		return nil
	}
	return &Error{Status: http.StatusBadRequest, Code: CodeURLCredentialsRefused,
		Msg: "a URL must not carry credentials (user:pass@) or, for base_url and org_url, a query string or fragment; the secret belongs in the credential", Fields: bad}
}
