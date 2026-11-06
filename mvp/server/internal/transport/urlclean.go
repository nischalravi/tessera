package transport

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Export cleaning of values that may hold a URL or a connection string.
//
// The rule fails closed: a string is kept only when it plainly is not a URL
// or DSN, or when it is an absolute URL that parses and can be cleaned
// reliably (userinfo, query and fragment removed). Anything else that looks
// like it could hold a credential (a URL inside longer text, a jdbc:/odbc:
// string, a key=value DSN, a value with a key such as password=) is left out
// of the export and listed under "excluded".

type cleanVerdict int

const (
	verdictKeep cleanVerdict = iota
	verdictCleaned
	verdictExcluded
)

var (
	absURLRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://[^\s]+$`)
	// A scheme-prefixed string of a kind that is not an ordinary URL.
	dsnSchemeRe = regexp.MustCompile(`(?i)^\s*(jdbc|odbc|adodb|ado|dsn)\s*[:=]`)
	// key=value pairs that carry a credential or make up a DSN.
	credPairRe = regexp.MustCompile(`(?i)(^|[\s;,&?(\[{"'/\-])(password|passwd|pwd|pass|passphrase|secret|[a-z_]*token|api[_-]?key|access[_-]?key|account[_-]?key|sharedaccesskey|sas|sig|signature|authorization|credentials?)\s*=`)
	dsnPairRe  = regexp.MustCompile(`(?i)(^|[\s;,(])(server|host|hostname|data[ _]source|driver|dsn|database|dbname|initial catalog|provider|port)\s*=`)
	// A query string or a protocol-relative authority in a string that is not a plain absolute URL.
	queryRe    = regexp.MustCompile(`\?[^\s]*=`)
	bearerRe   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}`)
	embeddedRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://`)
	textSecret = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|[a-z_]*token|api[_-]?key|access[_-]?key|private[_-]?key)\w*"?\s*[:=]\s*["']?[^\s"',}]`)
	urlTokenRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>\x60]*`)
	protoRelRe = regexp.MustCompile(`^\s*//[^/\s]`)
)

// suspicious reports whether a string might hold a URL or DSN.
func suspicious(s string) bool {
	return embeddedRe.MatchString(s) || dsnSchemeRe.MatchString(s) || credPairRe.MatchString(s) || dsnPairRe.MatchString(s) ||
		queryRe.MatchString(s) || bearerRe.MatchString(s) || protoRelRe.MatchString(s)
}

// cleanString returns the string to export and what happened to it.
func cleanString(s string) (string, cleanVerdict) {
	if !suspicious(s) {
		return s, verdictKeep
	}
	if !absURLRe.MatchString(s) {
		return "", verdictExcluded // jdbc:/odbc/DSN, a URL inside text, a bare key=value string
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", verdictExcluded
	}
	if u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery {
		// Nothing to strip. A credential-looking pair in the path still fails closed.
		if credPairRe.MatchString(u.EscapedPath()) || bearerRe.MatchString(u.EscapedPath()) {
			return "", verdictExcluded
		}
		return s, verdictKeep
	}
	u.User, u.RawQuery, u.Fragment, u.ForceQuery = nil, "", "", false
	out := u.String()
	if suspiciousAfterClean(out) {
		return "", verdictExcluded
	}
	return out, verdictCleaned
}

func suspiciousAfterClean(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(s, "?#@") {
		return true
	}
	return credPairRe.MatchString(u.EscapedPath()) || bearerRe.MatchString(u.EscapedPath()) || embeddedRe.MatchString(u.EscapedPath())
}

// cleanValue walks a decoded JSON value. bad reports a value that must not
// be exported.
func cleanValue(x any) (out any, changed, bad bool) {
	switch t := x.(type) {
	case string:
		s, v := cleanString(t)
		switch v {
		case verdictExcluded:
			return nil, false, true
		case verdictCleaned:
			return s, true, false
		}
		return t, false, false
	case []any:
		for i := range t {
			n, c, b := cleanValue(t[i])
			if b {
				return nil, false, true
			}
			t[i], changed = n, changed || c
		}
		return t, changed, false
	case map[string]any:
		for k, v := range t {
			if s, ok := v.(string); ok && s != "" && secretNamed(k) {
				return nil, false, true
			}
			n, c, b := cleanValue(v)
			if b {
				return nil, false, true
			}
			t[k], changed = n, changed || c
		}
		return t, changed, false
	}
	return x, false, false
}

func secretNamed(k string) bool {
	lk := strings.ToLower(k)
	return slices.ContainsFunc(secretWords, func(w string) bool { return strings.Contains(lk, w) }) &&
		!strings.HasSuffix(lk, "_ref") && !strings.HasSuffix(lk, "_reference")
}

// cleanConfig cleans a connection's configuration. Top-level keys with a
// value that cannot be cleaned reliably are dropped and returned in
// excluded; cleaned reports that a URL was cleaned in place.
func cleanConfig(raw json.RawMessage) (out json.RawMessage, cleaned bool, excluded []string) {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return json.RawMessage(`{}`), false, []string{"*"}
	}
	for _, k := range sortedKeys(m) {
		n, c, bad := cleanValue(m[k])
		if s, ok := m[k].(string); ok && s != "" && secretNamed(k) {
			bad = true
		}
		switch {
		case bad:
			delete(m, k)
			excluded = append(excluded, k)
		case c:
			m[k], cleaned = n, true
		}
	}
	if len(excluded) == 0 && !cleaned {
		return raw, false, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{}`), false, []string{"*"}
	}
	return b, cleaned, excluded
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// overlayExportable reports whether an overlay body can be exported as is.
// Bodies are not rewritten: one that may carry a credential or a URL that
// cannot be cleaned reliably is left out whole.
func overlayExportable(body string) bool {
	var v any
	if json.Unmarshal([]byte(body), &v) == nil {
		if _, c, bad := cleanValue(v); bad || c {
			return false
		}
		return true
	}
	if textSecret.MatchString(body) || credPairRe.MatchString(body) || dsnSchemeRe.MatchString(body) || bearerRe.MatchString(body) {
		return false
	}
	for _, tok := range urlTokenRe.FindAllString(body, -1) {
		if _, v := cleanString(tok); v != verdictKeep {
			return false
		}
	}
	return true
}

// cleanURLField cleans an IdP URL field: the value to export, whether it
// was cleaned in place and whether it was left out.
func cleanURLField(p *string) (out *string, cleaned, excluded bool) {
	if p == nil {
		return nil, false, false
	}
	s, v := cleanString(*p)
	switch v {
	case verdictExcluded:
		return nil, false, true
	case verdictCleaned:
		return &s, true, false
	}
	return p, false, false
}
