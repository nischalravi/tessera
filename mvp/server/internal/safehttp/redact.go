package safehttp

import (
	"errors"
	"net/url"
	"strings"
)

// RedactURL is raw with everything after the authority replaced by "/…":
// scheme://host[:port]/…, or scheme://host[:port] when there is no path,
// query or fragment. Webhook URLs often carry their credential in the path or
// query (Slack, Teams, Sumo Logic), so this is the only form of a webhook URL
// that may reach an error string, an API response, a stored last_error or an
// audit event (#333). User info is dropped too.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	out := u.Scheme + "://" + u.Host
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		out += "/…"
	}
	return out
}

// ScrubError returns err's message with every URL it carries reduced to
// RedactURL: a *url.Error (what http.Client.Do returns) keeps its Op, the
// redacted URL and the inner error, and any remaining occurrence of target, its path or its
// query is cut out as well, in case the inner error quotes them (a redirect,
// a parse failure). nil stays nil.
func ScrubError(err error, target string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		inner := "request failed"
		if ue.Err != nil {
			inner = ue.Err.Error()
		}
		msg = strings.Replace(msg, ue.Error(), ue.Op+" "+RedactURL(ue.URL)+": "+inner, 1)
		msg = scrubURL(msg, ue.URL)
	}
	return scrubURL(msg, target)
}

// scrubURL cuts raw out of msg, and its path, query, fragment and any path
// segment or query value long enough (8+ bytes) to be a secret.
func scrubURL(msg, raw string) string {
	if raw == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, raw, RedactURL(raw))
	u, err := url.Parse(raw)
	if err != nil {
		return msg
	}
	frags := []string{u.RawQuery, u.EscapedPath(), u.Path, u.Fragment}
	// a long path segment or query value on its own is likely the token
	frags = append(frags, strings.Split(u.Path, "/")...)
	if q, err := url.ParseQuery(u.RawQuery); err == nil {
		for _, vs := range q {
			frags = append(frags, vs...)
		}
	}
	for _, frag := range frags {
		frag = strings.Trim(frag, "/")
		if len(frag) >= 8 {
			msg = strings.ReplaceAll(msg, frag, "…")
		}
	}
	return msg
}
