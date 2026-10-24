package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The versioned API (issue #587): every /api/ route is also served under
// /api/v1/. The prefix is stripped before anything else sees the request, so
// a v1 request has the same route, session or token, permission, CSRF check,
// rate limits and audit event as its unversioned twin (the audit event names
// the route's /api/... path). The unversioned paths stay for the UI.
//
// Routes that follow their own standard (/scim/v2, /t/{slug}/oauth,
// /.well-known) are not aliased: they have their own versioning.
//
// Compatibility policy: docs/api/compatibility.md.

// v1Prefix is the versioned prefix; v1Alias maps it onto the route table.
const (
	v1Prefix = "/api/v1/"
	v1Base   = "/api/"
)

// minSunsetNotice is the least notice a removal gets: the Sunset date must be
// at least this long after the Deprecation date.
const minSunsetNotice = 6 * 30 * 24 * time.Hour

// Deprecation announces the removal of a v1 route (RFC 9745 Deprecation,
// RFC 8594 Sunset). Pattern is the route's registered pattern, for example
// "/api/policies".
type Deprecation struct {
	Method, Pattern string
	// Deprecated is when the route was deprecated; Sunset when it stops working.
	Deprecated, Sunset time.Time
	// Link is an optional URL of the migration guide (rel="deprecation").
	Link string
}

// checkDeprecations panics on a deprecation the policy forbids: notice shorter
// than six months, or a route that does not exist. It runs at startup, like
// the route requirement checks of handle.
func (s *Server) checkDeprecations() {
	for _, d := range s.cfg.Deprecations {
		if d.Sunset.Sub(d.Deprecated) < minSunsetNotice {
			panic(fmt.Sprintf("api: deprecation of %s %s gives less than 6 months' notice", d.Method, d.Pattern))
		}
		found := false
		for _, rt := range s.routes {
			found = found || (rt.method == d.Method && rt.pattern == d.Pattern && strings.HasPrefix(rt.pattern, v1Base))
		}
		if !found {
			panic(fmt.Sprintf("api: deprecation of %s %s names no /api route", d.Method, d.Pattern))
		}
	}
}

// versioned serves /api/v1/... as /api/..., marks the answer with the API
// version, and adds Deprecation and Sunset headers to deprecated routes.
func (s *Server) versioned(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, v1Prefix)
		if !ok || rest == "" {
			next.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = v1Base + rest
		if r.URL.RawPath != "" {
			r2.URL.RawPath = v1Base + strings.TrimPrefix(r.URL.RawPath, v1Prefix)
		}
		w.Header().Set("Tessera-API-Version", "1")
		if len(s.cfg.Deprecations) > 0 {
			if rt, _, _ := s.find(r2.Method, r2.URL.Path); rt != nil {
				s.deprecationHeaders(w, rt)
			}
		}
		next.ServeHTTP(w, r2)
	})
}

func (s *Server) deprecationHeaders(w http.ResponseWriter, rt *route) {
	for _, d := range s.cfg.Deprecations {
		if d.Method != rt.method || d.Pattern != rt.pattern {
			continue
		}
		h := w.Header()
		// RFC 9745: Deprecation is a structured-field date, "@" and Unix seconds.
		h.Set("Deprecation", "@"+strconv.FormatInt(d.Deprecated.Unix(), 10))
		h.Set("Sunset", d.Sunset.UTC().Format(http.TimeFormat))
		if d.Link != "" {
			h.Add("Link", "<"+d.Link+`>; rel="deprecation"`)
		}
		return
	}
}
