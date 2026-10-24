package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	grpapi "github.com/nischalravi/tessera/mvp/server/internal/groups/api"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
)

// The complete public API document (issue #587): GET /api/openapi.json.
//
// It is built from the route table, so a route cannot be registered without
// being documented (TestOpenAPI_MatchesRouteTable). Every operation gets its
// path parameters, the error responses every route can answer, the permission
// and the token scopes it needs, and whether it demands step-up. Richer
// hand-written detail is layered on top where it exists: the original
// /openapi.json (core routes), the readiness and rotation documents, and the
// groups document (query parameters, request and response schemas). A route
// none of them describes still has a request body and a response of the
// top-level JSON-object shape; its fields are not described.

// openAPIDocs are the embedded documents layered over the generated base,
// least specific first.
func (s *Server) openAPIDocs() [][]byte {
	return [][]byte{openAPIDoc, readinessOpenAPIDoc, rotationOpenAPIDoc}
}

type oamap = map[string]any

// fullOpenAPI returns the document, built once: the route table is fixed
// after New.
func (s *Server) fullOpenAPI() ([]byte, error) {
	s.specOnce.Do(func() { s.spec, s.specErr = s.buildOpenAPI() })
	return s.spec, s.specErr
}

func (s *Server) fullOpenAPIHandler(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	b, err := s.fullOpenAPI()
	if err != nil {
		return nil, err
	}
	return rawJSON(b), nil
}

var pathParamRE = regexp.MustCompile(`\{([A-Za-z0-9_]+)(\.\.\.)?\}`)

func (s *Server) buildOpenAPI() ([]byte, error) {
	paths := oamap{}
	schemas := oamap{}
	var groupRoutes []grpapi.RouteInfo
	for _, rt := range s.routes {
		item, _ := paths[rt.pattern].(oamap)
		if item == nil {
			item = oamap{}
			paths[rt.pattern] = item
		}
		item[strings.ToLower(rt.method)] = baseOperation(rt)
		if grpapi.Covers(rt.method, rt.pattern) {
			groupRoutes = append(groupRoutes, grpapi.RouteInfo{Method: rt.method, Pattern: rt.pattern, Perm: string(rt.spec.Perm), StepUp: rt.spec.Authn != nil})
		}
	}
	docs := s.openAPIDocs()
	if g, err := grpapi.OpenAPI(groupRoutes, s.authn.Cookies.Name()); err != nil {
		return nil, err
	} else {
		docs = append(docs, g)
	}
	for _, raw := range docs {
		var d oamap
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		if c, ok := d["components"].(oamap); ok {
			if sc, ok := c["schemas"].(oamap); ok {
				for k, v := range sc {
					schemas[k] = v
				}
			}
		}
		ps, _ := d["paths"].(oamap)
		for pat, v := range ps {
			item, ok := paths[pat].(oamap)
			if !ok {
				continue // documented by a hand-written document, not registered here
			}
			ops, _ := v.(oamap)
			for method, ov := range ops {
				if base, ok := item[method].(oamap); ok {
					if o, ok := ov.(oamap); ok {
						overlay(base, o)
					}
				}
			}
		}
	}
	for k, v := range commonSchemas() {
		schemas[k] = v
	}
	doc := oamap{
		"openapi": "3.1.0",
		"info": oamap{
			"title": "Tessera API", "version": "1.0.0",
			"description": apiDescription,
		},
		"servers": []oamap{{"url": "/", "description": "This deployment"}},
		"tags":    tagList(paths),
		"paths":   paths,
		"components": oamap{
			"schemas":         schemas,
			"responses":       commonResponses(),
			"securitySchemes": s.securitySchemes(),
		},
		"security": []oamap{{"session": []string{}}, {"oauth2": []string{}}},
	}
	return json.MarshalIndent(doc, "", " ")
}

const apiDescription = "Every route of the Tessera API, generated from the server's route table. " +
	"Machine clients sign in with the OAuth 2.0 client credentials grant (client_secret_basic or private_key_jwt, optionally DPoP-bound) at " +
	"/t/{tenant}/oauth/token and send the access token as `Authorization: Bearer`. A request is allowed when the permission the route needs " +
	"(x-tessera-permission) is held by the client's roles AND granted by one of its token scopes (x-tessera-scopes). " +
	"Routes marked x-tessera-step-up also demand a recent, strong sign-in and answer 401 step_up_required otherwise. " +
	"Every request is audited, and a request whose audit event cannot be written fails closed with 503 audit_unavailable. " +
	"Errors are JSON: {\"detail\": message} or {\"error\": code, \"detail\": message}; SCIM routes follow RFC 7644."

func (s *Server) securitySchemes() oamap {
	return oamap{
		"session": oamap{"type": "apiKey", "in": "cookie", "name": s.authn.Cookies.Name(), "description": "Browser session from the tenant's OIDC sign-in."},
		"oauth2": oamap{"type": "oauth2", "description": "Machine client: client credentials grant. Replace {tenant} with the tenant slug.",
			"flows": oamap{"clientCredentials": oamap{"tokenUrl": "/t/{tenant}/oauth/token", "scopes": scopeDescriptions()}}},
	}
}

func scopeDescriptions() oamap {
	return oamap{
		string(auth.ScopeRead):     "Read the graph, connections, jobs, provisioning and drift.",
		string(auth.ScopeWrite):    "Change data: requests, reviews, connections, roles, groups, workflows.",
		string(auth.ScopeAudit):    "Read and verify the audit ledger, alerts and SIEM feeds.",
		string(auth.ScopeAdmin):    "Administration: change requests, sessions, config transport, break-glass.",
		string(auth.ScopeEmailDSN): "Deliver mail delivery status reports; nothing else.",
		oauth.ScopeIntrospect:      "Call the token introspection endpoint.",
	}
}

// baseOperation is what the route table alone says about a route.
func baseOperation(rt *route) oamap {
	var params []oamap
	for _, m := range pathParamRE.FindAllStringSubmatch(rt.pattern, -1) {
		params = append(params, oamap{"name": m[1], "in": "path", "required": true, "schema": oamap{"type": "string"}})
	}
	responses := oamap{
		"200": oamap{"description": "Success", "content": oamap{"application/json": oamap{"schema": oamap{"$ref": "#/components/schemas/Object"}}}},
		"429": oamap{"$ref": "#/components/responses/RateLimited"},
		"500": oamap{"$ref": "#/components/responses/ServerError"},
		"503": oamap{"$ref": "#/components/responses/AuditUnavailable"},
	}
	if !rt.spec.Public {
		responses["401"] = oamap{"$ref": "#/components/responses/Unauthorized"}
		responses["403"] = oamap{"$ref": "#/components/responses/Forbidden"}
	}
	if len(params) > 0 {
		responses["404"] = oamap{"$ref": "#/components/responses/NotFound"}
	}
	write := rt.method != "GET" && rt.method != "HEAD" && rt.method != "OPTIONS"
	if write {
		responses["400"] = oamap{"$ref": "#/components/responses/BadRequest"}
		responses["409"] = oamap{"$ref": "#/components/responses/Conflict"}
		responses["413"] = oamap{"$ref": "#/components/responses/TooLarge"}
		responses["415"] = oamap{"$ref": "#/components/responses/UnsupportedMedia"}
	}
	op := oamap{
		"summary":     summaryOf(rt),
		"operationId": operationID(rt.method, rt.pattern),
		"tags":        []string{tagOf(rt.pattern)},
		"responses":   responses,
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
	if write {
		content := oamap{"application/json": oamap{"schema": oamap{"$ref": "#/components/schemas/Object"}}}
		for _, ct := range append([]string{rt.spec.BodyType}, rt.spec.BodyTypes...) {
			if ct != "" {
				content[ct] = oamap{"schema": oamap{"type": "string"}}
			}
		}
		op["requestBody"] = oamap{"required": false, "content": content}
	}
	switch {
	case rt.spec.Public:
		op["security"] = []oamap{}
		op["x-tessera-public"] = true
	default:
		perm := rt.spec.Perm
		scopes := []string{}
		for _, sc := range auth.ScopesFor(perm) {
			scopes = append(scopes, string(sc))
		}
		op["security"] = []oamap{{"session": []string{}}, {"oauth2": scopes}}
		op["x-tessera-permission"] = string(perm)
		op["x-tessera-scopes"] = scopes
		op["x-tessera-step-up"] = rt.spec.Authn != nil
	}
	return op
}

// overlay copies what a hand-written operation says over the generated one:
// descriptive fields replace, parameters and responses merge.
func overlay(base, o oamap) {
	for _, k := range []string{"summary", "description", "tags", "requestBody", "deprecated"} {
		if v, ok := o[k]; ok && !isEmptyDoc(v) {
			base[k] = v
		}
	}
	if ps, ok := o["parameters"].([]any); ok {
		have, _ := base["parameters"].([]oamap)
		for _, pv := range ps {
			p, ok := pv.(oamap)
			if !ok {
				continue
			}
			replaced := false
			for i, e := range have {
				if e["name"] == p["name"] && e["in"] == p["in"] {
					merged := oamap{}
					for k, v := range e {
						merged[k] = v
					}
					for k, v := range p {
						merged[k] = v
					}
					have[i], replaced = merged, true
				}
			}
			if !replaced {
				have = append(have, p)
			}
		}
		base["parameters"] = have
	}
	if rs, ok := o["responses"].(oamap); ok {
		br := base["responses"].(oamap)
		for code, v := range rs {
			switch {
			case strings.HasPrefix(code, "2"):
				delete(br, "200") // the generated success answer gives way to the documented one
			case br[code] != nil:
				continue // keep the shared error response
			}
			br[code] = v
		}
	}
}

func isEmptyDoc(v any) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case []string:
		return len(x) == 0
	}
	return v == nil
}

// operationID is unique per method and pattern.
func operationID(method, pattern string) string {
	r := strings.NewReplacer("/", "_", "{", "", "}", "", ":", "_", "-", "_", ".", "_")
	return strings.ToLower(method) + r.Replace(pattern)
}

// tagOf groups operations by the first path segment after /api.
func tagOf(pattern string) string {
	segs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	if segs[0] == "api" && len(segs) > 1 {
		segs = segs[1:]
	}
	t, _, _ := strings.Cut(segs[0], ":")
	if t == "t" || t == "public" {
		return "tenant-public"
	}
	if t == "" || strings.HasPrefix(t, "{") {
		return "root"
	}
	return t
}

func tagList(paths oamap) []oamap {
	seen := map[string]bool{}
	for pat := range paths {
		seen[tagOf(pat)] = true
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]oamap, len(names))
	for i, n := range names {
		out[i] = oamap{"name": n}
	}
	return out
}

// summaryOf words the handler's method name ("listIdentities" becomes "List
// identities"); a handler without one (a closure) gets its method and path.
func summaryOf(rt *route) string {
	if f := runtime.FuncForPC(reflect.ValueOf(rt.h).Pointer()); f != nil {
		name := f.Name()
		name = name[strings.LastIndex(name, ".")+1:]
		name = strings.TrimSuffix(name, "-fm")
		if name != "" && !strings.HasPrefix(name, "func") && !strings.Contains(name, "-") {
			return humanize(name)
		}
	}
	return rt.method + " " + rt.pattern
}

func humanize(camel string) string {
	var b strings.Builder
	for i, r := range camel {
		switch {
		case i == 0:
			b.WriteRune(unicode.ToUpper(r))
		case unicode.IsUpper(r):
			b.WriteByte(' ')
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func commonSchemas() oamap {
	str := oamap{"type": "string"}
	return oamap{
		"Object": oamap{"type": "object", "additionalProperties": true, "description": "A JSON object; the route's fields are not described here."},
		"Error": oamap{"type": "object", "required": []string{"detail"}, "properties": oamap{
			"error":  oamap{"type": "string", "description": "Machine-readable code, when the route sets one (login_required, step_up_required, forbidden, rate_limited, audit_unavailable, ...)."},
			"detail": str}},
	}
}

func commonResponses() oamap {
	e := func(desc string) oamap {
		return oamap{"description": desc, "content": oamap{"application/json": oamap{"schema": oamap{"$ref": "#/components/schemas/Error"}}}}
	}
	rl := e("Rate limited (rate_limited); wait Retry-After seconds.")
	rl["headers"] = oamap{"Retry-After": oamap{"description": "Seconds to wait.", "schema": oamap{"type": "integer"}}}
	return oamap{
		"Unauthorized":     e("Not signed in (login_required), the token is invalid or expired, or the route needs step-up (step_up_required)."),
		"Forbidden":        e("The caller's roles and token scopes do not grant the route's permission (forbidden), or conditional access denied it."),
		"NotFound":         e("No such object in the caller's tenant."),
		"BadRequest":       e("Invalid input."),
		"Conflict":         e("The request conflicts with the object's state."),
		"TooLarge":         e("Request body too large."),
		"UnsupportedMedia": e("Content-Type is not accepted (unsupported_media_type)."),
		"RateLimited":      rl,
		"ServerError":      e("Unexpected server error."),
		"AuditUnavailable": e("The audit event could not be written, so the request failed closed (audit_unavailable)."),
	}
}
