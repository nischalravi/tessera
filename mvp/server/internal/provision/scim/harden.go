package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Capabilities are the features a service advertises in /ServiceProviderConfig
// (RFC 7643 section 5). A feature the document does not mention stays Unknown
// and is treated as supported, so a sparse document never disables anything.
type Capabilities struct {
	Patch  Tri `json:"patch"`
	Bulk   Tri `json:"bulk"`
	Filter Tri `json:"filter"`
	ETag   Tri `json:"etag"`
	// BulkMaxOperations and FilterMaxResults are the advertised limits (0: none stated).
	// Tessera does not send /Bulk requests; the flag is surfaced for readiness.
	BulkMaxOperations int `json:"bulk_max_operations,omitempty"`
	FilterMaxResults  int `json:"filter_max_results,omitempty"`
}

func triOf(raw json.RawMessage) (t Tri, block map[string]json.RawMessage) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return Unknown, nil
	}
	var sup bool
	if v, ok := m["supported"]; ok && json.Unmarshal(v, &sup) == nil {
		if sup {
			return Yes, m
		}
		return No, m
	}
	return Unknown, m
}

func intOf(m map[string]json.RawMessage, k string) int {
	var n int
	if json.Unmarshal(m[k], &n) != nil || n < 0 || n > 1_000_000 {
		return 0
	}
	return n
}

// parseCapabilities reads the feature blocks of a ServiceProviderConfig.
func parseCapabilities(spc map[string]json.RawMessage) *Capabilities {
	var c Capabilities
	c.Patch, _ = triOf(spc["patch"])
	var bm, fm map[string]json.RawMessage
	c.Bulk, bm = triOf(spc["bulk"])
	c.Filter, fm = triOf(spc["filter"])
	c.ETag, _ = triOf(spc["etag"])
	c.BulkMaxOperations = intOf(bm, "maxOperations")
	c.FilterMaxResults = intOf(fm, "maxResults")
	return &c
}

// SetCapabilities installs capabilities recorded by an earlier Discover, so a
// client built for a later run behaves as one that has just discovered.
func (c *Client) SetCapabilities(cp *Capabilities) { c.caps.Store(cp) }

func (c *Client) patchSupported() bool {
	cp := c.caps.Load()
	return cp == nil || cp.Patch != No
}

func (c *Client) filterSupported() bool {
	cp := c.caps.Load()
	return cp == nil || cp.Filter != No
}

// filterFor drops the filter when the service says it has none; the caller
// then lists the collection and matches itself.
func (c *Client) filterFor(f string) string {
	if c.filterSupported() {
		return f
	}
	return ""
}

// pageLen is the count asked for per page: pageSize, or the service's
// advertised maximum when that is lower.
func (c *Client) pageLen() int {
	if cp := c.caps.Load(); cp != nil && cp.FilterMaxResults > 0 && cp.FilterMaxResults < pageSize {
		return cp.FilterMaxResults
	}
	return pageSize
}

// ifMatch returns an If-Match header for the resource's current ETag when the
// service advertises ETag support, and nil otherwise (including when it
// advertises support but sends no tag).
func (c *Client) ifMatch(ctx context.Context, op, path, id string) (http.Header, error) {
	if cp := c.caps.Load(); cp == nil || cp.ETag != Yes {
		return nil, nil
	}
	st, b, h, err := c.doH(ctx, http.MethodGet, op, path+"/"+url.PathEscape(id), nil, "", nil, nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, failStatus(op, st, b)
	}
	if tag := h.Get("ETag"); tag != "" {
		return http.Header{"If-Match": {tag}}, nil
	}
	return nil, nil
}

// failStatus maps a failing response to a target error. 412 (the ETag no
// longer matches: someone changed the resource) is retryable, since the next
// attempt reads the new tag.
func failStatus(op string, st int, body []byte) *target.Error {
	if st == http.StatusPreconditionFailed {
		return &target.Error{Status: st, Retryable: true, Msg: op + ": the resource changed since it was read (HTTP 412); retrying"}
	}
	return target.Fail(op, st, detail(body))
}

// scimTypes are the RFC 7644 section 3.12 error keywords with what each means here.
var scimTypes = map[string]string{
	"invalidFilter": "the filter was refused by the service",
	"tooMany":       "the filter matched more resources than the service returns",
	"uniqueness":    "a unique attribute value is already taken",
	"mutability":    "the attribute is read-only or immutable on this service",
	"invalidSyntax": "the request body was not valid SCIM",
	"invalidPath":   "the PATCH path was refused (check the preset's value-filter quirk)",
	"noTarget":      "the PATCH path matched nothing",
	"invalidValue":  "a value was refused (check the preset's boolean quirk)",
	"invalidVers":   "the SCIM version is not supported",
	"sensitive":     "the request would expose sensitive data in a URL",
}

// errorDetail renders a SCIM error body: the scimType keyword (when it is a
// known one) with its meaning, then the service's own detail.
func errorDetail(scimType, detail string) string {
	hint, ok := scimTypes[scimType]
	if !ok {
		return detail
	}
	if detail == "" {
		return scimType + ": " + hint
	}
	return scimType + " (" + hint + "): " + detail
}

// ---------------------------------------------------------------- PUT

// putOps is read-modify-write for a service without PATCH: GET the resource,
// apply the operations to it here, PUT the whole thing back.
func (c *Client) putOps(ctx context.Context, op, path, id, key string, ops []map[string]any) error {
	rp := path + "/" + url.PathEscape(id)
	st, b, h, err := c.doH(ctx, http.MethodGet, op, rp, nil, "", nil, nil)
	if err != nil {
		return err
	}
	if st != http.StatusOK {
		return failStatus(op, st, b)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil || doc == nil {
		return target.Permanent("%s: unreadable resource", op)
	}
	if err := applyOps(doc, ops); err != nil {
		return target.Permanent("%s: %v", op, err)
	}
	var extra http.Header
	if tag := h.Get("ETag"); tag != "" {
		if cp := c.caps.Load(); cp != nil && cp.ETag == Yes {
			extra = http.Header{"If-Match": {tag}}
		}
	}
	st, b, _, err = c.doH(ctx, http.MethodPut, op, rp, nil, key, doc, extra)
	if err != nil {
		return err
	}
	if st == http.StatusOK || st == http.StatusNoContent {
		return nil
	}
	return failStatus(op, st, b)
}

// applyOps applies PATCH operations to a resource document the way a server
// would, for the shapes this client sends: a top-level or one-level dotted
// attribute, and the members list (add, remove by value list or by
// members[value eq "x"], replace).
func applyOps(doc map[string]any, ops []map[string]any) error {
	for _, o := range ops {
		name, _ := o["op"].(string)
		name = strings.ToLower(name)
		path, _ := o["path"].(string)
		val := o["value"]
		switch {
		case name != "add" && name != "replace" && name != "remove":
			return fmt.Errorf("unsupported operation %q", name)
		case path == "members" || strings.HasPrefix(path, "members["):
			applyMembers(doc, name, path, val)
		case name == "remove":
			delete(doc, path)
		case path == "":
			m, ok := val.(map[string]any)
			if !ok {
				return fmt.Errorf("an operation with no path needs an object value")
			}
			for k, v := range m {
				doc[k] = v
			}
		default:
			setPath(doc, path, val)
		}
	}
	return nil
}

func setPath(doc map[string]any, path string, v any) {
	if !strings.Contains(path, ":") && strings.Count(path, ".") == 1 && !strings.Contains(path, "[") {
		parent, child, _ := strings.Cut(path, ".")
		m, _ := doc[parent].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		m[child] = v
		doc[parent] = m
		return
	}
	doc[path] = v
}

// memberValues reads member ids from a value this client built ([]member) or
// one decoded from a server document ([]any of objects).
func memberValues(v any) []string {
	var out []string
	switch x := v.(type) {
	case []member:
		for _, m := range x {
			out = append(out, m.Value)
		}
	case []map[string]any:
		for _, m := range x {
			if s, ok := m["value"].(string); ok {
				out = append(out, s)
			}
		}
	case []any:
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				if s, ok := m["value"].(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func applyMembers(doc map[string]any, name, path string, val any) {
	cur := memberValues(doc["members"])
	set := func(vals []string) {
		out := make([]map[string]any, 0, len(vals))
		for _, v := range vals {
			out = append(out, map[string]any{"value": v})
		}
		doc["members"] = out
	}
	switch name {
	case "add":
		for _, v := range memberValues(val) {
			if !slices.Contains(cur, v) {
				cur = append(cur, v)
			}
		}
		set(cur)
	case "replace":
		set(memberValues(val))
	case "remove":
		drop := memberValues(val)
		if rest, ok := strings.CutPrefix(path, `members[value eq "`); ok {
			id, _, _ := strings.Cut(rest, `"]`)
			drop = append(drop, strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(id))
		} else if val == nil {
			set(nil)
			return
		}
		var keep []string
		for _, v := range cur {
			if !slices.Contains(drop, v) {
				keep = append(keep, v)
			}
		}
		set(keep)
	}
}
