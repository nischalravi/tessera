package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// The uniform contract of /api/v1 (issue #587). It is applied to v1 requests
// only: the unversioned paths, and with them the parity fixtures and the UI,
// answer exactly as before.
//
// Errors. Every answer with status 400 or more is
//
//	{"error": {"code": "...", "message": "...", "field": "...", "details": {...}}}
//
// code is the route's own error code when it has one (forbidden,
// step_up_required, rate_limited, ...) and otherwise one derived from the
// status (not_found, validation_error, ...). message is the route's text.
// field names the offending input when the route or the validator says which.
// details keeps any other fields the route sent (the step-up challenge, a
// change request id). A body that is not JSON (a stray plain-text error) gets
// the status's standard text, never the body.
//
// Lists. A GET that answers a JSON array answers {"items": [...], "next_cursor": ...}
// instead, cut by ?limit=1..500 (default 100) and ?cursor= (the next_cursor of
// the previous page; null or absent on the last page). A route that already
// pages with limit and offset and answers {"items": [...], "offset": n, ...}
// keeps its shape and gains next_cursor; its offset is driven by the cursor.
// filter, sort and the other query parameters are the route's own and pass
// through. A cursor is bound to the route and its other parameters: used with
// different ones it is 400 invalid_cursor.
//
// How a route pages depends on what it can do (v1PagingOf): native routes use
// limit and offset; GET /api/audit pages by keyset (before_seq), so it reaches
// every event; a short allow-list of routes that answer a full array is cut by
// the middleware, and a body over v1MaxBufferedBytes is passed on unchanged
// (header Tessera-Paging: skipped), never truncated. Every other route is not
// paged: its own parameters apply, and a cursor is 400 paging_unsupported.

const (
	v1DefaultLimit = 100
	v1MaxLimit     = 500
)

// v1MaxBufferedBytes caps what the middleware buffers to cut an array.
const v1MaxBufferedBytes = 1 << 20

// The audit keyset page asks the route for one row more than the page, so the
// route's own cap (MaxAuditLimit) must not bind it.
const _ = uint(MaxAuditLimit - (v1MaxLimit + 1))

// v1Page is what a request asks of a list. For a keyset page offset is the
// sequence number the page continues after.
type v1Page struct {
	kind   int
	offset int
	limit  int
	fp     string // fingerprint of the route and its non-paging query
}

// Kinds of paging (v1PagingOf).
const (
	v1None   = iota // not paged
	v1Cut           // the middleware cuts a full array
	v1Native        // the route pages with limit and offset
	v1Keyset        // GET /api/audit: before_seq
)

func v1PagingOf(pattern string) int {
	switch {
	case v1NativeRoutes[pattern]:
		return v1Native
	case pattern == "/api/audit":
		return v1Keyset
	case v1CutRoutes[pattern]:
		return v1Cut
	}
	return v1None
}

// v1NativeRoutes answer {"items", "limit", "offset", ...} and read limit and offset.
var v1NativeRoutes = map[string]bool{
	"/api/groups/folders": true, "/api/groups/native": true, "/api/groups/{id}/members": true,
	"/api/identities/{identity_id}/groups": true, "/api/groups/attr-defs": true, "/api/groups/attr-names": true,
	"/api/groups/loaders": true, "/api/groups/loaders/{id}/runs": true, "/api/groups/loaders/{id}/unresolved": true,
	"/api/groups/loader-tasks": true,
}

// v1CutRoutes answer a full array, take no paging parameters, and are small
// (a tenant's policies, connectors and inventories). Only these are cut by the
// middleware; the byte cap catches one that grows.
var v1CutRoutes = map[string]bool{
	"/api/policies": true, "/api/connectors": true, "/api/identities": true, "/api/accounts": true,
	"/api/groups": true, "/api/resources": true, "/api/violations": true,
}

// v1Query validates limit and cursor of a v1 GET and rewrites the request's
// query for the route's kind of paging (see v1PagingOf). On a refusal it
// returns the error code and field.
func v1Query(r *http.Request, pattern string) (pg v1Page, ok bool, code, field string) {
	pg = v1Page{limit: v1DefaultLimit, kind: v1PagingOf(pattern)}
	q := r.URL.Query()
	if pg.kind == v1None {
		if q.Has("cursor") {
			return pg, false, "paging_unsupported", "cursor"
		}
		return pg, true, "", "" // the route's own parameters apply
	}
	limitSet := false
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > v1MaxLimit {
			return pg, false, "invalid_limit", "limit"
		}
		pg.limit, limitSet = n, true
	}
	pg.fp = v1Fingerprint(r.URL.Path, q)
	if c := q.Get("cursor"); c != "" {
		off, ok := v1DecodeCursor(c, pg.fp)
		if !ok {
			return pg, false, "invalid_cursor", "cursor"
		}
		pg.offset = off
	}
	q.Del("cursor")
	switch pg.kind {
	case v1Native:
		if limitSet {
			q.Set("limit", strconv.Itoa(pg.limit))
		}
		if pg.offset > 0 {
			q.Set("offset", strconv.Itoa(pg.offset))
		}
	case v1Keyset:
		q.Set("limit", strconv.Itoa(pg.limit+1))
		if pg.offset > 0 {
			q.Set("before_seq", strconv.Itoa(pg.offset))
		}
	default: // cut: these routes take no paging parameters
		q.Del("offset")
		q.Del("limit")
	}
	r.URL.RawQuery = q.Encode()
	return pg, true, "", ""
}

// v1Fingerprint binds a cursor to the route and to the query parameters that
// select what is listed (everything but the paging ones).
func v1Fingerprint(path string, q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		if k != "cursor" && k != "limit" && k != "offset" && k != "before_seq" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(path))
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		h.Write([]byte("\x00" + k + "=" + strings.Join(vs, "\x01")))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// A cursor is base64url of "<offset>.<fingerprint>". It is opaque to clients
// and carries nothing secret.
func v1EncodeCursor(offset int, fp string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset) + "." + fp))
}

func v1DecodeCursor(c, fp string) (int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, false
	}
	off, got, ok := strings.Cut(string(raw), ".")
	n, err := strconv.Atoi(off)
	if !ok || err != nil || n < 0 || n > 1<<62 || got != fp {
		return 0, false
	}
	return n, true
}

// v1Writer buffers the answers the contract rewrites (errors, and the JSON
// bodies of GET lists) and passes everything else through untouched.
type v1Writer struct {
	http.ResponseWriter
	method  string
	page    v1Page
	hasPage bool
	status  int
	wrote   bool
	mode    int // 0 pass through, 1 error, 2 list
	buf     bytes.Buffer
}

const (
	v1Pass = iota
	v1Error
	v1List
)

func (w *v1Writer) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote, w.status = true, code
	ct := w.Header().Get("Content-Type")
	switch {
	case code >= 400:
		w.mode = v1Error
	case code == http.StatusOK && w.method == http.MethodGet && w.hasPage && strings.HasPrefix(ct, "application/json"):
		w.mode = v1List
	default:
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *v1Writer) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.mode == v1Pass {
		return w.ResponseWriter.Write(b)
	}
	if w.mode == v1List && w.buf.Len()+len(b) > v1MaxBufferedBytes {
		// too big to cut: send it as the route made it, never truncated
		w.mode = v1Pass
		w.Header().Set("Tessera-Paging", "skipped")
		w.ResponseWriter.WriteHeader(w.status)
		if _, err := w.ResponseWriter.Write(w.buf.Bytes()); err != nil { // #nosec G705 -- the route's own JSON answer, passed on whole as application/json with nosniff
			return 0, err
		}
		w.buf.Reset()
		return w.ResponseWriter.Write(b)
	}
	return w.buf.Write(b)
}

// Flush passes a streamed answer through; a buffered one is sent by finish.
func (w *v1Writer) Flush() {
	if w.mode == v1Pass {
		if f, ok := w.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (w *v1Writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// finish sends a buffered answer, rewritten.
func (w *v1Writer) finish() {
	var out []byte
	switch w.mode {
	case v1Error:
		out = v1ErrorBody(w.status, w.buf.Bytes())
		w.Header().Set("Content-Type", "application/json")
	case v1List:
		out = v1ListBody(w.buf.Bytes(), w.page)
	default:
		return
	}
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(w.status)
	_, _ = w.ResponseWriter.Write(out) // #nosec G705 -- JSON built here from the route's own answer, served as application/json with nosniff
}

// v1StatusCodes are the error codes of statuses a route gives no code for.
var v1StatusCodes = map[int]string{
	http.StatusBadRequest: "bad_request", http.StatusUnauthorized: "unauthorized", http.StatusForbidden: "forbidden",
	http.StatusNotFound: "not_found", http.StatusMethodNotAllowed: "method_not_allowed", http.StatusConflict: "conflict",
	http.StatusRequestEntityTooLarge: "payload_too_large", http.StatusUnsupportedMediaType: "unsupported_media_type",
	http.StatusUnprocessableEntity: "validation_error", http.StatusTooManyRequests: "rate_limited",
	http.StatusInternalServerError: "internal_error", http.StatusBadGateway: "bad_gateway",
	http.StatusServiceUnavailable: "service_unavailable", http.StatusGatewayTimeout: "timeout",
}

func v1StatusCode(status int) string {
	if c, ok := v1StatusCodes[status]; ok {
		return c
	}
	if status >= 500 {
		return "server_error"
	}
	return "client_error"
}

// v1ErrorBody wraps a route's error answer in the envelope.
func v1ErrorBody(status int, body []byte) []byte {
	code, msg, field := v1StatusCode(status), http.StatusText(status), ""
	var details map[string]json.RawMessage
	var obj map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimSpace(body), &obj) == nil && obj != nil {
		var s string
		if json.Unmarshal(obj["error"], &s) == nil && s != "" {
			code = s
		}
		if json.Unmarshal(obj["detail"], &s) == nil && s != "" {
			msg = s
		} else if json.Unmarshal(obj["message"], &s) == nil && s != "" {
			msg = s
		}
		if json.Unmarshal(obj["field"], &s) == nil && s != "" {
			field = s
		}
		// FastAPI-style validation: {"detail": [{"loc": [...], "msg": ..., "type": ...}]}
		var errs []struct {
			Loc []json.RawMessage `json:"loc"`
			Msg string            `json:"msg"`
		}
		if json.Unmarshal(obj["detail"], &errs) == nil && len(errs) > 0 {
			code, msg = "validation_error", "Request validation failed"
			if errs[0].Msg != "" {
				msg = errs[0].Msg
			}
			field = v1FieldOf(errs[0].Loc)
			details = map[string]json.RawMessage{"errors": obj["detail"]}
		}
		for k, v := range obj {
			switch k {
			case "error", "detail", "message", "field":
			default:
				if details == nil {
					details = map[string]json.RawMessage{}
				}
				details[k] = v
			}
		}
	}
	e := map[string]any{"code": code, "message": msg}
	if field != "" {
		e["field"] = field
	}
	if len(details) > 0 {
		e["details"] = details
	}
	out, err := json.Marshal(map[string]any{"error": e})
	if err != nil {
		return []byte(`{"error":{"code":"internal_error","message":"Internal Server Error"}}`)
	}
	return out
}

// v1FieldOf names the input a validation error is about: the loc without its
// leading "body", "query" or "path".
func v1FieldOf(loc []json.RawMessage) string {
	var parts []string
	for i, l := range loc {
		var s string
		if json.Unmarshal(l, &s) != nil {
			s = strings.Trim(string(l), `"`)
		}
		if i == 0 && (s == "body" || s == "query" || s == "path") {
			continue
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ".")
}

// v1ListBody turns a JSON array into a page, or adds next_cursor to a page the
// route made itself. Any other body is passed on as it is.
func v1ListBody(body []byte, pg v1Page) []byte {
	trim := bytes.TrimSpace(body)
	if len(trim) == 0 {
		return body
	}
	switch trim[0] {
	case '[':
		var items []json.RawMessage
		if json.Unmarshal(trim, &items) != nil {
			return body
		}
		if pg.kind == v1Keyset {
			return v1KeysetBody(items, pg, body)
		}
		if pg.offset > len(items) {
			items = nil
		} else {
			items = items[pg.offset:]
		}
		var next any
		if len(items) > pg.limit {
			items = items[:pg.limit]
			next = v1EncodeCursor(pg.offset+pg.limit, pg.fp)
		}
		if items == nil {
			items = []json.RawMessage{}
		}
		out, err := json.Marshal(map[string]any{"items": items, "next_cursor": next})
		if err != nil {
			return body
		}
		return out
	case '{':
		var o struct {
			Items  []json.RawMessage `json:"items"`
			Offset *int              `json:"offset"`
			Limit  *int              `json:"limit"`
			Total  *int              `json:"total"`
		}
		if json.Unmarshal(trim, &o) != nil || o.Items == nil || o.Offset == nil {
			return body
		}
		next := "null"
		end := *o.Offset + len(o.Items)
		more := o.Total != nil && end < *o.Total
		if o.Total == nil && o.Limit != nil && len(o.Items) > 0 && len(o.Items) >= *o.Limit {
			more = true // no total: a full page may have a next one
		}
		if more {
			b, _ := json.Marshal(v1EncodeCursor(end, pg.fp))
			next = string(b)
		}
		return append(trim[:len(trim)-1:len(trim)-1], []byte(`,"next_cursor":`+next+`}`)...)
	}
	return body
}

// v1KeysetBody pages the audit log: the route was asked for limit+1 rows after
// the cursor's sequence number, so a row beyond the limit means there is a next
// page, which starts after the last row kept.
func v1KeysetBody(items []json.RawMessage, pg v1Page, orig []byte) []byte {
	var next any
	if len(items) > pg.limit {
		items = items[:pg.limit]
		var last struct {
			Seq int `json:"seq"`
		}
		if json.Unmarshal(items[len(items)-1], &last) != nil || last.Seq < 1 {
			return orig // not an audit row: do not guess a cursor
		}
		next = v1EncodeCursor(last.Seq, pg.fp)
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	out, err := json.Marshal(map[string]any{"items": items, "next_cursor": next})
	if err != nil {
		return orig
	}
	return out
}
