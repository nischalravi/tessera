package api

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
)

// Request validation that reproduces FastAPI/pydantic v2 semantics (lax
// coercion rules, error types, messages and locations), so clients see the
// same 422 bodies as before the Go port. One deliberate difference: unknown
// body fields are rejected (pydantic's "extra_forbidden" error) instead of
// being silently ignored.

// verr is one validation error item.
type verr struct {
	Type  string
	Loc   []any
	Msg   string
	Input any
	Ctx   ojson.Object
}

func (e verr) object() ojson.Object {
	o := ojson.Object{{Key: "type", Value: e.Type}, {Key: "loc", Value: e.Loc}, {Key: "msg", Value: e.Msg},
		{Key: "input", Value: e.Input}}
	if e.Ctx != nil {
		o = append(o, ojson.KV{Key: "ctx", Value: e.Ctx})
	}
	return o
}

// validationError is a 422 response.
type validationError struct{ errs []verr }

func (v *validationError) Error() string { return "request validation failed" }

func (v *validationError) body() ojson.Object {
	items := make([]ojson.Object, len(v.errs))
	for i, e := range v.errs {
		items[i] = e.object()
	}
	return ojson.Object{{Key: "detail", Value: items}}
}

func loc(base []any, more ...any) []any {
	out := make([]any, 0, len(base)+len(more))
	return append(append(out, base...), more...)
}

// ------------------------------------------------------------ scalars

var intString = regexp.MustCompile(`^[+-]?[0-9]+(_[0-9]+)*$`)
var floatIntString = regexp.MustCompile(`^[+-]?[0-9]+(_[0-9]+)*\.0*$`)

func parseIntString(raw string) (int64, *verr) {
	s := strings.TrimSpace(raw)
	if intString.MatchString(s) || floatIntString.MatchString(s) {
		s = strings.ReplaceAll(s, "_", "")
		if i := strings.IndexByte(s, '.'); i >= 0 {
			s = s[:i]
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, &verr{Type: "int_parsing_size", Msg: "Unable to parse input string as an integer, exceeded maximum size", Input: raw}
		}
		return n, nil
	}
	return 0, &verr{Type: "int_parsing", Msg: "Input should be a valid integer, unable to parse string as an integer", Input: raw}
}

func toInt(v any) (int64, *verr) {
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return n, nil
		}
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil || math.IsInf(f, 0) || math.Abs(f) >= 9.2e18 {
			return 0, &verr{Type: "int_parsing_size", Msg: "Unable to parse input string as an integer, exceeded maximum size", Input: v}
		}
		if f != math.Trunc(f) {
			return 0, &verr{Type: "int_from_float", Msg: "Input should be a valid integer, got a number with a fractional part", Input: v}
		}
		return int64(f), nil
	case string:
		return parseIntString(x)
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	}
	return 0, &verr{Type: "int_type", Msg: "Input should be a valid integer", Input: v}
}

func toFloat(v any) (float64, *verr) {
	switch x := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return 0, &verr{Type: "float_parsing", Msg: "Input should be a valid number, unable to parse string as a number", Input: v}
		}
		return f, nil
	case string:
		f, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(x), "_", ""), 64)
		if err != nil {
			return 0, &verr{Type: "float_parsing", Msg: "Input should be a valid number, unable to parse string as a number", Input: v}
		}
		return f, nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	}
	return 0, &verr{Type: "float_type", Msg: "Input should be a valid number", Input: v}
}

var boolStrings = map[string]bool{"0": false, "off": false, "f": false, "false": false, "n": false, "no": false,
	"1": true, "on": true, "t": true, "true": true, "y": true, "yes": true}

func parseBoolString(s string) (bool, *verr) {
	if b, ok := boolStrings[strings.ToLower(s)]; ok {
		return b, nil
	}
	return false, &verr{Type: "bool_parsing", Msg: "Input should be a valid boolean, unable to interpret input", Input: s}
}

func toBool(v any) (bool, *verr) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		return parseBoolString(x)
	case json.Number:
		if f, err := strconv.ParseFloat(x.String(), 64); err == nil && (f == 0 || f == 1) {
			return f == 1, nil
		}
		return false, &verr{Type: "bool_parsing", Msg: "Input should be a valid boolean, unable to interpret input", Input: v}
	}
	return false, &verr{Type: "bool_type", Msg: "Input should be a valid boolean", Input: v}
}

func toStr(v any) (string, *verr) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", &verr{Type: "string_type", Msg: "Input should be a valid string", Input: v}
}

func expected(lits []string) string {
	q := make([]string, len(lits))
	for i, l := range lits {
		q[i] = "'" + l + "'"
	}
	if len(q) == 1 {
		return q[0]
	}
	return strings.Join(q[:len(q)-1], ", ") + " or " + q[len(q)-1]
}

func toLiteral(v any, lits []string) (string, *verr) {
	if s, ok := v.(string); ok {
		for _, l := range lits {
			if s == l {
				return s, nil
			}
		}
	}
	exp := expected(lits)
	return "", &verr{Type: "literal_error", Msg: "Input should be " + exp, Input: v, Ctx: ojson.Object{{Key: "expected", Value: exp}}}
}

// ------------------------------------------------------------ models

type kind int

const (
	kInt kind = iota
	kFloat
	kBool
	kStr
	kLiteral
	kDict
	kIntList
	kModelList
)

type field struct {
	name     string
	kind     kind
	required bool
	nullable bool
	def      any
	lits     []string
	model    []field
}

func modelTypeErr(l []any, v any) verr {
	return verr{Type: "model_attributes_type", Loc: l,
		Msg: "Input should be a valid dictionary or object to extract fields from", Input: v}
}

// validateModel checks v against fields; values are int64, float64, bool,
// string, ojson.Object, []int64 or []map[string]any (nil when null).
func validateModel(v any, fields []field, base []any) (map[string]any, []verr) {
	obj, ok := v.(ojson.Object)
	if !ok {
		return nil, []verr{modelTypeErr(base, v)}
	}
	out := map[string]any{}
	var errs []verr
	known := map[string]bool{}
	for _, f := range fields {
		known[f.name] = true
		raw, present := obj.Get(f.name)
		if !present {
			if f.required {
				errs = append(errs, verr{Type: "missing", Loc: loc(base, f.name), Msg: "Field required", Input: obj})
				continue
			}
			out[f.name] = f.def
			continue
		}
		if raw == nil && f.nullable {
			out[f.name] = nil
			continue
		}
		val, fe := validateField(raw, f, loc(base, f.name))
		if len(fe) > 0 {
			errs = append(errs, fe...)
			continue
		}
		out[f.name] = val
	}
	for _, kv := range obj {
		if !known[kv.Key] {
			errs = append(errs, verr{Type: "extra_forbidden", Loc: loc(base, kv.Key), Msg: "Extra inputs are not permitted", Input: kv.Value})
		}
	}
	return out, errs
}

func one(l []any, e *verr) []verr {
	e.Loc = l
	return []verr{*e}
}

func validateField(raw any, f field, l []any) (any, []verr) {
	switch f.kind {
	case kInt:
		n, e := toInt(raw)
		if e != nil {
			return nil, one(l, e)
		}
		return n, nil
	case kFloat:
		n, e := toFloat(raw)
		if e != nil {
			return nil, one(l, e)
		}
		return n, nil
	case kBool:
		b, e := toBool(raw)
		if e != nil {
			return nil, one(l, e)
		}
		return b, nil
	case kStr:
		s, e := toStr(raw)
		if e != nil {
			return nil, one(l, e)
		}
		return s, nil
	case kLiteral:
		s, e := toLiteral(raw, f.lits)
		if e != nil {
			return nil, one(l, e)
		}
		return s, nil
	case kDict:
		o, ok := raw.(ojson.Object)
		if !ok {
			return nil, []verr{{Type: "dict_type", Loc: l, Msg: "Input should be a valid dictionary", Input: raw}}
		}
		return o, nil
	case kIntList, kModelList:
		arr, ok := raw.([]any)
		if !ok {
			return nil, []verr{{Type: "list_type", Loc: l, Msg: "Input should be a valid list", Input: raw}}
		}
		var errs []verr
		ints := []int64{}
		models := []map[string]any{}
		for i, item := range arr {
			if f.kind == kIntList {
				n, e := toInt(item)
				if e != nil {
					errs = append(errs, one(loc(l, i), e)...)
					continue
				}
				ints = append(ints, n)
			} else {
				m, me := validateModel(item, f.model, loc(l, i))
				if len(me) > 0 {
					errs = append(errs, me...)
					continue
				}
				models = append(models, m)
			}
		}
		if len(errs) > 0 {
			return nil, errs
		}
		if f.kind == kIntList {
			return ints, nil
		}
		return models, nil
	}
	return raw, nil
}

// ------------------------------------------------------------ request body

// errBodyTooLarge is returned when the body exceeds the configured limit.
var errBodyTooLarge = errors.New("request body too large")

// errBodyUnreadable is returned for bodies that are not valid UTF-8 JSON text.
var errBodyUnreadable = errors.New("there was an error parsing the body")

// readBody returns the decoded body: nil when empty, a JSON value for JSON
// content types, or the raw text otherwise (which then fails model validation,
// as in FastAPI).
func readBody(r *http.Request) (any, bool, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, false, errBodyTooLarge
		}
		return nil, false, err
	}
	if len(data) == 0 {
		return nil, false, nil
	}
	// As in FastAPI: no Content-Type, or application/json / application/*+json,
	// means the body is parsed as JSON; anything else is passed on as text.
	ct := r.Header.Get("Content-Type")
	isJSON := ct == ""
	if ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil {
			if main, sub, ok := strings.Cut(mt, "/"); ok && main == "application" && (sub == "json" || strings.HasSuffix(sub, "+json")) {
				isJSON = true
			}
		}
	}
	if !utf8.Valid(data) {
		return nil, false, errBodyUnreadable
	}
	if !isJSON {
		return string(data), true, nil
	}
	if msg, pos, ok := checkJSON(string(data)); !ok {
		return nil, false, &validationError{[]verr{{Type: "json_invalid", Loc: []any{"body", pos}, Msg: "JSON decode error",
			Input: ojson.Object{}, Ctx: ojson.Object{{Key: "error", Value: msg}}}}}
	}
	v, err := ojson.Decode(data)
	if err != nil { // NaN / Infinity: valid for CPython, not representable here
		return nil, false, &validationError{[]verr{{Type: "json_invalid", Loc: []any{"body", 0}, Msg: "JSON decode error",
			Input: ojson.Object{}, Ctx: ojson.Object{{Key: "error", Value: "Expecting value"}}}}}
	}
	return v, true, nil
}

// bodyModel reads and validates a JSON body. required=false allows a missing
// body (returns nil map, nil).
func bodyModel(r *http.Request, fields []field, required bool) (map[string]any, []verr, error) {
	v, present, err := readBody(r)
	if err != nil {
		return nil, nil, err
	}
	if !present {
		if required {
			return nil, []verr{{Type: "missing", Loc: []any{"body"}, Msg: "Field required", Input: nil}}, nil
		}
		return nil, nil, nil
	}
	m, errs := validateModel(v, fields, []any{"body"})
	return m, errs, nil
}

// ------------------------------------------------------------ query & path

type params struct {
	r    *http.Request
	path map[string]string
	errs []verr
	// scope is set for phased routes only (see tenantMode).
	scope readiness.Scope
}

func (p *params) query(name string) (string, bool) {
	vals, ok := p.r.URL.Query()[name]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[len(vals)-1], true // last value wins, as in Starlette
}

func (p *params) pathInt(name string) int64 {
	n, e := parseIntString(p.path[name])
	if e != nil {
		p.errs = append(p.errs, one([]any{"path", name}, e)...)
	}
	return n
}

func (p *params) pathLiteral(name string, lits []string) string {
	s, e := toLiteral(p.path[name], lits)
	if e != nil {
		p.errs = append(p.errs, one([]any{"path", name}, e)...)
	}
	return s
}

func (p *params) queryInt(name string, def int64, ge, le *int64) int64 {
	raw, ok := p.query(name)
	if !ok {
		return def
	}
	n, e := parseIntString(raw)
	if e != nil {
		p.errs = append(p.errs, one([]any{"query", name}, e)...)
		return def
	}
	if ge != nil && n < *ge {
		p.errs = append(p.errs, verr{Type: "greater_than_equal", Loc: []any{"query", name},
			Msg: "Input should be greater than or equal to " + strconv.FormatInt(*ge, 10), Input: raw,
			Ctx: ojson.Object{{Key: "ge", Value: *ge}}})
	} else if le != nil && n > *le {
		p.errs = append(p.errs, verr{Type: "less_than_equal", Loc: []any{"query", name},
			Msg: "Input should be less than or equal to " + strconv.FormatInt(*le, 10), Input: raw,
			Ctx: ojson.Object{{Key: "le", Value: *le}}})
	}
	return n
}

func (p *params) queryOptInt(name string) *int64 {
	raw, ok := p.query(name)
	if !ok {
		return nil
	}
	n, e := parseIntString(raw)
	if e != nil {
		p.errs = append(p.errs, one([]any{"query", name}, e)...)
		return nil
	}
	return &n
}

func (p *params) queryOptBool(name string) *bool {
	raw, ok := p.query(name)
	if !ok {
		return nil
	}
	b, e := parseBoolString(raw)
	if e != nil {
		p.errs = append(p.errs, one([]any{"query", name}, e)...)
		return nil
	}
	return &b
}

func (p *params) queryOptStr(name string) *string {
	raw, ok := p.query(name)
	if !ok {
		return nil
	}
	return &raw
}

func (p *params) queryOptLiteral(name string, lits []string) *string {
	raw, ok := p.query(name)
	if !ok {
		return nil
	}
	s, e := toLiteral(raw, lits)
	if e != nil {
		p.errs = append(p.errs, one([]any{"query", name}, e)...)
		return nil
	}
	return &s
}

func i64(v int64) *int64 { return &v }

// clampInt narrows a validated int64 query or body number to int with an explicit
// range check, so the conversion is safe whatever the platform's int size.
func clampInt(n int64) int {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int(n)
}
