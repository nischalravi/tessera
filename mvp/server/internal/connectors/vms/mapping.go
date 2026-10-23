package vms

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

// applyMapping takes the fields a source's mapping names from the vendor's own
// worker object (a Fieldglass or Beeline custom field, say) and lets them
// replace what the documented fields gave. raw is the worker object as the
// vendor sent it. A path that is missing, empty or not a plain value leaves the
// documented field alone. It returns the vendor's modified-at text, replaced
// when updated_at is mapped, for the event id.
func applyMapping(rec *connectors.VmsRecord, raw json.RawMessage, mapping map[string]string, modified string) string {
	if len(mapping) == 0 {
		return modified
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return modified
	}
	keys := make([]string, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := lookupText(obj, mapping[k])
		if v == "" {
			continue
		}
		switch k {
		case "worker_id":
			rec.WorkerID = v
		case "name":
			rec.Name = v
		case "email":
			rec.Email = v
		case "supplier":
			rec.Supplier = v
		case "role":
			rec.Role = v
		case "sponsor_email":
			rec.SponsorEmail = v
		case "sponsor_employee_id":
			rec.SponsorEmployeeID = v
		case "status":
			rec.Status = status(v)
		case "start_date":
			rec.StartsAt = parseTime(v)
		case "end_date":
			rec.EndsAt = parseTime(v)
		case "updated_at":
			if t := parseTime(v); t != nil {
				rec.UpdatedAt = *t
				modified = v
			}
		}
	}
	return modified
}

// lookupText follows a dotted path through nested objects and returns the plain
// value at its end as text: a string, a number or a boolean. Anything else
// (an object, an array, null) is "".
func lookupText(obj map[string]any, path string) string {
	var cur any = obj
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		if cur, ok = m[seg]; !ok {
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}
