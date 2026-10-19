package sod

import "encoding/json"

func jsonOf(v any) ([]byte, error) { return json.Marshal(v) }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}
