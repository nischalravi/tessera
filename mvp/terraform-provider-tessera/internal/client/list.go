package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	listLimit    = 500
	maxListPages = 200
)

// List reads every item of a list route. Routes answer a bare JSON array or {"items": [...], "next_cursor": ...};
// both are read, and a next_cursor is followed (500 items a page, at most 200 pages). query is optional.
func (c *Client) List(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	var all []json.RawMessage
	cursor := ""
	for page := 0; page < maxListPages; page++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		if page > 0 || cursor != "" {
			q.Set("cursor", cursor)
		}
		q.Set("limit", fmt.Sprint(listLimit))
		var raw json.RawMessage
		if err := c.Do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &raw); err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var items []json.RawMessage
			if err := json.Unmarshal(trimmed, &items); err != nil {
				return nil, err
			}
			return append(all, items...), nil
		}
		var env struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor *string           `json:"next_cursor"`
		}
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("the answer to GET %s is not a list: %w", path, err)
		}
		all = append(all, env.Items...)
		if env.NextCursor == nil || *env.NextCursor == "" {
			return all, nil
		}
		cursor = *env.NextCursor
	}
	return nil, fmt.Errorf("GET %s has more than %d pages; narrow it with a filter", path, maxListPages)
}
