package plan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client sends one API request. body, if not nil, is sent as JSON. The
// implementation owns authentication (the CLI's DPoP-bound OAuth session) and
// returns the status and body whatever the status is; an error is a failure to
// get an answer at all (and a step-up demand, which the CLI reports itself).
type Client interface {
	Call(ctx context.Context, method, path string, body any, header http.Header) (status int, out []byte, err error)
}

// APIError is an error answer of the API ({"error": code, "detail": message}).
type APIError struct {
	Status  int
	Code    string
	Message string
	// Index is the batch operation an atomic batch refused, or -1.
	Index int
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("the server answered %d", e.Status)
	if e.Code != "" {
		s += " " + printable(e.Code)
	}
	if e.Message != "" {
		s += ": " + printable(e.Message)
	}
	return s
}

// printable drops control characters from text the server sent.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// call makes a request and decodes a 2xx JSON answer into out (if not nil).
func call(ctx context.Context, c Client, method, path string, body, out any, header http.Header) (int, error) {
	status, raw, err := c.Call(ctx, method, path, body, header)
	if err != nil {
		return status, err
	}
	if status >= 400 {
		e := &APIError{Status: status, Index: -1}
		var doc struct {
			Error   string   `json:"error"`
			Detail  string   `json:"detail"`
			Message string   `json:"message"`
			Index   *int     `json:"index"`
			Path    []string `json:"path"`
		}
		if json.Unmarshal(raw, &doc) == nil {
			e.Code, e.Message = doc.Error, doc.Detail
			if e.Message == "" {
				e.Message = doc.Message
			}
			if len(doc.Path) > 0 {
				e.Message = strings.TrimSpace(e.Message + " (" + strings.Join(doc.Path, " -> ") + ")")
			}
			if doc.Index != nil {
				e.Index = *doc.Index
			}
		}
		return status, e
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return status, fmt.Errorf("the server's answer is not the JSON expected: %w", err)
		}
	}
	return status, nil
}

// pageSize is the page the listings are read in (the API's maximum).
const pageSize = 500

// maxPages bounds a listing, so a misbehaving server cannot hold the CLI.
const maxPages = 2000

// listAll reads every page of a listing ({"items": [...], "limit", "offset"}).
func listAll[T any](ctx context.Context, c Client, path string, query url.Values) ([]T, error) {
	var all []T
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("limit", strconv.Itoa(pageSize))
		q.Set("offset", strconv.Itoa(page*pageSize))
		var out struct {
			Items []T `json:"items"`
		}
		if _, err := call(ctx, c, http.MethodGet, path+"?"+q.Encode(), nil, &out, nil); err != nil {
			return nil, err
		}
		all = append(all, out.Items...)
		if len(out.Items) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("%s has more than %d entries", path, maxPages*pageSize)
}
