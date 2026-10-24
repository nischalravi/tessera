package restgen

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// ErrTruncated is returned (wrapped) when a listing hit a configured cap
// (limits.max_pages or limits.max_records) before its last page. The records
// read so far were delivered; the caller must not treat them as complete.
var ErrTruncated = errors.New("restgen: listing stopped at a configured limit")

// listSpec is what walking a collection needs: a Resource, or the member list
// of one record.
type listSpec struct {
	path      string // path template, expanded with vars
	query     map[string]string
	itemsPath string
	pg        Pagination
}

func (r *Resource) list() listSpec {
	return listSpec{path: r.Path, query: r.Query, itemsPath: r.ItemsPath, pg: r.Pagination}
}

func (m *Members) list() listSpec {
	return listSpec{path: m.Path, query: m.Query, itemsPath: m.ItemsPath, pg: m.Pagination}
}

// walk reads a collection page by page and calls each for every record, in
// order. It returns how many pages it read. The walk is bounded by the limits,
// refuses a next link that leaves the base URL's origin, and stops with an
// error if the server repeats a page address or a cursor (a loop).
func (c *Client) walk(ctx context.Context, ls listSpec, vars Vars, each func(rec any) error) (int, error) {
	pg := ls.pg
	p, err := expandPath(ls.path, vars)
	if err != nil {
		return 0, err
	}
	base := expandQuery(ls.query, vars)
	itemsPath, err := optionalPath(ls.itemsPath)
	if err != nil {
		return 0, err
	}
	nextPath, err := optionalPath(pg.NextPath)
	if err != nil {
		return 0, err
	}
	page, offset, cursor := pg.StartPage, 0, ""
	if page == 0 {
		page = 1
	}
	var nextURL *url.URL
	seen := map[string]bool{}
	pages, records := 0, 0
	for {
		var u *url.URL
		if nextURL != nil {
			u = nextURL
		} else {
			q := url.Values{}
			for k, v := range base {
				q[k] = v
			}
			switch pg.Style {
			case PagePage:
				q.Set(pg.PageParam, strconv.Itoa(page))
			case PageOffset:
				q.Set(pg.OffsetParam, strconv.Itoa(offset))
			case PageCursor:
				if cursor != "" {
					q.Set(pg.CursorParam, cursor)
				}
			}
			if pg.SizeParam != "" && pg.PageSize > 0 {
				q.Set(pg.SizeParam, strconv.Itoa(pg.PageSize))
			}
			if u, err = buildURL(c.base, p, q); err != nil {
				return pages, err
			}
		}
		if key := u.String(); seen[key] {
			return pages, fmt.Errorf("the server repeated a page address: pagination %q is not advancing", pg.Style)
		} else {
			seen[key] = true
		}
		if pages >= c.lim.MaxPages {
			return pages, fmt.Errorf("%w: %d pages", ErrTruncated, pages)
		}
		resp, err := c.do(ctx, request{method: http.MethodGet, u: u})
		if err != nil {
			return pages, err
		}
		if resp.Status < 200 || resp.Status > 299 {
			return pages, &StatusError{Status: resp.Status, Op: "list " + ls.path, Detail: errorDetail(resp.Body), RetryAfter: resp.RetryAfter}
		}
		doc, err := resp.JSON()
		if err != nil {
			return pages, fmt.Errorf("list %s: %v", ls.path, err)
		}
		pages++
		items := selectItems(itemsPath, doc)
		for _, it := range items {
			if records >= c.lim.MaxRecords {
				return pages, fmt.Errorf("%w: %d records", ErrTruncated, records)
			}
			records++
			if err := each(it); err != nil {
				return pages, err
			}
		}
		nextURL = nil
		switch pg.Style {
		case "", PageNone:
			return pages, nil
		case PagePage:
			if len(items) == 0 || len(items) < pg.PageSize {
				return pages, nil
			}
			page++
		case PageOffset:
			if len(items) == 0 || len(items) < pg.PageSize {
				return pages, nil
			}
			offset += len(items)
		case PageCursor:
			n, _ := nextPath.First(doc)
			next, _ := Scalar(n)
			if next == "" || len(items) == 0 {
				return pages, nil
			}
			if next == cursor {
				return pages, errors.New("the server returned the same cursor again: pagination is not advancing")
			}
			cursor = next
		case PageLinkHeader:
			link := nextLink(resp.Header.Values("Link"))
			if link == "" {
				return pages, nil
			}
			if nextURL, err = c.follow(u, link); err != nil {
				return pages, err
			}
		case PageNextURL:
			n, _ := nextPath.First(doc)
			next, _ := Scalar(n)
			if next == "" {
				return pages, nil
			}
			if nextURL, err = c.follow(u, next); err != nil {
				return pages, err
			}
		}
	}
}

// follow resolves a next link from a response against the page it came from
// and refuses it unless it stays on the base URL's origin: the credential goes
// with the request, and a response must not be able to send it elsewhere.
func (c *Client) follow(from *url.URL, link string) (*url.URL, error) {
	ref, err := url.Parse(link)
	if err != nil || len(link) > 2048 {
		return nil, errors.New("the server sent a next link that is not a URL")
	}
	abs := from.ResolveReference(ref)
	abs.Fragment = ""
	u, err := connsync.SameOrigin(c.base, abs.String())
	if err != nil {
		return nil, errors.New("the server sent a next link to another host; it was not followed")
	}
	return u, nil
}

// nextLink finds the rel="next" target in Link headers (RFC 8288).
func nextLink(values []string) string {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if !strings.HasPrefix(part, "<") {
				continue
			}
			end := strings.IndexByte(part, '>')
			if end < 0 {
				continue
			}
			for _, param := range strings.Split(part[end+1:], ";") {
				k, val, _ := strings.Cut(strings.TrimSpace(param), "=")
				if strings.EqualFold(k, "rel") && containsRel(strings.Trim(val, `"`), "next") {
					return part[1:end]
				}
			}
		}
	}
	return ""
}

func containsRel(rels, want string) bool {
	for _, r := range strings.Fields(rels) {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

func optionalPath(s string) (*Path, error) {
	if s == "" || s == "$" {
		return CompilePath("$")
	}
	return CompilePath(s)
}

// selectItems returns the records of a response: the nodes at itemsPath, or
// when that is one array, its elements.
func selectItems(p *Path, doc any) []any {
	sel := p.Select(doc)
	if len(sel) == 1 {
		if a, ok := sel[0].([]any); ok {
			return a
		}
		if _, ok := sel[0].(map[string]any); !ok {
			return nil
		}
	}
	return sel
}
