package successfactors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// maxRows bounds the rows read from one entity, so a hostile or broken source
// cannot turn into an unbounded read (connsync.MaxPages bounds the pages too).
const maxRows = 2_000_000

// maxField bounds every string kept from a response.
const maxField = 256

// odataString renders v as an OData string literal for $filter: wrapped in
// single quotes with every embedded single quote doubled. Control characters
// are refused, so a value can neither end the literal nor smuggle an operator.
// Every value that reaches a $filter goes through it.
func odataString(v string) (string, error) {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("successfactors: a filter value has a control character")
		}
	}
	return "'" + strings.ReplaceAll(v, "'", "''") + "'", nil
}

// odataTime renders a time as an OData v2 datetime literal.
func odataTime(t time.Time) string {
	return "datetime'" + t.UTC().Format("2006-01-02T15:04:05") + "'"
}

// flex reads a JSON string, number or boolean as text (OData v2 sends Int64 as
// a string and Int32 as a number, and a tenant's picklists vary).
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0 || string(b) == "null":
		*f = ""
	case b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flex(clip(s))
	case b[0] == '{' || b[0] == '[':
		*f = "" // an expanded navigation property that was not asked for
	default:
		*f = flex(clip(string(b)))
	}
	return nil
}

func clip(s string) string {
	if len(s) > maxField {
		return s[:maxField]
	}
	return s
}

// parseTime reads an OData date: /Date(ms)/ (with an optional offset), an ISO
// timestamp or a plain date. The open end SuccessFactors uses (year 9999) is no
// date.
func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var t time.Time
	if strings.HasPrefix(s, "/Date(") && strings.HasSuffix(s, ")/") {
		body := s[len("/Date(") : len(s)-2]
		if i := strings.LastIndexAny(body, "+-"); i > 0 {
			body = body[:i]
		}
		ms, err := strconv.ParseInt(body, 10, 64)
		if err != nil || ms < -62135596800000 || ms > 253402300799999+86400000 {
			return nil
		}
		t = time.UnixMilli(ms).UTC()
	} else {
		ok := false
		for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04:05.999999999"} {
			if p, err := time.Parse(layout, s); err == nil {
				t, ok = p.UTC(), true
				break
			}
		}
		if !ok {
			return nil
		}
	}
	if t.Year() >= 9999 {
		return nil
	}
	return &t
}

// odPage is one OData v2 collection page: {"d": {"results": [...], "__next": "..."}}.
type odPage[T any] struct {
	D struct {
		Results []T    `json:"results"`
		Next    string `json:"__next"`
	} `json:"d"`
}

// entityURL builds the first page URL of an entity set. $format=json makes the
// server answer JSON whatever the Accept header says.
func (c *Connector) entityURL(entity string, q url.Values) string {
	q = cloneValues(q)
	q.Set("$format", "json")
	u := *c.base
	u.Path = odataRoot + "/" + entity
	u.RawQuery = encodeQuery(q)
	return u.String()
}

// encodeQuery encodes a query with %20 for spaces and unescaped $ in names, the
// form OData servers document.
func encodeQuery(q url.Values) string {
	return strings.ReplaceAll(strings.ReplaceAll(q.Encode(), "+", "%20"), "%24", "$")
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// listAll walks an entity set through __next. A relative __next is resolved
// against the page it came from; connsync.Walk then refuses any link that
// leaves the configured host.
func listAll[T any](ctx context.Context, c *Connector, entity string, q url.Values, each func(T) error) error {
	rows := 0
	return connsync.Walk(ctx, c.base, c.entityURL(entity, q), func(ctx context.Context, pageURL string) (string, error) {
		var p odPage[T]
		if _, err := c.api.GetJSON(ctx, pageURL, nil, &p); err != nil {
			return "", err
		}
		if rows += len(p.D.Results); rows > maxRows {
			return "", fmt.Errorf("%w: too many rows", connsync.ErrMalformed)
		}
		for _, it := range p.D.Results {
			if err := each(it); err != nil {
				return "", err
			}
		}
		if p.D.Next == "" {
			return "", nil
		}
		cur, err := url.Parse(pageURL)
		if err != nil {
			return "", err
		}
		next, err := cur.Parse(p.D.Next)
		if err != nil {
			return "", fmt.Errorf("%w: bad __next link", connsync.ErrMalformed)
		}
		return next.String(), nil
	})
}
