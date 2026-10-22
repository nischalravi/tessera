package vms

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Limits of a CSV feed.
const (
	MaxCSVBytes = 8 << 20
	MaxCSVRows  = 50000
)

// canonical are the fields of a CSV row. A file names them with these headers
// unless Settings.Mapping renames a column. Required: worker_id, email, and a
// name (name, or first_name and last_name). A row without end_date or sponsor is
// still read: the intake rejects or holds it, and says why.
var canonical = map[string]bool{"worker_id": true, "name": true, "first_name": true, "last_name": true, "email": true,
	"supplier": true, "role": true, "sponsor_email": true, "sponsor_employee_id": true, "status": true, "start_date": true,
	"end_date": true, "updated_at": true}

// ErrCSV is a feed that cannot be read at all (a malformed file, a missing
// column). A single bad row is not an error: it becomes a record the intake rejects.
var ErrCSV = errors.New("vms: unreadable CSV feed")

// CSVResult is a parsed feed.
type CSVResult struct {
	Records []*connectors.VmsRecord
	// BadRows counts the rows that could not be read as a record (wrong number of
	// fields); they are skipped and never quoted.
	BadRows int
}

// ParseCSV reads a CSV feed. asOf stamps the rows that carry no updated_at, so
// a later import of the same file reads as the same version of each record.
func ParseCSV(r io.Reader, set Settings, asOf time.Time) (*CSVResult, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxCSVBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSV, err)
	}
	if len(raw) > MaxCSVBytes {
		return nil, fmt.Errorf("%w: the file is larger than %d MiB", ErrCSV, MaxCSVBytes>>20)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // a spreadsheet's byte-order mark
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, fmt.Errorf("%w: the file is not UTF-8 text", ErrCSV)
	}
	cr := csv.NewReader(bytes.NewReader(raw))
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: no header row", ErrCSV)
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	idx := map[string]int{}
	for f := range canonical {
		name := f
		if m := set.Mapping[f]; m != "" {
			name = m
		}
		if i, ok := col[strings.ToLower(strings.TrimSpace(name))]; ok {
			idx[f] = i
		}
	}
	for _, need := range []string{"worker_id", "email"} {
		if _, ok := idx[need]; !ok {
			return nil, fmt.Errorf("%w: no %s column", ErrCSV, need)
		}
	}
	if _, ok := idx["name"]; !ok {
		if _, ok := idx["first_name"]; !ok {
			return nil, fmt.Errorf("%w: no name (or first_name and last_name) column", ErrCSV)
		}
	}
	var layouts []string
	if set.DateFormat != "" {
		layouts = []string{set.DateFormat}
	}
	out := &CSVResult{}
	for n := 0; ; n++ {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) && !errors.Is(err, csv.ErrBareQuote) && !errors.Is(err, csv.ErrQuote) {
				out.BadRows++
				continue
			}
			return nil, fmt.Errorf("%w: a quote is not closed or misplaced", ErrCSV)
		}
		if n >= MaxCSVRows {
			return nil, fmt.Errorf("%w: more than %d rows", ErrCSV, MaxCSVRows)
		}
		get := func(f string) string {
			if i, ok := idx[f]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		if len(row) == 1 && strings.TrimSpace(row[0]) == "" {
			continue // a blank line
		}
		name := get("name")
		if name == "" {
			name = strings.TrimSpace(get("first_name") + " " + get("last_name"))
		}
		rec := &connectors.VmsRecord{System: "csv", WorkerID: get("worker_id"), Name: name, Email: get("email"),
			Supplier: get("supplier"), Role: get("role"), SponsorEmail: get("sponsor_email"),
			SponsorEmployeeID: get("sponsor_employee_id"), Status: status(get("status")),
			StartsAt: parseTime(get("start_date"), layouts...), EndsAt: parseTime(get("end_date"), layouts...)}
		if rec.Status == "" {
			rec.Status = connectors.VmsActive // a file of current contractors need not say so
		}
		upd := get("updated_at")
		if t := parseTime(upd, layouts...); t != nil {
			rec.UpdatedAt = *t
		} else {
			rec.UpdatedAt, upd = asOf.UTC(), ""
		}
		rec.EventID = eventID("csv", rec.WorkerID, rec.Status, tstr(rec.StartsAt), tstr(rec.EndsAt), rec.SponsorEmployeeID,
			strings.ToLower(rec.SponsorEmail), strings.ToLower(rec.Email), strings.ToLower(rec.Name), upd)
		out.Records = append(out.Records, rec)
	}
}

// CSVFetcher fetches a CSV feed over HTTPS with an optional bearer token.
type CSVFetcher struct {
	URL      string // absolute, built from the source's base URL and csv_path
	Token    connsync.Secret
	HC       *http.Client // internal/safehttp
	Settings Settings
	Now      func() time.Time
}

// Fetch reads the feed.
func (f *CSVFetcher) Fetch(ctx context.Context) (*CSVResult, error) {
	if f.HC == nil {
		return nil, errors.New("vms: an internal/safehttp client is required")
	}
	hdr := http.Header{"Accept": {"text/csv"}, "User-Agent": {"tessera-connector/vms"}}
	if !f.Token.Empty() {
		hdr.Set("Authorization", "Bearer "+f.Token.Reveal())
	}
	c := &connsync.Client{HC: f.HC, Now: f.Now}
	resp, err := c.Do(ctx, http.MethodGet, f.URL, hdr, nil)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	return ParseCSV(bytes.NewReader(resp.Body), f.Settings, now())
}
