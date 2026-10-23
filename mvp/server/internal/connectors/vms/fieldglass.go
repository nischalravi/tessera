package vms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// DefaultFieldglassPath is the worker listing endpoint.
const DefaultFieldglassPath = "/api/v1/workers"

// Fieldglass reads SAP Fieldglass workers. The listing is
//
//	GET <workers_path>?page_size=N[&modified_after=<RFC 3339>]
//	{"workers":[{"worker_id","first_name","last_name","email","status",
//	             "start_date","end_date","supplier_name","job_title",
//	             "buyer_manager_email","buyer_manager_id","modified_at"}],
//	 "next_page": "<absolute URL on the same host>" | null}
//
// status is Active, Pending Start, Completed or Terminated. The buyer-side
// manager of the worker is the sponsor.
type Fieldglass struct{ *rest }

type fgWorker struct {
	WorkerID   string `json:"worker_id"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Email      string `json:"email"`
	Status     string `json:"status"`
	StartDate  string `json:"start_date"`
	EndDate    string `json:"end_date"`
	Supplier   string `json:"supplier_name"`
	JobTitle   string `json:"job_title"`
	MgrEmail   string `json:"buyer_manager_email"`
	MgrID      string `json:"buyer_manager_id"`
	ModifiedAt string `json:"modified_at"`
}

// VmsRecords implements connectors.VmsConnector.
func (f *Fieldglass) VmsRecords(ctx context.Context, since *time.Time, yield func(*connectors.VmsRecord) error) error {
	path := f.set.WorkersPath
	if path == "" {
		path = DefaultFieldglassPath
	}
	q := url.Values{"page_size": {strconv.Itoa(f.set.PageSize)}}
	if since != nil {
		q.Set("modified_after", since.UTC().Format(time.RFC3339))
	}
	return connsync.Walk(ctx, f.base, f.url(path, q), func(ctx context.Context, pageURL string) (string, error) {
		var page struct {
			Workers  []json.RawMessage `json:"workers"`
			NextPage *string           `json:"next_page"`
		}
		if _, err := f.api.GetJSON(ctx, pageURL, nil, &page); err != nil {
			return "", err
		}
		for i := range page.Workers {
			var w fgWorker
			if err := json.Unmarshal(page.Workers[i], &w); err != nil {
				return "", fmt.Errorf("fieldglass: a worker is not readable: %w", err)
			}
			rec := &connectors.VmsRecord{System: "fieldglass", WorkerID: w.WorkerID,
				Name: strings.TrimSpace(w.FirstName + " " + w.LastName), Email: w.Email, Supplier: w.Supplier, Role: w.JobTitle,
				SponsorEmployeeID: w.MgrID, SponsorEmail: w.MgrEmail, Status: status(w.Status),
				StartsAt: parseTime(w.StartDate), EndsAt: parseTime(w.EndDate)}
			if t := parseTime(w.ModifiedAt); t != nil {
				rec.UpdatedAt = *t
			}
			modified := applyMapping(rec, page.Workers[i], f.set.Mapping, w.ModifiedAt)
			rec.EventID = eventID("fieldglass", rec.WorkerID, rec.Status, tstr(rec.StartsAt), tstr(rec.EndsAt), rec.SponsorEmployeeID,
				strings.ToLower(rec.SponsorEmail), strings.ToLower(rec.Email), modified)
			if err := yield(rec); err != nil {
				return "", err
			}
		}
		if page.NextPage == nil {
			return "", nil
		}
		return *page.NextPage, nil
	})
}
