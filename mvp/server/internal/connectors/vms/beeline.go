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

// DefaultBeelinePath is the assignment listing endpoint.
const DefaultBeelinePath = "/api/v2/assignments"

// Beeline reads Beeline assignments. The listing is
//
//	GET <workers_path>?limit=N[&modified_since=<RFC 3339>]
//	{"data":[{"id","state","start","end","vendor","position","updated",
//	          "worker":{"first_name","last_name","email"},
//	          "manager":{"email","employee_id"}}],
//	 "links":{"next":"<absolute URL on the same host>"}}
//
// state is pending, active, closed or terminated. The assignment's hiring
// manager is the sponsor.
type Beeline struct{ *rest }

type blAssignment struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Start  string `json:"start"`
	End    string `json:"end"`
	Vendor string `json:"vendor"`
	Role   string `json:"position"`
	Update string `json:"updated"`
	Worker struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
	} `json:"worker"`
	Manager struct {
		Email      string `json:"email"`
		EmployeeID string `json:"employee_id"`
	} `json:"manager"`
}

// VmsRecords implements connectors.VmsConnector.
func (b *Beeline) VmsRecords(ctx context.Context, since *time.Time, yield func(*connectors.VmsRecord) error) error {
	path := b.set.WorkersPath
	if path == "" {
		path = DefaultBeelinePath
	}
	q := url.Values{"limit": {strconv.Itoa(b.set.PageSize)}}
	if since != nil {
		q.Set("modified_since", since.UTC().Format(time.RFC3339))
	}
	return connsync.Walk(ctx, b.base, b.url(path, q), func(ctx context.Context, pageURL string) (string, error) {
		var page struct {
			Data  []json.RawMessage `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if _, err := b.api.GetJSON(ctx, pageURL, nil, &page); err != nil {
			return "", err
		}
		for i := range page.Data {
			var a blAssignment
			if err := json.Unmarshal(page.Data[i], &a); err != nil {
				return "", fmt.Errorf("beeline: an assignment is not readable: %w", err)
			}
			rec := &connectors.VmsRecord{System: "beeline", WorkerID: a.ID,
				Name: strings.TrimSpace(a.Worker.FirstName + " " + a.Worker.LastName), Email: a.Worker.Email, Supplier: a.Vendor,
				Role: a.Role, SponsorEmployeeID: a.Manager.EmployeeID, SponsorEmail: a.Manager.Email, Status: status(a.State),
				StartsAt: parseTime(a.Start), EndsAt: parseTime(a.End)}
			if t := parseTime(a.Update); t != nil {
				rec.UpdatedAt = *t
			}
			modified := applyMapping(rec, page.Data[i], b.set.Mapping, a.Update)
			rec.EventID = eventID("beeline", rec.WorkerID, rec.Status, tstr(rec.StartsAt), tstr(rec.EndsAt), rec.SponsorEmployeeID,
				strings.ToLower(rec.SponsorEmail), strings.ToLower(rec.Email), modified)
			if err := yield(rec); err != nil {
				return "", err
			}
		}
		return page.Links.Next, nil
	})
}
