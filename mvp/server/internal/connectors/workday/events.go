package workday

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

const eventsCheckpoint = "events"

var eventIDRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// wChange is one side (from or to) of a job or manager change.
type wChange struct {
	Title   string `json:"businessTitle"`
	Org     wOrg   `json:"supervisoryOrganization"`
	Manager wRef   `json:"manager"`
}

// wEvent is an effective-dated worker event as the events endpoint returns it.
type wEvent struct {
	ID            string  `json:"id"`
	Type          string  `json:"type"` // HIRE, TERMINATE, JOB_CHANGE, MANAGER_CHANGE
	EffectiveDate string  `json:"effectiveDate"`
	Reason        string  `json:"reason"`
	Worker        wRef    `json:"worker"`
	From          wChange `json:"from"`
	To            wChange `json:"to"`
}

// eventsState is the (empty) snapshot an events checkpoint carries: the cursor
// is the whole position, but Decide wants a non-empty state.
type eventsState struct{ Version int }

// StreamEvents yields the worker events as HRIS events: hire as joiner,
// terminate as leaver, job and manager change as mover, oldest effective date
// first. Future-dated events keep their future effective date and are never
// applied by the connector (see the package comment). since, when set, reads
// events updated since then and leaves the checkpoint alone; otherwise the
// stored events checkpoint is used and advanced.
func (c *Connector) StreamEvents(ctx context.Context, since *time.Time, yield func(connectors.Event) error) error {
	start := c.now()
	st, err := c.loadState(ctx)
	if err != nil {
		return err
	}
	var from *time.Time // Updated_From, nil for a full read
	if since != nil {
		s := since.UTC()
		from = &s
	} else {
		plan, err := connsync.Decide(ctx, System, eventsCheckpoint, start, c.cfg.MaxIncrementalAge)
		if err != nil {
			return err
		}
		if !plan.Full {
			if wm, ok := loadWatermark(plan.Prior.Cursor, start); ok {
				from = &wm
			}
		}
	}
	events, err := c.readEvents(ctx, from, start)
	if isWatermarkRefused(err) && from != nil {
		from = nil
		events, err = c.readEvents(ctx, nil, start)
	}
	if err != nil {
		return err
	}
	var recs []*connectors.HrisEventRecord
	seen := map[string]bool{}
	for _, e := range events {
		if r := c.record(e, st, start); r != nil && !seen[r.ExternalID] {
			seen[r.ExternalID] = true
			recs = append(recs, r)
		}
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].EffectiveAt.Equal(recs[j].EffectiveAt) {
			return recs[i].EffectiveAt.Before(recs[j].EffectiveAt)
		}
		return recs[i].ExternalID < recs[j].ExternalID
	})
	for _, r := range recs {
		if err := yield(r); err != nil {
			return err
		}
	}
	if since == nil {
		c.saveEvents(ctx, start, from == nil)
	}
	return ctx.Err()
}

// readEvents reads the events updated since from, or (nil) every event
// effective within the window or later, which includes future-dated ones.
func (c *Connector) readEvents(ctx context.Context, from *time.Time, now time.Time) ([]wEvent, error) {
	q := url.Values{}
	if from != nil {
		q.Set("Updated_From", from.UTC().Format(time.RFC3339))
	} else {
		q.Set("Effective_From", now.Add(-c.cfg.EventWindow).UTC().Format("2006-01-02"))
	}
	var out []wEvent
	err := listAll(ctx, c, c.events, q, func(e wEvent) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("workday: worker events: %w", err)
	}
	return out, nil
}

func (c *Connector) saveEvents(ctx context.Context, start time.Time, full bool) {
	store := connsync.StoreFrom(ctx)
	if store == nil {
		return
	}
	blob, err := connsync.EncodeState(eventsState{Version: 1})
	if err != nil {
		return
	}
	cp := &connsync.Checkpoint{Cursor: start.Add(-watermarkOverlap).UTC().Format(time.RFC3339), State: blob, UpdatedAt: start}
	if full {
		cp.FullSyncAt = &start
	} else if prior, err := store.Load(ctx, System, eventsCheckpoint); err == nil && prior != nil {
		cp.FullSyncAt = prior.FullSyncAt
	}
	_ = store.Save(ctx, System, eventsCheckpoint, cp)
}

func normType(t string) string {
	return strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToUpper(strings.TrimSpace(t)))
}

func date(t time.Time) string { return t.UTC().Format("2006-01-02") }

// record maps one event, or returns nil for one that cannot be used (unknown
// type, no usable date, no worker it can be tied to).
func (c *Connector) record(e wEvent, st *state, now time.Time) *connectors.HrisEventRecord {
	eff := parseDate(e.EffectiveDate)
	if eff == nil || !eventIDRE.MatchString(e.ID) {
		return nil
	}
	w := st.Workers[e.Worker.ID]
	if w == nil {
		w = &wWorker{}
	}
	xid := e.Worker.EmployeeID
	if xid == "" {
		xid = w.EmployeeID
	}
	if xid == "" && e.Worker.ID != "" && st.Workers[e.Worker.ID] != nil {
		xid = "workday:" + e.Worker.ID
	}
	if xid == "" || len(xid) > 128 {
		return nil
	}
	ref := &connectors.IdentityRef{ExternalID: xid, Email: w.Email}
	empOf := func(r wRef) string {
		if r.EmployeeID != "" {
			return r.EmployeeID
		}
		if m := st.Workers[r.ID]; m != nil && r.ID != "" {
			return m.xid()
		}
		return ""
	}
	obj := ojson.Object{}
	put := func(k, v string) {
		if v != "" {
			obj = append(obj, ojson.KV{Key: k, Value: v})
		}
	}
	first := func(ss ...string) string {
		for _, s := range ss {
			if s != "" {
				return s
			}
		}
		return ""
	}
	// Past the window the legacy process already handled it.
	historical := eff.Before(now.Add(-c.cfg.EventWindow))
	rec := &connectors.HrisEventRecord{ExternalID: "wd-evt-" + e.ID, Identity: ref, EffectiveAt: *eff}

	switch normType(e.Type) {
	case "HIRE":
		rec.Type = "joiner"
		put("name", first(w.Descriptor, e.Worker.Descriptor, xid))
		put("email", w.Email)
		put("department", first(e.To.Org.Descriptor, w.Org.Descriptor))
		put("team", teamSlug(first(e.To.Org.Descriptor, w.Org.Descriptor)))
		put("title", first(e.To.Title, w.Title))
		put("manager_external_id", first(empOf(e.To.Manager), empOf(w.Manager)))
		put("worker_type", w.WorkerType.Descriptor)
		put("employee_id", xid)
		if eff.After(now) {
			// Pre-hire: there is no identity yet, the joiner flow creates it.
			rec.Identity = nil
		} else {
			// The worker record already made the identity; executing the
			// joiner would create the person a second time.
			historical = true
		}
	case "TERMINATE":
		rec.Type = "leaver"
		put("reason", first(e.Reason, "Termination"))
		put("last_day", date(*eff))
		put("employee_id", xid)
	case "JOB_CHANGE", "MANAGER_CHANGE":
		rec.Type = "mover"
		toOrg := first(e.To.Org.Descriptor, e.From.Org.Descriptor, w.Org.Descriptor)
		to := teamSlug(toOrg)
		if to == "" {
			// Without a target team the mover plan would strip the old team's
			// access: better no event than a wrong one.
			return nil
		}
		from := teamSlug(e.From.Org.Descriptor)
		if from == "" && e.To.Org.Descriptor == "" {
			from = to // no organization change: no access change
		}
		put("from_department", e.From.Org.Descriptor)
		put("to_department", first(e.To.Org.Descriptor, e.From.Org.Descriptor))
		put("from_team", from)
		put("to_team", to)
		put("new_title", e.To.Title)
		put("from_manager_external_id", empOf(e.From.Manager))
		put("to_manager_external_id", empOf(e.To.Manager))
		put("change", strings.ToLower(normType(e.Type)))
		put("employee_id", xid)
	default:
		return nil
	}
	if historical {
		obj = append(obj, ojson.KV{Key: "historical", Value: true})
	}
	rec.Payload = obj
	return rec
}
