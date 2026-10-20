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
)

const checkpointName = "discover"

// watermarkOverlap is subtracted from the sync start when it is stored as the
// checkpoint cursor, so a clock difference with the source never hides a change.
const watermarkOverlap = 5 * time.Minute

// maxField bounds every string kept from a response.
const maxField = 256

type wOrg struct {
	ID         string `json:"id"`
	Descriptor string `json:"descriptor"`
}

type wRef struct {
	ID         string `json:"id"`
	EmployeeID string `json:"employeeId"`
	Descriptor string `json:"descriptor"`
}

// wWorker is a worker as the REST endpoint returns it (and as it is stored in
// the checkpoint snapshot).
type wWorker struct {
	ID              string `json:"id"`
	Descriptor      string `json:"descriptor"`
	EmployeeID      string `json:"employeeId"`
	Email           string `json:"primaryWorkEmail"`
	WorkerType      wOrg   `json:"workerType"`
	Title           string `json:"businessTitle"`
	Org             wOrg   `json:"supervisoryOrganization"`
	Manager         wRef   `json:"manager"`
	HireDate        string `json:"hireDate"`
	TerminationDate string `json:"terminationDate"`
	Active          *bool  `json:"active"`
}

// xid is the external id of the worker's identity and account: the employee
// id, which is also what other systems carry for correlation.
func (w *wWorker) xid() string {
	if w.EmployeeID != "" {
		return w.EmployeeID
	}
	return "workday:" + w.ID
}

// valid reports whether a worker row is usable, and trims its strings.
func (w *wWorker) valid() bool {
	if w.ID == "" || len(w.ID) > 128 || len(w.EmployeeID) > 128 {
		return false
	}
	for _, p := range []*string{&w.Descriptor, &w.Email, &w.Title, &w.Org.Descriptor, &w.Org.ID, &w.WorkerType.ID, &w.WorkerType.Descriptor,
		&w.Manager.ID, &w.Manager.EmployeeID, &w.Manager.Descriptor} {
		if len(*p) > maxField {
			*p = (*p)[:maxField]
		}
	}
	return true
}

// as returns what is true on day now. A hire date still ahead means not hired
// yet; a termination date still ahead means still working.
func (w *wWorker) as(now time.Time) (hired, terminated bool, termAt *time.Time) {
	hired = true
	if h := parseDate(w.HireDate); h != nil && h.After(now) {
		hired = false
	}
	if t := parseDate(w.TerminationDate); t != nil && !t.After(now) {
		terminated, termAt = true, t
	} else if t == nil && w.Active != nil && !*w.Active {
		terminated = true
	}
	return hired, terminated, termAt
}

// state is the checkpoint snapshot: every worker by id.
type state struct {
	Version int
	Workers map[string]*wWorker
}

const stateVersion = 1

func newState() *state { return &state{Version: stateVersion, Workers: map[string]*wWorker{}} }

// loadWatermark validates a stored cursor.
func loadWatermark(cursor string, now time.Time) (time.Time, bool) {
	wm, err := time.Parse(time.RFC3339, cursor)
	if err != nil || wm.After(now.Add(time.Hour)) {
		return time.Time{}, false
	}
	return wm, true
}

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	start := c.now()
	plan, err := connsync.Decide(ctx, System, checkpointName, start, c.cfg.MaxIncrementalAge)
	if err != nil {
		return nil, err
	}
	st, full := newState(), plan.Full
	var wm time.Time
	if !full {
		var ok bool
		if wm, ok = loadWatermark(plan.Prior.Cursor, start); !ok ||
			connsync.DecodeState(plan.Prior.State, st) != nil || st.Version != stateVersion || st.Workers == nil {
			st, full = newState(), true
		}
	}
	if full {
		err = c.readWorkers(ctx, st, nil)
	} else if err = c.readWorkers(ctx, st, &wm); isWatermarkRefused(err) {
		// Workday cannot answer from that watermark (too old): start over.
		st, full = newState(), true
		err = c.readWorkers(ctx, st, nil)
	}
	if err != nil {
		return nil, err
	}
	res := c.build(st, start)
	c.save(ctx, st, start, full)
	return res, nil
}

// isWatermarkRefused reports whether Workday refused an Updated_From value.
func isWatermarkRefused(err error) bool {
	s := connsync.Status(err)
	return s == 400 || s == 410
}

func (c *Connector) save(ctx context.Context, st *state, start time.Time, full bool) {
	store := connsync.StoreFrom(ctx)
	if store == nil {
		return
	}
	blob, err := connsync.EncodeState(st)
	if err != nil {
		_ = store.Delete(ctx, System, checkpointName)
		return
	}
	cp := &connsync.Checkpoint{Cursor: start.Add(-watermarkOverlap).UTC().Format(time.RFC3339), State: blob, UpdatedAt: start}
	if full {
		cp.FullSyncAt = &start
	} else if prior, err := store.Load(ctx, System, checkpointName); err == nil && prior != nil {
		cp.FullSyncAt = prior.FullSyncAt
	}
	_ = store.Save(ctx, System, checkpointName, cp)
}

// readWorkers reads the workers (those updated since wm, when given) and merges
// them into st by id.
func (c *Connector) readWorkers(ctx context.Context, st *state, wm *time.Time) error {
	q := url.Values{}
	if wm != nil {
		q.Set("Updated_From", wm.UTC().Format(time.RFC3339))
	}
	err := listAll(ctx, c, c.workers, q, func(w wWorker) error {
		if w.valid() {
			st.Workers[w.ID] = &w
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("workday: workers: %w", err)
	}
	return nil
}

// loadState returns the snapshot Discover saved, or reads the workers when
// there is none (no store, or an unusable checkpoint). Nothing is saved.
func (c *Connector) loadState(ctx context.Context) (*state, error) {
	if s := connsync.StoreFrom(ctx); s != nil {
		if cp, err := s.Load(ctx, System, checkpointName); err == nil && cp != nil {
			st := newState()
			if connsync.DecodeState(cp.State, st) == nil && st.Version == stateVersion && st.Workers != nil {
				return st, nil
			}
		}
	}
	st := newState()
	if err := c.readWorkers(ctx, st, nil); err != nil {
		return nil, err
	}
	return st, nil
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// teamSlug is the team name the joiner / mover flow keys birthright access on:
// the organization's name, lower case.
func teamSlug(name string) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

func (c *Connector) build(st *state, now time.Time) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{}
	ids := make([]string, 0, len(st.Workers))
	for id := range st.Workers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// manager references by worker id
	empOf := func(r wRef) string {
		if r.EmployeeID != "" {
			return r.EmployeeID
		}
		if m := st.Workers[r.ID]; m != nil && r.ID != "" {
			return m.xid()
		}
		return ""
	}
	seenIdent, seenAcct, seenGroup := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		w := st.Workers[id]
		hired, terminated, termAt := w.as(now)
		if !hired {
			continue // not a person yet: only the hire event exists (see StreamEvents)
		}
		xid := w.xid()
		name := w.Descriptor
		if name == "" {
			name = xid
		}
		status := "active"
		if terminated {
			status = "terminated"
		}
		hire := parseDate(w.HireDate)
		if c.cfg.EmitIdentities && !seenIdent[xid] {
			seenIdent[xid] = true
			rec := connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "human", Email: strp(w.Email),
				Department: strp(w.Org.Descriptor), Title: strp(w.Title), Status: status, HiredAt: hire, TerminatedAt: termAt}
			if m := empOf(w.Manager); m != "" && m != xid {
				rec.Manager = &connectors.IdentityRef{ExternalID: m}
			}
			res.Identities = append(res.Identities, rec)
		}
		if seenAcct[xid] {
			continue
		}
		seenAcct[xid] = true
		attrs := map[string]string{}
		for k, v := range map[string]string{"employeeId": w.EmployeeID, "email": w.Email, "workerType": w.WorkerType.Descriptor,
			"organization": w.Org.Descriptor, "businessTitle": w.Title, "hireDate": w.HireDate, "terminationDate": w.TerminationDate} {
			if v != "" {
				attrs[k] = v
			}
		}
		acctStatus := "active"
		if terminated {
			acctStatus = "disabled"
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: xid, Username: xid,
			Identity: &connectors.IdentityRef{ExternalID: xid, Email: w.Email}, Kind: "user", Status: acctStatus,
			CreatedAt: hire, Attributes: attrs})
		if terminated || w.Org.ID == "" || len(w.Org.ID) > 128 {
			continue
		}
		gx := "org:" + w.Org.ID
		if !seenGroup[gx] {
			seenGroup[gx] = true
			gname := w.Org.Descriptor
			if gname == "" {
				gname = w.Org.ID
			}
			res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: gx, Name: gname, Kind: "supervisory_org"})
		}
		res.Edges = append(res.Edges, connectors.EdgeRecord{Relation: "member_of",
			Src: connectors.Ref{Kind: "account", System: System, ExternalID: xid},
			Dst: connectors.Ref{Kind: "group", System: System, ExternalID: gx}})
	}
	return res
}
