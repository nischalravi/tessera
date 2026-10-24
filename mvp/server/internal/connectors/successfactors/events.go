package successfactors

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

var eventKeyRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// StreamEvents yields the lifecycle changes of the last EventWindow, and the
// future-dated ones, as HRIS events: an employment start is a joiner, an
// employment end a leaver, and a new job row that changes the department or the
// manager a mover. Each keeps its own effective date and is never applied by
// the connector (see the package comment). The events are derived from the
// employment and job dates, so a repeat read yields the same ids and ingest
// takes each once; since is not needed and is ignored.
func (c *Connector) StreamEvents(ctx context.Context, _ *time.Time, yield func(connectors.Event) error) error {
	now := c.now().UTC()
	from := now.Add(-c.cfg.EventWindow)
	st := &snapshot{users: map[string]*oUser{}, emps: map[string]*oEmp{}, jobs: map[string]*oJob{}, names: map[string]string{}}
	if err := c.readUsers(ctx, st); err != nil {
		return err
	}
	if err := c.readEmployments(ctx, st); err != nil {
		return err
	}
	// every job row that overlaps the window, including future-dated ones; the
	// row before a change ends the day before it starts, so look two days back
	byUser := map[string][]oJob{}
	far := now.AddDate(10, 0, 0)
	if err := c.readJobs(ctx, from.AddDate(0, 0, -2), far, func(j oJob) {
		byUser[string(j.UserID)] = append(byUser[string(j.UserID)], j)
	}); err != nil {
		return err
	}
	for id, js := range byUser {
		sort.SliceStable(js, func(i, k int) bool {
			a, b := parseTime(string(js[i].StartDate)), parseTime(string(js[k].StartDate))
			if a == nil || b == nil {
				return a == nil && b != nil
			}
			return a.Before(*b)
		})
		byUser[id] = js
		cur := currentJob(js, now)
		if cur == nil {
			cur = &js[0] // a pre-hire: the job it starts in
		}
		st.jobs[id] = cur
	}
	if err := c.readPeople(ctx, st); err != nil {
		return err
	}
	var recs []*connectors.HrisEventRecord
	seen := map[string]bool{}
	add := func(r *connectors.HrisEventRecord) {
		if r != nil && !seen[r.ExternalID] {
			seen[r.ExternalID] = true
			recs = append(recs, r)
		}
	}
	xidOf := map[string]string{}
	ps := c.people(st, now)
	for _, p := range ps {
		xidOf[p.userID] = p.personID
	}
	for _, p := range ps {
		if !eventKeyRE.MatchString(p.userID) || len(p.personID) > 128 {
			continue
		}
		add(c.joiner(p, from, now))
		add(c.leaver(p, from))
		js := byUser[p.userID]
		for i := 1; i < len(js); i++ {
			add(c.mover(p, js[i-1], js[i], from, xidOf))
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
	return ctx.Err()
}

// currentJob is the job row in force on day now.
func currentJob(js []oJob, now time.Time) *oJob {
	var cur *oJob
	for i := range js {
		s, e := parseTime(string(js[i].StartDate)), parseTime(string(js[i].EndDate))
		if s != nil && s.After(now) || e != nil && e.Before(now) {
			continue
		}
		if cur == nil || js[i].SeqNumber >= cur.SeqNumber {
			cur = &js[i]
		}
	}
	return cur
}

type payload struct{ ojson.Object }

func (p *payload) put(k, v string) {
	if v != "" {
		p.Object = append(p.Object, ojson.KV{Key: k, Value: v})
	}
}

func (c *Connector) joiner(p *person, from, now time.Time) *connectors.HrisEventRecord {
	if p.emp == nil || p.hire == nil || p.hire.Before(from) {
		return nil
	}
	var pl payload
	dept := ""
	if p.job != nil {
		dept = p.job.deptName()
	}
	pl.put("name", p.name)
	pl.put("email", p.email)
	pl.put("department", dept)
	pl.put("team", teamSlug(dept))
	pl.put("title", p.title)
	if p.job != nil && p.job.ManagerID != "" && string(p.job.ManagerID) != noManager {
		pl.put("manager_external_id", string(p.job.ManagerID))
	}
	pl.put("employee_id", p.personID)
	rec := &connectors.HrisEventRecord{ExternalID: "sf-evt-joiner-" + p.userID + "-" + day(*p.hire), Type: "joiner",
		Identity: &connectors.IdentityRef{ExternalID: p.personID, Email: p.email}, EffectiveAt: *p.hire}
	if p.hire.After(now) {
		rec.Identity = nil // pre-hire: there is no identity yet, the joiner flow creates it
	} else {
		// the employment record already made the identity; executing the
		// joiner would create the person a second time
		pl.Object = append(pl.Object, ojson.KV{Key: "historical", Value: true})
	}
	rec.Payload = pl.Object
	return rec
}

func (c *Connector) leaver(p *person, from time.Time) *connectors.HrisEventRecord {
	if p.emp == nil || p.end == nil || p.end.Before(from) {
		return nil
	}
	var pl payload
	pl.put("reason", "Termination")
	pl.put("last_day", day(*p.end))
	pl.put("employee_id", p.personID)
	return &connectors.HrisEventRecord{ExternalID: "sf-evt-leaver-" + p.userID + "-" + day(*p.end), Type: "leaver",
		Identity: &connectors.IdentityRef{ExternalID: p.personID, Email: p.email}, EffectiveAt: *p.end, Payload: pl.Object}
}

func (c *Connector) mover(p *person, prev, cur oJob, from time.Time, xidOf map[string]string) *connectors.HrisEventRecord {
	eff := parseTime(string(cur.StartDate))
	if eff == nil || eff.Before(from) {
		return nil
	}
	if cur.Department == prev.Department && cur.ManagerID == prev.ManagerID {
		return nil // a change that moves neither team nor manager changes no access
	}
	to := teamSlug(cur.deptName())
	if to == "" {
		// without a target team the mover plan would strip the old team's
		// access: better no event than a wrong one
		return nil
	}
	from2 := teamSlug(prev.deptName())
	if from2 == "" || cur.Department == prev.Department {
		from2 = to
	}
	mgr := func(j oJob) string {
		if j.ManagerID == "" || string(j.ManagerID) == noManager {
			return ""
		}
		if x := xidOf[string(j.ManagerID)]; x != "" {
			return x
		}
		return string(j.ManagerID)
	}
	var pl payload
	pl.put("from_department", prev.deptName())
	pl.put("to_department", cur.deptName())
	pl.put("from_team", from2)
	pl.put("to_team", to)
	pl.put("new_title", string(cur.JobTitle))
	pl.put("from_manager_external_id", mgr(prev))
	pl.put("to_manager_external_id", mgr(cur))
	pl.put("change", strings.ToLower(map[bool]string{true: "manager_change", false: "job_change"}[cur.Department == prev.Department]))
	pl.put("employee_id", p.personID)
	return &connectors.HrisEventRecord{ExternalID: "sf-evt-mover-" + p.userID + "-" + day(*eff), Type: "mover",
		Identity: &connectors.IdentityRef{ExternalID: p.personID, Email: p.email}, EffectiveAt: *eff, Payload: pl.Object}
}
